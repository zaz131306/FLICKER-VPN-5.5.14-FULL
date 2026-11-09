// popup.js — FLICKER VPN UI (TCP/443-стек: VLESS+Reality, Trojan, VMess, SS,
// WireGuard-«матрёшка»). Hysteria 2 — скрытый запасной стек (тумблер в Advanced).
//
// Безопасность: рендер только через textContent/createElement (никаких
// innerHTML-интерполяций пользовательских данных).

import { humanizeValidation } from "./lib/errors.js";
// FIX(5.5.8): разбор конфигов WireGuard/AmneziaWG прямо в попапе
import { parseWireGuardConf, parseAmneziaParams } from "./lib/share-parser.js";

// Хук самотестирования для live-проверок в реальном Firefox (geckodriver)
window.__flickerSelfTest = { ok: false, errors: [], status: null, nativeOnline: null, selected: null, tabs: {} };
window.addEventListener("error", (e) => {
  if (window.__flickerSelfTest) window.__flickerSelfTest.errors.push(String(e?.message || e));
});

const $ = (id) => document.getElementById(id);

const state = {
  servers: [],
  selectedId: null,
  status: "disconnected",
  speedHistory: [],
  autoSelectEnabled: false,
  busy: false,
  editingId: null,
  connectAfterSave: false,
  hideDead: true,
  lastRefreshAt: null,
  experimentalUdp: false,
  probe: { active: false, total: 0, done: 0, alive: 0, mode: null, pass: 0 },
  stageById: new Map(),     // id -> {stage, ok} для live-иконок проверки
  subscriptions: { count: 0, enabled: 0, lastFetchAt: null },
  // FIX(5.5.5): отбор по эффективности и постоянный блок мусорных нод
  maxPingMs: 1200,          // потолок задержки: медленнее = не «живой сервер»
  holdMaxMs: 120000,        // сколько держим прокси при обрыве
  blockedTotal: 0,
  blockedEntries: [],
  blockedVisible: false
};

// ---------- utils ----------
function toast(text, isError = false, ms = 2200) {
  const t = $("toast");
  t.textContent = text;
  t.className = "toast" + (isError ? " error" : "");
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => t.classList.add("hidden"), ms);
}

const humanError = humanizeValidation;

// Хватает ли учётных данных для протокола сервера
function hasCreds(s) {
  if (!s) return false;
  switch (s.protocol) {
    case "vless":
    case "vmess":
      return !!s.uuid;
    case "trojan":
    case "shadowsocks":
    case "hysteria2":
      return !!s.auth;
    case "wireguard":
      return !!(s.wireguard && s.wireguard.privateKey && s.wireguard.peerPublicKey);
    default:
      return true;
  }
}

// Живость: -2 мёртв, -1 неизвестно (тишина), null не проверялся, >=0 жив
const isDead = (s) => s.ping === -2;
const isAlive = (s) => typeof s.ping === "number" && s.ping >= 0;
// FIX(5.5.5): «живой» для пользователя = живой И не медленнее потолка.
// Узел за 4000 мс формально отвечал, но работать через него нельзя — в списке
// он помечается как медленный и в автовыбор не попадает.
const isSlow = (s) => isAlive(s) && s.ping > state.maxPingMs;
const isUsable = (s) => isAlive(s) && s.ping <= state.maxPingMs && !s.blocked;
function pingLabel(s) {
  if (s.checking || state.stageById.has(s.id)) return "⏳";
  if (s.ping == null) return "—";
  if (s.ping === -1) return "?";
  if (s.ping === -2) return "✕";
  if (isSlow(s)) return "🐢 " + s.ping + " ms";
  return s.ping + " ms";
}

// Статус-иконка сервера: ✅ живой / ⏳ проверяется / ❌ мёртвый / ❔ не проверен
function statusIcon(s) {
  if (isSlow(s)) return "🐢";
  if (s.blocked) return "⛔";
  if (s.checking || state.stageById.has(s.id)) {
    const st = state.stageById.get(s.id);
    return "⏳" + (st ? { tcp: "·tcp", quic: "·quic", http: "·http", geoip: "·geo" }[st.stage] || "" : "");
  }
  if (isAlive(s)) return "✅";
  if (isDead(s)) return "❌";
  return "❔";
}

function lastCheckLabel(s) {
  if (!s.lastCheckAt) return "";
  const d = new Date(s.lastCheckAt);
  const ageMin = Math.round((Date.now() - s.lastCheckAt) / 60000);
  if (ageMin < 1) return "проверен только что";
  if (ageMin < 60) return `проверен ${ageMin} мин назад`;
  if (ageMin < 1440) return `проверен ${Math.round(ageMin / 60)} ч назад`;
  return "проверен " + d.toLocaleDateString();
}

function fmtMB(bytes) {
  return ((bytes || 0) / 1024 / 1024).toFixed(1) + " MB";
}

function el(tag, className, text) {
  const n = document.createElement(tag);
  if (className) n.className = className;
  if (text != null) n.textContent = text;
  return n;
}

// ---------- tabs ----------
document.querySelectorAll(".tab").forEach((t) => {
  t.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((x) => x.classList.remove("active"));
    t.classList.add("active");
    const panel = document.querySelector(`.panel[data-panel="${t.dataset.tab}"]`);
    if (panel) panel.classList.add("active");
    if (window.__flickerSelfTest) {
      window.__flickerSelfTest.tabs[t.dataset.tab] = {
        clicked: true,
        panelVisible: !!panel && getComputedStyle(panel).display !== "none",
        children: panel ? panel.childElementCount : 0
      };
    }
  });
});

// ---------- servers ----------
// Троттлинг рендера: probeStage/serversUpdated приходят пачками (тысячи
// событий на прогон), полный ререндер списка на каждое событие убивает
// контент-процесс вкладки (проверено живым Firefox: «Browsing context has
// been discarded»).
let renderQueued = false;
let lastProbeBurstAt = 0;   // момент последнего probeStage-события
function scheduleRender() {
  if (renderQueued) return;
  renderQueued = true;
  // Во время массовой проверки (1000+ серверов) события идут по несколько
  // раз в секунду: перерисовка 400 строк каждые 400 мс перегревает процесс
  // вкладки вплоть до OOM (проверено живым Firefox на 1 ГБ RAM). В burst-
  // режиме рендерим раз в 2 с — счётчики живы/мёртвы всё равно обновляются.
  const delay = Date.now() - lastProbeBurstAt < 3000 ? 2000 : 400;
  setTimeout(() => {
    renderQueued = false;
    renderServers($("serverSearch").value);
  }, delay);
}

const MAX_RENDER_ITEMS = 400; // потолок строк в списке (остальные — за подсказкой)

async function loadServers() {
  const res = await browser.runtime.sendMessage({ action: "getServers" });
  state.servers = res.servers || [];
  renderServers();
}

function renderServers(filter = "") {
  const list = $("serverList");
  const proto = $("protoFilter").value;
  list.innerHTML = "";
  const visibleAll = state.servers
    // FIX(5.5.5): «Скрывать недоступные» скрывает и мёртвых, и мусор по пингу —
    // пользователю нужен рабочий список, а не тысяча узлов за 4000 мс
    .filter((s) => !(state.hideDead && (isDead(s) || isSlow(s) || s.blocked)))
    .filter((s) => !filter || (s.name || "").toLowerCase().includes(filter.toLowerCase()))
    .filter((s) => proto === "all" || s.protocol === proto)
    .filter((s) => s.protocol !== "hysteria2" || state.experimentalUdp || isAlive(s) || s.id === state.selectedId);
  // hideDead выключен → пользователь хочет ВИДЕТЬ мёртвых: показываем их
  // первыми (иначе при списке 1000+ они не попадут в лимит отрисовки).
  // Сортировка стабильна: внутри групп сохраняется порядок «лучшие сверху».
  if (!state.hideDead) {
    // непригодные (мёртвые/медленные) вниз, пригодные — в порядке эффективности
    const bad = (x) => (isDead(x) || isSlow(x) || x.blocked) ? 1 : 0;
    visibleAll.sort((a, b) => bad(b) - bad(a));
  }
  let visible = visibleAll.slice(0, MAX_RENDER_ITEMS);
  // выбранный сервер виден ВСЕГДА, даже если не попал в лимит отрисовки
  // (ICU-сортировка ставит emoji-имена перед латиницей — без этого только
  // что сохранённый сервер мог «пропасть» из длинного списка)
  if (state.selectedId && !visible.some((s) => s.id === state.selectedId)) {
    const sel = visibleAll.find((s) => s.id === state.selectedId);
    if (sel) visible = [sel, ...visible];
  }
  visible.forEach((s) => {
      const checking = s.checking || state.stageById.has(s.id);
      const classes = ["server-item"];
      if (s.id === state.selectedId) classes.push("selected");
      if (checking) classes.push("checking");
      // мёртвые не удаляем из списка, а помечаем серым
      if (isDead(s) && !checking) classes.push("dead");
      const item = el("div", classes.join(" "));

      item.appendChild(el("span", "flag", s.flag || "🌍"));
      item.appendChild(el("span", "status-icon", statusIcon(s)));

      const info = el("div", "info");
      info.appendChild(el("div", "name", s.name || s.id));

      const protoLabel = { vless: "VLESS", trojan: "TROJAN", vmess: "VMESS", shadowsocks: "SS", wireguard: "WG", hysteria2: "HY2", direct: "DIRECT" }[s.protocol] || (s.protocol || "?").toUpperCase();
      const metaBits = [`${s.host}:${s.port}`, protoLabel];
      if (s.protocol === "vless" && s.reality) metaBits.push("Reality");
      if (s.protocol === "vless" && s.flow) metaBits.push("Vision");
      if (s.protocol === "wireguard" && s.detour) metaBits.push("🪆 матрёшка");
      // FIX(5.5.8): видно, у каких нод есть обфускация от DPI
      if (s.protocol === "wireguard" && s.wireguard?.amnezia) metaBits.push("🛡 AWG");
      if (s.countryCode) metaBits.push(s.countryCode);
      if (s.sub) metaBits.push("подписка");
      if (s.demo && !hasCreds(s)) metaBits.push("демо (нужен пароль)");
      info.appendChild(el("div", "meta", metaBits.join(" · ")));

      const sub = el("div", "sub-meta");
      const bits = [];
      const lc = lastCheckLabel(s);
      if (lc) bits.push(lc);
      if (s.exitIp) bits.push("exit " + s.exitIp);
      if (isDead(s) && s.lastError) bits.push(s.lastError);
      if (s.checksTotal) bits.push(`успех ${s.checksOk || 0}/${s.checksTotal}`);
      sub.textContent = bits.join(" · ");
      if (bits.length) info.appendChild(sub);
      item.appendChild(info);

      const pingCls = isDead(s) ? " dead" : (isAlive(s) ? "" : " unknown");
      item.appendChild(el("span", "ping" + pingCls, pingLabel(s)));

      const edit = el("button", "edit-btn", "✎");
      edit.title = "Изменить сервер";
      edit.addEventListener("click", (e) => {
        e.stopPropagation();
        openServerModal(s, false);
      });
      item.appendChild(edit);

      const del = el("button", "delete-btn", "×");
      del.title = "Удалить";
      del.addEventListener("click", (e) => {
        e.stopPropagation();
        deleteServer(s.id);
      });
      item.appendChild(del);

      item.addEventListener("click", () => onServerPicked(s.id));
      item.title = s.lastError ? String(s.lastError) : (s.name || s.id);
      list.appendChild(item);
    });

  if (visibleAll.length > MAX_RENDER_ITEMS) {
    list.appendChild(el("div", "meta", `…и ещё ${visibleAll.length - MAX_RENDER_ITEMS} (список отсортирован: лучшие сверху)`));
  }
  if (!list.childElementCount) {
    list.appendChild(el("div", "meta", state.hideDead
      ? "Нет доступных серверов. Обновите подписку или добавьте свой."
      : "Ничего не найдено"));
  }
  // счётчик живых и время обновления
  const subs = state.servers.filter((s) => s.sub);
  // FIX(5.5.5): считаем ПРИГОДНЫХ (ответили в пределах потолка), а не просто
  // ответивших: иначе «живых: 300» при 250 из них за 4000 мс вводило в заблуждение
  const usable = state.servers.filter(isUsable).length;
  const alive = state.servers.filter(isAlive).length;
  const slow = state.servers.filter(isSlow).length;
  const dead = state.servers.filter(isDead).length;
  const checking = state.servers.filter((s) => s.checking).length;
  $("serversCountVal").textContent =
    `Пригодных: ${usable} из ${state.servers.length}` +
    (usable !== alive ? ` · живых ${alive}` : "") +
    (slow ? ` · 🐢 медленных: ${slow}` : "") +
    (dead ? ` · мёртвых: ${dead}` : "") +
    (checking ? ` · ⏳ ${checking}` : "");
  renderBlockedLine();
  $("lastRefreshVal").textContent = state.lastRefreshAt
    ? "обновлено " + new Date(state.lastRefreshAt).toLocaleTimeString()
    : "ещё не обновлено";
  $("subsInfoVal").textContent = subs.length
    ? `Из подписок: ${subs.length} · источников: ${state.subscriptions.count || 0}`
    : "Подписки не загружены — нажмите «Обновить подписку»";
}

// ---------- FIX(5.5.5): постоянный блок мусорных нод ----------
//
// Узел, признанный мусором (пинг выше потолка, серия провалов, нестабильность),
// уходит в реестр блоков по ОТПЕЧАТКУ (адрес+порт+протокол+ключ), а не по id.
// Поэтому обновление подписки не может вернуть его в список. Здесь — строка
// «в блоке: N» и панель с причинами и точечной разблокировкой.

/** renderBlockedLine — строка-сводка под настройкой отбора. */
function renderBlockedLine() {
  const val = $("blockedVal");
  if (!val) return;
  const n = state.blockedTotal || 0;
  val.textContent = n
    ? `В блоке: ${n} (не вернутся в список)`
    : "В блоке: 0";
  const show = $("showBlockedBtn");
  const clear = $("clearBlockedBtn");
  if (show) show.classList.toggle("hidden", !n);
  if (clear) clear.classList.toggle("hidden", !n);
}

/** loadBlocklist — забрать реестр из background и нарисовать. */
async function loadBlocklist() {
  const r = await browser.runtime.sendMessage({ action: "getBlocklist" }).catch(() => null);
  if (!r) return;
  state.blockedTotal = r.total || 0;
  state.blockedEntries = r.entries || [];
  state.blockLabels = r.labels || {};
  renderBlockedLine();
  if (state.blockedVisible) renderBlockedList();
}

/** renderBlockedList — панель с причинами блока и точечной разблокировкой. */
function renderBlockedList() {
  const box = $("blockedList");
  if (!box) return;
  if (!state.blockedVisible) { box.classList.add("hidden"); box.innerHTML = ""; return; }
  box.classList.remove("hidden");
  box.innerHTML = "";
  if (!state.blockedEntries.length) {
    box.appendChild(el("div", "meta", "Пусто"));
    return;
  }
  const LIMIT = 200;
  for (const e of state.blockedEntries.slice(0, LIMIT)) {
    const row = el("div", "blocked-item");
    const why = state.blockLabels?.[e.reason] || e.reason || "—";
    row.appendChild(el("span", "", "⛔"));
    const info = el("div", "why");
    info.appendChild(el("div", "", e.label || e.host || e.key));
    info.appendChild(el("div", "meta",
      `${why}${e.ping ? " · " + e.ping + " мс" : ""}` +
      `${e.hits > 1 ? " · подписка пыталась вернуть " + e.hits + "×" : ""}` +
      `${e.blockedAt ? " · " + new Date(e.blockedAt).toLocaleDateString() : ""}`));
    row.appendChild(info);
    const btn = el("button", "link-btn unblock", "разблокировать");
    btn.addEventListener("click", async () => {
      await browser.runtime.sendMessage({ action: "unblockServer", key: e.key, id: e.serverId || null });
      toast("Узел разблокирован — вернётся после ближайшей проверки");
      await loadBlocklist();
      loadServers();
    });
    row.appendChild(btn);
    box.appendChild(row);
  }
  if (state.blockedEntries.length > LIMIT) {
    box.appendChild(el("div", "meta", `…и ещё ${state.blockedEntries.length - LIMIT}`));
  }
}

// Индикатор прогресса проверки
function renderProbeProgress() {
  const p = state.probe;
  const box = $("probeProgress");
  if (!p.active) {
    box.classList.add("hidden");
    return;
  }
  box.classList.remove("hidden");
  const pct = p.total ? Math.round((p.done / p.total) * 100) : 0;
  $("probeBarFill").style.width = pct + "%";
  const passLabel = p.passes > 2
    ? ` (прогон ${p.pass}/${p.passes})`
    : (p.pass === 2 ? " (повторный прогон)" : "");
  $("probeProgressText").textContent =
    `⏳ Проверяется ${p.done}/${p.total} · живых ${p.alive}${passLabel}`;
}

/**
 * onServerPicked — клик по серверу в списке.
 *
 * Исправление бага версии 4: selectServer() только перерисовывал шапку, поэтому
 * при подключённом туннеле выбор другой ноды выглядел как переключение, но
 * трафик продолжал идти через старую. Единственным способом сменить сервер было
 * «отключиться → подключиться», и между этими нажатиями маршрутизация
 * снималась — окно утечки в системный прокси.
 * Теперь выбор другой ноды при активном туннеле вызывает switchServer в
 * background, который меняет её атомарно.
 */
async function onServerPicked(id) {
  const prevSelected = state.selectedId;
  selectServer(id);

  if (state.status !== "connected" && state.status !== "connecting") return;
  const active = state.currentServerId;
  if (!active || active === id) return;

  const s = state.servers.find((x) => x.id === id);
  state.busy = true;
  toast(`Переключаюсь на ${s?.name || id}…`);
  const r = await browser.runtime.sendMessage({ action: "switchServer", serverId: id }).catch(() => null);
  state.busy = false;
  if (!r?.ok) {
    toast(r?.error ? "Ошибка: " + humanError(r.error) : "Не удалось переключиться", true, 4500);
    if (r?.rolledBack) selectServer(active);   // откатились — возвращаем и выбор
    else selectServer(prevSelected);
  }
  updateUI();
}

function selectServer(id) {
  state.selectedId = id;
  const s = state.servers.find((x) => x.id === id);
  if (!s) return;
  $("currentFlag").textContent = s.flag || "🌍";
  $("currentName").textContent = s.name || s.id;
  const protoLabel = { vless: "VLESS", trojan: "TROJAN", vmess: "VMESS", shadowsocks: "SS", wireguard: "WG", hysteria2: "HY2", direct: "DIRECT" }[s.protocol] || (s.protocol || "?").toUpperCase();
  $("currentProto").textContent = protoLabel + (s.reality ? "·REALITY" : "") + (s.detour ? "·🪆" : "");
  $("currentPing").textContent = pingLabel(s);
  $("pingVal").textContent = pingLabel(s);
  renderServers($("serverSearch").value);
  browser.storage.local.set({ selectedServer: id });
}

async function deleteServer(id) {
  if (!confirm("Удалить этот сервер?")) return;
  const res = await browser.runtime.sendMessage({ action: "deleteServer", serverId: id });
  state.servers = res.servers || [];
  if (state.selectedId === id) {
    state.selectedId = null;
    $("currentFlag").textContent = "🌍";
    $("currentName").textContent = "Выберите сервер";
    $("currentProto").textContent = "—";
    $("currentPing").textContent = "— ms";
  }
  renderServers($("serverSearch").value);
  toast("Сервер удалён");
}

$("serverSearch").addEventListener("input", (e) => renderServers(e.target.value));
$("protoFilter").addEventListener("change", () => renderServers($("serverSearch").value));

// ---------- connect ----------
async function doConnect(s) {
  if (state.busy) return;
  state.busy = true;
  $("connectBtn").disabled = true;
  try {
    const res = await browser.runtime.sendMessage({
      action: "toggleConnect",
      config: s ? { ...s } : null
    });
    if (!res.ok) toast("Ошибка: " + humanError(res.error), true, 4500);
    else toast("Подключение…");
  } finally {
    state.busy = false;
    $("connectBtn").disabled = false;
    updateUI();
  }
}

$("connectBtn").addEventListener("click", async () => {
  if (state.busy) return;
  if (state.status !== "disconnected") {
    await browser.runtime.sendMessage({ action: "disconnect" });
    return;
  }
  const s = state.servers.find((x) => x.id === state.selectedId);
  if (!s && !state.autoSelectEnabled) {
    toast("Выберите сервер на вкладке «Серверы»", true);
    return;
  }
  if (s && !hasCreds(s)) {
    toast("У сервера нет учётных данных — заполните форму", true, 3500);
    openServerModal(s, true);
    return;
  }
  await doConnect(s);
});

// ---------- auto select / auto switch ----------
$("autoSelectToggle").addEventListener("change", async (e) => {
  state.autoSelectEnabled = e.target.checked;
  await browser.runtime.sendMessage({ action: "setAutoSelect", enabled: e.target.checked });
});

$("autoSwitchToggle").addEventListener("change", async (e) => {
  await browser.runtime.sendMessage({ action: "setAutoSwitch", enabled: e.target.checked });
});

// ---------- подписки и проверка серверов ----------
function setProbeButtonsBusy(busy) {
  $("refreshSubsBtn").disabled = busy;
  $("checkAllBtn").disabled = busy;
}

$("refreshSubsBtn").addEventListener("click", async () => {
  const btn = $("refreshSubsBtn");
  btn.textContent = "⏳ Скачиваем подписки…";
  btn.disabled = true;
  try {
    const res = await browser.runtime.sendMessage({ action: "refreshSubscriptions", force: true });
    if (res?.ok) {
      const perSource = (res.perSource || [])
        .map((p) => p.error ? `${p.id}:❌` : (p.skipped ? null : `${p.id}:${p.count}`))
        .filter(Boolean).join(" · ");
      toast(`Подписки обновлены: +${res.added} новых, всего ${res.total} (${perSource})`, false, 3500);
      await loadServers();
    } else {
      toast("Ошибка: " + humanError(res?.error || "подписки не обновились"), true, 4000);
    }
  } finally {
    btn.textContent = "📥 Обновить подписку";
    btn.disabled = false;
  }
});

$("checkAllBtn").addEventListener("click", async () => {
  const res = await browser.runtime.sendMessage({ action: "checkAllServers" });
  if (!res?.ok) {
    toast(res?.error || "Не удалось запустить проверку", true, 3500);
    return;
  }
  state.probe = { active: true, total: res.total || 0, done: 0, alive: 0, mode: res.mode, pass: res.pass };
  state.stageById.clear();
  setProbeButtonsBusy(true);
  renderProbeProgress();
  toast(`Проверяем ${res.total} серверов: TCP → TLS/QUIC → HTTP через туннель`, false, 3000);
});

$("cancelProbeBtn").addEventListener("click", async () => {
  await browser.runtime.sendMessage({ action: "cancelProbe" });
});

// FIX(5.5.9): полный отчёт об обрывах — одним кликом, чтобы разбор не требовал
// от пользователя вручную собирать диагностику
$("breakReportBtn").addEventListener("click", () => { copyBreakReport(); });

$("subsSettingsBtn").addEventListener("click", () => {
  if (browser.runtime.openOptionsPage) browser.runtime.openOptionsPage();
  else window.open(browser.runtime.getURL("options.html"));
});

// ---------- UI update ----------
const QUALITY_MAP = {
  excellent: "🟢 Отличное",
  good: "🟡 Хорошее",
  fair: "🟠 Среднее",
  poor: "🔴 Плохое",
  unknown: "—"
};

async function updateUI() {
  let st;
  try {
    st = await browser.runtime.sendMessage({ action: "getStatus" });
  } catch (e) {
    return; // background ещё не готов
  }
  state.status = st.status || (st.isConnected ? "connected" : "disconnected");
  // v5: id ноды, которая РЕАЛЬНО держит туннель. Без него шапка могла показывать
  // один сервер, а трафик шёл через другой (selectServer только перерисовывал UI).
  state.currentServerId = st.currentServer?.id || null;
  state.switching = !!st.switching;
  updateDirectWarn(st);   // FIX(5.5.9): direct/DPI-узел — это не VPN, говорим сразу

  const btn = $("connectBtn");
  const badge = $("statusBadge");

  badge.classList.remove("active", "pending", "blocked");
  if (st.killSwitchBlocked) {
    badge.textContent = "KILL SWITCH";
    badge.classList.add("blocked");
    btn.classList.remove("connected");
    btn.querySelector(".btn-label").textContent = "СБРОСИТЬ БЛОКИРОВКУ";
    btn.querySelector(".btn-icon").textContent = "⛔";
  } else if (state.status === "connected") {
    badge.textContent = "CONNECTED";
    badge.classList.add("active");
    btn.classList.add("connected");
    btn.querySelector(".btn-label").textContent = "ОТКЛЮЧИТЬСЯ";
    btn.querySelector(".btn-icon").textContent = "■";
  } else if (state.status === "connecting") {
    badge.textContent = "CONNECTING…";
    badge.classList.add("pending");
    btn.classList.remove("connected");
    btn.querySelector(".btn-label").textContent = "ПОДКЛЮЧЕНИЕ…";
    btn.querySelector(".btn-icon").textContent = "◌";
  } else {
    badge.textContent = "DISCONNECTED";
    btn.classList.remove("connected");
    btn.querySelector(".btn-label").textContent = "ПОДКЛЮЧИТЬСЯ";
    btn.querySelector(".btn-icon").textContent = "▶";
  }

  if (st.subscriptions) state.subscriptions = st.subscriptions;
  if (st.probe?.passes) state.probe.passes = st.probe.passes;
  if (st.probe && st.probe.active && !state.probe.active) {
    state.probe = { ...state.probe, ...st.probe };
    setProbeButtonsBusy(true);
    renderProbeProgress();
  }

  $("speedVal").textContent = (st.currentSpeed ?? 0).toFixed(1) + " Mbps";
  $("trafficVal").textContent = fmtMB(st.bytesReceived);
  $("sentVal").textContent = fmtMB(st.bytesSent);
  $("recvVal").textContent = fmtMB(st.bytesReceived);
  $("rttVal").textContent = (st.stats?.rtt || 0) + " ms";
  $("dropVal").textContent = st.stats?.droppedPackets || 0;

  const quality = st.stats?.connectionQuality || "unknown";
  $("qualityVal").textContent = QUALITY_MAP[quality] || "—";
  $("currentQuality").textContent = QUALITY_MAP[quality] || "—";
  const protoNames = { vless: "VLESS", trojan: "TROJAN", vmess: "VMESS", shadowsocks: "SS", wireguard: "WIREGUARD", hysteria2: "HY2", direct: "DIRECT" };
  $("protoVal").textContent = st.currentProtocol ? (protoNames[st.currentProtocol] || st.currentProtocol.toUpperCase()) : "—";

  // Три состояния, а не два: «порт открыт» ещё не значит, что хост живой.
  // Firefox создаёт Port сразу, а «No such native application» прилетает позже
  // через onDisconnect — в версии 4 точка всё это время горела зелёным.
  const dot = $("nativeStatus");
  const verified = !!st.nativeVerified;
  const portOnly = !!st.nativeOnline && !verified;
  dot.className = "native-dot " + (verified ? "online" : "offline");
  dot.title = verified
    ? `Native host: подключён${st.nativeInfo?.version ? ", v" + st.nativeInfo.version : ""}`
    : portOnly
      ? "Native host: порт открыт, но hello не пришёл — процесс не запустился или упал"
      : "Native host: НЕ подключён" + (st.nativeLastError ? "\nПричина: " + st.nativeLastError : "");
  $("nativeVal").textContent = verified ? "online" : portOnly ? "port" : "offline";
  $("nativeVal").style.color = verified ? "var(--accent-2)" : portOnly ? "var(--warning)" : "var(--danger)";
  // 5.5.4: старый хост (4.x) — не «online», а причина всех срывов подключения:
  // красим в красный и говорим прямо, что делать.
  {
    const hv = String(st.nativeInfo?.version || "");
    const hMajor = parseInt(hv.split(".")[0], 10);
    if (verified && !Number.isNaN(hMajor) && hMajor < 5) {
      dot.className = "native-dot offline";
      dot.title = `Native host v${hv} УСТАРЕЛ — установите FLICKER VPN 5.5.4 (FlickerVPN-Setup-5.5.4.exe)`;
      $("nativeVal").textContent = `v${hv} (устарел!)`;
      $("nativeVal").style.color = "var(--danger)";
    }
  }
  {
    // FIX(5.5.13): показываем и порт хоста, и порт, на котором ФАКТИЧЕСКИ
    // вооружён браузер. При autoPort они расходятся, и молчание панели стоило
    // пользователю часа диагностики: «SOCKS5 порт: 1080» при живом 1081.
    const sp = st.socksPort || 1080;
    const ap = st.armedPort;
    const armed = st.proxyArmed && ap && Number(ap) !== Number(sp) ? ` · прокси на ${ap}` : "";
    $("footerInfo").textContent = st.tunnel
      ? `${st.tunnel.mode} · SOCKS5 127.0.0.1:${sp}${armed}`
      : `SOCKS5 127.0.0.1:${sp}${armed}`;
  }
  updateProxyWarn(st);
  // версия берётся из манифеста: в версии 4 здесь было захардкожено «v4.0.0»,
  // из-за чего новая сборка выглядела как старая
  if ($("verVal")) {
    try {
      const mf = browser.runtime.getManifest?.();
      $("verVal").textContent = "v" + (mf?.version || "?");
    } catch { $("verVal").textContent = "v?"; }
  }

  if (st.stats?.startedAt && state.status === "connected") {
    const sec = Math.floor((Date.now() - st.stats.startedAt) / 1000);
    const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
    $("uptimeVal").textContent = h > 0 ? `${h}h ${m}m ${s}s` : `${m}m ${s}s`;
  } else {
    $("uptimeVal").textContent = "—";
  }

  state.speedHistory.push(st.currentSpeed || 0);
  if (state.speedHistory.length > 60) state.speedHistory.shift();
  drawChart();

  if (window.__flickerSelfTest) {
    window.__flickerSelfTest.status = state.status;
    window.__flickerSelfTest.nativeOnline = st.nativeOnline;
    window.__flickerSelfTest.selected = state.selectedId;
    window.__flickerSelfTest.killSwitchBlocked = st.killSwitchBlocked;
    window.__flickerSelfTest.proxyMode = st.proxyMode;
    window.__flickerSelfTest.socksPort = st.socksPort;
    window.__flickerSelfTest.hostCaps = st.nativeInfo?.caps?.length || 0;
    window.__flickerSelfTest.nativeCompat = st.nativeInfo?.compat || null;
  }
}

function drawChart() {
  const c = $("speedChart");
  if (!c) return;
  const ctx = c.getContext("2d");
  const W = c.width, H = c.height;
  ctx.clearRect(0, 0, W, H);
  const data = state.speedHistory;
  if (data.length < 2) return;
  const max = Math.max(1, ...data);

  ctx.strokeStyle = "rgba(136,146,176,0.15)";
  ctx.lineWidth = 1;
  for (let i = 1; i < 4; i++) {
    const y = (H / 4) * i;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
  }

  ctx.strokeStyle = "#5b8cff";
  ctx.lineWidth = 2;
  ctx.beginPath();
  data.forEach((v, i) => {
    const x = (i / (data.length - 1)) * W;
    const y = H - (v / max) * (H - 10) - 5;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.stroke();

  ctx.lineTo(W, H); ctx.lineTo(0, H); ctx.closePath();
  const grad = ctx.createLinearGradient(0, 0, W, H);
  grad.addColorStop(0, "rgba(91,140,255,0.4)");
  grad.addColorStop(1, "rgba(91,140,255,0)");
  ctx.fillStyle = grad;
  ctx.fill();

  ctx.fillStyle = "#8892b0";
  ctx.font = "9px sans-serif";
  ctx.fillText(max.toFixed(1) + " Mbps", 4, 10);
}

// ---------- Failsafe прокси (v5.3) ----------
// Расширение не имеет права оставить браузер без интернета: прокси вооружается
// только после подтверждения от native host и автоматически освобождается, если
// туннель умер. Здесь — индикация состояния и аварийная кнопка.

function proxyWarnMessage(st) {
  // FIX(5.5.12): режим маршрутизации «Ничего» — выбор пользователя, а не авария.
  // Раньше он показывался как «Прокси возвращён браузеру» / «VPN подключён, но
  // прокси не вооружён», то есть как поломка, которую надо чинить.
  if (st.tunnel?.mode === "off" || st.proxyMode === "off-mode") {
    return "Маршрутизация через VPN выключена (режим «Ничего»): трафик идёт напрямую. " +
           "Вернуть VPN: вкладка «Дополнительно» → «Маршрутизация» → Smart или «Всё через VPN».";
  }
  // Порядок веток важен: "released" — самое важное состояние для пользователя
  // (расширение отдало прокси обратно), его нельзя перекрывать сообщением
  // «подключён, но не вооружён», даже если status ещё connected.
  if (st.proxyMode === "holding") {
    return "Обрыв туннеля: прокси НЕ возвращён браузеру, трафик держится на туннеле — " +
           "восстанавливаю соединение (до 60 c). Страницы могут открываться с задержкой.";
  }
  if (st.proxyMode === "released") {
    return "Прокси возвращён браузеру — трафик идёт напрямую." +
      (st.proxyReleasedByUser
        ? ""
        // FIX(5.5.5): состояние больше не конечное — расширение само
        // поднимает туннель заново, говорим об этом прямо
        : " Туннель не подтвердил живость, сработала защита. Восстановление идёт автоматически " +
          "(повтор каждые 15–60 c); если не вернётся — проверь native host.");
  }
  if (st.status === "connected" && !st.proxyArmed) {
    if (st.proxyMode === "pending-verify") {
      return "Туннель поднимается: ждём, пока native host подтвердит, что SOCKS5 слушает. " +
             "Прокси НЕ перехвачен, браузер работает напрямую.";
    }
    return `VPN подключён, но прокси не вооружён (режим: ${st.proxyMode || "?"}). Браузер работает напрямую.`;
  }
  if (st.lastProxyError && !st.proxyArmed) return "Ошибка прокси: " + st.lastProxyError;
  return null;
}

function updateProxyWarn(st) {
  const box = $("proxyWarn"), txt = $("proxyWarnText");
  if (!box || !txt) return;
  const msg = proxyWarnMessage(st);
  if (msg) { txt.textContent = msg; box.classList.remove("hidden"); }
  else box.classList.add("hidden");
}

$("releaseProxyBtn").addEventListener("click", async () => {
  const r = await browser.runtime.sendMessage({
    action: "releaseProxy", reason: "по кнопке в popup"
  }).catch(() => null);
  toast(r?.ok ? "Прокси возвращён браузеру" : "Не удалось освободить прокси", !r?.ok, 4000);
  updateUI();
});

// ---------- Режим маршрутизации (v5) ----------
// Решение «что через VPN» принимается в background.js (lib/split-tunnel.js),
// здесь только отображение и переключение.

const TUNNEL_MODE_UI = {
  smart:   { short: "Smart",        hint: "зарубежное через VPN, РФ напрямую" },
  blocked: { short: "Только блок.", hint: "минимальный расход ноды" },
  all:     { short: "Всё",          hint: "полный туннель — медленно на бесплатной ноде" },
  off:     { short: "Выкл",         hint: "трафик идёт напрямую" }
};

// FIX(5.5.12): последнее ПОДТВЕРЖДЁННОЕ расширение значение режима. Нужно,
// чтобы откатить селект, если изменение оказалось случайным (колесо мыши).
let lastKnownTunnelMode = null;

function applyTunnelUi(t) {
  if (!t) return;
  const ui = TUNNEL_MODE_UI[t.mode] || { short: t.mode, hint: "" };
  if (t.mode) lastKnownTunnelMode = t.mode;

  const sel = $("tunnelMode");
  if (sel && sel.value !== t.mode) sel.value = t.mode;

  const note = $("tunnelModeNote");
  if (note) note.textContent = t.description || ui.hint;

  const stats = $("tunnelModeStats");
  if (stats) {
    // собираем текстом, без innerHTML: значения приходят из background
    const lines = [
      `через VPN: ${t.vpnDomains} доменов`,
      `напрямую: ${t.directDomains} доменов + ${t.directCidrs} подсетей РФ`,
      t.perRequest
        ? "решение принимается по каждому запросу"
        : "fallback: manual proxy (CIDR-правила применит sing-box)"
    ];
    stats.textContent = lines.join(" · ");
  }

  const chip = $("tunnelModeChip");
  if (chip) {
    chip.textContent = ui.short;
    chip.title = `Режим: ${ui.short} — ${t.description || ui.hint}. Нажмите, чтобы настроить.`;
  }
  const hint = $("tunnelModeHint");
  if (hint) hint.textContent = ui.hint;
}

// FIX(5.5.12): в Firefox селект меняет значение от КОЛЕСА МЫШИ и от стрелок.
// В отчёте пользователя это дало [release] режим маршрутизации: off — один
// случайный скролл вкладки «Дополнительно» выключал VPN и рвал туннель.
// Колесу менять режим запрещаем.
$("tunnelMode").addEventListener("wheel", (e) => {
  e.preventDefault();
  const sel = e.currentTarget;
  sel.blur();
  // прокрутку не съедаем — передаём её документу
  const scroller = document.scrollingElement || document.documentElement;
  if (scroller) scroller.scrollTop += (e.deltaY || 0);
}, { passive: false });

$("tunnelMode").addEventListener("change", async () => {
  const mode = $("tunnelMode").value;
  // «Ничего» — единственное значение, которое снимает прокси и пускает трафик
  // напрямую. Спрашиваем подтверждение: случайный скролл/стрелка больше не
  // выключают VPN.
  if (mode === "off") {
    const sure = confirm(
      "Выключить маршрутизацию через VPN?\n\n" +
      "Весь трафик пойдёт напрямую (мимо туннеля), прокси будет возвращён браузеру.\n" +
      "Обратно включить: тот же селект → «Всё через VPN» или «Smart»."
    );
    if (!sure) {
      $("tunnelMode").value = lastKnownTunnelMode || "smart";
      return;
    }
  }
  const r = await browser.runtime.sendMessage({ action: "setTunnelMode", mode }).catch(() => null);
  if (r?.ok) {
    applyTunnelUi(r.tunnel);
    // FIX(5.5.12): повторная установка того же режима ничего не меняет —
    // не врем пользователю тостом и не перезапускаем туннель
    toast(r.unchanged
      ? `Маршрутизация уже: ${TUNNEL_MODE_UI[mode]?.short || mode}`
      : `Маршрутизация: ${TUNNEL_MODE_UI[mode]?.short || mode}`);
  } else {
    toast(r?.error || "Не удалось применить режим", true, 4000);
    // откатываем селектор к фактическому состоянию
    const st = await browser.runtime.sendMessage({ action: "getTunnelMode" }).catch(() => null);
    if (st?.ok) applyTunnelUi(st);
  }
});

$("tunnelModeChip").addEventListener("click", () => {
  document.querySelector('.tab[data-tab="advanced"]')?.click();
});

// ---------- Advanced tab ----------
$("saveAdvanced").addEventListener("click", async () => {
  await browser.runtime.sendMessage({ action: "setKillSwitch", enabled: $("killSwitchEnabled").checked });
  await browser.runtime.sendMessage({
    action: "setSplitTunneling",
    enabled: $("splitTunnelingEnabled").checked,
    domains: $("excludedDomains").value.split("\n").map((d) => d.trim()).filter(Boolean)
  });
  await browser.runtime.sendMessage({ action: "setBypassSystemProxy", enabled: $("bypassSystemProxy").checked });
  await browser.runtime.sendMessage({ action: "setHoldProxy", enabled: $("holdProxyToggle").checked });
  await browser.runtime.sendMessage({ action: "setStrictLiveness", enabled: $("strictLivenessToggle").checked });
  await browser.runtime.sendMessage({ action: "setExperimentalUdp", enabled: $("experimentalUdpToggle").checked });
  state.experimentalUdp = $("experimentalUdpToggle").checked;
  applyExperimentalVisibility();
  renderServers($("serverSearch").value);
  toast("Настройки сохранены и применены");
});

// FIX(5.5.5): потолок пинга применяется сразу, без общей кнопки «Сохранить» —
// иначе пользователь менял число, не видел эффекта и решал, что фильтр не работает.
$("maxPingInput")?.addEventListener("change", async (e) => {
  const v = Math.round(Number(e.target.value));
  const r = await browser.runtime.sendMessage({ action: "setMaxPing", maxPingMs: v }).catch(() => null);
  if (!r?.ok) {
    toast(r?.error || "Недопустимое значение (50…20000 мс)", true, 4000);
    e.target.value = state.maxPingMs;
    return;
  }
  state.maxPingMs = r.maxPingMs;
  toast(`Порог ${r.maxPingMs} мс · пригодных: ${r.usable}`);
  loadServers();
});

$("holdMaxInput")?.addEventListener("change", async (e) => {
  const sec = Math.round(Number(e.target.value));
  const r = await browser.runtime.sendMessage({ action: "setHoldMax", holdMaxMs: sec * 1000 }).catch(() => null);
  if (!r?.ok) {
    toast(r?.error || "Недопустимое значение (15…600 c)", true, 4000);
    e.target.value = Math.round(state.holdMaxMs / 1000);
    return;
  }
  state.holdMaxMs = r.holdMaxMs;
  toast(`Прокси удерживается до ${Math.round(r.holdMaxMs / 1000)} c`);
});

$("showBlockedBtn")?.addEventListener("click", async () => {
  state.blockedVisible = !state.blockedVisible;
  $("showBlockedBtn").textContent = state.blockedVisible ? "скрыть" : "показать";
  if (state.blockedVisible) await loadBlocklist();
  renderBlockedList();
});

$("clearBlockedBtn")?.addEventListener("click", async () => {
  if (!confirm(`Разблокировать все узлы (${state.blockedTotal})? Мусор вернётся в список и снова будет проверяться.`)) return;
  const r = await browser.runtime.sendMessage({ action: "clearBlocklist" }).catch(() => null);
  if (r?.ok) {
    toast(`Разблокировано: ${r.cleared}`);
    state.blockedVisible = false;
    const sb = $("showBlockedBtn");
    if (sb) sb.textContent = "показать";
    renderBlockedList();
    await loadBlocklist();
    loadServers();
  }
});

function applyExperimentalVisibility() {
  // HY2-опция в форме сервера видна только с тумблером «Экспериментальное»
  const opt = $("mProtoHy2");
  if (opt) opt.classList.toggle("hidden", !state.experimentalUdp);
}

// ---------- WireGuard tab (включая «матрёшку») ----------
function updateWgDetourVisibility() {
  const on = $("wgDetourEnabled").checked;
  $("wgDetourVlessFields").classList.toggle("hidden", !on || $("wgDetourProto").value !== "vless");
  $("wgDetourTrojanFields").classList.toggle("hidden", !on || $("wgDetourProto").value !== "trojan");
}
$("wgDetourEnabled").addEventListener("change", updateWgDetourVisibility);
$("wgDetourProto").addEventListener("change", updateWgDetourVisibility);

$("saveWireguardBtn").addEventListener("click", async () => {
  const host = $("wgHost").value.trim();
  const port = parseInt($("wgPort").value, 10);
  const priv = $("wgPrivateKey").value.trim();
  const pub = $("wgPeerKey").value.trim();
  if (!host) { $("wgStatus").textContent = "❌ Укажите endpoint (хост)"; return; }
  if (!port || port < 1 || port > 65535) { $("wgStatus").textContent = "❌ Некорректный порт"; return; }
  if (!priv || !pub) { $("wgStatus").textContent = "❌ Нужны приватный ключ клиента и публичный ключ сервера"; return; }

  const address = $("wgAddress").value.split(",").map((s) => s.trim()).filter(Boolean);
  const allowedIPs = $("wgAllowedIps").value.split(",").map((s) => s.trim()).filter(Boolean);
  const mtu = parseInt($("wgMtu").value, 10) || 1280;
  const reserved = $("wgReserved").value.split(",").map((n) => parseInt(n.trim(), 10)).filter((n) => Number.isFinite(n));

  const server = {
    id: "wg_" + Date.now(),
    name: $("wgName").value.trim() || (host + " (WireGuard)"),
    host, port,
    protocol: "wireguard",
    flag: "🧅",
    ping: null,
    tlsEnabled: false,
    wireguard: {
      privateKey: priv,
      peerPublicKey: pub,
      preSharedKey: $("wgPsk").value.trim(),
      address,
      allowedIPs: allowedIPs.length ? allowedIPs : ["0.0.0.0/0", "::/0"],
      mtu,
      reserved: reserved.length === 3 ? reserved : undefined,
      keepalive: 25
    }
  };

  if ($("wgDetourEnabled").checked) {
    const dHost = $("wgDetourHost").value.trim();
    const dPort = parseInt($("wgDetourPort").value, 10) || 443;
    if (!dHost) { $("wgStatus").textContent = "❌ Матрёшка: укажите сервер детура"; return; }
    const proto = $("wgDetourProto").value;
    const detour = { protocol: proto, server: dHost, port: dPort };
    if (proto === "vless") {
      detour.uuid = $("wgDetourUuid").value.trim();
      detour.flow = $("wgDetourFlow").value;
      detour.fingerprint = $("wgDetourFp").value;
      detour.sni = $("wgDetourSni").value.trim();
      const pbk = $("wgDetourPbk").value.trim();
      if (pbk) detour.reality = { publicKey: pbk, shortId: $("wgDetourSid").value.trim() };
      if (!detour.uuid) { $("wgStatus").textContent = "❌ Матрёшка: VLESS-детуру нужен UUID"; return; }
    } else {
      detour.password = $("wgDetourPassword").value;
      detour.sni = $("wgDetourTrojanSni").value.trim();
      if (!detour.password) { $("wgStatus").textContent = "❌ Матрёшка: Trojan-детуру нужен пароль"; return; }
    }
    server.detour = detour;
    server.name = $("wgName").value.trim() || (host + " 🪆 через " + dHost);
  }

  const res = await browser.runtime.sendMessage({ action: "saveServer", server });
  if (res?.servers) {
    state.servers = res.servers;
    renderServers($("serverSearch").value);
    selectServer(server.id);
  }
  $("wgStatus").textContent = server.detour
    ? "✅ Сохранено: WireGuard-«матрёшка» через " + server.detour.protocol.toUpperCase()
    : "✅ Сохранено: прямой WireGuard";
  toast("WireGuard-сервер сохранён");
});

// ---------- modal: add / edit server ----------
const PROTO_SECTIONS = () => document.querySelectorAll("[data-proto]");

function updateModalSections() {
  const proto = $("mProto").value;
  for (const sec of PROTO_SECTIONS()) {
    const protos = (sec.dataset.proto || "").split(/\s+/);
    sec.classList.toggle("hidden", !protos.includes(proto));
  }
  updateModalWarn();
}

function openServerModal(server, needCreds) {
  state.editingId = server ? server.id : null;
  state.connectAfterSave = !!needCreds;
  $("mTitle").textContent = server
    ? (needCreds ? "Нужны учётные данные сервера" : "Параметры сервера")
    : "Новый сервер";
  $("mName").value = server?.name || "";
  $("mHost").value = server?.host || "";
  $("mPort").value = server?.port || 443;
  $("mProto").value = server?.protocol || "vless";
  $("mUuid").value = server?.uuid || "";
  $("mFlow").value = server?.flow || "";
  $("mPbk").value = server?.reality?.publicKey || "";
  $("mSid").value = server?.reality?.shortId || "";
  $("mFp").value = server?.fingerprint || "chrome";
  $("mAuth").value = server?.auth || "";
  $("mCipher").value = server?.cipher && ["auto", "aes-128-gcm", "chacha20-poly1305", "none"].includes(server.cipher) ? server.cipher : "auto";
  $("mSsMethod").value = server?.protocol === "shadowsocks" ? (server?.cipher || "") : "";
  $("mSni").value = server?.sni || "";
  $("mTransportType").value = server?.transport?.type || "";
  $("mTransportPath").value = server?.transport?.path || "";
  $("mTransportHost").value = server?.transport?.host || server?.transport?.serviceName || "";
  $("mWgPriv").value = server?.wireguard?.privateKey || "";
  $("mWgPub").value = server?.wireguard?.peerPublicKey || "";
  $("mWgAddr").value = (server?.wireguard?.address || []).join(", ");
  $("mWgAllowed").value = (server?.wireguard?.allowedIPs || []).join(", ") || "0.0.0.0/0, ::/0";
  { // FIX(5.5.8): параметры AmneziaWG
    const a = server?.wireguard?.amnezia || {};
    $("mWgJc").value = a.jc ?? "";
    $("mWgJmin").value = a.jmin ?? "";
    $("mWgJmax").value = a.jmax ?? "";
    $("mWgS1").value = a.s1 ?? "";
    $("mWgS2").value = a.s2 ?? "";
    $("mWgH1").value = a.h1 ?? "";
    $("mWgH2").value = a.h2 ?? "";
    $("mWgH3").value = a.h3 ?? "";
    $("mWgH4").value = a.h4 ?? "";
    $("mWgConf").value = "";
  }
  $("mObfs").value = server?.obfs?.type || "none";
  $("mObfsPass").value = server?.obfs?.password || "";
  $("mInsecure").checked = !!server?.tls?.insecure;
  applyExperimentalVisibility();
  updateModalSections();
  $("serverModal").classList.remove("hidden");
  const focusId = { vless: "mUuid", vmess: "mUuid", trojan: "mAuth", shadowsocks: "mAuth", hysteria2: "mAuth", wireguard: "mWgPriv" }[$("mProto").value];
  if (focusId) $(focusId).focus();
}

// Предупреждения формы: пустые обязательные credential
function updateModalWarn() {
  const proto = $("mProto").value;
  const msgs = [];
  if ((proto === "vless" || proto === "vmess") && !$("mUuid").value.trim()) {
    msgs.push("UUID не указан — сохранение запрещено.");
  }
  if ((proto === "trojan" || proto === "shadowsocks" || proto === "hysteria2") && !$("mAuth").value) {
    msgs.push("Пароль не указан — сохранение запрещено.");
  }
  if (proto === "vless" && $("mPbk").value.trim() && !$("mSni").value.trim()) {
    msgs.push("Для Reality укажите SNI (обычно домен-маскировка, например www.microsoft.com).");
  }
  if (proto === "wireguard" && (!$("mWgPriv").value.trim() || !$("mWgPub").value.trim())) {
    msgs.push("Нужны приватный ключ клиента и публичный ключ сервера.");
  }
  const w = $("mWarn");
  w.textContent = msgs.join(" ");
  w.classList.toggle("hidden", msgs.length === 0);
}
["mProto", "mUuid", "mAuth", "mPbk", "mSni", "mWgPriv", "mWgPub"].forEach((id) => {
  $(id).addEventListener("input", updateModalWarn);
  $(id).addEventListener("change", updateModalWarn);
});
$("mProto").addEventListener("change", updateModalSections);

// FIX(5.5.8): вставили .conf от своего сервера (wg-quick / AmneziaWG, например
// от bivlked/amneziawg-installer) — разбираем и заполняем форму целиком.
$("mWgParseConf").addEventListener("click", () => {
  const text = $("mWgConf").value.trim();
  if (!text) { toast("Вставьте текст конфига (.conf) целиком", true); return; }
  const r = parseWireGuardConf(text, { source: "custom" });
  if (!r || !r.ok) { toast("Конфиг не разобран: " + (r?.error || "неизвестная ошибка"), true, 4500); return; }
  const s = r.server;
  $("mProto").value = "wireguard";
  $("mName").value = s.name || "";
  $("mHost").value = s.host || "";
  $("mPort").value = String(s.port || 51820);
  $("mWgPriv").value = s.wireguard.privateKey || "";
  $("mWgPub").value = s.wireguard.peerPublicKey || "";
  $("mWgAddr").value = (s.wireguard.address || []).join(", ");
  $("mWgAllowed").value = (s.wireguard.allowedIPs || []).join(", ") || "0.0.0.0/0, ::/0";
  const a = s.wireguard.amnezia || {};
  $("mWgJc").value = a.jc ?? ""; $("mWgJmin").value = a.jmin ?? ""; $("mWgJmax").value = a.jmax ?? "";
  $("mWgS1").value = a.s1 ?? ""; $("mWgS2").value = a.s2 ?? "";
  $("mWgH1").value = a.h1 ?? ""; $("mWgH2").value = a.h2 ?? ""; $("mWgH3").value = a.h3 ?? ""; $("mWgH4").value = a.h4 ?? "";
  updateModalSections();
  updateModalWarn();
  toast(r.amnezia
    ? "🛡 AmneziaWG-конфиг разобран: обфускация Jc/Jmin/Jmax/S1/S2/H1..H4 подставлена"
    : "WireGuard-конфиг разобран. Обфускации AmneziaWG в нём нет — DPI может рвать такой туннель.",
  false, 4500);
});

// FIX(5.5.9): «Диагностика (direct)» и DPI-обход — это НЕ VPN-туннель. По
// диагностике пользователь сидел именно на таком узле: статус «подключено»,
// прокси вооружён, а трафик идёт напрямую. Показываем это явно в шапке.
function updateDirectWarn(st) {
  const box = $("directWarn");
  if (!box) return;
  const txt = $("directWarnText");
  const srv = st?.currentServer || {};
  const on = !!st && st.status === "connected" && !!st.currentIsLocal;
  if (txt) {
    txt.textContent = !on ? ""
      : srv.protocol === "dpi"
        ? "🛡 Сейчас включён DPI-обход (локально, без сервера): трафик НЕ шифруется и IP НЕ меняется. Это обход блокировок, а не VPN."
        : `⚠ Сейчас выбран узел «${srv.name || srv.id}» (direct) — это НЕ VPN: трафик идёт напрямую, IP не меняется. Выбери сервер из списка или включи автовыбор.`;
  }
  box.classList.toggle("hidden", !on);
}

// FIX(5.5.9): отчёт об обрывах одним кликом — вместо ручного сбора диагностики
async function copyBreakReport() {
  let text = "";
  try {
    const r = await browser.runtime.sendMessage({ action: "getBreakReport" });
    text = r?.report || "отчёт пуст";
  } catch (e) {
    toast("Отчёт не получен: " + (e?.message || e), true, 4000);
    return;
  }
  console.warn("[flicker] отчёт об обрывах:\n" + text);
  let copied = false;
  try {
    await navigator.clipboard.writeText(text);
    copied = true;
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { copied = document.execCommand("copy"); } catch { copied = false; }
    ta.remove();
  }
  toast(copied
    ? "📋 Отчёт скопирован — вставляй в чат (версии, удержание, ступень восстановления, журнал событий)"
    : "Отчёт напечатан в консоли (Ctrl+Shift+J) — скопируй оттуда",
  !copied, 5000);
}

// FIX(5.5.8): одним видимым блоком — что делает восстановление и есть ли
// подозрение на DPI (раньше пользователь видел только «Обрыв туннеля…»).
async function refreshRecoveryHint() {
  const box = $("recoveryHint");
  if (!box) return;
  let st = null;
  try { st = await browser.runtime.sendMessage({ action: "getStatus" }); } catch { return; }
  const bits = [];
  // FIX(5.5.9): видно, что прокси держится на туннеле и сколько ещё
  if (st?.proxyMode === "holding") {
    const rem = typeof st.holdRemainingMs === "number" ? Math.round(st.holdRemainingMs / 1000) : null;
    bits.push(`🔌 держу прокси на туннеле${rem != null ? `, ещё ~${rem} c без прогресса — отпущу` : ""} ` +
              `(ступень «${st.recoveryStage || "same"}», попытка ${st.recoveryAttempt || 0})`);
  }
  if (st?.probeActive) {
    bits.push(`⏳ хост проверяет ${st.probeTotal || "?"} серверов — ответы о живости задерживаются, это не обрыв`);
  }
  if (st && st.status === "connected" && st.currentIsLocal) {
    bits.push("⚠ текущий узел — не VPN (direct/DPI): трафик не шифруется");
  }
  if (st?.suspectedDpi) {
    bits.push("⚠ похоже на DPI-блокировку: туннели одного профиля рвутся на разных нодах — нужны Reality/TLS-443, «матрёшка», DPI-режим или свой AmneziaWG-сервер");
  }
  if (st && st.recoveryStage && st.recoveryStage !== "same") {
    bits.push(`🔧 восстановление: ступень «${st.recoveryStage}»` +
      (st.lastRecovery?.attempt ? `, попытка ${st.lastRecovery.attempt}` : "") +
      (st.recoveryStage === "rotate" ? " — ушёл с ноды, которая обрывалась" : ""));
  }
  if (st?.awgUnsupported) bits.push("🛡 AmneziaWG: хост не объявил поддержку — обфускация не применяется, туннель идёт обычным WireGuard");
  const slow = (state.servers || []).filter((s) => typeof s.ping === "number" && s.ping > (state.maxPingMs || 1e9)).length;
  if (slow && state.maxPingMs) bits.push(`🐢 потолок пинга ${state.maxPingMs} мс отсеял ${slow} нод`);
  box.textContent = bits.join(" · ");
  box.classList.toggle("hidden", bits.length === 0);
}

function closeServerModal() {
  $("serverModal").classList.add("hidden");
  state.editingId = null;
  state.connectAfterSave = false;
}

$("addServerBtn").addEventListener("click", () => openServerModal(null, false));
$("loadExamplesBtn").addEventListener("click", async () => {
  const res = await browser.runtime.sendMessage({ action: "loadExamples" });
  if (res?.servers) {
    state.servers = res.servers;
    renderServers($("serverSearch").value);
  }
  toast(res?.added ? `Добавлено примеров: ${res.added}` : "Примеры уже в списке");
});
$("mCancel").addEventListener("click", closeServerModal);
$("serverModal").addEventListener("click", (e) => {
  if (e.target === $("serverModal")) closeServerModal();
});

$("mSave").addEventListener("click", async () => {
  const name = $("mName").value.trim();
  const host = $("mHost").value.trim();
  const port = parseInt($("mPort").value, 10);
  const protocol = $("mProto").value;

  if (!host) { toast("Укажите хост", true); return; }
  if (!port || port < 1 || port > 65535) { toast("Некорректный порт", true); return; }

  const s = {
    id: state.editingId || "u_" + Date.now(),
    name: name || host,
    host,
    port,
    protocol,
    flag: "🌐",
    ping: null
  };

  const transportType = $("mTransportType").value;
  const makeTransport = () => transportType ? {
    type: transportType,
    path: $("mTransportPath").value.trim() || (transportType === "ws" || transportType === "http" || transportType === "httpupgrade" ? "/" : ""),
    host: transportType === "grpc" ? "" : $("mTransportHost").value.trim(),
    serviceName: transportType === "grpc" ? $("mTransportHost").value.trim() : ""
  } : undefined;

  switch (protocol) {
    case "vless": {
      const uuid = $("mUuid").value.trim();
      if (!uuid) { toast("Для VLESS нужен UUID", true); return; }
      s.uuid = uuid;
      s.flow = $("mFlow").value;
      s.fingerprint = $("mFp").value;
      s.sni = $("mSni").value.trim();
      const pbk = $("mPbk").value.trim();
      if (pbk) s.reality = { publicKey: pbk, shortId: $("mSid").value.trim() };
      s.tlsEnabled = !!(pbk || s.sni);
      s.tls = { verify: !$("mInsecure").checked, insecure: $("mInsecure").checked };
      s.transport = makeTransport();
      break;
    }
    case "vmess": {
      const uuid = $("mUuid").value.trim();
      if (!uuid) { toast("Для VMess нужен UUID", true); return; }
      s.uuid = uuid;
      s.cipher = $("mCipher").value;
      s.sni = $("mSni").value.trim();
      s.tlsEnabled = !!s.sni;
      s.tls = { verify: !$("mInsecure").checked, insecure: $("mInsecure").checked };
      s.transport = makeTransport();
      break;
    }
    case "trojan": {
      const auth = $("mAuth").value;
      if (!auth) { toast("Для Trojan нужен пароль", true); return; }
      s.auth = auth;
      s.sni = $("mSni").value.trim() || host;
      s.tlsEnabled = true;
      s.tls = { verify: !$("mInsecure").checked, insecure: $("mInsecure").checked };
      s.transport = makeTransport();
      break;
    }
    case "shadowsocks": {
      const auth = $("mAuth").value;
      if (!auth) { toast("Для Shadowsocks нужен пароль", true); return; }
      s.auth = auth;
      s.cipher = $("mSsMethod").value.trim() || "2022-blake3-aes-128-gcm";
      s.tlsEnabled = false;
      break;
    }
    case "wireguard": {
      const priv = $("mWgPriv").value.trim();
      const pub = $("mWgPub").value.trim();
      if (!priv || !pub) { toast("Нужны ключи WireGuard", true); return; }
      // FIX(5.5.8): AmneziaWG-обфускация, если заполнено хотя бы одно поле
      const awg = parseAmneziaParams({
        jc: $("mWgJc").value, jmin: $("mWgJmin").value, jmax: $("mWgJmax").value,
        s1: $("mWgS1").value, s2: $("mWgS2").value,
        h1: $("mWgH1").value, h2: $("mWgH2").value, h3: $("mWgH3").value, h4: $("mWgH4").value
      });
      if (awg && Number(awg.jmin) > Number(awg.jmax)) {
        toast("AmneziaWG: Jmin не может быть больше Jmax — конфиг нерабочий", true, 4000);
        return;
      }
      if (awg && Object.entries(awg).some(([, v]) => Number(v) > 4294967295 || Number(v) < 0)) {
        toast("AmneziaWG: значения должны быть в диапазоне 0…4294967295 (uint32)", true, 4000);
        return;
      }
      s.wireguard = {
        privateKey: priv,
        peerPublicKey: pub,
        address: $("mWgAddr").value.split(",").map((x) => x.trim()).filter(Boolean),
        allowedIPs: $("mWgAllowed").value.split(",").map((x) => x.trim()).filter(Boolean),
        mtu: 1280,
        keepalive: 25,
        ...(awg ? { amnezia: awg } : {})
      };
      s.tlsEnabled = false;
      break;
    }
    case "hysteria2": {
      const auth = $("mAuth").value;
      if (!auth) { toast("Для Hysteria 2 нужен пароль", true); return; }
      const prev = state.servers.find((x) => x.id === state.editingId);
      s.auth = auth;
      s.sni = prev?.sni || ""; // SNI у hy2 берётся из ссылки подписки — в форме поля нет
      s.obfs = { type: $("mObfs").value, password: $("mObfsPass").value };
      s.tlsEnabled = true;
      s.tls = { verify: false, insecure: true };
      break;
    }
    case "direct":
      s.tlsEnabled = false;
      break;
    default:
      toast("Неизвестный протокол", true); return;
  }

  const wasConnectAfterSave = state.connectAfterSave;
  const res = await browser.runtime.sendMessage({ action: "saveServer", server: s });
  closeServerModal();
  let fresh = s;
  if (res?.servers) {
    state.servers = res.servers;
    fresh = res.servers.find((x) => x.id === s.id) || s;
    renderServers($("serverSearch").value);
    selectServer(s.id);
  } else {
    await loadServers();
    selectServer(s.id);
  }
  toast("Сервер сохранён");
  if (wasConnectAfterSave && hasCreds(fresh)) {
    await doConnect(fresh);
  }
  ["mName", "mHost", "mUuid", "mAuth", "mPbk", "mSid", "mSni", "mTransportPath", "mTransportHost", "mWgPriv", "mWgPub", "mWgAddr", "mObfsPass",
   "mWgJc", "mWgJmin", "mWgJmax", "mWgS1", "mWgS2", "mWgH1", "mWgH2", "mWgH3", "mWgH4", "mWgConf"].forEach((id) => { $(id).value = ""; });
  $("mPort").value = "443";
});

// ---------- авто-обновление списка серверов ----------
$("hideDeadToggle").addEventListener("change", async (e) => {
  state.hideDead = e.target.checked;
  await browser.runtime.sendMessage({ action: "setSettings", hideDead: e.target.checked });
  renderServers($("serverSearch").value);
});

$("autoRefreshToggle").addEventListener("change", async (e) => {
  await browser.runtime.sendMessage({ action: "setSettings", autoRefresh: e.target.checked });
  toast(e.target.checked ? "Авто-обновление включено" : "Авто-обновление выключено");
});

// ---------- background events ----------
browser.runtime.onMessage.addListener((msg) => {
  if (msg.type === "error") toast("⚠ " + msg.message, true, 4500);
  if (msg.type === "killswitch") toast("⛔ " + msg.message, true, 4000);
  if (msg.type === "status") updateUI();
  // FIX(5.5.13): хост ушёл на другой порт (autoPort: 1080 занят → 1081),
  // reconcileSocksPort шлёт именно «socksPort». Без этой строки подвал панели
  // продолжал показывать 1080, хотя браузер уже вооружён на 1081.
  if (msg.type === "socksPort") updateUI();
  if (msg.type === "tunnelMode") applyTunnelUi(msg);
  if (msg.type === "proxyReleased") {
    if (msg.reason) toast("🆘 Прокси возвращён браузеру: " + msg.reason, true, 6000);
    updateUI();
  }
  if (msg.type === "serverSwitched") {
    if (msg.ok) toast(`Переключено на ${msg.toName || msg.to}`, false, 2500);
    else toast(msg.error ? "Ошибка: " + humanError(msg.error) : "Переключение не удалось", true, 4500);
    loadServers();
  }

  if (msg.type === "serversUpdated" && msg.servers) {
    state.servers = msg.servers;
    state.lastRefreshAt = msg.at || Date.now();
    scheduleRender();
  }

  if (msg.type === "subscriptionsUpdated") {
    // FIX(5.5.5): честно показываем, сколько мусора отклонено на входе
    const rej = msg.blockedRejected ? `, отклонено заблокированных: ${msg.blockedRejected}` : "";
    toast(`Подписки: +${msg.added ?? 0} новых, пригодных ${msg.usable ?? msg.total ?? 0}${rej}`, false, 3000);
    if (typeof msg.blockedTotal === "number") state.blockedTotal = msg.blockedTotal;
    if (typeof msg.maxPingMs === "number") state.maxPingMs = msg.maxPingMs;
    renderBlockedLine();
    loadServers();
  }

  if (msg.type === "nodeBlocked") {
    state.blockedTotal = msg.total ?? state.blockedTotal + 1;
    renderBlockedLine();
    if (state.blockedVisible) loadBlocklist();
  }

  if (msg.type === "blockedNodes") {
    state.blockedTotal = msg.total ?? state.blockedTotal;
    renderBlockedLine();
  }

  // живой стрим многоэтапной проверки
  if (msg.type === "probeStarted") {
    state.probe = { active: true, total: msg.total || 0, done: 0, alive: 0, mode: msg.mode, pass: msg.pass };
    state.stageById.clear();
    setProbeButtonsBusy(true);
    renderProbeProgress();
    scheduleRender();
  }

  if (msg.type === "probeStage") {
    lastProbeBurstAt = Date.now();
    if (msg.stage === "http" || msg.stage === "geoip" || msg.fatal) {
      state.stageById.delete(msg.id);
      state.probe.done++;
      if (msg.ok && msg.stage === "http") state.probe.alive++;
      // сервер изменил статус — обновим его данные на месте, без полного цикла
      const srv = state.servers.find((x) => x.id === msg.id);
      if (srv) {
        delete srv.checking;
        if (msg.stage === "http") {
          if (msg.ok) { srv.ping = typeof msg.latencyMs === "number" && msg.latencyMs >= 0 ? msg.latencyMs : srv.ping; }
          else { srv.ping = -2; if (msg.error) srv.lastError = msg.error; }
        } else if (msg.fatal && !msg.ok) {
          srv.ping = -2;
          if (msg.error) srv.lastError = msg.error;
        }
      }
    } else {
      state.stageById.set(msg.id, { stage: msg.stage, ok: msg.ok });
    }
    renderProbeProgress();       // дешёвое: текст + ширина бара
    scheduleRender();            // тяжёлое: не чаще раза в 400 мс
  }

  if (msg.type === "probeDone") {
    state.probe = { ...state.probe, active: false, done: msg.total ?? state.probe.total, alive: msg.alive ?? 0, passes: msg.passes ?? state.probe.passes };
    state.stageById.clear();
    setProbeButtonsBusy(false);
    renderProbeProgress();
    // FIX(5.5.5): итоги отбора — пригодные, отправленные в постоянный блок
    if (typeof msg.blockedTotal === "number") state.blockedTotal = msg.blockedTotal;
    if (typeof msg.maxPingMs === "number") state.maxPingMs = msg.maxPingMs;
    renderBlockedLine();
    if (!msg.cancelled) {
      toast(`Пригодных ${msg.alive ?? 0} из ${msg.total ?? state.probe.total}` +
        (msg.blocked ? ` · ⛔ в блок: ${msg.blocked}` : "") +
        (msg.culled && !msg.blocked ? ` · отсеяно: ${msg.culled}` : ""), false, 3800);
    }
    loadServers();
    if (state.blockedVisible) loadBlocklist();
  }

  if (msg.type === "autoSwitch") {
    toast("🔁 " + msg.message, false, 4000);
    updateUI();
  }

  // FIX(5.5.5): видно, что расширение борется за туннель, а не зависло
  if (msg.type === "livenessWarn") {
    toast("ℹ " + msg.message, false, 6000);
  }
  if (msg.type === "proxyHolding") {
    if (msg.reason) toast("🔌 Обрыв — держу прокси, восстанавливаю: " + msg.reason, true, 5000);
    updateUI();
  }
  if (msg.type === "autoRecover") {
    // FIX(5.5.8): показываем, КУДА уходим и почему — иначе выглядит как
    // бесконечный «обрыв туннеля» без объяснений
    toast(msg.note
      ? `🔧 ${msg.note}`
      : `🔧 Возвращаю туннель (попытка ${msg.attempt || 1}, ступень «${msg.stage || "same"}»)…`,
    false, 4200);
    updateUI();
    refreshRecoveryHint();
  }
  if (msg.type === "directNode") {          // FIX(5.5.9): сели на «не VPN» узел
    toast("⚠ " + (msg.message || "Текущий узел — не VPN"), true, 7000);
    refreshRecoveryHint();
  }
  if (msg.type === "proxyHolding") {        // FIX(5.5.9): сколько ещё держим
    refreshRecoveryHint();
  }
  if (msg.type === "recoveryStage") {
    if (msg.note) toast("🔧 " + msg.note, false, 4200);
    if (msg.suspectedDpi) {
      toast("⚠ Похоже на DPI-блокировку: туннели одного профиля рвутся на разных нодах. " +
            "Помогут Reality/TLS-443, «матрёшка», DPI-режим или свой AmneziaWG-сервер.", true, 7000);
    }
    refreshRecoveryHint();
  }

  if (msg.type === "serverSelected" && msg.id) {
    selectServer(msg.id);
  }
});

// ---------- init ----------
(async () => {
  await loadServers();

  const saved = await browser.storage.local.get([
    "selectedServer", "autoSelect"
  ]);

  if (saved.selectedServer && state.servers.some((s) => s.id === saved.selectedServer)) {
    selectServer(saved.selectedServer);
  } else if (state.servers.length) {
    // авто-выбор: лучший живой из подписок (список отсортирован по задержке)
    const bestAlive = state.servers.find((s) => s.sub && typeof s.ping === "number" && s.ping >= 0);
    selectServer((bestAlive || state.servers[0]).id);
  }

  state.autoSelectEnabled = saved.autoSelect || false;
  $("autoSelectToggle").checked = state.autoSelectEnabled;

  const st0 = await browser.runtime.sendMessage({ action: "getStatus" }).catch(() => null);
  if (st0) {
    $("killSwitchEnabled").checked = st0.killSwitchEnabled || false;
    $("splitTunnelingEnabled").checked = st0.splitTunneling || false;
    $("excludedDomains").value = (st0.excludedDomains || []).join("\n");
    $("autoSwitchToggle").checked = st0.autoSwitchEnabled ?? true;
    $("bypassSystemProxy").checked = st0.bypassSystemProxy !== false;
    $("holdProxyToggle").checked = st0.holdProxy !== false;
    $("strictLivenessToggle").checked = st0.strictLiveness === true;
    state.hideDead = st0.hideDead ?? true;
    state.lastRefreshAt = st0.lastRefreshAt || null;
    // FIX(5.5.5): потолок пинга, длительность удержания и размер блок-листа
    if (typeof st0.maxPingMs === "number") state.maxPingMs = st0.maxPingMs;
    if (typeof st0.holdMaxMs === "number") state.holdMaxMs = st0.holdMaxMs;
    if (st0.blocked) state.blockedTotal = st0.blocked.total || 0;
    const mp = $("maxPingInput");
    if (mp) mp.value = state.maxPingMs;
    const hm = $("holdMaxInput");
    if (hm) hm.value = Math.round(state.holdMaxMs / 1000);
    renderBlockedLine();
    loadBlocklist();
    state.experimentalUdp = !!st0.experimentalUdp;
    $("experimentalUdpToggle").checked = state.experimentalUdp;
    $("hideDeadToggle").checked = state.hideDead;
    $("autoRefreshToggle").checked = st0.autoRefresh ?? true;
    if (st0.subscriptions) state.subscriptions = st0.subscriptions;
    applyTunnelUi(st0.tunnel);
    updateProxyWarn(st0);
    applyExperimentalVisibility();
    // подписочные серверы протухли (>10 мин) или не проверялись — quick-проба
    const hasSubs = state.servers.some((s) => s.sub);
    const stale = !state.lastRefreshAt || Date.now() - state.lastRefreshAt > 600_000;
    if (hasSubs && stale && !st0.probe?.active) {
      browser.runtime.sendMessage({ action: "probeServers", mode: "quick" }).catch(() => {});
    }
  }

  updateWgDetourVisibility();
  refreshRecoveryHint();          // FIX(5.5.8): состояние восстановления и фильтров
  // FIX(5.5.9): предупреждение о не-VPN узле рисуется в updateUI (там свежий статус)
  updateUI();
  setInterval(updateUI, 1000);
  if (window.__flickerSelfTest) window.__flickerSelfTest.ok = true;
})();
