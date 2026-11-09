// options.js — страница настроек FLICKER VPN Pro
const $ = (id) => document.getElementById(id);

$("diagBtn").addEventListener("click", async () => {
  const out = $("diagOut");
  out.textContent = "Выполняется диагностика…";
  try {
    const st = await browser.runtime.sendMessage({ action: "diagnose" });
    const pr = st.probe || {};
    const lines = [];
    if (st.ok) {
      lines.push("✅ Native host: подключён (hello получен)");
    } else if (pr.portOpened) {
      lines.push("⚠ Native host: порт открыт, но hello не пришёл — процесс запустился и не отвечает");
    } else {
      lines.push("❌ Native host: НЕ подключён — Firefox не смог запустить процесс");
    }
    if (pr.lastError) lines.push(`   причина от Firefox: ${pr.lastError}`);
    if (pr.hostName) lines.push(`   имя хоста: ${pr.hostName}`);
    if (pr.extVersion) lines.push(`   версия расширения: ${pr.extVersion}`);
    if (st.native?.version) lines.push(`   версия хоста: ${st.native.version}${st.native.compat === "old" ? " — УСТАРЕЛ, установите 5.5.4!" : ""}`);
    if (st.native?.drivers?.length) lines.push(`   драйверы: ${st.native.drivers.join(", ")}`);
    if (st.native?.caps?.length) lines.push(`   возможности: ${st.native.caps.join(", ")}`);
    lines.push(`Статус туннеля: ${st.status?.status || "?"}`);
    {
      // FIX(5.5.14): «активен» при локальном транспорте direct означало
      // «браузер смотрит на порт, где никто не слушает»: интернета нет, а панель
      // говорит, что всё хорошо. Теперь причина напечатана прямо здесь.
      const pe = st.status?.proxyEnabled;
      const why = st.status?.proxyBlockedReason;
      lines.push(`Прокси браузера: ${pe ? "активен" : "не вооружён"}` +
        (st.status?.currentIsLocal ? "  ← выбран локальный транспорт (НЕ VPN), трафик идёт напрямую" : "") +
        (!pe && why ? `  (${why})` : ""));
    }
    {
      // FIX(5.5.13): порт хоста И порт, на котором вооружён браузер. При
      // autoPort (1080 занят → 1081) это разные числа, и в отчёте пользователя
      // шапка показывала 1080, тогда как хост слушал 1081.
      const sp = st.status?.socksPort || 1080;
      const ap = st.status?.armedPort;
      const armed = st.status?.proxyArmed
        ? (ap && Number(ap) !== Number(sp) ? ` (прокси браузера вооружён на ${ap})` : " (прокси браузера вооружён на нём же)")
        : " (прокси браузера НЕ вооружён)";
      lines.push(`SOCKS5 порт: ${sp}${armed}`);
    }
    lines.push(`Kill switch: ${st.status?.killSwitchEnabled ? "включён" : "выключен"}${st.status?.killSwitchBlocked ? " (АКТИВЕН — трафик заблокирован)" : ""}`);
    if (st.status?.tunnel) {
      const t = st.status.tunnel;
      lines.push(`Маршрутизация: ${t.mode} — ${t.description || ""}`);
      lines.push(`   через VPN ${t.vpnDomains} доменов, напрямую ${t.directDomains} доменов + ${t.directCidrs} подсетей РФ`);
      lines.push(`   механизм: ${t.perRequest ? "proxy.onRequest (per-request)" : "manual proxy (fallback)"}`);
    }
    if (st.status?.rating) lines.push(`Нод с историей замеров: ${st.status.rating.tracked}`);
    if (st.status?.currentServer) {
      lines.push(`Сервер: ${st.status.currentServer.name || st.status.currentServer.host} (${st.status.currentProtocol})`);
    }
    // Ждём ответ diagnose от хоста (приходит broadcast-ом)
    if (!st.ok && Array.isArray(pr.checklist) && pr.checklist.length) {
      lines.push("", "Что проверить:");
      for (const c of pr.checklist) lines.push("  " + c);
    }
    out.textContent = lines.join("\n");
  } catch (e) {
    out.textContent = "❌ Ошибка диагностики: " + (e?.message || e);
  }
});

// Ждём broadcast diagnose от background
browser.runtime.onMessage.addListener((msg) => {
  if (msg.type === "diagnose" && msg.data) {
    const d = msg.data;
    const extra = [
      "",
      "— Ответ native host —",
      `Туннель активен: ${d.tunnelActive ? "да" : "нет"}`,
      d.driver ? `Драйвер: ${d.driver}` : null,
      d.socksListening ? `SOCKS5 слушает: ${d.listenAddr}` : "SOCKS5: не слушает",
      d.tunnelAlive === true ? "Туннель жив: контрольный dial через туннель пройден"
        : d.tunnelAlive === false ? "⚠ ТУННЕЛЬ МЁРТВ: SOCKS слушает, но контрольный dial не прошёл" : null,
      `Передано: ↑${((d.bytesSent || 0) / 1048576).toFixed(2)} MB ↓${((d.bytesReceived || 0) / 1048576).toFixed(2)} MB`,
      d.logPath ? `Лог хоста: ${d.logPath}` : null,
      d.logTail ? `— последние строки лога хоста —\n${d.logTail}` : null
    ].filter(Boolean).join("\n");
    $("diagOut").textContent += extra;
  }
});

$("savePortBtn").addEventListener("click", async () => {
  const port = parseInt($("socksPort").value, 10);
  if (!port || port < 1 || port > 65535) {
    alert("Порт должен быть в диапазоне 1–65535");
    return;
  }
  const res = await browser.runtime.sendMessage({ action: "setSocksPort", port });
  alert(res?.ok ? "Порт сохранён. Переподключите туннель." : "Ошибка: " + (res?.error || "?"));
});

(async () => {
  const st = await browser.runtime.sendMessage({ action: "getStatus" }).catch(() => null);
  if (st?.socksPort) $("socksPort").value = st.socksPort;
  // версию берём из манифеста: хардкод в options.html расходился с manifest.json
  try {
    const mf = browser.runtime.getManifest?.();
    if (mf?.version && $("verVal")) $("verVal").textContent = mf.version;
  } catch { /* getManifest недоступен — оставляем прочерк */ }
})();

$("resetBtn").addEventListener("click", async () => {
  if (!confirm("Вы уверены? Все настройки и серверы будут удалены.")) return;
  await browser.runtime.sendMessage({ action: "resetAll" });
  alert("Все данные очищены");
  location.reload();
});

// ================= Локальный DPI-обход (v5.4) =================
//
// Режим без сервера и без native host: ciadpi (ByeDPI, MIT) поднимает SOCKS5
// на этом же компьютере, FLICKER направляет на него трафик браузера.

let dpiState = null;

function setMsg(el, text, kind) {
  if (!el) return;
  el.textContent = text || "";
  el.classList.remove("ok", "err");
  if (kind) el.classList.add(kind);
  el.style.display = text ? "" : "none";
}

function renderDpi(d) {
  if (!d) return;
  dpiState = d;
  $("dpiDesc").textContent = d.description;
  $("dpiPort").value = d.port;

  const sel = $("dpiPreset");
  if (sel.options.length !== d.presets.length) {
    sel.textContent = "";
    for (const p of d.presets) {
      const o = document.createElement("option");
      o.value = p.id;
      o.textContent = p.name;
      o.title = p.note;
      sel.appendChild(o);
    }
  }
  sel.value = d.presetId;
  $("dpiArgs").value = d.customArgs || "";
  $("dpiCmd").textContent = d.command;
  $("dpiBat").textContent = d.serviceBat;
  // v5.5: второй движок — GoodbyeDPI
  const gd = d.goodbyedpi;
  if (gd && $("gdpiPreset")) {
    $("gdpiDesc").textContent = gd.description;
    const gsel = $("gdpiPreset");
    gsel.innerHTML = "";
    for (const p of gd.presets) {
      const o = document.createElement("option");
      o.value = p.id;
      o.textContent = p.name;
      o.title = (p.note || "") + "\n" + p.args;
      gsel.appendChild(o);
    }
    gsel.value = gd.presetId;
    $("gdpiArgs").value = gd.customArgs || "";
    $("gdpiCmd").textContent = gd.command;
    $("gdpiBat").textContent = gd.serviceBat;
    const gmsgs = [...(gd.argsErrors || []).map((e) => "❌ " + e),
                   ...(gd.argsWarnings || []).map((w) => "⚠ " + w)];
    setMsg($("gdpiArgsMsg"), gmsgs.join("\n"), (gd.argsErrors || []).length ? "err" : "ok");
  }

  const msgs = [];
  for (const e of d.argsErrors || []) msgs.push("✗ " + e);
  for (const w of d.argsWarnings || []) msgs.push("⚠ " + w);
  if (!msgs.length) {
    msgs.push(d.activeArgsSource === "custom"
      ? "✓ аргументы валидны (свои, пресет переопределён)"
      : `✓ аргументы валидны (пресет: ${d.presetId})`);
  }
  setMsg($("dpiArgsMsg"), msgs.join("\n"), d.argsErrors?.length ? "err" : "ok");
}

async function loadDpi() {
  const r = await browser.runtime.sendMessage({ action: "getDpiConfig" }).catch(() => null);
  if (r?.ok) renderDpi(r.dpi);
}

$("dpiPreset").addEventListener("change", () => { $("dpiArgs").value = ""; });

$("dpiSaveBtn").addEventListener("click", async () => {
  const r = await browser.runtime.sendMessage({
    action: "setDpiConfig",
    port: parseInt($("dpiPort").value, 10),
    presetId: $("dpiPreset").value,
    args: $("dpiArgs").value.trim(),
    gdPresetId: $("gdpiPreset") ? $("gdpiPreset").value : undefined,
    gdArgs: $("gdpiArgs") ? $("gdpiArgs").value.trim() : undefined
  }).catch(() => null);
  if (r?.dpi) renderDpi(r.dpi);
  if (r?.ok) alert("Сохранено. Команда обновлена — перезапусти ciadpi с новыми аргументами.");
  else alert("Ошибка: " + ((r?.errors || []).join("; ") || r?.error || "?"));
});

$("dpiProbeBtn").addEventListener("click", async () => {
  const btn = $("dpiProbeBtn");
  btn.disabled = true;
  btn.textContent = "Проверяю…";
  const r = await browser.runtime.sendMessage({
    action: "probeDpi", port: parseInt($("dpiPort").value, 10)
  }).catch(() => null);
  btn.disabled = false;
  btn.textContent = "Проверить, запущен ли ciadpi";
  if (r?.ok) {
    alert(`ciadpi отвечает на 127.0.0.1:${$("dpiPort").value} (HTTP ${r.status}).` +
      (r.verifiedVia === false ? "\n\nВнимание: запрос не прошёл через proxy.onRequest, проверка неполная." : "") +
      "\n\nТеперь в popup выбери сервер «DPI-обход (локально, без сервера)» и нажми «Подключиться».");
  } else {
    alert(r?.hint || "ciadpi не отвечает. Запусти его командой выше.");
  }
});

$("dpiCopyBtn").addEventListener("click", async () => {
  const text = $("dpiCmd").textContent;
  try {
    await navigator.clipboard.writeText(text);
    $("dpiCopyBtn").textContent = "Скопировано";
  } catch {
    // clipboard API может быть недоступен — показываем текст для ручного копирования
    alert("Скопируй вручную:\n\n" + text);
    $("dpiCopyBtn").textContent = "Скопировать команду";
    return;
  }
  setTimeout(() => { $("dpiCopyBtn").textContent = "Скопировать команду"; }, 1800);
});

$("dpiBatBtn").addEventListener("click", () => {
  // сохраняем .bat через Blob + object URL: скачивание работает без сервера
  const blob = new Blob([$("dpiBat").textContent], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "flicker-dpi-service.bat";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
});

// v5.5: обработчики GoodbyeDPI
if ($("gdpiPreset")) {
  $("gdpiPreset").addEventListener("change", () => { $("gdpiArgs").value = ""; });

  $("gdpiCopyBtn").addEventListener("click", async () => {
    const text = $("gdpiCmd").textContent;
    try {
      await navigator.clipboard.writeText(text);
      $("gdpiCopyBtn").textContent = "Скопировано";
    } catch {
      alert("Скопируй вручную:\n\n" + text);
      return;
    }
    setTimeout(() => { $("gdpiCopyBtn").textContent = "Скопировать команду"; }, 1800);
  });

  $("gdpiBatBtn").addEventListener("click", () => {
    const blob = new Blob([$("gdpiBat").textContent], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "flicker-goodbyedpi-service.bat";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  });
}

loadDpi();

// ================= Рейтинг нод (v5) =================

const pad = (v, n) => String(v ?? "—").padStart(n);

async function renderRating() {
  const out = $("ratingSummary");
  if (!out) return;
  out.textContent = "Загрузка…";
  const r = await browser.runtime.sendMessage({ action: "getRatingSummary", limit: 10 }).catch(() => null);
  if (!r?.ok) {
    out.textContent = "❌ Не удалось получить рейтинг: " + (r?.error || "нет ответа от background");
    return;
  }
  const sm = r.summary || {};
  const lines = [
    // FIX(5.5.10): сводка — только по VPN-нодам. Локальные транспорты
    // (direct/dpi) раньше давали «доверенных: 1» ровно за счёт «Диагностики»,
    // которая VPN не является.
    `Всего VPN-нод: ${sm.total ?? 0}` + (sm.nonVpn ? ` (+${sm.nonVpn} локальных транспортов — не VPN, в сводке не учитываются)` : ""),
    `  доверенных (подключаются без прогрева): ${sm.trusted ?? 0}`,
    `  мёртвых:                                ${sm.dead ?? 0}`,
    `  без истории:                            ${sm.cold ?? 0}`,
    `  средняя скорость доверенных:            ${sm.avgMbps ?? 0} Мбит/с`
  ];
  if ((sm.trusted ?? 0) === 0 && (sm.total ?? 0) > 0) {
    lines.push("  ⚠ доверенных VPN-нод нет: подключение идёт через прогрев/пробу, а не мгновенно");
  }
  if (r.top?.length) {
    lines.push("", "Топ по рейтингу:");
    r.top.forEach((n, i) => {
      const name = String(n.name || n.host || n.id).slice(0, 32);
      // FIX(5.5.13): в подписке почти все ноды называются одинаково
      // («.𖥔 ݁ ˖ִ🛸༄˖°.») — без адреса топ нечитаем, отличить ноду от ноды
      // и пожаловаться на конкретную невозможно.
      const addr = n.host ? `${n.host}${n.port ? ":" + n.port : ""}` : String(n.id || "");
      lines.push(
        `  ${String(i + 1).padStart(2)}. ${pad(n.score, 5)}  ${pad(n.protocol, 10)}  ${name.padEnd(32)} ` +
        `${addr.padEnd(30)} ` +
        `${pad(n.rtt, 5)} мс  ${pad(n.mbps, 6)} Мбит/с  ok ${n.okCount ?? 0}/err ${n.failCount ?? 0}` +
        (n.failStreak ? `  (подряд ${n.failStreak})` : "") +
        // FIX(5.5.10): direct/dpi в топе помечены — это не VPN-нода
        (n.nonVpn ? "  ← НЕ VPN (локальный транспорт)" : "")
      );
    });
  } else {
    lines.push("", "Истории пока нет — ноды ещё не проверялись и не использовались.");
  }
  out.textContent = lines.join("\n");
}

$("ratingRefreshBtn")?.addEventListener("click", renderRating);
$("ratingResetBtn")?.addEventListener("click", async () => {
  if (!confirm("Сбросить накопленную статистику по всем нодам? Придётся заново их прогревать.")) return;
  await browser.runtime.sendMessage({ action: "resetRating" });
  renderRating();
});
renderRating();

// ================= Подписки (задача 1) =================

let subsState = [];

function fmtAgo(ts) {
  if (!ts) return "ещё не скачан";
  const min = Math.round((Date.now() - ts) / 60000);
  if (min < 1) return "скачан только что";
  if (min < 60) return `скачан ${min} мин назад`;
  if (min < 1440) return `скачан ${Math.round(min / 60)} ч назад`;
  return "скачан " + new Date(ts).toLocaleDateString();
}

function renderSubs() {
  const box = $("subsList");
  box.textContent = "";
  for (const s of subsState) {
    const row = document.createElement("div");
    row.className = "sub-row";

    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = s.enabled !== false;
    cb.dataset.id = s.id;
    cb.className = "sub-enabled";
    row.appendChild(cb);

    const info = document.createElement("div");
    info.className = "sub-info";
    const name = document.createElement("div");
    name.className = "sub-name";
    name.textContent = (s.builtin ? "★ " : "") + (s.name || s.id);
    const url = document.createElement("div");
    url.className = "sub-url";
    url.textContent = s.url;
    url.title = s.url;
    info.appendChild(name);
    info.appendChild(url);
    if (s.note) {
      const note = document.createElement("div");
      note.className = "sub-url";
      note.textContent = s.note;
      info.appendChild(note);
    }
    row.appendChild(info);

    const sel = document.createElement("select");
    sel.dataset.id = s.id;
    sel.className = "sub-refresh";
    for (const [val, label] of [[60, "каждый час"], [360, "каждые 6 ч"], [720, "каждые 12 ч"], [1440, "ежедневно"]]) {
      const o = document.createElement("option");
      o.value = String(val);
      o.textContent = label;
      if (Number(s.refreshMinutes) === val) o.selected = true;
      sel.appendChild(o);
    }
    row.appendChild(sel);

    const state = document.createElement("div");
    state.className = "sub-state";
    const cnt = document.createElement("div");
    cnt.textContent = s.lastCount ? `HY2-узлов: ${s.lastCount}` : "—";
    const when = document.createElement("div");
    when.textContent = fmtAgo(s.lastFetchAt);
    state.appendChild(cnt);
    state.appendChild(when);
    if (s.lastError) {
      const err = document.createElement("div");
      err.className = "bad";
      err.textContent = s.lastError.slice(0, 60);
      err.title = s.lastError;
      state.appendChild(err);
    }
    row.appendChild(state);
    box.appendChild(row);
  }

  const customs = subsState.filter((s) => !s.builtin).map((s) => s.url);
  $("customSubs").value = customs.join("\\n");
}

async function loadSubs() {
  const res = await browser.runtime.sendMessage({ action: "getSubscriptions" });
  subsState = res?.subscriptions || [];
  renderSubs();
  if (res?.summary) {
    $("subsOut").textContent =
      `Серверов из подписок: ${res.summary.subTotal} · живых: ${res.summary.alive} · ` +
      `мёртвых: ${res.summary.dead} · не проверено: ${res.summary.unknown}`;
  }
}

$("saveSubsBtn").addEventListener("click", async () => {
  const enabled = {};
  document.querySelectorAll(".sub-enabled").forEach((cb) => { enabled[cb.dataset.id] = cb.checked; });
  const refreshMinutes = {};
  document.querySelectorAll(".sub-refresh").forEach((sel) => { refreshMinutes[sel.dataset.id] = Number(sel.value); });
  const custom = $("customSubs").value.split("\\n").map((u) => u.trim()).filter(Boolean);
  const res = await browser.runtime.sendMessage({ action: "setSubscriptions", enabled, refreshMinutes, custom });
  if (res?.ok) {
    subsState = res.subscriptions;
    renderSubs();
    $("subsOut").textContent = "Источники сохранены. Обновляются по расписанию; можно нажать «Обновить подписки сейчас».";
  } else {
    $("subsOut").textContent = "Ошибка сохранения: " + (res?.error || "?");
  }
});

$("refreshSubsBtn").addEventListener("click", async () => {
  const btn = $("refreshSubsBtn");
  btn.disabled = true;
  $("subsOut").textContent = "Скачиваем подписки и запускаем многоэтапную проверку узлов…";
  try {
    const res = await browser.runtime.sendMessage({ action: "refreshSubscriptions", force: true });
    if (res?.ok) {
      const lines = (res.perSource || []).map((p) =>
        p.error ? `  ❌ ${p.id}: ${p.error}` : (p.skipped ? `  ⏭ ${p.id}: свежий` : `  ✅ ${p.id}: HY2-узлов ${p.count}`));
      $("subsOut").textContent =
        `Готово: новых серверов +${res.added}, обновлено ${res.updated}, всего из подписок ${res.total}.\\n` +
        lines.join("\\n") +
        "\\nПроверка живости (TCP → QUIC → HTTP через туннель) запущена — результаты появятся во вкладке «Серверы».";
      await loadSubs();
    } else {
      $("subsOut").textContent = "Ошибка: " + (res?.error || "?");
    }
  } catch (e) {
    $("subsOut").textContent = "Ошибка: " + (e?.message || e);
  } finally {
    btn.disabled = false;
  }
});

loadSubs().catch(() => {});

