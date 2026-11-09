#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Патч 5.5.12 — по четвёртому отчёту пользователя (стояла 5.5.10).

Отчёт показал: основная починка работает (трафик идёт через реальную ноду,
«release» в журнале нет), НО остались два самостоятельных дефекта, которые
и дают «периодический обрыв туннеля + ошибка возврата прокси».

1) [release] режим маршрутизации: off
   Единственное место, которое освобождает прокси с такой причиной, —
   обработчик setTunnelMode, режим TUNNEL_MODES.OFF. Отправляет его только
   popup.js:812 (change на селекте «Маршрутизация»). В Firefox селект меняет
   значение от КОЛЕСА МЫШИ и от стрелок: один случайный скролл вкладки
   «Дополнительно» выключал VPN. Дальше хуже:
     • обработчик OFF освобождал прокси и ТУТ ЖЕ перезапускал туннель
       (switchServer на ту же ноду) — «выключить VPN» рвало работающий туннель;
     • «connected» от хоста сбрасывал proxyReleasedByUser, и прокси
       вооружался обратно, хотя пользователь выбрал «Ничего»;
     • режима OFF не было в applyProxyModeNow — он держался только на флаге,
       который сбрасывался в трёх местах.
   В журнале пользователя: 09:23:04 [release] режим маршрутизации: off →
   09:23:10 [start] той же ноды.

2) Карусель перезапусков каждые ~20 c
   Хост: «порт 127.0.0.1:1080 занят — SOCKS слушает 127.0.0.1:1081»,
   «switch: de15.h1cloud.net -> de15.h1cloud.net», «ступень=same попытка=0»,
   [start] 09:22:50 / 09:23:10 / 09:23:43 и «proxy HOLD: туннель больше не
   подтверждён» сразу после connected.
   Механика:
     • ack/diagnose приносят ФАКТИЧЕСКИЙ listen-порт, но расширение только
       запоминало его: браузер оставался вооружён на мёртвый 1080;
     • контрольная проба шла в 1080 → «не подтверждён» → HOLD/release →
       восстановление;
     • восстановление брало ту же ноду (ступень «same» доступна при
       recoveryAttempt ≤ 1), а recoveryAttempt обнулялся на ГОЛОМ
       «connected» → backoff не рос → рестарт каждые 15 c без конца.

Что делаем:
  A. Режим OFF становится авторитетным: гейт в applyProxyModeNow, без
     перезапуска туннеля, без проб/верификации, с явным снятием флага при
     возврате на реальный режим. Повторная установка того же режима — no-op.
     В popup: подтверждение перед «Ничего» и запрет менять режим колесом.
  B. Сверка порта (ack.listen и diagnose.listenAddr): перевооружение прокси на
     фактический порт без снятия, обнуление неудач подтверждения, зачёт
     прогресса удержания; вердикты проб, ушедших на старый порт, — устаревшие.
  C. Анти-карусель: счётчики восстановления обнуляются только на
     ПОДТВЕРЖДЁННОМ туннеле; учёт подряд идущих перезапусков одной ноды;
     после 3 неподтверждённых перезапусков ступень «same» пропускается
     (принудительная ротация), а пауза растёт до 120 c.
"""
import io, os, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
EXT = os.path.join(ROOT, "ext")
BG = os.path.join(EXT, "background.js")
POP = os.path.join(EXT, "popup.js")
MAN = os.path.join(EXT, "manifest.json")


def rd(p):
    with io.open(p, "r", encoding="utf-8") as f:
        return f.read()


def wr(p, s):
    with io.open(p, "w", encoding="utf-8") as f:
        f.write(s)


applied, failed = [], []


def sub(path, old, new, tag):
    s = rd(path)
    n = s.count(old)
    if n != 1:
        failed.append((tag, os.path.basename(path), n))
        return False
    wr(path, s.replace(old, new, 1))
    applied.append(tag)
    return True


# ============================================================ A. STATE ====
sub(BG, '''  lastStartAt: null,          // когда последний раз послали хосту start''',
    '''  lastStartAt: null,          // когда последний раз послали хосту start
  // FIX(5.5.12): на каком порту прокси вооружён ФАКТИЧЕСКИ. Хост при занятом
  // 1080 уходит на 1081 (autoPort) и сообщает адрес в ack.listen и
  // diagnose.listenAddr. Без сверки браузер оставался на мёртвом порту, проба
  // не проходила, и нода перезапускалась каждые 15 c.
  armedPort: null,
  lastStartServerId: null,    // какую ноду поднимали в последний раз
  lastStartVerified: false,   // подтвердился ли тот старт
  sameNodeRestarts: 0,        // подряд идущие перезапуски одной ноды без подтверждения
  lastRestartAt: null,
  unverifiedBudgets: 0,       // сколько бюджетов подтверждения подряд исчерпано без вердикта''', "state.portLoop")

# =========================================================== B. consts ====
sub(BG, '''const START_GRACE_MS = 10_000;''',
    '''const START_GRACE_MS = 10_000;
// FIX(5.5.12): анти-карусель. В отчёте пользователя хост получал start той же
// ноды каждые ~20 c (switch: de15 -> de15, ступень=same, попытка=0): туннель
// поднимался, не подтверждался, восстановление снова брало ту же ноду, а
// счётчик попыток обнулялся на голом «connected», поэтому backoff не рос.
// После RESTART_LOOP_MAX неподтверждённых перезапусков одной ноды ступень
// «same» пропускается (принудительная ротация), а пауза между попытками
// растёт до RESTART_LOOP_BACKOFF_MS.
const RESTART_LOOP_MAX = 3;
const RESTART_LOOP_BACKOFF_MS = 120_000;
// FIX(5.5.12): как часто переспрашиваем подтверждение, когда бюджет исчерпан,
// но смерть туннеля НЕ доказана (хост молчит, heartbeat свежий).
const VERIFY_RETRY_GAP_MS = 30_000;''', "consts.loop")

# =================================================== C. очередь прокси ====
sub(BG, '''let proxyApplyChain = Promise.resolve();
function applyProxyMode() {
  // FIX(5.5.5): каждое изменение маршрутизации фиксируется в storage.session —
  // это единственная память, которая переживает выгрузку MV3-страницы (RC-1).
  const run = proxyApplyChain
    .then(() => applyProxyModeNow(), () => applyProxyModeNow())
    .then(() => persistSession(), () => persistSession());
  proxyApplyChain = run.then(() => {}, () => {});
  return run;
}''',
    '''let proxyApplyChain = Promise.resolve();

/**
 * enqueueProxyApply (FIX 5.5.12) — поставить операцию над proxy.settings в ту
 * же очередь, в которой живёт applyProxyMode. Иначе перевооружение на новый
 * порт могло разминуться с applyProxyModeNow, и последнее слово осталось бы за
 * настройкой с мёртвым портом.
 */
function enqueueProxyApply(fn) {
  const run = proxyApplyChain.then(fn, fn).then(() => persistSession(), () => persistSession());
  proxyApplyChain = run.then(() => {}, () => {});
  return run;
}

function applyProxyMode() {
  // FIX(5.5.5): каждое изменение маршрутизации фиксируется в storage.session —
  // это единственная память, которая переживает выгрузку MV3-страницы (RC-1).
  return enqueueProxyApply(applyProxyModeNow);
}

/** parseListenPort — «127.0.0.1:1081» → 1081 (null, если не разобралось). */
function parseListenPort(addr) {
  if (addr == null || addr === "") return null;
  if (Number.isInteger(addr)) return addr > 0 && addr <= 65535 ? addr : null;
  const p = Number(String(addr).trim().split(":").pop());
  return Number.isInteger(p) && p > 0 && p <= 65535 ? p : null;
}

/**
 * reconcileSocksPort (FIX 5.5.12) — хост сказал, что SOCKS слушает НЕ там,
 * куда вооружён браузер (autoPort: 1080 был занят, хост ушёл на 1081).
 *
 * До 5.5.12 расширение только запоминало новый порт, а браузер продолжал
 * слать трафик на старый: контрольный запрос шёл в никуда, цикл подтверждения
 * объявлял «туннель больше не подтверждён», прокси освобождался, и нода
 * перезапускалась каждые 15 c. Теперь сдвиг порта:
 *   • сразу перевооружает прокси на фактический порт (без снятия и HOLD);
 *   • обнуляет счётчик неудач подтверждения — прежние были про мёртвый порт;
 *   • засчитывается как прогресс удержания (HOLD не истекает посреди починки).
 *
 * @param {number|string} port фактический порт/адрес от хоста
 * @param {string} via        откуда узнали («ack» | «diagnose»)
 * @returns {Promise<boolean>} true, если порт действительно уточнён
 */
async function reconcileSocksPort(port, via) {
  const p = parseListenPort(port);
  if (!p) return false;
  const wrongArmed = !!STATE.proxyArmed && STATE.armedPort != null &&
    Number(STATE.armedPort) !== p;
  if (p === STATE.socksPort && !wrongArmed) return false;

  const oldSock = STATE.socksPort;
  const oldArmed = STATE.armedPort;
  STATE.socksPort = p;
  STATE.verifyFails = 0;
  broadcastUI({ type: "socksPort", port: p });
  const note = `хост слушает ${p}` +
    (oldSock !== p ? ` (STATE было ${oldSock})` : "") +
    (wrongArmed ? `, прокси был вооружён на ${oldArmed} — перевооружаю` : "") +
    ` [${via || "?"}]`;
  console.warn("[flicker] SOCKS-порт:", note);
  journal("port-shift", note);
  dbgNative({ command: "dbg", text: "port-shift: " + note });
  markHoldProgress("уточнён порт SOCKS: " + p);

  if (wrongArmed) {
    await enqueueProxyApply(async () => {
      // во время атомарной смены ноды и в режиме «Ничего» прокси не трогаем
      if (STATE.switching || STATE.tunnelMode === TUNNEL_MODES.OFF) return;
      if (!STATE.proxyArmed) return;
      const built = buildManualValue();
      await browser.proxy.settings.set({ value: built.value });
      STATE.lastArmedProxyValue = built.value;
      STATE.armedPort = Number(built.value.socksPort) || p;
      STATE.proxyMode = "socks";
      dbgNative({
        command: "dbg",
        text: `proxy=socks port=${STATE.armedPort} (перевооружено после autoPort)`
      });
    });
  } else if (STATE.proxyArmed) {
    STATE.armedPort = p;
  }
  return true;
}''', "proxy.queue+reconcile")

# ======================================================== D. ack порта ====
sub(BG, '''      if (typeof msg.listen === "string") {
        const p = Number(msg.listen.split(":").pop());
        if (Number.isInteger(p) && p > 0 && p !== STATE.socksPort) {
          console.warn("[flicker] SOCKS-порт сдвинут хостом:", STATE.socksPort, "->", p);
          STATE.socksPort = p;
          broadcastUI({ type: "socksPort", port: p });
        }
      }
      break;''',
    '''      // FIX(5.5.12): listen из ack — источник правды о порте. Раньше сдвиг
      // только запоминался, а браузер оставался вооружён на мёртвый порт
      // (см. reconcileSocksPort).
      {
        const p = parseListenPort(msg.listen);
        if (p) {
          reconcileSocksPort(p, "ack")
            .catch((e) => console.warn("[flicker] reconcile ack:", e?.message || e));
        }
      }
      break;''', "native.ack")

# ==================================================== E. diagnose порта ====
sub(BG, '''      // v5.3: ответ diagnose — источник правды о живости туннеля.
      // Хост отдаёт { tunnelActive, driver, socksListening, listenAddr, ... }.
      const d = msg.data || msg;''',
    '''      // v5.3: ответ diagnose — источник правды о живости туннеля.
      // Хост отдаёт { tunnelActive, driver, socksListening, listenAddr, ... }.
      const d = msg.data || msg;
      // FIX(5.5.12): diagnose приходит чаще, чем ack, и тоже несет фактический
      // listenAddr. Сверяем порт ЗДЕСЬ и до вердикта о живости: иначе проба,
      // ушедшая на старый порт, объявляла мёртвым живой туннель.
      {
        const lp = parseListenPort(d && d.listenAddr);
        if (lp) {
          reconcileSocksPort(lp, "diagnose")
            .catch((e) => console.warn("[flicker] reconcile diagnose:", e?.message || e));
        }
      }''', "native.diagnosePort")

# ============================================= F. armedPort: вооружение ====
sub(BG, '''        STATE.lastArmedProxyValue = value;   // FIX(5.5.5): снимок боевой настройки
        STATE.proxyEnabled = true;
        STATE.proxyArmed = true;
        startWatchdog();''',
    '''        STATE.lastArmedProxyValue = value;   // FIX(5.5.5): снимок боевой настройки
        STATE.armedPort = null;              // FIX(5.5.12): per-request — порта в настройках нет
        STATE.proxyEnabled = true;
        STATE.proxyArmed = true;
        startWatchdog();''', "armedPort.perRequest")

sub(BG, '''      STATE.lastArmedProxyValue = value;   // FIX(5.5.5): снимок боевой настройки
      STATE.proxyEnabled = true;
      STATE.proxyArmed = true;
      STATE.proxyReleasedByUser = false;''',
    '''      STATE.lastArmedProxyValue = value;   // FIX(5.5.5): снимок боевой настройки
      STATE.armedPort = Number(value.socksPort) || activeProxyPort();  // FIX(5.5.12)
      STATE.proxyEnabled = true;
      STATE.proxyArmed = true;
      STATE.proxyReleasedByUser = false;''', "armedPort.manual")

sub(BG, '''    STATE.proxyEnabled = false;
    STATE.proxyArmed = false;
    STATE.lastArmedProxyValue = null;
    STATE.tunnelVerified = false;''',
    '''    STATE.proxyEnabled = false;
    STATE.proxyArmed = false;
    STATE.armedPort = null;              // FIX(5.5.12)
    STATE.lastArmedProxyValue = null;
    STATE.tunnelVerified = false;''', "armedPort.tunnelOff")

sub(BG, '''  const wasArmed = STATE.proxyArmed;
  STATE.proxyArmed = false;
  STATE.lastArmedProxyValue = null;''',
    '''  const wasArmed = STATE.proxyArmed;
  STATE.proxyArmed = false;
  STATE.armedPort = null;                // FIX(5.5.12)
  STATE.lastArmedProxyValue = null;''', "armedPort.release")

# ============================================ G. режим OFF авторитетен ====
sub(BG, '''    dbgNative({ command: "dbg", text: "proxy: skipped (switching)" });
    return;
  }
  try {
    if (STATE.killSwitchBlocked) {''',
    '''    dbgNative({ command: "dbg", text: "proxy: skipped (switching)" });
    return;
  }
  try {
    // FIX(5.5.12): режим маршрутизации «Ничего» — решение пользователя, и оно
    // авторитетнее любой автоматики. До этого «off» держался только на флаге
    // proxyReleasedByUser, который сбрасывался на «connected» и при каждом
    // успешном вооружении: прокси возвращался на туннель вопреки выбору.
    if (STATE.tunnelMode === TUNNEL_MODES.OFF) {
      await setProxyNone();
      STATE.proxyEnabled = false;
      STATE.proxyArmed = false;
      STATE.armedPort = null;
      STATE.lastArmedProxyValue = null;
      STATE.holdSince = null;
      STATE.lastHoldProgressAt = null;
      clearTimeout(STATE.watchdogTimer);
      STATE.watchdogTimer = null;
      STATE.proxyMode = "off-mode";
      dbgNative({ command: "dbg", text: "proxy=none (режим маршрутизации: off)" });
      return;
    }
    if (STATE.killSwitchBlocked) {''', "proxy.offGate")

sub(BG, '''  verifyRunning: false,       // FIX(5.5.5): цикл подтверждения уже идёт''',
    '''  verifyRunning: false,       // FIX(5.5.5): цикл подтверждения уже идёт
  verifyProbing: false,       // FIX(5.5.12): внутри итерации цикла идёт проба (await)''',
    "state.verifyProbing")

sub(BG, '''function scheduleVerify() {
  // FIX(5.5.5): защита от второго параллельного цикла (retry — асинхронный,
  // и во время await verifyTimer обнулён).
  if (STATE.verifyRunning) return;''',
    '''function scheduleVerify() {
  // FIX(5.5.12): в режиме «Ничего» прокси снят по воле пользователя —
  // подтверждать нечего. Проба к тому же временно вооружала manual-прокси
  // (probeThroughProxy), то есть «выключенный VPN» всё равно тянул трафик.
  if (STATE.tunnelMode === TUNNEL_MODES.OFF) return;
  // FIX(5.5.12): «осиротевший» цикл подтверждения. verifyRunning взводится
  // здесь, а сбрасывается только в finish(); но таймер цикла снимают и извне
  // (releaseProxy — в трёх ветках, плюс обработчик сообщения releaseProxy).
  // После такого снятия флаг оставался true НАВСЕГДА: scheduleVerify() больше
  // ничего не запрашивал, diagnose не уходил, прокси не вооружался — тупик
  // «туннель не подтверждён, трафик напрямую» до ручного переподключения.
  if (STATE.verifyRunning && !STATE.verifyTimer && !STATE.verifyProbing) {
    console.warn("[flicker] цикл подтверждения осиротел (verifyRunning без таймера) — сбрасываю");
    journal("verify-orphan", "цикл подтверждения сброшен: таймер снят извне, флаг остался");
    STATE.verifyRunning = false;
  }
  // FIX(5.5.5): защита от второго параллельного цикла (retry — асинхронный,
  // и во время await verifyTimer обнулён).
  if (STATE.verifyRunning) return;''', "verify.offGate+orphan")

sub(BG, '''  const finish = () => {
    STATE.verifyRunning = false;
    clearTimeout(STATE.verifyTimer);
    STATE.verifyTimer = null;
  };''',
    '''  const finish = () => {
    STATE.verifyRunning = false;
    STATE.verifyProbing = false;      // FIX(5.5.12)
    clearTimeout(STATE.verifyTimer);
    STATE.verifyTimer = null;
  };''', "verify.finish")

# ================================================ H. setTunnelMode ====
sub(BG, '''        case "setTunnelMode": {
          const mode = String(msg.mode || "");
          if (!Object.values(TUNNEL_MODES).includes(mode)) {
            sendResponse({ ok: false, error: "Неизвестный режим: " + mode });
            break;
          }
          STATE.tunnelMode = mode;
          await browser.storage.local.set({ tunnelMode: mode });
          await rebuildRuleset({ mode });
          if (mode === TUNNEL_MODES.OFF) {
            // «Ничего не через VPN» = расширение вообще не должно держать прокси
            STATE.proxyReleasedByUser = true;
            await releaseProxy("режим маршрутизации: off");
          } else {
            await applyProxyMode();
          }
          // правила уехали и в sing-box — пересобираем туннель атомарно,
          // чтобы на время пересборки трафик не уходил мимо VPN
          if (STATE.status === "connected" && STATE.currentServer) {
            const re = await switchServer(STATE.currentServer);
            if (!re.ok) broadcastUI({ type: "error", message: re.error });
          }
          broadcastUI({ type: "tunnelMode", ...statusPayload().tunnel });
          sendResponse({ ok: true, tunnel: statusPayload().tunnel });
          break;
        }''',
    '''        case "setTunnelMode": {
          const mode = String(msg.mode || "");
          if (!Object.values(TUNNEL_MODES).includes(mode)) {
            sendResponse({ ok: false, error: "Неизвестный режим: " + mode });
            break;
          }
          const prevMode = STATE.tunnelMode;
          // FIX(5.5.12): повторная установка ТОГО ЖЕ режима — не событие.
          // Селект в popup меняет значение от колеса мыши и стрелок, и каждый
          // такой «change» перезапускал туннель атомарной сменой ноды.
          if (mode === prevMode) {
            sendResponse({ ok: true, unchanged: true, tunnel: statusPayload().tunnel });
            break;
          }
          STATE.tunnelMode = mode;
          await browser.storage.local.set({ tunnelMode: mode });
          await rebuildRuleset({ mode });
          journal("tunnel-mode", `${prevMode || "-"} → ${mode}`);
          if (mode === TUNNEL_MODES.OFF) {
            // «Ничего не через VPN» = расширение вообще не должно держать прокси
            STATE.proxyReleasedByUser = true;
            await releaseProxy("режим маршрутизации: off");
            // FIX(5.5.12): гасим цикл подтверждения — в режиме «Ничего»
            // подтверждать нечего, а проба временно вооружала manual-прокси,
            // то есть «выключенный VPN» всё равно тянул трафик через ноду.
            clearTimeout(STATE.verifyTimer);
            STATE.verifyTimer = null;
            STATE.verifyRunning = false;
            STATE.verifyProbing = false;
            STATE.verifyFails = 0;
            // FIX(5.5.12): доводим состояние до «off-mode» общим путём — UI и
            // отчёт показывают честную причину (выбор пользователя), а не
            // «прокси возвращён браузеру» как аварию.
            await applyProxyMode();
            // FIX(5.5.12): туннель НЕ перезапускаем. Прежний код после release
            // уходил в switchServer(та же нода): «выключить VPN» своими руками
            // рвало работающий туннель, а ответ «connected» сбрасывал
            // proxyReleasedByUser и вооружал прокси обратно. В журнале
            // пользователя: [release] режим маршрутизации: off → через 6 c
            // [start] той же ноды.
          } else {
            // FIX(5.5.12): выход из «Ничего» — снимаем запрет на вооружение,
            // иначе прокси не вернётся на туннель до ручного переподключения.
            STATE.proxyReleasedByUser = false;
            await applyProxyMode();
          }
          // правила уехали и в sing-box — пересобираем туннель атомарно,
          // чтобы на время пересборки трафик не уходил мимо VPN
          if (mode !== TUNNEL_MODES.OFF && STATE.status === "connected" && STATE.currentServer) {
            const re = await switchServer(STATE.currentServer);
            if (!re.ok) broadcastUI({ type: "error", message: re.error });
          } else if (mode !== TUNNEL_MODES.OFF && STATE.status === "disconnected" &&
                     !STATE.switching && !STATE.recovering) {
            // FIX(5.5.12): режим включили, а туннеля нет — поднимаем, иначе
            // «Ничего → Всё» оставляло пользователя без VPN до ручного клика.
            // Намерение берём из последней настоящей VPN-ноды (5.5.11).
            if (!STATE.resumeServerId && STATE.lastVpnServerId) {
              STATE.resumeServerId = STATE.lastVpnServerId;
            }
            scheduleRecovery("возврат из режима «Ничего»: " + mode);
          }
          broadcastUI({ type: "tunnelMode", ...statusPayload().tunnel });
          sendResponse({ ok: true, tunnel: statusPayload().tunnel });
          break;
        }''', "msg.setTunnelMode")

# ================================================ I. вердикты подтверждения ====
sub(BG, '''      const pr = await probeThroughProxy(STATE.socksPort)
        .catch((e) => ({ ok: false, error: String(e?.message || e) }));
      handleVerifyResult(pr.ok, { socksListening: pr.ok, via: "browser-probe", error: pr.error });''',
    '''      // FIX(5.5.12): запоминаем порт пробы — если хост за это время уточнил
      // listen (autoPort), вердикт устарел и смертью туннеля не является.
      const portProbed = STATE.socksPort;
      STATE.verifyProbing = true;                 // FIX(5.5.12): цикл внутри await
      const pr = await probeThroughProxy(portProbed)
        .catch((e) => ({ ok: false, error: String(e?.message || e) }));
      STATE.verifyProbing = false;
      handleVerifyResult(pr.ok, {
        socksListening: pr.ok, via: "browser-probe", error: pr.error, probedPort: portProbed
      });''', "verify.probePort")

sub(BG, '''      const confirm = await probeThroughProxy(STATE.socksPort)
        .catch((e) => ({ ok: false, error: String(e?.message || e) }));
      if (confirm.ok) {
        handleVerifyResult(true, { socksListening: true, via: "browser-probe-confirm" });
        finish();
        return;
      }
      finish();''',
    '''      const portConfirm = STATE.socksPort;
      STATE.verifyProbing = true;                 // FIX(5.5.12): цикл внутри await
      const confirm = await probeThroughProxy(portConfirm)
        .catch((e) => ({ ok: false, error: String(e?.message || e) }));
      STATE.verifyProbing = false;
      if (confirm.ok) {
        handleVerifyResult(true, { socksListening: true, via: "browser-probe-confirm", probedPort: portConfirm });
        finish();
        return;
      }
      // FIX(5.5.12): порт за время пробы уточнил хост — вердикт устарел,
      // спрашиваем заново уже на правильном порту (а не гасим туннель).
      if (portConfirm !== STATE.socksPort) {
        finish();
        journal("verify-stale", `проба на ${portConfirm} устарела: хост слушает ${STATE.socksPort}`);
        scheduleVerify();
        return;
      }
      finish();''', "verify.confirmPort")

sub(BG, '''  if (ok) {
    STATE.tunnelVerified = true;
    STATE.verifyFails = 0;
    STATE.lastVerifiedAt = Date.now();''',
    '''  if (ok) {
    STATE.tunnelVerified = true;
    STATE.verifyFails = 0;
    STATE.lastVerifiedAt = Date.now();
    // FIX(5.5.12): вот ТЕПЕРЬ туннель настоящий — обнуляем счётчики
    // восстановления. Раньше они обнулялись на голом «connected» от хоста
    // (который приходит ДО поднятого SOCKS), из-за чего backoff не рос и одна
    // и та же нода перезапускалась каждые 15 c.
    STATE.autoRecoverAttempts = 0;
    STATE.recoveryAttempt = 0;
    STATE.sameNodeRestarts = 0;
    STATE.unverifiedBudgets = 0;
    STATE.lastStartVerified = true;''', "verify.okReset")

sub(BG, '''  } else {
    STATE.tunnelVerified = false;
    // FIX(5.5.9): пока хост жуёт пробу сотен серверов''',
    '''  } else {
    STATE.tunnelVerified = false;
    // FIX(5.5.12): вердикт по пробе, ушедшей на ДРУГОЙ порт, — не вердикт о
    // туннеле (хост сдвинул SOCKS через autoPort, браузер ещё на старом).
    if (d && d.probedPort && Number(d.probedPort) !== Number(STATE.socksPort)) {
      STATE.verifyFails = 0;
      markHoldProgress(`проба на старый порт ${d.probedPort} — хост слушает ${STATE.socksPort}`);
      journal("verify-stale", `проба на ${d.probedPort} устарела: хост слушает ${STATE.socksPort}`);
      if (STATE.status === "connected" && !STATE.verifyTimer && !STATE.verifyRunning) scheduleVerify();
      return;
    }
    // FIX(5.5.12): режим «Ничего» — прокси снят по воле пользователя,
    // подтверждать нечего. Неудачи не считаем, ноду не перезапускаем.
    if (STATE.tunnelMode === TUNNEL_MODES.OFF) {
      STATE.verifyFails = 0;
      return;
    }
    // FIX(5.5.9): пока хост жуёт пробу сотен серверов''', "verify.failGuards")

# ==================================================== J. анти-карусель ====
sub(BG, '''        STATE.autoRecoverAttempts = 0;   // серия неудачных автопереключений сброшена
        clearRecovery();                 // FIX(5.5.5): восстановление больше не нужно''',
    '''        // FIX(5.5.12): счётчики восстановления на голом «connected» НЕ
        // обнуляем — хост отвечает «connected» до того, как sing-box поднимет
        // SOCKS. Обнуление переехало в handleVerifyResult(ok). Иначе backoff
        // не рос: рестарт → connected → сброс → рестарт каждые 15 c.
        clearRecoveryTimer();            // таймер больше не нужен, счётчик оставляем''', "native.connectedNoReset")

sub(BG, '''function clearRecovery() {
  clearTimeout(STATE.recoveryTimer);
  STATE.recoveryTimer = null;
  STATE.recoveryAttempt = 0;
}''',
    '''/** FIX(5.5.12): снять таймер восстановления, НЕ обнуляя backoff. */
function clearRecoveryTimer() {
  clearTimeout(STATE.recoveryTimer);
  STATE.recoveryTimer = null;
}

function clearRecovery() {
  clearRecoveryTimer();
  STATE.recoveryAttempt = 0;
}''', "recovery.clearTimer")

sub(BG, '''    if (STATE.status === "connected" || STATE.status === "connecting") {
      STATE.recoveryAttempt = 0;
      return;
    }''',
    '''    if (STATE.status === "connected" || STATE.status === "connecting") {
      // FIX(5.5.12): backoff обнуляем только если туннель ПОДТВЕРЖДЁН.
      if (STATE.tunnelVerified) STATE.recoveryAttempt = 0;
      return;
    }''', "recovery.attemptReset")

sub(BG, '''  const delay = Math.min(
    RECOVERY_RETRY_BASE_MS * Math.pow(2, STATE.recoveryAttempt || 0),
    RECOVERY_RETRY_MAX_MS
  );''',
    '''  const baseDelay = Math.min(
    RECOVERY_RETRY_BASE_MS * Math.pow(2, STATE.recoveryAttempt || 0),
    RECOVERY_RETRY_MAX_MS
  );
  // FIX(5.5.12): карусель — одну ноду перезапускали RESTART_LOOP_MAX раз
  // подряд без подтверждения. Долбить её каждые 15 c бесполезно: пауза растёт.
  const looping = (STATE.sameNodeRestarts || 0) >= RESTART_LOOP_MAX;
  const delay = looping ? Math.max(baseDelay, RESTART_LOOP_BACKOFF_MS) : baseDelay;''', "recovery.delay")

sub(BG, '''      const pick = pickRecoveryTarget(servers, reason);
      const srv = pick.server;''',
    '''      let pick = pickRecoveryTarget(servers, reason);
      // FIX(5.5.12): принудительный уход со ступени «same», если нода
      // перезапускалась RESTART_LOOP_MAX раз подряд и так и не подтвердилась.
      // В отчёте пользователя хост получал start той же ноды каждые ~20 c
      // (switch: de15 -> de15, ступень=same, попытка=0).
      if (pick.stage === "same" && (STATE.sameNodeRestarts || 0) >= RESTART_LOOP_MAX) {
        const savedAttempt = STATE.recoveryAttempt;
        // ступень «same» доступна только при attempt ≤ 1 — поднимаем планку
        STATE.recoveryAttempt = Math.max(savedAttempt, 2);
        const rotated = pickRecoveryTarget(servers, reason + " | карусель перезапусков");
        STATE.recoveryAttempt = savedAttempt;
        if (rotated.server && rotated.server.id !== pick.server?.id) {
          journal("restart-loop",
            `нода ${pick.server?.id} не подтвердилась ${STATE.sameNodeRestarts} раз подряд — ухожу на ${rotated.server.id} (${rotated.stage})`);
          broadcastUI({
            type: "error",
            message: `Узел не подтверждается ${STATE.sameNodeRestarts} раз подряд — больше не перезапускаю его каждые 15 c, пробую другой (${rotated.stage}).`
          });
          pick = rotated;
        } else {
          journal("restart-loop",
            `нода ${pick.server?.id || "-"} не подтвердилась ${STATE.sameNodeRestarts} раз подряд, альтернатив нет — пауза ${Math.round(RESTART_LOOP_BACKOFF_MS / 1000)} c`);
        }
      }
      const srv = pick.server;''', "recovery.rotateOnLoop")

sub(BG, '''  STATE.lastStartAt = Date.now();   // FIX(5.5.11): отсчёт грации после старта''',
    '''  STATE.lastStartAt = Date.now();   // FIX(5.5.11): отсчёт грации после старта
  // FIX(5.5.12): учёт карусели — сколько раз подряд поднимаем ОДНУ И ТУ ЖЕ
  // ноду, так и не дождавшись подтверждения туннеля.
  if (STATE.lastStartServerId === (server?.id || null) && !STATE.lastStartVerified) {
    STATE.sameNodeRestarts = (STATE.sameNodeRestarts || 0) + 1;
  } else {
    STATE.sameNodeRestarts = 0;
  }
  STATE.lastStartServerId = server?.id || null;
  STATE.lastStartVerified = false;
  STATE.lastRestartAt = Date.now();''', "start.loopCount")

# ================================================ K. отчёт и статус ====
sub(BG, '''    startGraceLeftMs: isStamp(STATE.lastStartAt)
      ? Math.max(0, START_GRACE_MS - (Date.now() - STATE.lastStartAt)) : 0,''',
    '''    startGraceLeftMs: isStamp(STATE.lastStartAt)
      ? Math.max(0, START_GRACE_MS - (Date.now() - STATE.lastStartAt)) : 0,
    // FIX(5.5.12): сверка порта и карусель перезапусков — видно в отчёте
    armedPort: STATE.armedPort,
    sameNodeRestarts: STATE.sameNodeRestarts || 0,
    lastStartServerId: STATE.lastStartServerId,
    restartLoop: (STATE.sameNodeRestarts || 0) >= RESTART_LOOP_MAX,''', "status.portLoop")

sub(BG, '''            `SOCKS порт: ${activeProxyPort()} | потолок пинга: ${STATE.maxPingMs} мс`,''',
    '''            `SOCKS порт: ${activeProxyPort()} (вооружён на: ${st.armedPort ?? "-"}) | потолок пинга: ${STATE.maxPingMs} мс`,
            `перезапуски одной ноды подряд без подтверждения: ${st.sameNodeRestarts} (карусель: ${st.restartLoop ? "ДА" : "нет"}) | нода последнего старта: ${st.lastStartServerId || "-"}`,''', "report.portLoop")

sub(BG, '''  isStamp,                  // FIX(5.5.11)''',
    '''  isStamp,                  // FIX(5.5.11)
  // FIX(5.5.12): сверка порта, режим OFF, анти-карусель
  parseListenPort,
  reconcileSocksPort,
  enqueueProxyApply,
  clearRecoveryTimer,
  TUNNEL_MODES,
  RESTART_LOOP_MAX,
  RESTART_LOOP_BACKOFF_MS,
  VERIFY_RETRY_GAP_MS,
  buildManualValue,''', "test.exports")

# ================================================== L. popup: селект ====
sub(POP, '''function proxyWarnMessage(st) {
  // Порядок веток важен: "released" — самое важное состояние для пользователя''',
    '''function proxyWarnMessage(st) {
  // FIX(5.5.12): режим маршрутизации «Ничего» — выбор пользователя, а не авария.
  // Раньше он показывался как «Прокси возвращён браузеру» / «VPN подключён, но
  // прокси не вооружён», то есть как поломка, которую надо чинить.
  if (st.tunnel?.mode === "off" || st.proxyMode === "off-mode") {
    return "Маршрутизация через VPN выключена (режим «Ничего»): трафик идёт напрямую. " +
           "Вернуть VPN: вкладка «Дополнительно» → «Маршрутизация» → Smart или «Всё через VPN».";
  }
  // Порядок веток важен: "released" — самое важное состояние для пользователя''', "popup.offWarn")

sub(POP, '''function applyTunnelUi(t) {
  if (!t) return;
  const ui = TUNNEL_MODE_UI[t.mode] || { short: t.mode, hint: "" };

  const sel = $("tunnelMode");
  if (sel && sel.value !== t.mode) sel.value = t.mode;''',
    '''// FIX(5.5.12): последнее ПОДТВЕРЖДЁННОЕ расширение значение режима. Нужно,
// чтобы откатить селект, если изменение оказалось случайным (колесо мыши).
let lastKnownTunnelMode = null;

function applyTunnelUi(t) {
  if (!t) return;
  const ui = TUNNEL_MODE_UI[t.mode] || { short: t.mode, hint: "" };
  if (t.mode) lastKnownTunnelMode = t.mode;

  const sel = $("tunnelMode");
  if (sel && sel.value !== t.mode) sel.value = t.mode;''', "popup.lastKnownMode")

sub(POP, '''$("tunnelMode").addEventListener("change", async () => {
  const mode = $("tunnelMode").value;
  const r = await browser.runtime.sendMessage({ action: "setTunnelMode", mode }).catch(() => null);''',
    '''// FIX(5.5.12): в Firefox селект меняет значение от КОЛЕСА МЫШИ и от стрелок.
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
      "Выключить маршрутизацию через VPN?\\n\\n" +
      "Весь трафик пойдёт напрямую (мимо туннеля), прокси будет возвращён браузеру.\\n" +
      "Обратно включить: тот же селект → «Всё через VPN» или «Smart»."
    );
    if (!sure) {
      $("tunnelMode").value = lastKnownTunnelMode || "smart";
      return;
    }
  }
  const r = await browser.runtime.sendMessage({ action: "setTunnelMode", mode }).catch(() => null);''', "popup.wheel+confirm")

sub(POP, '''    applyTunnelUi(r.tunnel);
    toast(`Маршрутизация: ${TUNNEL_MODE_UI[mode]?.short || mode}`);''',
    '''    applyTunnelUi(r.tunnel);
    // FIX(5.5.12): повторная установка того же режима ничего не меняет —
    // не врем пользователю тостом и не перезапускаем туннель
    toast(r.unchanged
      ? `Маршрутизация уже: ${TUNNEL_MODE_UI[mode]?.short || mode}`
      : `Маршрутизация: ${TUNNEL_MODE_UI[mode]?.short || mode}`);''', "popup.toast")

# ==================================== N. тупик «connected, но не подтверждён» ====
sub(BG, '''      recoverIfConfirmedDead("хост не подтвердил туннель за " + Math.round(budget / 1000) + " c")
        .catch((e) => console.error("[flicker] recover:", e));
      return;''',
    '''      const whyUnconfirmed = "хост не подтвердил туннель за " + Math.round(budget / 1000) + " c";
      // FIX(5.5.12): ТУПИК ЗАПРЕЩЁН. Если смерть не доказана (хост молчит на
      // diagnose, но heartbeat свежий), прежний код просто выходил из цикла:
      // статус «connected», прокси не вооружён, таймеров ноль — пользователь
      // сидел так до ручного клика. Продолжаем спрашивать реже, а после
      // RESTART_LOOP_MAX неподтверждённых бюджетов чиним принудительно
      // (с анти-карусельной паузой и ротацией ноды).
      const recovered = await recoverIfConfirmedDead(whyUnconfirmed)
        .catch((e) => { console.error("[flicker] recover:", e); return false; });
      if (!recovered && STATE.status === "connected" && !STATE.tunnelVerified &&
          STATE.tunnelMode !== TUNNEL_MODES.OFF && !STATE.switching) {
        STATE.unverifiedBudgets = (STATE.unverifiedBudgets || 0) + 1;
        journal("verify-unconfirmed",
          `${whyUnconfirmed}; смерть не доказана — переспрашиваю, цикл ${STATE.unverifiedBudgets}/${RESTART_LOOP_MAX}`);
        markHoldProgress("жду подтверждения туннеля (смерть не доказана)");
        if (STATE.unverifiedBudgets >= RESTART_LOOP_MAX) {
          STATE.unverifiedBudgets = 0;
          // форсируем анти-карусель: дальше только ротация и длинная пауза
          STATE.sameNodeRestarts = Math.max(STATE.sameNodeRestarts || 0, RESTART_LOOP_MAX);
          await recoverFromDeadTunnel("туннель не подтверждается: " + whyUnconfirmed)
            .catch((e) => console.error("[flicker] recover:", e));
        } else {
          clearTimeout(STATE.verifyTimer);
          STATE.verifyTimer = setTimeout(() => {
            STATE.verifyTimer = null;
            if (STATE.status === "connected" && !STATE.tunnelVerified &&
                STATE.tunnelMode !== TUNNEL_MODES.OFF) scheduleVerify();
          }, VERIFY_RETRY_GAP_MS);
        }
      }
      return;''', "verify.noDeadEnd")

# ============================================== O. смена на ту же ноду ====
sub(BG, '''async function switchServer(server) {
  if (!server || (!server.host && !server.server)) {
    return { ok: false, error: "Не указан сервер" };
  }
  const prev = STATE.currentServer;
''',
    '''async function switchServer(server, opts = {}) {
  if (!server || (!server.host && !server.server)) {
    return { ok: false, error: "Не указан сервер" };
  }
  const prev = STATE.currentServer;

  // FIX(5.5.12): «смена» на ту же ноду, на которой мы уже сидим и которая
  // ПОДТВЕРЖДЕНА, — не смена, а лишний разрыв рабочего туннеля с окном прямого
  // трафика. В отчёте пользователя хост получал «switch: de15.h1cloud.net ->
  // de15.h1cloud.net» каждые ~20 c. Исключение — opts.force: setTunnelMode
  // обязан атомарно пересобрать туннель, чтобы новые правила уехали в sing-box.
  if (!opts.force && prev && server.id && prev.id === server.id &&
      STATE.status === "connected" && STATE.tunnelVerified) {
    journal("switch-noop", `уже на ${server.id} и туннель подтверждён — не рву`);
    dbgNative({ command: "dbg", text: `switch skipped: уже на ${server.host}, туннель подтверждён` });
    return { ok: true, noop: true, status: STATE.status };
  }
''', "switch.sameNodeNoop")

sub(BG, '''            const re = await switchServer(STATE.currentServer);''',
    '''            const re = await switchServer(STATE.currentServer, { force: true });''',
    "switch.forceOnMode")

# ========================================================== M. версия ====
s = rd(MAN)
assert s.count('"version": "5.5.11"') == 1, "manifest version anchor"
wr(MAN, s.replace('"version": "5.5.11"', '"version": "5.5.12"', 1))
applied.append("manifest.version")

print("APPLIED:", len(applied))
for a in applied:
    print("  +", a)
if failed:
    print("FAILED:")
    for t, p, n in failed:
        print("  !", t, p, "matches=", n)
    sys.exit(1)
