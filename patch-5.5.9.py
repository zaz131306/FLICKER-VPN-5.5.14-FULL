#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Патч 5.5.9 — по диагностике пользователя (хост 5.5.4, расширение 5.5.8).

Что показал дамп:
  1) Текущая нода — «Диагностика (direct)»: это локальный transport, НЕ VPN.
     Статус «connected», прокси вооружён, а трафик идёт напрямую.
  2) `probe: старт 600 серверов (mode=full)` — пока хост жуёт пробу, diagnose
     отвечает поздно → «туннель больше не подтверждён» → HOLD-окна по 15–25 c
     на каждом переключении. Это не смерть туннеля, но выглядит как обрыв.
  3) Удержание считается от ПЕРВОГО обрыва и не продлевается, пока идёт
     починка: backoff 15→30→60 c + бюджет вооружения до 45 c > holdMaxMs 120 c,
     поэтому прокси возвращался браузеру прямо посреди восстановления.
     Плюс: после возврата lastArmedProxyValue обнулялся — удержание больше не
     могло включиться до успешного подключения; и canHold требовал status
     connected/connecting, хотя восстановление идёт уже в disconnected.
  4) `порт 127.0.0.1:1080 занят — SOCKS слушает 127.0.0.1:1081` — авто-порт
     сработал штатно (proxy=socks port=1081), но 1081 = дефолт ciadpi:
     при включённом DPI-режиме будет конфликт.

Плюс журнал событий и отчёт одним кликом — чтобы следующий разбор не требовал
руками собирать диагностику.
"""
import io, os, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
EXT = os.path.join(ROOT, "ext")
BG = os.path.join(EXT, "background.js")
PHTML = os.path.join(EXT, "popup.html")
PJS = os.path.join(EXT, "popup.js")
MAN = os.path.join(EXT, "manifest.json")

def rd(p):
    with io.open(p, "r", encoding="utf-8") as f: return f.read()
def wr(p, s):
    with io.open(p, "w", encoding="utf-8") as f: f.write(s)
applied, failed = [], []
def sub(path, old, new, tag):
    s = rd(path); n = s.count(old)
    if n != 1:
        failed.append((tag, os.path.basename(path), n)); return False
    wr(path, s.replace(old, new, 1)); applied.append(tag); return True

# =========================================================== STATE
sub(BG, '''  holdSince: null,            // с какого момента держим (ограничение HOLD_MAX_MS)''',
'''  holdSince: null,            // с какого момента держим (ограничение HOLD_MAX_MS)
  // FIX(5.5.9): удержание продлевается ПО ПРОГРЕССУ восстановления, а не
  // абсолютным таймером от первого обрыва (иначе один цикл «backoff 15→30→60 c
  // + бюджет вооружения 45 c» всегда длиннее удержания и прокси возвращался
  // браузеру прямо посреди починки).
  lastHoldProgressAt: null,   // последний РЕАЛЬНЫЙ прогресс (stats/verify-ok/новая попытка/смена ноды)
  lastArmedProxySnapshot: null, // снимок боевой настройки: удержание должно уметь включиться СНОВА
  journal: [],                // кольцо последних событий — отчёт одним кликом
  journalAt: {},              // троттлинг повторяющихся записей
  directWarnAt: 0,            // не спамим предупреждением о direct-узле
  probeWarnAt: 0,             // не спамим «хост занят пробой»''', "state.hold")

# =========================================================== consts
sub(BG, 'const HOLD_MAX_MS = 120_000;\n',
'''const HOLD_MAX_MS = 120_000;
// FIX(5.5.9): абсолютный потолок удержания. Пока восстановление делает прогресс,
// прокси держится на туннеле; но вечной дыры «браузер без интернета» быть не
// должно, поэтому после 10 минут без результата прокси честно возвращается
// (или блокируется kill switch, если он включён). advanced.holdHardCapMs —
// переопределение, advanced.holdUnbounded = true — держать без потолка.
const HOLD_HARD_CAP_MS = 10 * 60 * 1000;
const JOURNAL_MAX = 120;
const JOURNAL_THROTTLE_MS = 20_000;
''', "consts.hold")

# =========================================================== helpers
sub(BG, '''/** holdMaxMs — действующее ограничение удержания прокси. */
function holdMaxMs() {
  return Number.isFinite(STATE.holdMaxMs) && STATE.holdMaxMs > 0 ? STATE.holdMaxMs : HOLD_MAX_MS;
}''',
'''/** holdMaxMs — действующее ограничение удержания прокси. */
function holdMaxMs() {
  return Number.isFinite(STATE.holdMaxMs) && STATE.holdMaxMs > 0 ? STATE.holdMaxMs : HOLD_MAX_MS;
}

// ================= FIX(5.5.9): удержание по прогрессу + журнал =================

/** Абсолютный потолок удержания (advanced.holdHardCapMs / holdUnbounded). */
function holdHardCapMs() {
  if (STATE.advanced?.holdUnbounded === true) return Infinity;
  const v = Number(STATE.advanced?.holdHardCapMs);
  return Number.isFinite(v) && v >= holdMaxMs() ? v : HOLD_HARD_CAP_MS;
}

/**
 * journal — кольцо последних событий. Нужно, чтобы разбор обрыва не требовал
 * от пользователя руками собирать диагностику: в попапе есть кнопка
 * «Скопировать отчёт», которая отдаёт весь журнал разом.
 */
function journal(kind, text) {
  try {
    const key = kind;
    const now = Date.now();
    // однотипные события пишем не чаще раза в JOURNAL_THROTTLE_MS (без спама)
    if (STATE.journalAt[key] && now - STATE.journalAt[key] < JOURNAL_THROTTLE_MS &&
        !/^(release|hold-start|stage|tunnel-lost|direct)$/.test(kind)) return;
    STATE.journalAt[key] = now;
    STATE.journal.push({ t: now, kind, text: String(text == null ? "" : text).slice(0, 400) });
    if (STATE.journal.length > JOURNAL_MAX) STATE.journal.splice(0, STATE.journal.length - JOURNAL_MAX);
  } catch { /* журнал не должен ломать восстановление */ }
}

/**
 * markHoldProgress — ЗАЧЁТ прогресса восстановления.
 * Продлевает удержание: пока что-то реально происходит (хост шлёт stats,
 * туннель подтверждён, началась новая попытка/смена ноды), прокси остаётся на
 * туннеле. Просто «мы снова попросили diagnose» прогрессом НЕ считается —
 * иначе удержание стало бы бесконечным.
 */
function markHoldProgress(what) {
  STATE.lastHoldProgressAt = Date.now();
  if (what) journal("progress", what);
}

/** Держим ли прокси сейчас: по прогрессу, с абсолютным потолком. */
function holdStillWanted(now = Date.now()) {
  if (!STATE.holdSince) return true;                 // ещё не начали держать
  const progressAt = STATE.lastHoldProgressAt || STATE.holdSince;
  const sinceProgress = now - progressAt;
  const sinceStart = now - STATE.holdSince;
  if (sinceProgress > holdMaxMs()) return false;     // никакого прогресса — отпускаем
  if (sinceStart > holdHardCapMs()) return false;    // абсолютный потолок
  return true;
}

/** Сколько ещё держим прокси (для UI), мс; null — не держим. */
function holdRemainingMs(now = Date.now()) {
  if (!STATE.holdSince) return null;
  const progressAt = STATE.lastHoldProgressAt || STATE.holdSince;
  const a = holdMaxMs() - (now - progressAt);
  const b = holdHardCapMs() - (now - STATE.holdSince);
  return Math.max(0, Math.min(a, b));
}

/** Локальный транспорт: это НЕ VPN-туннель (трафик идёт напрямую/через ciadpi). */
function isLocalTransport(s) {
  return !!s && (s.protocol === "direct" || s.protocol === "dpi");
}

/**
 * warnDirectNode — «Диагностика (direct)» даёт статус connected и вооружённый
 * прокси, но трафик идёт НАПРЯМУЮ. По диагностике пользователя именно этот узел
 * был выбран, то есть «VPN подключён» при полном отсутствии VPN. Молчать нельзя.
 */
function warnDirectNode(server) {
  const now = Date.now();
  journal("direct", `выбран узел ${server?.id || "?"} (${server?.protocol}) — это не VPN`);
  if (now - (STATE.directWarnAt || 0) < 5 * 60 * 1000) return;
  STATE.directWarnAt = now;
  const m = server?.protocol === "dpi"
    ? "Включён DPI-обход (локально, без сервера): трафик не шифруется и IP не меняется — это обход блокировок, а не VPN."
    : `Выбран узел «${server?.name || server?.id}» (протокол direct) — это НЕ VPN: трафик идёт напрямую, IP не меняется. ` +
      "Выбери сервер из списка (вкладка «Серверы») или включи автовыбор.";
  console.warn("[flicker] " + m);
  broadcastUI({ type: "error", message: m });
  broadcastUI({ type: "directNode", serverId: server?.id || null, protocol: server?.protocol || null, message: m });
  notify("FLICKER VPN", m);
}

/** Хост сейчас занят пробой серверов: diagnose отвечает поздно, это не смерть. */
function probeRunning() {
  return !!(STATE.probe && STATE.probe.active);
}''', "helpers.hold")

# =========================================================== releaseProxy: switching-ветка
sub(BG, '''    const nowSw = Date.now();
    if (!STATE.holdSince) STATE.holdSince = nowSw;
    if (nowSw - STATE.holdSince <= holdMaxMs()) {''',
'''    const nowSw = Date.now();
    if (!STATE.holdSince) { STATE.holdSince = nowSw; STATE.lastHoldProgressAt = nowSw; }
    if (holdStillWanted(nowSw)) {           // FIX(5.5.9): по прогрессу, не по абсолютному таймеру''',
      "release.switching.deadline")

# =========================================================== releaseProxy: основная ветка
sub(BG, '''  const canHold = STATE.holdProxy && !opts.byUser && !STATE.proxyReleasedByUser &&
    !!STATE.lastArmedProxyValue && !STATE.killSwitchBlocked && !STATE.switching &&
    (STATE.status === "connected" || STATE.status === "connecting");
  if (canHold) {
    const now = Date.now();
    const firstHold = !STATE.holdSince;
    if (firstHold) STATE.holdSince = now;
    if (now - STATE.holdSince <= holdMaxMs()) {''',
'''  // FIX(5.5.9): три причины, по которым прокси всё-таки уезжал браузеру:
  //  (a) canHold требовал status connected/connecting — но восстановление идёт
  //      уже в disconnected, и любой поздний вызов освобождал прокси сразу;
  //  (b) после освобождения lastArmedProxyValue = null → удержание больше не
  //      могло включиться до успешного подключения (остаток аварии — напрямую);
  //  (c) срок считался от первого обрыва и не продлевался прогрессом.
  const recoveryInFlight = !!STATE.recovering || !!STATE.recoveryTimer ||
    (STATE.recoveryStage && STATE.recoveryStage !== "same");
  const canHold = STATE.holdProxy && !opts.byUser && !STATE.proxyReleasedByUser &&
    !!(STATE.lastArmedProxyValue || STATE.lastArmedProxySnapshot) &&
    !STATE.killSwitchBlocked && !STATE.switching &&
    (STATE.status === "connected" || STATE.status === "connecting" || recoveryInFlight);
  if (canHold) {
    const now = Date.now();
    const firstHold = !STATE.holdSince;
    if (firstHold) {
      STATE.holdSince = now;
      STATE.lastHoldProgressAt = now;
      journal("hold-start", reason || "обрыв туннеля");
      console.warn(`[flicker] удержание прокси: окно без прогресса ${Math.round(holdMaxMs() / 1000)} c, ` +
                   `потолок ${Math.round(holdHardCapMs() / 1000)} c`);
    }
    if (holdStillWanted(now)) {''', "release.canHold")

sub(BG, '''      if (firstHold) {
        console.warn("[flicker] обрыв — держу прокси на туннеле и чиню на месте:", reason);
        notify("FLICKER VPN", "Обрыв туннеля. Прокси НЕ возвращён браузеру — восстанавливаю соединение…");
      }''',
'''      if (firstHold) {
        console.warn("[flicker] обрыв — держу прокси на туннеле и чиню на месте:", reason);
        notify("FLICKER VPN", "Обрыв туннеля. Прокси НЕ возвращён браузеру — восстанавливаю соединение…");
      }
      // FIX(5.5.9): в UI видно, сколько ещё держим и что происходит
      broadcastUI({
        type: "proxyHolding", reason: reason || null, since: STATE.holdSince,
        remainingMs: holdRemainingMs(now), progressAt: STATE.lastHoldProgressAt,
        stage: STATE.recoveryStage, attempt: STATE.recoveryAttempt || 0
      });''', "release.holdUi")

sub(BG, '''    console.warn("[flicker] держал прокси " + Math.round((now - STATE.holdSince) / 1000) +
                 " c без результата");''',
'''    console.warn("[flicker] держал прокси " + Math.round((now - STATE.holdSince) / 1000) +
                 " c без результата (без прогресса " +
                 Math.round((now - (STATE.lastHoldProgressAt || STATE.holdSince)) / 1000) + " c)");
    journal("hold-expired", `держал ${Math.round((now - STATE.holdSince) / 1000)} c, причина: ${reason || "-"}`);''',
      "release.holdExpiredLog")

sub(BG, '''  STATE.holdSince = null;
  const wasArmed = STATE.proxyArmed;
  STATE.proxyArmed = false;
  STATE.lastArmedProxyValue = null;''',
'''  // FIX(5.5.9): снимок боевой настройки СОХРАНЯЕМ — иначе после этого возврата
  // удержание не сможет включиться снова и остаток аварии браузер просидит
  // напрямую (ровно то, на что жаловался пользователь).
  if (STATE.lastArmedProxyValue) STATE.lastArmedProxySnapshot = STATE.lastArmedProxyValue;
  STATE.holdSince = null;
  STATE.lastHoldProgressAt = null;
  STATE.recoveryStage = "same";       // следующий обрыв начинаем с чистой лестницы
  const wasArmed = STATE.proxyArmed;
  STATE.proxyArmed = false;
  STATE.lastArmedProxyValue = null;''', "release.snapshot")

sub(BG, '''  broadcastUI({ type: "proxyReleased", reason: reason || null, wasArmed });
  if (wasArmed && reason) {
    notify("FLICKER VPN", "Туннель не работает — прокси возвращён браузеру. " + reason);
  }
  persistSession();
}''',
'''  broadcastUI({ type: "proxyReleased", reason: reason || null, wasArmed });
  journal("release", reason || "без причины");
  if (wasArmed && reason) {
    notify("FLICKER VPN", "Туннель не работает — прокси возвращён браузеру. " + reason);
  }
  // FIX(5.5.9): возврат прокси — НЕ конец работы. Чиним дальше, и как только
  // туннель вернётся, прокси снова вооружится (и снова сможет удерживаться).
  if (!opts.byUser && !STATE.proxyReleasedByUser && !STATE.killSwitchBlocked) {
    scheduleRecovery("после возврата прокси браузеру продолжаю восстановление");
  }
  persistSession();
}''', "release.keepRecovering")

# =========================================================== verify: проба хоста ≠ смерть
sub(BG, '''  } else {
    STATE.tunnelVerified = false;
    if (STATE.proxyArmed) {
      STATE.verifyFails++;''',
'''  } else {
    STATE.tunnelVerified = false;
    // FIX(5.5.9): пока хост жуёт пробу сотен серверов (в логе пользователя —
    // «probe: старт 600 серверов (mode=full)»), diagnose отвечает поздно и
    // расширение объявляло «туннель больше не подтверждён» на каждом цикле.
    // Это не смерть туннеля: неудачи НЕ считаем, ноды не переключаем,
    // удержание продлеваем и один раз в 30 c объясняем в UI, что происходит.
    if (probeRunning()) {
      markHoldProgress("хост занят пробой серверов — подтверждение задерживается");
      const nowP = Date.now();
      if (nowP - (STATE.probeWarnAt || 0) > 30_000) {
        STATE.probeWarnAt = nowP;
        broadcastUI({
          type: "error",
          message: `Native host сейчас проверяет ${STATE.probe?.total || "?"} серверов — ответы о живости туннеля задерживаются. ` +
                   "Это НЕ обрыв: прокси удерживается на туннеле. Хочешь быстрее — отмени проверку."
        });
      }
      return;
    }
    if (STATE.proxyArmed) {
      STATE.verifyFails++;''', "verify.probeAware")

sub(BG, '''  if (ok) {
    STATE.tunnelVerified = true;
    STATE.verifyFails = 0;
    STATE.lastVerifiedAt = Date.now();''',
'''  if (ok) {
    STATE.tunnelVerified = true;
    STATE.verifyFails = 0;
    STATE.lastVerifiedAt = Date.now();
    markHoldProgress("туннель подтверждён хостом");   // FIX(5.5.9): зачёт прогресса
    journal("verify-ok", d?.via || "diagnose");''', "verify.okProgress")

# =========================================================== stats/hello = прогресс
sub(BG, '''    case "stats":
      // FIX(5.5.5): heartbeat от хоста — признак, что туннель жив. Если прокси''',
'''    case "stats":
      // FIX(5.5.9): stats от хоста — доказательство, что туннель жив:
      // продлеваем удержание (иначе прокси возвращается посреди починки)
      if (STATE.status === "connected") markHoldProgress("stats от хоста");
      // FIX(5.5.5): heartbeat от хоста — признак, что туннель жив. Если прокси''',
      "stats.progress")

sub(BG, '''      STATE.nativeCaps = new Set(Array.isArray(msg.caps) ? msg.caps : []);''',
'''      STATE.nativeCaps = new Set(Array.isArray(msg.caps) ? msg.caps : []);
      // FIX(5.5.9): версия и возможности хоста пишутся в журнал — именно их
      // не хватало, чтобы понять, почему обрыв повторяется
      journal("host-hello", `host ${msg.version || "?"} caps=[${[...STATE.nativeCaps].join(",")}] drivers=[${(msg.drivers || []).join(",")}]`);
      markHoldProgress("native host ответил hello");''', "hello.journal")

# =========================================================== direct-узел
sub(BG, '''  STATE.currentServer = server;
  STATE.currentProtocol = composed.config.protocol;
  STATE.status = "connecting";''',
'''  STATE.currentServer = server;
  STATE.currentProtocol = composed.config.protocol;
  // FIX(5.5.9): «Диагностика (direct)» даёт connected и вооружённый прокси, но
  // трафик идёт НАПРЯМУЮ. По диагностике пользователя был выбран именно этот
  // узел — то есть «VPN работает» при отсутствии VPN. Говорим прямо.
  if (isLocalTransport(server)) warnDirectNode(server);
  journal("start", `${server?.id || "?"} ${composed.config.protocol} ${server?.host || ""}:${server?.port || ""}`);
  STATE.status = "connecting";''', "start.directWarn")

sub(BG, '''  const pool = (servers || []).filter(
    (s) => serverHasCredentials(s) && !s.blocked && !isServerDead(s)
  );''',
'''  const pool = (servers || []).filter(
    // FIX(5.5.9): локальные транспорты (direct/dpi) не являются VPN-нодами и
    // автовыбором выбираться не должны: иначе «подключено» без VPN
    (s) => serverHasCredentials(s) && !s.blocked && !isServerDead(s) && !isLocalTransport(s)
  );''', "autoSelect.noLocal")

# =========================================================== лестница: прогресс
sub(BG, '''      const fromId = STATE.resumeServerId || null;
      if (pick.stage !== STATE.recoveryStage) {''',
'''      const fromId = STATE.resumeServerId || null;
      // FIX(5.5.9): новая попытка восстановления — это прогресс: удержание
      // продлевается, пока мы реально работаем, а не пока не истечёт таймер
      markHoldProgress(`попытка ${STATE.recoveryAttempt}: ${pick.stage} → ${srv.id}`);
      journal("recovery", `попытка ${STATE.recoveryAttempt} ступень ${pick.stage} нода ${srv.id}${pick.note ? " | " + pick.note : ""}`);
      if (pick.stage !== STATE.recoveryStage) {''', "ladder.progress")

# =========================================================== handleTunnelLost: журнал
sub(BG, '''function handleTunnelLost(reason) {
  console.warn("[flicker] tunnel lost:", reason);''',
'''function handleTunnelLost(reason) {
  console.warn("[flicker] tunnel lost:", reason);
  journal("tunnel-lost", reason || "?");''', "lost.journal")

# =========================================================== statusPayload
sub(BG, '''    holdProxy: STATE.holdProxy,''',
'''    holdProxy: STATE.holdProxy,
    // FIX(5.5.9): что с удержанием и не сидим ли мы на «не-VPN» узле
    holdRemainingMs: holdRemainingMs(),
    holdProgressAt: STATE.lastHoldProgressAt,
    holdHardCapMs: holdHardCapMs() === Infinity ? null : holdHardCapMs(),
    vpnActive: STATE.status === "connected" && !isLocalTransport(STATE.currentServer),
    currentIsLocal: isLocalTransport(STATE.currentServer),
    probeActive: probeRunning(),
    probeTotal: STATE.probe?.total || 0,
    journalTail: STATE.journal.slice(-12),''', "status.hold")

# =========================================================== отчёт одним кликом
sub(BG, '''        case "diagnose": {
          // Переподключаемся с нуля, чтобы получить СВЕЖУЮ ошибку, а не''',
'''        case "getBreakReport": {
          // FIX(5.5.9): весь разбор обрыва — одним текстом, чтобы не собирать
          // диагностику руками. Копируется в попапе кнопкой «Скопировать отчёт».
          const st = statusPayload();
          const srv = STATE.currentServer || {};
          const lines = [
            `FLICKER VPN — отчёт об обрывах (${new Date().toISOString()})`,
            `расширение: ${VERSION} | хост: ${STATE.nativeInfo?.version || "нет"} | compat: ${STATE.nativeCompat}`,
            `caps хоста: [${[...(STATE.nativeCaps || [])].join(", ")}]`,
            `драйверы: [${(STATE.nativeInfo?.drivers || []).join(", ")}]`,
            `статус: ${st.status} | прокси: ${st.proxyMode} | armed: ${st.proxyArmed} | verified: ${st.tunnelVerified}`,
            `VPN активен: ${st.vpnActive ? "да" : "НЕТ"} | текущий узел: ${srv.id || "-"} (${srv.protocol || "-"}) ${srv.host || ""}:${srv.port || ""}`,
            `локальный транспорт вместо VPN: ${st.currentIsLocal ? "ДА — трафик идёт напрямую/через ciadpi" : "нет"}`,
            `SOCKS порт: ${activeProxyPort()} | потолок пинга: ${STATE.maxPingMs} мс`,
            `удержание: holdProxy=${STATE.holdProxy} holdMaxMs=${Math.round(holdMaxMs() / 1000)}c hardCap=${st.holdHardCapMs == null ? "∞" : Math.round(st.holdHardCapMs / 1000) + "c"} осталось=${st.holdRemainingMs == null ? "-" : Math.round(st.holdRemainingMs / 1000) + "c"}`,
            `восстановление: ступень=${st.recoveryStage} попытка=${st.recoveryAttempt} подозрение на DPI=${st.suspectedDpi ? "ДА" : "нет"}`,
            `последнее восстановление: ${st.lastRecovery ? JSON.stringify(st.lastRecovery) : "-"}`,
            `обрывы по нодам (10 мин): ${JSON.stringify(st.deaths)}`,
            `проба серверов: active=${st.probeActive} total=${st.probeTotal} alive=${st.probe?.alive ?? "-"} pass=${st.probe?.pass ?? "-"}`,
            `verifyFails: ${st.verifyFails} | lastVerifiedAt: ${st.lastVerifiedAt ? new Date(st.lastVerifiedAt).toISOString() : "-"} | lastStatsAt: ${st.lastStatsAt ? new Date(st.lastStatsAt).toISOString() : "-"}`,
            `kill switch: ${st.killSwitchEnabled ? "вкл" : "выкл"} (blocked=${st.killSwitchBlocked}) | последняя ошибка порта: ${st.nativeLastError || "-"}`,
            `AWG: ${st.awgUnsupported ? "хост не поддерживает (caps: amnezia нет)" : "не задействован"}`,
            "",
            "— журнал событий —",
            ...STATE.journal.slice(-60).map((j) => `${new Date(j.t).toISOString().slice(11, 19)} [${j.kind}] ${j.text}`)
          ];
          sendResponse({ ok: true, report: lines.join("\\n"), status: st });
          break;
        }

        case "diagnose": {
          // Переподключаемся с нуля, чтобы получить СВЕЖУЮ ошибку, а не''',
      "action.breakReport")

# =========================================================== __test
sub(BG, '''  byPingAsc,
  armStabilityReset,''',
'''  byPingAsc,
  armStabilityReset,
  // FIX(5.5.9)
  holdStillWanted,
  holdRemainingMs,
  markHoldProgress,
  journal,
  isLocalTransport,
  warnDirectNode,
  probeRunning,
  handleVerifyResult,''', "test.exports")

# =========================================================== popup.html
sub(PHTML, '''      <!-- FIX(5.5.8): что делает восстановление прямо сейчас и чем отфильтрован список -->
      <div id="recoveryHint" class="meta hidden"></div>''',
'''      <!-- FIX(5.5.8): что делает восстановление прямо сейчас и чем отфильтрован список -->
      <div id="recoveryHint" class="meta hidden"></div>
      <!-- FIX(5.5.9): «Диагностика (direct)» и DPI-обход — это НЕ VPN. По
           диагностике пользователь сидел именно на таком узле: статус
           «подключено», прокси вооружён, а трафик идёт напрямую. -->
      <div id="directWarn" class="proxy-warn hidden" style="border-color:#e2b400;background:#2a2410">
        <span id="directWarnText"></span>
      </div>''', "html.directWarn")

sub(PHTML, '''        <button id="subsSettingsBtn" class="link-btn" title="Управление источниками подписок">⚙ источники</button>''',
'''        <button id="subsSettingsBtn" class="link-btn" title="Управление источниками подписок">⚙ источники</button>
        <button id="breakReportBtn" class="link-btn" title="Скопировать полный отчёт об обрывах (версии, удержание, журнал событий)">📋 отчёт</button>''',
      "html.reportBtn")

# =========================================================== popup.js
sub(PJS, '''/** Что делает восстановление и чем отфильтрован список — одним видимым блоком. */''',
'''// FIX(5.5.9): «Диагностика (direct)» / DPI-обход — это не VPN-туннель.
function updateDirectWarn(st) {
  const box = $("directWarn");
  if (!box) return;
  const txt = $("directWarnText");
  const srv = st?.currentServer;
  const on = !!st && st.status === "connected" && !!st.currentIsLocal;
  if (txt) {
    txt.textContent = on
      ? (srv?.protocol === "dpi"
        ? "🛡 Сейчас включён DPI-обход (локально, без сервера): трафик НЕ шифруется и IP НЕ меняется. Это обход блокировок, а не VPN."
        : `⚠ Сейчас выбран узел «${srv?.name || srv?.id}» (direct) — это НЕ VPN: трафик идёт напрямую, IP не меняется. Выбери сервер из списка или включи автовыбор.`)
      : "";
  }
  box.classList.toggle("hidden", !on);
}

// FIX(5.5.9): отчёт об обрывах одним кликом — вместо ручного сбора диагностики
async function copyBreakReport() {
  try {
    const r = await browser.runtime.sendMessage({ action: "getBreakReport" });
    const text = r?.report || "отчёт пуст";
    let copied = false;
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
    } catch { /* clipboard может быть недоступен в попапе */ }
    if (!copied) {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      try { copied = document.execCommand("copy"); } catch { copied = false; }
      ta.remove();
    }
    toast(copied
      ? "📋 Отчёт скопирован — вставляй в чат (там версии, удержание, ступень восстановления и журнал событий)"
      : "Не удалось скопировать — открой консоль (Ctrl+Shift+J), отчёт напечатан там",
    !copied, 5000);
    if (!copied) console.warn("[flicker] отчёт об обрывах:\\n" + text);
    else console.warn("[flicker] отчёт об обрывах:\\n" + text);
  } catch (e) {
    toast("Отчёт не получен: " + (e?.message || e), true, 4000);
  }
}

/** Что делает восстановление и чем отфильтрован список — одним видимым блоком. */''',
      "js.directWarn")

sub(PJS, '''  const bits = [];
  if (st?.suspectedDpi) {''',
'''  const bits = [];
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
  if (st?.suspectedDpi) {''', "js.hint.hold")

sub(PJS, '''  updateWgDetourVisibility();
  refreshRecoveryHint();          // FIX(5.5.8): состояние восстановления и фильтров''',
'''  updateWgDetourVisibility();
  refreshRecoveryHint();          // FIX(5.5.8): состояние восстановления и фильтров
  updateDirectWarn(lastStatus);   // FIX(5.5.9): не VPN-узел — видно сразу''',
      "js.init.directWarn")

sub(PJS, '''  if (msg.type === "recoveryStage") {''',
'''  if (msg.type === "directNode") {          // FIX(5.5.9): сели на «не VPN» узел
    toast("⚠ " + (msg.message || "Текущий узел — не VPN"), true, 7000);
    refreshRecoveryHint();
  }
  if (msg.type === "proxyHolding") {        // FIX(5.5.9): сколько ещё держим
    refreshRecoveryHint();
  }
  if (msg.type === "recoveryStage") {''', "js.events.direct")

print("APPLIED:", len(applied))
for a in applied: print("  +", a)
if failed:
    print("FAILED:")
    for t, p, n in failed: print("  !", t, p, "matches=", n)
    sys.exit(1)
