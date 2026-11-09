#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Патч 5.5.14 — по шестому отчёту пользователя (5.5.13 + хост 5.5.4).

Отчёт: «похер какой сервер — ни ютуб, ни рутор не подрубает, выплевывает».
Дамп: шапка панели + 12 срезов «Ответ native host», 22:00:10 → 22:10:37.

Хронология из дампа:
  22:00:10  хост запущен (pid 10332), announce от popup
  22:00–22:04  шапка: «Статус туннеля: connected», «Прокси браузера: активен»,
               «SOCKS5 порт: 1080 (прокси браузера вооружён на нём же)»,
               «Сервер: Диагностика (direct)», а хост на все срезы отвечает
               «Туннель активен: нет / SOCKS5: не слушает».
               → браузер 4 минуты смотрел на 127.0.0.1:1080, где НИКТО не
                 слушал. Это и есть «нихера не подрубает, выплевывает».
  22:04:09  dbg: proxy HOLD: туннель больше не подтверждён
            dbg: proxy HOLD (жду подтверждения)
            dbg: mode=all: … туннель не рву, прокси переустановлен на месте
  22:04:17  probe: старт 600 серверов (mode=full)  → до 22:10:37 (6m20s)
            всё это время каждый цикл подтверждения продлевал удержание
            («хост занят пробой серверов»), то есть браузер продолжал стучаться
            в мёртвый порт ещё 6 минут.
  22:06:06  switch: 127.0.0.1 -> 64.176.2.21, порт 1080 занят → 1081,
            port-shift → proxy=socks port=1081 passthrough=4   ← здесь наконец
            прокси вооружён на живой порт
  22:06:47  liveness: dial отклонён (0x1) → «проигнорирован (подряд 1, трафик есть)»
  22:07:34  liveness: dial отклонён (0x1) → и снова ничего: серия обнуляется
            при каждой смене ноды, а «трафик есть» обеспечивается нашими же
            контрольными запросами
  22:10:37  probe: готово — 32 живых из 600
  Рейтинг:  доверенных 0, мёртвых 50, без истории 1755

Три самостоятельных дефекта:

A. Локальный транспорт «Диагностика (direct)» оставлял браузер на мёртвом
   SOCKS-порту. Хост для драйвера direct слушатель НЕ поднимает (сам и пишет
   «SOCKS5: не слушает»), а расширение:
     • в proxy.onRequest возвращало socks5 127.0.0.1:activeProxyPort() с
       завершающим null (fallback запрещён) — то есть КАЖДЫЙ запрос умирал;
     • в manual-режиме вооружало тот же порт;
     • цикл подтверждения не проходил → releaseProxy → HOLD, а HOLD держит
       последний вооружённый снимок, то есть тот же мёртвый порт.
   Панель при этом показывала «connected / Прокси браузера: активен».

B. HOLD защищал заведомо мёртвый конец. Смысл удержания — не отдать браузер
   напрямую, пока туннель вот-вот вернётся. Если хост прямо сказал
   «SOCKS не слушает», если хост вообще не на связи, или если выбран
   локальный транспорт — держать нечего: удержание превращается в отказ
   интернета своими руками. Плюс markHoldProgress() в ветке «хост занят
   пробой» продлевал это состояние на всё время пробы (6 минут в отчёте).

C. Мёртвая нода не определялась. Прежнее правило (3 отказа dial подряд +
   45 c + НУЛЕВОЙ трафик) на практике не срабатывает никогда:
     • серия обнуляется при каждой смене ноды (softLivenessReset), а пользователь
       переключал ноды каждые 20–40 c;
     • «нулевого трафика» не бывает: контрольные запросы расширения сами идут
       через туннель и дают байты (в отчёте «Передано ↑0.00 ↓0.00 MB», но
       «трафик есть»).
   В итоге расширение сидело на ноде, которая не пропускает трафик, и
   писало «Туннель жив».

Что делаем:
  A. protocol === "direct" (не dpi) → трафик НАПРЯМУЮ: proxy.onRequest отдаёт
     DIRECT, manual-прокси снимается, цикл подтверждения не запускается,
     HOLD не включается, proxyMode = "local-direct", в журнал и в dbg пишется
     честная причина. Панель показывает «локальный транспорт (НЕ VPN)».
  B. endpointDead(): локальный транспорт / хост не на связи / последний
     diagnose сказал socksListening=false (свежий, ≤60 c). При таком конце
     HOLD запрещён (canHold и wantHold), а «хост занят пробой» больше не
     продлевает удержание. Отказ удержания пишется в журнал (hold-refused).
  C. Второй независимый арбитр: на tunnelAlive=false от хоста сразу гоняем
     СОБСТВЕННЫЙ контрольный запрос через SOCKS. Прошёл — нода рабочая,
     dial хоста игнорируем (и пишем об этом). Не прошёл — два независимых
     подтверждения, нода признаётся мёртвой и лестница уходит на другую,
     не дожидаясь 45 c и «нулевого трафика». Прежний мягкий путь сохранён.
  D. Честность: «Прокси браузера» в диагностике показывает причину, по которой
     прокси не вооружён; dbg про смену режима больше не утверждает
     «прокси переустановлен», а печатает фактический proxyMode.
"""
import io, os, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
EXT = os.path.join(ROOT, "ext")
BG = os.path.join(EXT, "background.js")
OPT = os.path.join(EXT, "options.js")
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


def sub_span(path, start, end, new, tag):
    """Заменить текст от start до end (не включая end) — для переноса блока."""
    s = rd(path)
    if s.count(start) != 1 or s.count(end) != 1:
        failed.append((tag, os.path.basename(path), (s.count(start), s.count(end))))
        return False
    i = s.index(start)
    j = s.index(end)
    if j < i:
        failed.append((tag, os.path.basename(path), "order"))
        return False
    wr(path, s[:i] + new + s[j:])
    applied.append(tag)
    return True


# ======================================================= A1. поля STATE ====
sub(BG, """  stoppedByUser: false,""",
    """  stoppedByUser: false,
  // FIX(5.5.14): что последний раз сказал хост про SOCKS-слушатель. Нужно,
  // чтобы отличать «туннель вот-вот вернётся» (держать прокси) от «слушателя
  // нет и не будет» (держать нечего, браузер надо вернуть к прямому трафику).
  lastSocksListening: null,
  lastDiagnoseAt: 0,
  lastOwnProbeOk: null,       // результат НАШЕГО контрольного запроса через SOCKS
  lastOwnProbeAt: 0,
  ownProbeInFlight: false,""",
    "A1.stateFields")

# ============================================ A2. локальный транспорт direct ====
sub(BG, """  const routing = STATE.status === "connected" ||
    (STATE.holdProxy && STATE.proxyMode === "holding");""",
    """  // FIX(5.5.14): «Диагностика (direct)» — локальный транспорт: native host не
  // поднимает для него SOCKS-слушатель (в отчёте хост сам пишет «SOCKS5: не
  // слушает»). Направлять запросы на 127.0.0.1:1080 в этом состоянии означало
  // оставить браузер вообще без интернета, причём без fallback: завершающий null
  // в массиве запрещает откат на прокси браузера. Только DIRECT.
  if (STATE.tunnelKind !== "dpi" && STATE.currentServer?.protocol === "direct") return DIRECT;

  const routing = STATE.status === "connected" ||
    (STATE.holdProxy && STATE.proxyMode === "holding");""",
    "A2.perRequestDirect")

sub(BG, """    if (STATE.status === "connected") {
      // FAILSAFE: не перехватываем прокси, пока native host не подтвердил, что""",
    """    // FIX(5.5.14): локальный транспорт direct. Слушателя нет, подтверждать
    // нечего, держать нечего — прокси снимается, трафик идёт напрямую, и панель
    // говорит об этом прямо. До этой правки расширение вооружало браузер на
    // порт, где никто не слушал, и уходило в HOLD на том же мёртвом снимке:
    // в отчёте пользователя 4 минуты «connected / Прокси браузера: активен»
    // при «SOCKS5: не слушает» и полностью мёртвом браузере.
    if (STATE.tunnelKind !== "dpi" && STATE.currentServer?.protocol === "direct") {
      STATE.tunnelVerified = true;      // подтверждать нечего: туннеля нет
      clearTimeout(STATE.verifyTimer);
      STATE.verifyTimer = null;
      STATE.verifyRunning = false;
      STATE.verifyFails = 0;
      if (STATE.proxyMode === "local-direct" && !STATE.proxyArmed) return;  // уже здесь
      await setProxyNone();
      STATE.proxyEnabled = false;
      STATE.proxyArmed = false;
      STATE.armedPort = null;
      STATE.lastArmedProxyValue = null;
      STATE.holdSince = null;
      STATE.lastHoldProgressAt = null;
      STATE.proxyMode = "local-direct";
      dbgNative({
        command: "dbg",
        text: "proxy=none (локальный транспорт direct: SOCKS-слушателя нет, трафик идёт напрямую — это НЕ VPN)"
      });
      journal("local-direct",
        "прокси снят: выбран локальный транспорт direct, трафик идёт напрямую (не VPN)");
      broadcastUI({
        type: "directNode",
        message: "Выбран служебный узел «Диагностика (direct)»: трафик идёт НАПРЯМУЮ, это не VPN. " +
                 "Прокси снят, чтобы не оставлять браузер на порту без слушателя."
      });
      return;
    }

    if (STATE.status === "connected") {
      // FAILSAFE: не перехватываем прокси, пока native host не подтвердил, что""",
    "A3.applyDirectBranch")

sub(BG, """function handleVerifyResult(ok, d) {
  if (ok) {""",
    """function handleVerifyResult(ok, d) {
  // FIX(5.5.14): для локального транспорта direct вердикт подтверждения
  // бессмыслен: слушателя нет, diagnose всегда вернёт socksListening=false, и
  // расширение начинало «чинить» то, чего не существует (release → HOLD на
  // мёртвом порту). Состояние local-direct выставляется в applyProxyModeNow.
  if (STATE.tunnelKind !== "dpi" && STATE.currentServer?.protocol === "direct" &&
      STATE.proxyMode === "local-direct") {
    STATE.verifyFails = 0;
    return;
  }
  if (ok) {""",
    "A4.verifyIgnoresDirect")

# ================================================ B. HOLD не держит мёртвое ====
sub(BG, """/** Сколько ещё держим прокси (для UI), мс; null — не держим. */""",
    """/**
 * endpointDead — FIX(5.5.14): держать прокси НЕ НА ЧЕМ.
 *
 * Удержание (HOLD) имеет смысл, пока SOCKS-слушатель вот-вот вернётся. Если
 * выбран локальный транспорт (direct — слушателя нет в принципе), если native
 * host не на связи, или если последний diagnose прямо сказал «не слушаю»
 * (свежий, не старше 60 c), то удержание оставляет браузер на МЁРТВОМ порту:
 * ни VPN, ни интернета, и панель при этом показывает «connected / прокси
 * активен». В отчёте пользователя ровно так прошли 22:00:10 → 22:06:06.
 *
 * @returns {string|null} причина, либо null если конец живой
 */
function endpointDead() {
  if (STATE.tunnelKind !== "dpi" && STATE.currentServer?.protocol === "direct") {
    return "локальный транспорт direct: SOCKS-слушателя нет";
  }
  if (STATE.nativeOnline === false) return "native host не на связи";
  if (STATE.lastSocksListening === false && isStamp(STATE.lastDiagnoseAt) &&
      (Date.now() - STATE.lastDiagnoseAt) <= 60_000) {
    return "хост сообщил, что SOCKS не слушает";
  }
  return null;
}

/** Сколько ещё держим прокси (для UI), мс; null — не держим. */""",
    "B1.endpointDeadHelper")

sub(BG, """  const canHold = STATE.holdProxy && !opts.byUser && !STATE.proxyReleasedByUser &&
    haveLiveProxy && !STATE.killSwitchBlocked && !STATE.switching &&
    (STATE.status === "connected" || STATE.status === "connecting" || recoveryInFlight);""",
    """  // FIX(5.5.14): удержание запрещено, если конец заведомо мёртв: держать
  // нечего, а браузер остаётся без интернета. Отказ удержания — событие, его
  // видно в журнале и в логе хоста.
  const deadEnd = endpointDead();
  if (deadEnd && STATE.holdProxy && haveLiveProxy && !opts.byUser &&
      !STATE.proxyReleasedByUser && !STATE.switching) {
    journal("hold-refused", "удержание отменено: " + deadEnd + " — возвращаю браузер к прямому трафику");
    dbgNative({ command: "dbg", text: "proxy: HOLD отменён (" + deadEnd + ") — мёртвый порт не держу" });
  }
  const canHold = STATE.holdProxy && !opts.byUser && !STATE.proxyReleasedByUser &&
    haveLiveProxy && !STATE.killSwitchBlocked && !STATE.switching && !deadEnd &&
    (STATE.status === "connected" || STATE.status === "connecting" || recoveryInFlight);""",
    "B2.canHoldRefusesDeadEnd")

sub(BG, """    const wantHold = STATE.holdProxy && !STATE.proxyReleasedByUser &&
      STATE.lastArmedProxyValue && !STATE.killSwitchBlocked &&
      (STATE.resumeServerId || STATE.recoveryTimer || STATE.recovering);""",
    """    // FIX(5.5.14): …и то же самое в основном пути: на мёртвом конце HOLD
    // не включается, браузер возвращается к прямому трафику сразу.
    const wantHold = STATE.holdProxy && !STATE.proxyReleasedByUser &&
      STATE.lastArmedProxyValue && !STATE.killSwitchBlocked && !endpointDead() &&
      (STATE.resumeServerId || STATE.recoveryTimer || STATE.recovering);""",
    "B3.wantHoldRefusesDeadEnd")

sub(BG, """    if (probeRunning()) {
      markHoldProgress("хост занят пробой серверов — подтверждение задерживается");""",
    """    if (probeRunning()) {
      // FIX(5.5.14): продлевать удержание можно, только если есть что держать.
      // В отчёте 6-минутная проба 600 серверов продлевала HOLD на порту, где
      // никто не слушал: браузер сидел без интернета всё это время.
      if (!endpointDead()) markHoldProgress("хост занят пробой серверов — подтверждение задерживается");""",
    "B4.probeDoesNotExtendDeadHold")

sub(BG, """      const baseOk = !!(d && (d.socksListening === true || d.tunnelActive === true));""",
    """      // FIX(5.5.14): запоминаем, что хост сказал про слушатель, — по этому
      // признаку endpointDead() отличает «туннель вот-вот вернётся» от
      // «держать нечего».
      if (d && typeof d.socksListening === "boolean") {
        STATE.lastSocksListening = d.socksListening;
        STATE.lastDiagnoseAt = Date.now();
      }
      const baseOk = !!(d && (d.socksListening === true || d.tunnelActive === true));""",
    "B5.recordSocksListening")

# ================================================== C. вердикт по мёртвой ноде ====
sub(BG, """function softLivenessNote() {""",
    """/**
 * declareSoftDead — FIX(5.5.14): общий вердикт «нода не пропускает трафик».
 *
 * Вынесен из обработчика diagnose, потому что подтверждений теперь два и они
 * приходят из разных мест:
 *   1. прежнее мягкое правило (3 отказа dial подряд + 45 c + нулевой трафик) —
 *      на практике не срабатывало никогда: серия обнуляется при каждой смене
 *      ноды, а «нулевого трафика» не бывает, потому что контрольные запросы
 *      расширения сами идут через туннель (в отчёте: «Передано ↑0.00 ↓0.00 MB»,
 *      но «трафик есть»);
 *   2. НОВОЕ: dial хоста отклонён И наш собственный контрольный запрос через
 *      SOCKS не прошёл — два независимых подтверждения, ждать 45 c незачем.
 *
 * @param {string} reason человекочитаемая причина
 * @returns {boolean} true, если вердикт вынесен (cooldown учтён внутри)
 */
function declareSoftDead(reason) {
  const now = Date.now();
  if (STATE.softDeadActAt != null && now - STATE.softDeadActAt <= SOFT_DEAD_COOLDOWN_MS) return false;
  STATE.softDeadActAt = now;
  console.warn("[flicker] soft liveness: " + reason);
  dbgNative({ command: "dbg", text: "soft liveness: DEAD " + reason });
  journal("soft-dead", reason);
  broadcastUI({
    type: "error",
    message: "⚠ " + reason + ". Считаю ноду мёртвой и ухожу на другую — прокси остаётся на туннеле, если он есть."
  });
  softLivenessReset();
  // две отметки обрыва (эта + внутри recoverFromDeadTunnel) дают
  // DEATHS_BEFORE_ROTATE, поэтому лестница сразу ротирует ноду,
  // а не пробует ту же самую снова
  const deadId = STATE.currentServer?.id || null;
  if (deadId) noteTunnelDeath(deadId, reason, transportFingerprint(STATE.currentServer));
  recoverFromDeadTunnel(reason).catch((e) => console.error("[flicker] soft-dead recover:", e));
  return true;
}

function softLivenessNote() {""",
    "C1.declareSoftDeadHelper")

sub_span(BG,
    "        if (v.dead && cooled) {\n",
    "        } else if (now - (STATE.lastSoftWarnAt || 0) > 60_000) {",
    """        // FIX(5.5.14): второй независимый арбитр. Отдельный блок, а не звено
        // цепочки ниже: предупреждение в UI («dial не прошёл, но SOCKS слушает»)
        // должно остаться в любом случае.
        if (!v.dead && !STATE.ownProbeInFlight && !STATE.verifyProbing &&
            STATE.status === "connected" && STATE.tunnelKind !== "dpi" &&
            !isLocalTransport(STATE.currentServer)) {
          // Хост говорит «dial отклонён», но его одного мало: медленная нода не
          // укладывается в свой же таймаут (поэтому прежнее правило и было
          // мягким). Гоняем СОБСТВЕННЫЙ контрольный запрос через SOCKS:
          //   • прошёл    → нода рабочая, dial хоста игнорируем и пишем об этом;
          //   • не прошёл → два независимых подтверждения: нода мёртвая,
          //     лестница уходит на другую, не дожидаясь 45 c и «нулевого трафика».
          //     Прежнее правило на практике не срабатывало никогда: серия
          //     обнуляется при каждой смене ноды, а «нулевого трафика» не бывает —
          //     контрольные запросы расширения сами идут через туннель (в отчёте
          //     «Передано ↑0.00 ↓0.00 MB», но «трафик есть»).
          STATE.ownProbeInFlight = true;
          const portProbed = STATE.socksPort;
          const streakAtProbe = v.streak;
          probeThroughProxy(portProbed)
            .catch((e) => ({ ok: false, error: String(e?.message || e) }))
            .then((pr) => {
              STATE.ownProbeInFlight = false;
              STATE.lastOwnProbeOk = !!pr.ok;
              STATE.lastOwnProbeAt = Date.now();
              if (pr.ok) {
                dbgNative({
                  command: "dbg",
                  text: "soft liveness: dial хоста не прошёл, но контрольный запрос браузера через SOCKS прошёл — нода рабочая"
                });
                return;
              }
              // вердикт устарел: порт сдвинулся (autoPort), статус сменился,
              // пользователь уже ушёл на другую ноду
              if (portProbed !== STATE.socksPort || STATE.status !== "connected") return;
              if (isLocalTransport(STATE.currentServer)) return;
              declareSoftDead(
                `узел не пропускает трафик: контрольный dial хоста отклонён (${streakAtProbe}-й раз) ` +
                `И контрольный запрос браузера через SOCKS не прошёл: ${pr.error || "нет ответа"}`);
            });
        }
        // FIX(5.5.14): вердикт выносится общей функцией (см. declareSoftDead).
        if (v.dead && cooled) {
          softDeadHandled = declareSoftDead(
            `узел не пропускает трафик: контрольный dial через туннель отклонён ` +
            `${v.streak} раз подряд за ${Math.round(v.durMs / 1000)} c, передано 0 байт`);
""",
    "C2.twoArbiters")

# ================================================ D. честность панели/dbg ====
sub(BG, """    armedPort: STATE.armedPort,""",
    """    armedPort: STATE.armedPort,
    // FIX(5.5.14): почему прокси не вооружён, если статус «connected». Без этого
    // панель показывала «Прокси браузера: активен» при браузере, смотрящем в
    // мёртвый порт.
    proxyBlockedReason: endpointDead(),""",
    "D1.statusPayloadReason")

sub(BG, """              text: `mode=${mode}: правила хосту не отправляются (нет cap routeRules) — туннель не рву, прокси переустановлен на месте`""",
    """              text: `mode=${mode}: правила хосту не отправляются (нет cap routeRules) — туннель не рву, прокси: ${STATE.proxyMode}`""",
    "D2.modeDbgHonest")

sub(OPT, """    lines.push(`Прокси браузера: ${st.status?.proxyEnabled ? "активен" : "выключен"}`);""",
    """    {
      // FIX(5.5.14): «активен» при локальном транспорте direct означало
      // «браузер смотрит на порт, где никто не слушает»: интернета нет, а панель
      // говорит, что всё хорошо. Теперь причина напечатана прямо здесь.
      const pe = st.status?.proxyEnabled;
      const why = st.status?.proxyBlockedReason;
      lines.push(`Прокси браузера: ${pe ? "активен" : "не вооружён"}` +
        (st.status?.currentIsLocal ? "  ← выбран локальный транспорт (НЕ VPN), трафик идёт напрямую" : "") +
        (!pe && why ? `  (${why})` : ""));
    }""",
    "D3.optionsHonestProxy")

# ========================================================== E. версия ====
s = rd(MAN)
assert s.count('"version": "5.5.13"') == 1, "manifest version anchor"
wr(MAN, s.replace('"version": "5.5.13"', '"version": "5.5.14"', 1))
applied.append("E.manifestVersion")

print("APPLIED:", len(applied))
for a in applied:
    print("  +", a)
if failed:
    print("FAILED:")
    for t, p, n in failed:
        print("  !", t, p, "matches=", n)
    sys.exit(1)
