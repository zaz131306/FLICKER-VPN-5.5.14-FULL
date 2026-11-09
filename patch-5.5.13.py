#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Патч 5.5.13 — по пятой диагностике пользователя (5.5.12 + хост 5.5.4).

Дамп: 37 срезов «Ответ native host» подряд, 13:54:21 → 14:02:49, пользователь
руками переключал ноды (~14 смен) и каждый раз снимал диагностику.

Что подтвердилось как ПОЧИНЕННОЕ (ничего не трогаем):
  • autoPort: «порт 127.0.0.1:1080 занят — SOCKS слушает 127.0.0.1:1081» →
    «dbg: port-shift: … перевооружаю [ack]» → «proxy=socks port=1081».
    Карусели рестартов одной ноды в дампе нет вообще.
  • 36 из 37 срезов: «Туннель жив: контрольный dial пройден».
  • мягкая живость честно проигнорировала один отказ dial («подряд 1, трафик
    есть»), а на трёх отказах подряд панель показала «⚠ ТУННЕЛЬ МЁРТВ»
    (срезы 17–20, нода hw5.roghanmo.com — реально мёртвая, dial отклонён 0x1).
  • рейтинг помечает локальный транспорт: «← НЕ VPN (локальный транспорт)».

Что дамп вскрыл НОВОГО:

1) «dbg: proxy=none» посреди смены ноды — 14:00:04, 14:01:42, 14:02:17.
   Это и есть остаточная «ошибка возврата прокси браузеру». Механика:
     switchServer: switching=true → status="connecting" → sendToNative(stop)
       → await startTunnel() → ack пришёл → startTunnel вернул {pending:true}
       → finally: switching=FALSE
     и только ПОТОМ хост присылает «status: disconnected» — ответ на наш же
     stop. Ветка else в обработчике статуса guarded только флагом switching,
     а он уже сброшен:
       status="disconnected" → applyProxyMode() → hold не положен (ни
       resumeServerId, ни recoveryTimer, ни recovering — смена штатная) →
       setProxyNone() → БРАУЗЕР УХОДИТ НАПРЯМУЮ до «connected» новой ноды.
   Окно короткое (в дампе — доли секунды), но оно есть на КАЖДОЙ смене ноды,
   а попадание в него зависит от порядка сообщений: в 3 из 14 смен хост
   ответил на stop позже, чем startTunnel вернул ack. Хуже вариант порядка:
   если запоздалый «disconnected» приходит ПОСЛЕ «connected» новой ноды, то
   `status==="connected" && !switching` → handleTunnelLost() → только что
   поднятый туннель считается оборванным: минус в рейтинг, HOLD, восстановление.

2) Смена режима маршрутизации рвёт работающий туннель:
     14:02:03 dbg: proxy=socks … passthrough=182        ← режим all → smart
     14:02:03 dbg: switch: 193.124.35.241 -> 193.124.35.241
   Атомарный рестарт делался, чтобы новые правила уехали в sing-box. Но
   composeConfig шлёт routeRules/tunnelMode ТОЛЬКО если хост объявил cap
   routeRules/route-rules/routing, а хост 5.5.4 объявляет
   «ack, autoPort, diagnose, probe, liveness» — правил он не получает в
   принципе, маршрутизацию держит proxy.settings, который переустанавливается
   тут же, на месте. То есть рестарт — чистая потеря: разрыв + окно прямого
   трафика (см. п.1) ради ничего.

3) Панель не знает о сдвиге порта. reconcileSocksPort шлёт
   broadcastUI({type:"socksPort"}), а popup.js реагирует только на
   {type:"status"} → в подвале висит старый 1080, пока не придёт очередной
   статус. В дампе шапка диагностики: «SOCKS5 порт: 1080» при живом 1081.
   Плюс сама шапка не показывает, на каком порту ДЕЙСТВИТЕЛЬНО вооружён
   браузер, — а это главный вопрос при autoPort.

4) Топ рейтинга нечитаем: все ноды подписки называются одинаково
   («.𖥔 ݁ ˖ִ🛸༄˖°.»), адреса нет — отличить ноду от ноды невозможно.
   И локальный транспорт «Диагностика (direct)» занимает 2-е место топа
   (помечен, но в рейтинге участвует).

Что делаем:
  A. Ожидаемый stop-ack: switchServer помечает, что следующий «disconnected» —
     ответ на наш stop; обработчик статуса такой ответ игнорирует полностью
     (ни смена статуса, ни handleTunnelLost, ни applyProxyMode). Метка живёт
     SWITCH_STOP_ACK_MS, снимается потреблением (первый же «disconnected»),
     на stopTunnel и при неудачном старте. На «connected» НЕ снимается: ответ
     на stop может прийти и позже. Настоящий обрыв обрабатывается как раньше.
  B. Режим маршрутизации меняется БЕЗ рестарта туннеля, если хост не получает
     правил (нет cap routeRules). Если получает — атомарный рестарт остаётся.
  C. Порт: popup обновляется по «socksPort»; подвал и шапка диагностики
     показывают и порт хоста, и порт, на котором вооружён браузер.
  D. Топ рейтинга: только VPN-ноды, у каждой печатается host:port.
  E. Заодно закрыт тупик, который стал виден после A: «disconnected» от хоста
     вне состояния «connected» не оставлял ни намерения, ни таймера — прокси
     уходил браузеру навсегда. Теперь восстановление ставится ДО applyProxyMode
     (прокси остаётся в HOLD), кроме «отключено пользователем» и режима «Ничего».
"""
import io, os, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
EXT = os.path.join(ROOT, "ext")
BG = os.path.join(EXT, "background.js")
POP = os.path.join(EXT, "popup.js")
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


# ============================================================ A. STATE ====
sub(BG, '''  // ---- защита от утечки при смене ноды ----
  switching: false,           // идёт атомарная смена сервера: proxy.settings не трогаем''',
    '''  // ---- защита от утечки при смене ноды ----
  switching: false,           // идёт атомарная смена сервера: proxy.settings не трогаем
  // FIX(5.5.13): ждём ли мы «disconnected» как ответ на НАШ stop в ходе смены
  // ноды. switchServer сбрасывает switching сразу, как startTunnel вернул ack
  // ({pending:true}), а ответ на stop хост присылает ПОЗЖЕ — и он заставал
  // статус без защиты: status="disconnected" → applyProxyMode → proxy=none,
  // то есть браузер уходил напрямую посреди штатной смены ноды.
  pendingStopAck: false,
  pendingStopAckAt: 0,''',
    "A.stateFields")

sub(BG, '''const START_GRACE_MS = 10_000;''',
    '''const START_GRACE_MS = 10_000;
// FIX(5.5.13): сколько ждём ответ хоста на наш stop при смене ноды. В дампе
// пользователя этот ответ приходил в том же тике (доли секунды), но порядок
// сообщений не гарантирован: ответ мог прийти и ПОСЛЕ «connected» новой ноды.
// Окно намеренно короткое — 10 c: проглоченный настоящим обрывом статус всё
// равно добирается вердиктом подтверждения (HOLD → восстановление), а держать
// метку дольше незачем.
const SWITCH_STOP_ACK_MS = 10_000;''',
    "A.constWindow")

# switchServer: метим ожидаемый stop-ack
sub(BG, '''    STATE.status = "connecting";
    STATE.currentSpeed = 0;
    sendToNative({ command: "stop" });
    broadcastUI({ type: "status", status: "connecting" });''',
    '''    STATE.status = "connecting";
    STATE.currentSpeed = 0;
    // FIX(5.5.13): этот stop — наш, штатный. Его «disconnected» придёт, когда
    // switching уже сброшен (startTunnel вернул pending), и без метки он ронял
    // статус в disconnected и отдавал прокси браузеру (dbg: proxy=none).
    STATE.pendingStopAck = true;
    STATE.pendingStopAckAt = Date.now();
    sendToNative({ command: "stop" });
    broadcastUI({ type: "status", status: "connecting" });''',
    "A.switchMarksStopAck")

# switchServer: старт не удался — метку снимаем
sub(BG, '''    const res = await startTunnel(server);
    if (res.ok) return res;

    // Откат: лучше остаться на прежней ноде, чем сидеть без VPN.''',
    '''    const res = await startTunnel(server);
    if (res.ok) return res;

    // FIX(5.5.13): старт не удался — «ожидаемого» disconnected больше нет.
    // Иначе настоящий обрыв в течение окна был бы проглочен, а статус остался
    // «connecting» до 20-секундного watchdog.
    STATE.pendingStopAck = false;

    // Откат: лучше остаться на прежней ноде, чем сидеть без VPN.''',
    "A.switchFailureClears")

# NB: на «connected» метку НЕ снимаем. Ответ хоста на наш stop может прийти и
# ПОСЛЕ «connected» новой ноды (в дампе порядок гуляет: то «proxy=none» до
# connected, то наоборот). Метка живёт до потребления (первый же disconnected)
# либо до истечения SWITCH_STOP_ACK_MS; снять её на connected — значит вернуть
# вариант, где запоздалый stop-ack роняет только что поднятый туннель через
# handleTunnelLost.

# обработчик статуса: ожидаемый stop-ack игнорируем ПОЛНОСТЬЮ
sub(BG, '''      } else {
        // во время атомарной смены ноды «disconnected» от хоста — это ожидаемый
        // ответ на наш stop, а не обрыв; kill switch включать нельзя
        if (STATE.status === "connected" && !STATE.switching) {''',
    '''      } else {
        // FIX(5.5.13): ответ на НАШ stop в ходе смены ноды. Он штатно приходит
        // ПОСЛЕ того, как switching сброшен (startTunnel вернул {pending:true}),
        // и до 5.5.13 делал две беды:
        //   • status="connecting" → "disconnected" → applyProxyMode() → hold не
        //     положен (смена штатная: ни resumeServerId, ни recoveryTimer) →
        //     setProxyNone() → браузер ушёл напрямую посреди смены;
        //   • если новый туннель уже успел ответить «connected», то срабатывал
        //     handleTunnelLost("туннель закрыт") → свежий туннель объявлялся
        //     оборванным: минус в рейтинг, HOLD, восстановление.
        // В дампе пользователя это строки «dbg: proxy=none» в 14:00:04,
        // 14:01:42 и 14:02:17 — по одной почти на каждое переключение ноды.
        if (STATE.pendingStopAck && isStamp(STATE.pendingStopAckAt) &&
            (Date.now() - STATE.pendingStopAckAt) <= SWITCH_STOP_ACK_MS) {
          STATE.pendingStopAck = false;   // метка одноразовая: потреблена
          journal("switch-stop-ack",
            "ответ хоста на наш stop во время смены ноды проигнорирован: статус и прокси не тронуты");
          dbgNative({
            command: "dbg",
            text: "stop-ack: ответ на stop при смене ноды — статус " + STATE.status + ", прокси не трогаю"
          });
          broadcastUI({ type: "status", status: STATE.status });
          break;
        }
        // во время атомарной смены ноды «disconnected» от хоста — это ожидаемый
        // ответ на наш stop, а не обрыв; kill switch включать нельзя
        if (STATE.status === "connected" && !STATE.switching) {''',
    "A.ignoreStopAck")

# stopTunnel: явный стоп — метка недействительна
sub(BG, '''  // для DPI-режима native host не задействован — слать stop некому
  if (STATE.tunnelKind !== "dpi") sendToNative({ command: "stop" });''',
    '''  // FIX(5.5.13): явное/аварийное отключение — следующий «disconnected»
  // настоящий, глотать его нельзя (иначе статус залипнет в «connecting»).
  STATE.pendingStopAck = false;
  // для DPI-режима native host не задействован — слать stop некому
  if (STATE.tunnelKind !== "dpi") sendToNative({ command: "stop" });''',
    "A.stopTunnelClears")

# ------------------------------------------------ A2. тупик на connecting ----
# В самом дампе этого случая нет, но защита stop-ack сделала ветку заметной:
# «disconnected» от хоста, когда статус уже НЕ «connected» (рукопожатие не
# состоялось во время «connecting»), до 5.5.13 только гасил статус и звал
# applyProxyMode(). handleTunnelLost требует status === "connected" и не
# срабатывает → не появляется ни resumeServerId, ни recoveryTimer, а
# 20-секундный watchdog тоже проверяет «connecting» и молчит. Итог: прокси
# отдан браузеру (proxy=none) и ни одного таймера — вечный прямой трафик.
sub(BG, """  pendingStopAck: false,
  pendingStopAckAt: 0,""",
    """  pendingStopAck: false,
  pendingStopAckAt: 0,
  // FIX(5.5.13): последнее отключение было ЯВНЫМ («Отключить»). Без этой метки
  // нельзя отличить ответ хоста на наш stop от настоящего обрыва, а чинить
  // туннель после того, как пользователь его выключил, нельзя.
  stoppedByUser: false,""",
    "A2.stateStoppedByUser")

sub(BG, """  if (byUser) {
    STATE.resumeServerId = null;""",
    """  if (byUser) {
    STATE.stoppedByUser = true;   // FIX(5.5.13): руками выключено — не воскрешать
    STATE.resumeServerId = null;""",
    "A2.stopTunnelMarksUser")

sub(BG, """async function startTunnel(server) {
  // DPI-обход не требует ни сервера, ни native host — отдельный путь""",
    """async function startTunnel(server) {
  // FIX(5.5.13): любой старт — намерение держать туннель. Снимаем метку
  // «выключено пользователем», иначе следующий неожиданный «disconnected»
  // останется без восстановления.
  STATE.stoppedByUser = false;
  // DPI-обход не требует ни сервера, ни native host — отдельный путь""",
    "A2.startClearsUserStop")

sub(BG, """        if (!STATE.switching) STATE.status = "disconnected";
        STATE.stats.startedAt = null;
        applyProxyMode();""",
    """        if (!STATE.switching) STATE.status = "disconnected";
        STATE.stats.startedAt = null;
        // FIX(5.5.13): тупик. Хост сообщил «disconnected», когда мы уже не
        // «connected» (рукопожатие не состоялось): handleTunnelLost не вызван,
        // намерения и таймера нет, watchdog молчит — прокси уходил браузеру
        // НАВСЕГДА. Ставим восстановление ДО applyProxyMode, чтобы прокси
        // остался в HOLD, а не уехал в none.
        if (!STATE.switching && !STATE.stoppedByUser && !STATE.recoveryTimer &&
            !STATE.recovering && STATE.tunnelMode !== TUNNEL_MODES.OFF) {
          const scheduled = scheduleRecovery("хост сообщил disconnected (статус " +
            (msg.status || "?") + ")");
          if (scheduled) {
            journal("host-disconnect-recovery",
              "хост опустил туннель вне обрыва — восстановление запланировано, прокси держим");
          }
        }
        applyProxyMode();""",
    "A2.recoverOnHostDisconnect")

# =============================================== B. правила и рестарт ====
sub(BG, '''function composeConfig(server) {''',
    '''/**
 * FIX(5.5.13): получает ли хост наши правила маршрутизации вообще.
 *
 * composeConfig кладёт routeRules/tunnelMode в конфиг ТОЛЬКО при этом cap —
 * иначе Go-хост (5.5.4) не знает таких полей и молча их игнорирует. Значит
 * атомарный рестарт туннеля «чтобы правила уехали в sing-box» при таком хосте
 * не доставляет правил НИКУДА: маршрутизацию держит proxy.settings, который
 * переустанавливается на месте. Рестарт в этом случае — только разрыв и окно
 * прямого трафика (в дампе: «switch: 193.124.35.241 -> 193.124.35.241» на
 * смене режима all → smart).
 *
 * @returns {boolean}
 */
function nativeSupportsRouteRules() {
  const caps = STATE.nativeCaps || new Set();
  return caps.has("routeRules") || caps.has("route-rules") || caps.has("routing") ||
    STATE.advanced?.forceRouteRules === true;
}

function composeConfig(server) {''',
    "B.routeRulesHelper")

sub(BG, '''  const caps = STATE.nativeCaps || new Set();
  const hostSupportsRules = caps.has("routeRules") || caps.has("route-rules") || caps.has("routing");
  if (hostSupportsRules || STATE.advanced?.forceRouteRules === true) {''',
    '''  // FIX(5.5.13): условие вынесено в nativeSupportsRouteRules() — оно же решает,
  // нужен ли атомарный рестарт туннеля при смене режима маршрутизации.
  if (nativeSupportsRouteRules()) {''',
    "B.composeUsesHelper")

sub(BG, '''          // правила уехали и в sing-box — пересобираем туннель атомарно,
          // чтобы на время пересборки трафик не уходил мимо VPN
          if (mode !== TUNNEL_MODES.OFF && STATE.status === "connected" && STATE.currentServer) {
            const re = await switchServer(STATE.currentServer, { force: true });
            if (!re.ok) broadcastUI({ type: "error", message: re.error });
          } else if (''',
    '''          // правила уехали и в sing-box — пересобираем туннель атомарно,
          // чтобы на время пересборки трафик не уходил мимо VPN
          if (mode !== TUNNEL_MODES.OFF && STATE.status === "connected" && STATE.currentServer &&
              nativeSupportsRouteRules()) {
            const re = await switchServer(STATE.currentServer, { force: true });
            if (!re.ok) broadcastUI({ type: "error", message: re.error });
          } else if (mode !== TUNNEL_MODES.OFF && STATE.status === "connected" &&
                     STATE.currentServer) {
            // FIX(5.5.13): хост правил не получает (у 5.5.4 caps = ack, autoPort,
            // diagnose, probe, liveness) — маршрутизацию держит proxy.settings,
            // и applyProxyMode() выше уже переустановил его на месте: bypass-лист
            // поменялся без единого разрыва. Рвать работающий туннель незачем:
            // в дампе это выглядело как «switch: 193.124.35.241 -> 193.124.35.241»
            // с последующим «proxy=none».
            dbgNative({
              command: "dbg",
              text: `mode=${mode}: правила хосту не отправляются (нет cap routeRules) — туннель не рву, прокси переустановлен на месте`
            });
            journal("tunnel-mode-noop",
              `режим ${mode}: хост без cap routeRules — рестарт не нужен, прокси переустановлен`);
          } else if (''',
    "B.modeChangeNoRestart")

# ==================================================== C. порт в UI ====
sub(POP, '''  if (msg.type === "status") updateUI();''',
    '''  if (msg.type === "status") updateUI();
  // FIX(5.5.13): хост ушёл на другой порт (autoPort: 1080 занят → 1081),
  // reconcileSocksPort шлёт именно «socksPort». Без этой строки подвал панели
  // продолжал показывать 1080, хотя браузер уже вооружён на 1081.
  if (msg.type === "socksPort") updateUI();''',
    "C.popupSocksPortRefresh")

sub(POP, '''  $("footerInfo").textContent = st.tunnel
    ? `${st.tunnel.mode} · SOCKS5 127.0.0.1:${st.socksPort || 1080}`
    : `SOCKS5 127.0.0.1:${st.socksPort || 1080}`;''',
    '''  {
    // FIX(5.5.13): показываем и порт хоста, и порт, на котором ФАКТИЧЕСКИ
    // вооружён браузер. При autoPort они расходятся, и молчание панели стоило
    // пользователю часа диагностики: «SOCKS5 порт: 1080» при живом 1081.
    const sp = st.socksPort || 1080;
    const ap = st.armedPort;
    const armed = st.proxyArmed && ap && Number(ap) !== Number(sp) ? ` · прокси на ${ap}` : "";
    $("footerInfo").textContent = st.tunnel
      ? `${st.tunnel.mode} · SOCKS5 127.0.0.1:${sp}${armed}`
      : `SOCKS5 127.0.0.1:${sp}${armed}`;
  }''',
    "C.popupFooterArmedPort")

sub(OPT, '''    lines.push(`SOCKS5 порт: ${st.status?.socksPort || 1080}`);''',
    '''    {
      // FIX(5.5.13): порт хоста И порт, на котором вооружён браузер. При
      // autoPort (1080 занят → 1081) это разные числа, и в отчёте пользователя
      // шапка показывала 1080, тогда как хост слушал 1081.
      const sp = st.status?.socksPort || 1080;
      const ap = st.status?.armedPort;
      const armed = st.status?.proxyArmed
        ? (ap && Number(ap) !== Number(sp) ? ` (прокси браузера вооружён на ${ap})` : " (прокси браузера вооружён на нём же)")
        : " (прокси браузера НЕ вооружён)";
      lines.push(`SOCKS5 порт: ${sp}${armed}`);
    }''',
    "C.optionsArmedPort")

# ======================================================= D. топ рейтинга ====
sub(BG, '''          const vpnServers = servers.filter((s) => !isLocalTransport(s));
          const ranked = rankCandidates(STATE.rating, servers, { limit: Number(msg.limit) || 10, explore: 0 })''',
    '''          const vpnServers = servers.filter((s) => !isLocalTransport(s));
          // FIX(5.5.13): топ — только VPN-ноды. «Диагностика (direct)» в дампе
          // стояла на 2-м месте топа: подпись честная («← НЕ VPN»), но место в
          // рейтинге она занимала и вытесняла реальную ноду из видимой десятки.
          const ranked = rankCandidates(STATE.rating, vpnServers, { limit: Number(msg.limit) || 10, explore: 0 })''',
    "D.rankVpnOnly")

sub(BG, '''                id: r.id, name: r.server?.name || r.server?.host, host: r.server?.host,
                protocol: r.server?.protocol, tier: e.tier,''',
    '''                id: r.id, name: r.server?.name || r.server?.host, host: r.server?.host,
                port: r.server?.port,     // FIX(5.5.13): имена нод из подписки
                protocol: r.server?.protocol, tier: e.tier,''',
    "D.rankPort")

sub(OPT, '''      const name = String(n.name || n.host || n.id).slice(0, 32);
      lines.push(
        `  ${String(i + 1).padStart(2)}. ${pad(n.score, 5)}  ${pad(n.protocol, 10)}  ${name.padEnd(32)} ` +''',
    '''      const name = String(n.name || n.host || n.id).slice(0, 32);
      // FIX(5.5.13): в подписке почти все ноды называются одинаково
      // («.𖥔 ݁ ˖ִ🛸༄˖°.») — без адреса топ нечитаем, отличить ноду от ноды
      // и пожаловаться на конкретную невозможно.
      const addr = n.host ? `${n.host}${n.port ? ":" + n.port : ""}` : String(n.id || "");
      lines.push(
        `  ${String(i + 1).padStart(2)}. ${pad(n.score, 5)}  ${pad(n.protocol, 10)}  ${name.padEnd(32)} ` +
        `${addr.padEnd(30)} ` +''',
    "D.optionsAddr")

# ========================================================== E. версия ====
s = rd(MAN)
assert s.count('"version": "5.5.12"') == 1, "manifest version anchor"
wr(MAN, s.replace('"version": "5.5.12"', '"version": "5.5.13"', 1))
applied.append("E.manifestVersion")

print("APPLIED:", len(applied))
for a in applied:
    print("  +", a)
if failed:
    print("FAILED:")
    for t, p, n in failed:
        print("  !", t, p, "matches=", n)
    sys.exit(1)
