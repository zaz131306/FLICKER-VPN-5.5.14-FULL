// stop-ack.test.mjs — FIX(5.5.13): запоздалый ответ хоста на НАШ stop при смене
// ноды не должен ронять статус и отдавать прокси браузеру.
//
// Что показал пятый дамп пользователя (5.5.12 + хост 5.5.4, 37 срезов
// «Ответ native host», 13:54:21 → 14:02:49, ~14 ручных смен ноды):
//
//   14:01:42 dbg: switch: 140.225.209.180 -> 193.124.35.241
//   14:01:42 SOCKS5 слушает 127.0.0.1:1081
//   14:01:42 туннель: vless (193.124.35.241:443) connecting
//   14:01:42 dbg: proxy=none                    ← БРАУЗЕР УШЁЛ НАПРЯМУЮ
//   14:01:42 туннель: vless (193.124.35.241:443) connected
//   14:01:42 dbg: proxy=socks port=1081 kind=native passthrough=4
//
// то же в 14:00:04 и 14:02:17. Механика:
//   switchServer: switching=true → status="connecting" → sendToNative(stop)
//     → await startTunnel() → ack → вернул {pending:true} → finally:
//     switching=FALSE.
//   Ответ хоста на stop («status: disconnected») приходит ПОСЛЕ этого, и ветка
//   else обработчика статуса защищена только флагом switching:
//     status="disconnected" → applyProxyMode() → hold не положен (смена
//     штатная: ни resumeServerId, ни recoveryTimer, ни recovering) →
//     setProxyNone() → proxy=none.
//   Попадание в окно зависит от порядка сообщений: в 3 из 14 смен хост ответил
//   на stop позже, чем startTunnel вернул ack. При обратном порядке (ответ на
//   stop после «connected» новой ноды) срабатывал handleTunnelLost — свежий
//   туннель объявлялся оборванным: минус в рейтинг, HOLD, восстановление.
//
// Теперь switchServer метит ожидаемый stop-ack, а обработчик статуса такой
// ответ игнорирует полностью: ни статус, ни handleTunnelLost, ни applyProxyMode.
// Метка одноразовая (первый же «disconnected») и живёт SWITCH_STOP_ACK_MS;
// снимается также на stopTunnel и при неудачном старте. Настоящий обрыв
// обрабатывается ровно как раньше — это проверяется здесь же.
//
// Запуск: node --test tests/
//   BG_DIR=../flicker-5.5.12/ext node --test tests/stop-ack.test.mjs → RED

import test from "node:test";
import assert from "node:assert/strict";
import { loadBackground, connectAndArm, VLESS_SERVER, VLESS_SERVER_B } from "./bg-harness.mjs";

const A = { ...VLESS_SERVER, id: "srv-a", name: "DE15", host: "de15.example.test", ping: 40 };
const B = { ...VLESS_SERVER_B, id: "srv-b", name: "FI1", host: "fi1.example.test", ping: 60 };

const jkinds = (STATE) => STATE.journal.map((j) => j.kind);
const jtail = (STATE) => JSON.stringify(STATE.journal.slice(-8).map((j) => j.kind + ":" + j.text.slice(0, 60)));

/** Прокси, отданные браузеру напрямую (proxy=none / clear). */
const directHandovers = (api, from = 0) =>
  api.proxyLog.slice(from).filter((c) => c.op === "clear" ||
    (c.value && (c.value.proxyType === "none" || c.value.proxyType === "system")));

/**
 * Хост, который на start отвечает ТОЛЬКО ack: «connected» придёт позже, как в
 * настоящем дампе. Именно в этом промежутке и гуляет ответ на наш stop.
 */
function lateConnectedHost(api, listen = "127.0.0.1:1080") {
  api.setResponder((msg) => {
    if (msg?.command === "start") return [{ type: "ack", listen }];
    if (msg?.command === "diagnose") {
      return {
        type: "diagnose",
        data: { socksListening: true, tunnelActive: true, tunnelAlive: true, listenAddr: listen, driver: "vless" }
      };
    }
    return null;   // stop: ответ шлём руками, в нужный момент
  });
}

const disconnected = (reason) => ({ type: "status", status: "disconnected", reason });
const connected = () => ({ type: "status", status: "connected" });

test("запоздалый ответ на stop не отдаёт прокси браузеру (dbg: proxy=none)", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    await connectAndArm(ctx, { server: A });
    const { STATE, api, clock, T } = ctx;
    assert.equal(STATE.proxyArmed, true, "стартуем с вооружённым прокси");
    lateConnectedHost(api);

    const mark = api.proxyLog.length;
    const p = T.switchServer(B);
    await clock.flush();
    await clock.flush();
    assert.equal(STATE.switching, false, "ack получен, switching сброшен (как в жизни)");
    assert.equal(STATE.status, "connecting");

    // вот он — ответ хоста на наш stop, пришедший ПОСЛЕ сброса switching
    api.hostSend(disconnected("stop"));
    await clock.flush();
    await clock.flush();

    assert.equal(STATE.status, "connecting", "статус не упал в disconnected: " + jtail(STATE));
    assert.equal(STATE.proxyArmed, true, "прокси остался вооружён");
    assert.equal(directHandovers(api, mark).length, 0,
      "окно прямого трафика при смене ноды: " + JSON.stringify(directHandovers(api, mark)));
    assert.ok(jkinds(STATE).includes("switch-stop-ack"), "в журнале видно проигнорированный stop-ack: " + jtail(STATE));
    assert.ok(!jkinds(STATE).includes("tunnel-lost"), "обрыв не объявлен: " + jtail(STATE));

    // новая нода поднялась — прокси вооружается штатно
    api.hostSend(connected());
    await clock.flush();
    const r = await p;
    assert.equal(r.ok, true, r.error);
    await clock.advance(3_500);
    assert.equal(STATE.currentServer.id, "srv-b");
    assert.equal(STATE.status, "connected");
    assert.equal(STATE.proxyArmed, true);
    assert.equal(directHandovers(api, mark).length, 0, "за всю смену браузер не уходил напрямую");
  } finally { await ctx.teardown(); }
});

test("stop-ack, пришедший ПОСЛЕ connected новой ноды, не роняет свежий туннель", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    await connectAndArm(ctx, { server: A });
    const { STATE, api, clock, T } = ctx;
    lateConnectedHost(api);

    const mark = api.proxyLog.length;
    const p = T.switchServer(B);
    await clock.flush();
    api.hostSend(connected());          // новая нода уже поднята
    await clock.flush();
    api.hostSend(disconnected("stop")); // а ответ на stop опоздал
    await clock.flush();
    await clock.flush();

    assert.equal(STATE.status, "connected", "свежий туннель жив: " + jtail(STATE));
    assert.ok(!jkinds(STATE).includes("tunnel-lost"), "handleTunnelLost не сработал: " + jtail(STATE));
    assert.equal(STATE.resumeServerId, null, "намерение восстановления не появилось из ниоткуда");
    assert.equal(STATE.proxyArmed, true);
    assert.equal(directHandovers(api, mark).length, 0, "прокси не снят");
    await p;
  } finally { await ctx.teardown(); }
});

test("настоящий обрыв (смены ноды не было) обрабатывается как раньше", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    await connectAndArm(ctx, { server: A });
    const { STATE, api, clock } = ctx;
    assert.equal(STATE.pendingStopAck, false, "без смены ноды метки нет");

    api.hostSend(disconnected("туннель закрыт"));
    await clock.flush();
    await clock.flush();

    assert.equal(STATE.status, "disconnected", "обрыв принят");
    assert.ok(jkinds(STATE).includes("tunnel-lost"), "в журнале tunnel-lost: " + jtail(STATE));
    assert.equal(STATE.resumeServerId, "srv-a", "намерение вернуться на ноду живо");
    assert.ok(STATE.recoveryTimer != null || STATE.recovering, "восстановление запланировано");
  } finally { await ctx.teardown(); }
});

test("метка одноразовая: следующий disconnected после потребления — настоящий", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    await connectAndArm(ctx, { server: A });
    const { STATE, api, clock, T } = ctx;
    lateConnectedHost(api);

    const p = T.switchServer(B);
    await clock.flush();
    api.hostSend(disconnected("stop"));   // потребовали метку
    await clock.flush();
    api.hostSend(connected());
    await clock.flush();
    await p;
    assert.equal(STATE.status, "connected");

    api.hostSend(disconnected("реальный обрыв"));
    await clock.flush();
    await clock.flush();
    assert.equal(STATE.status, "disconnected", "второй disconnected не проглочен: " + jtail(STATE));
    assert.ok(jkinds(STATE).includes("tunnel-lost"), "tunnel-lost на месте: " + jtail(STATE));
  } finally { await ctx.teardown(); }
});

test("метка протухает: disconnected через 20 c после stop — настоящий, и тупика нет", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    await connectAndArm(ctx, { server: A });
    const { STATE, api, clock, T } = ctx;
    lateConnectedHost(api);

    const mark = api.proxyLog.length;
    const p = T.switchServer(B);
    await clock.flush();
    assert.equal(STATE.pendingStopAck, true, "метка поставлена");
    STATE.pendingStopAckAt = clock.now - 20_000;   // окно SWITCH_STOP_ACK_MS истекло

    api.hostSend(disconnected("рукопожатие не состоялось"));
    await clock.flush();
    await clock.flush();

    assert.equal(STATE.status, "disconnected", "протухшую метку не уважаем: " + jtail(STATE));
    assert.ok(!jkinds(STATE).includes("switch-stop-ack"), "stop-ack не засчитан: " + jtail(STATE));
    // FIX(5.5.13), п.E: статус уже не «connected», поэтому handleTunnelLost не
    // вызван. До починки здесь не оставалось ни намерения, ни таймера — прокси
    // уезжал браузеру навсегда (watchdog проверяет только «connecting»).
    assert.ok(STATE.recoveryTimer != null || STATE.recovering,
      "восстановление запланировано, тупика нет: " + jtail(STATE));
    assert.equal(directHandovers(api, mark).length, 0, "прокси в HOLD, а не отдан браузеру");
    p.catch(() => {});
  } finally { await ctx.teardown(); }
});

test("stopTunnel и неудачный старт снимают метку; руками выключенное не воскресает", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    await connectAndArm(ctx, { server: A });
    const { STATE, api, clock, T } = ctx;

    // 1) хост молчит на start → switchServer откатывается, метка снята
    api.setResponder(() => null);
    const pBad = T.switchServer(B);
    await clock.advance(3_000);      // ack-таймаут 2.5 c на новой ноде
    await clock.advance(3_000);      // и столько же на откате к прежней
    const bad = await pBad;
    assert.equal(STATE.pendingStopAck, false, "после неудачного старта метки нет: " + jtail(STATE));
    assert.equal(bad.ok, false, "смена не удалась: " + JSON.stringify(bad).slice(0, 160));

    // 2) явное отключение снимает метку и ставит «выключено пользователем»
    STATE.pendingStopAck = true;
    STATE.pendingStopAckAt = clock.now;
    await T.stopTunnel(true);
    assert.equal(STATE.pendingStopAck, false, "stopTunnel(byUser) снял метку");
    assert.equal(STATE.stoppedByUser, true, "помечено: выключено руками");
    assert.equal(STATE.status, "disconnected");

    // 3) ответ хоста на этот stop не должен поднять туннель обратно
    api.hostSend(disconnected("stop"));
    await clock.flush();
    await clock.flush();
    assert.equal(STATE.recoveryTimer, null, "«Отключить» не воскрешается: " + jtail(STATE));
    assert.equal(STATE.status, "disconnected");
  } finally { await ctx.teardown(); }
});

