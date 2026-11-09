// port-shift.test.mjs — FIX(5.5.12): сверка SOCKS-порта с тем, что реально
// слушает native host (autoPort).
//
// Что показал отчёт пользователя (хост 5.5.4, расширение 5.5.10):
//   «порт 127.0.0.1:1080 занят — SOCKS слушает 127.0.0.1:1081»
//   «proxy HOLD: туннель больше не подтверждён» сразу после «tunnel: connected»
//   «switch: de15.h1cloud.net -> de15.h1cloud.net», «ступень=same попытка=0»
//   [start] 09:22:50 → 09:23:10 → 09:23:43
//
// Механика: хост при занятом 1080 уходит на 1081 и сообщает адрес в ack.listen
// и diagnose.listenAddr. Расширение порт ЗАПОМИНАЛО, но уже вооружённый
// proxy.settings не трогало: браузер продолжал слать трафик на мёртвый 1080,
// контрольная проба не проходила → «туннель не подтверждён» → HOLD/возврат
// прокси → восстановление → рестарт той же ноды → снова 1081 → карусель.
//
// Теперь:
//   • сдвиг порта сразу перевооружает прокси (без снятия и без HOLD);
//   • неудачи подтверждения, полученные на старом порту, обнуляются;
//   • вердикт пробы, ушедшей на старый порт, считается устаревшим.
//
// Запуск: node --test tests/
//   BG_DIR=../flicker-5.5.11/ext node --test tests/port-shift.test.mjs → RED

import test from "node:test";
import assert from "node:assert/strict";
import { loadBackground, connectAndArm, VLESS_SERVER, VLESS_SERVER_B } from "./bg-harness.mjs";

const A = { ...VLESS_SERVER, id: "srv-a", name: "DE15", host: "de15.example.test", ping: 40 };
const B = { ...VLESS_SERVER_B, id: "srv-b", name: "FI1", host: "fi1.example.test", ping: 60 };

const kinds = (STATE) => STATE.journal.map((j) => j.kind);
// стартовый сброс унаследованной настройки прокси — штатное действие при
// загрузке страницы, к «возврату прокси браузеру» при обрыве отношения не имеет
const realReleases = (STATE) =>
  STATE.journal.filter((j) => j.kind === "release" && !/унаследованной/i.test(j.text));

test("autoPort: хост слушает 1081 — браузер вооружается на 1081, а не на мёртвый 1080", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    await connectAndArm(ctx, { server: A, host: { listenAddr: "127.0.0.1:1081" } });
    const { STATE, api } = ctx;

    assert.equal(STATE.socksPort, 1081, "фактический порт хоста запомнен");
    assert.equal(STATE.armedPort, 1081, "вооружён на тот же порт");
    assert.equal(STATE.proxyArmed, true);
    assert.equal(STATE.tunnelVerified, true);

    const armed = api.lastProxy();
    assert.equal(armed.proxyType, "manual");
    assert.equal(armed.socksPort, 1081, "в proxy.settings стоит порт хоста");

    assert.ok(kinds(STATE).includes("port-shift"), "сдвиг порта виден в журнале: " + JSON.stringify(STATE.journal));
    assert.equal(realReleases(STATE).length, 0, "прокси браузеру не возвращали: " + JSON.stringify(STATE.journal));
    assert.ok(!kinds(STATE).includes("hold-start"), "ложного HOLD на старте нет");
  } finally { await ctx.teardown(); }
});

test("diagnose принёс другой listenAddr — перевооружение на месте, без снятия прокси", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { host } = await connectAndArm(ctx, { server: A });
    const { STATE, api, clock } = ctx;
    assert.equal(STATE.armedPort, 1080, "стартовали на 1080");

    api.resetProxyLog();
    host.listenAddr = "127.0.0.1:1081";   // хост перезапустился и сдвинул порт
    api.hostSend({
      type: "diagnose",
      data: { socksListening: true, tunnelActive: true, tunnelAlive: true, listenAddr: "127.0.0.1:1081", driver: "vless" }
    });
    await clock.flush(30);

    assert.equal(STATE.socksPort, 1081);
    assert.equal(STATE.armedPort, 1081, "боевая настройка переведена на новый порт");
    assert.equal(STATE.proxyArmed, true, "прокси не снимался");
    assert.equal(api.lastProxy().socksPort, 1081);
    assert.equal(STATE.verifyFails, 0, "неудачи подтверждения обнулены");
    assert.equal(STATE.status, "connected");
    assert.equal(realReleases(STATE).length, 0, "возврата прокси не было: " + JSON.stringify(STATE.journal));
    assert.ok(!kinds(STATE).includes("hold-start"), "в HOLD не уходили");
  } finally { await ctx.teardown(); }
});

test("вердикт пробы, ушедшей на старый порт, не убивает туннель", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    await connectAndArm(ctx, { server: A });
    const { STATE, T, api, clock } = ctx;

    // хост уточнил порт, а вердикт пробы ещё про старый
    STATE.socksPort = 1081;
    const starts = api.commands("start").length;
    T.handleVerifyResult(false, { via: "browser-probe", probedPort: 1080, error: "NetworkError when connecting to SOCKS proxy" });
    await clock.flush(20);

    assert.equal(STATE.verifyFails, 0, "устаревшая проба не идёт в счётчик неудач");
    assert.equal(STATE.proxyArmed, true, "прокси остался на туннеле");
    assert.equal(STATE.status, "connected");
    assert.equal(STATE.recoveryTimer, null, "восстановление не запускалось");
    assert.equal(api.commands("start").length, starts, "ноду не перезапускали");
    assert.ok(kinds(STATE).includes("verify-stale"), "устаревший вердикт помечен в журнале");
  } finally { await ctx.teardown(); }
});

test("сдвиг порта засчитывается как прогресс удержания (HOLD не истекает посреди починки)", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    await connectAndArm(ctx, { server: A });
    const { STATE, T, clock } = ctx;
    STATE.holdSince = clock.now - 60_000;         // «держим» уже минуту
    STATE.lastHoldProgressAt = clock.now - 60_000;

    await T.reconcileSocksPort("127.0.0.1:1081", "diagnose");
    await clock.flush(20);

    assert.equal(STATE.socksPort, 1081);
    assert.ok(STATE.lastHoldProgressAt > clock.now - 60_000, "прогресс удержания зачтён");
    assert.equal(T.holdStillWanted(clock.now), true, "удержание продолжается");
  } finally { await ctx.teardown(); }
});

test("parseListenPort разбирает адрес хоста и не выдумывает порт", async () => {
  const ctx = await loadBackground();
  try {
    const { T } = ctx;
    assert.equal(T.parseListenPort("127.0.0.1:1081"), 1081);
    assert.equal(T.parseListenPort("1081"), 1081);
    assert.equal(T.parseListenPort(1081), 1081);
    assert.equal(T.parseListenPort("[::1]:1080"), 1080);
    assert.equal(T.parseListenPort(""), null);
    assert.equal(T.parseListenPort(null), null);
    assert.equal(T.parseListenPort("127.0.0.1:port"), null);
    assert.equal(T.parseListenPort(0), null);
    assert.equal(T.parseListenPort(70000), null);
  } finally { await ctx.teardown(); }
});

test("порт из ack не вооружает прокси в режиме «Ничего»", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { host } = await connectAndArm(ctx, { server: A });
    const { STATE, T, api, clock } = ctx;

    await api.fireRuntimeMessage({ action: "setTunnelMode", mode: "off" });
    await clock.flush(20);
    assert.equal(STATE.proxyArmed, false, "в режиме off прокси снят");

    api.resetProxyLog();
    host.listenAddr = "127.0.0.1:1081";
    api.hostSend({
      type: "diagnose",
      data: { socksListening: true, tunnelActive: true, tunnelAlive: true, listenAddr: "127.0.0.1:1081", driver: "vless" }
    });
    await clock.flush(30);

    assert.equal(STATE.socksPort, 1081, "порт запомнен");
    assert.equal(STATE.proxyArmed, false, "но прокси не вооружён — пользователь выбрал прямой трафик");
    const armed = api.lastProxy();
    assert.ok(!armed || armed.proxyType !== "manual", "manual-прокси не выставлялся: " + JSON.stringify(armed));
    assert.equal(T.statusPayload().proxyMode, "off-mode");
  } finally { await ctx.teardown(); }
});
