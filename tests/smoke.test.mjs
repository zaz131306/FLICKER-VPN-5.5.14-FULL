// smoke.test.mjs — регрессия: обычный сценарии не должны сломаться от правок.
//
// Эти тесты ОБЯЗАНЫ проходить и на оригинальной 5.5.4, и на починенной копии:
// они отсекают ситуацию «починили одно, сломали базовое».

import test from "node:test";
import assert from "node:assert/strict";
import { loadBackground, createFakeHost, connectAndArm, VLESS_SERVER, VLESS_SERVER_B } from "./bg-harness.mjs";

test("обычный цикл: подключился → отключился → прокси чист, туннель погашен", async () => {
  const ctx = await loadBackground({ storage: { servers: [VLESS_SERVER, VLESS_SERVER_B] } });
  const { api, STATE, T, clock } = ctx;
  try {
    await connectAndArm(ctx, {});
    assert.equal(STATE.status, "connected");
    assert.equal(STATE.proxyArmed, true);
    assert.equal(api.lastProxy().proxyType, "manual");

    await T.stopTunnel();
    await clock.flush();
    assert.equal(STATE.status, "disconnected");
    assert.equal(STATE.proxyArmed, false);
    assert.equal(api.lastProxy().proxyType, "none", "браузер должен остаться без прокси (не system!)");
    assert.ok(api.commands("stop").length >= 1, "хосту отправлен stop");
  } finally { await ctx.teardown(); }
});

test("после явного «Отключить» расширение не воскрешает туннель само", async () => {
  const ctx = await loadBackground({ storage: { servers: [VLESS_SERVER, VLESS_SERVER_B] } });
  const { api, STATE, T, clock } = ctx;
  try {
    await connectAndArm(ctx, {});
    const host = ctx.host;
    await T.stopTunnel();               // пользователь нажал «Отключить»
    await clock.flush();
    const startsBefore = host.startCalls;

    host.stats(3);
    await clock.advance(180_000);       // 3 минуты: alarm, watchdog, recovery
    api.fireAlarm("keepalive");
    await clock.advance(5_000);

    assert.equal(STATE.status, "disconnected", "самовольно подключаться нельзя");
    assert.equal(STATE.proxyArmed, false);
    assert.equal(host.startCalls, startsBefore, "команд start после «Отключить» быть не должно");
    assert.equal(api.lastProxy().proxyType, "none");
  } finally { await ctx.teardown(); }
});

test("DPI-режим (без native host) поднимается и вооружает прокси на порт ciadpi", async () => {
  const ctx = await loadBackground({ storage: { servers: [VLESS_SERVER] } });
  const { api, STATE, T, clock } = ctx;
  try {
    const host = createFakeHost(api, clock, { probeOk: true });
    ctx.host = host;
    host.hello();
    await clock.flush();

    const r = await T.startDpiTunnel({ id: "dpi-local", name: "DPI", host: "127.0.0.1", port: 1081, protocol: "dpi" });
    await clock.flush();
    assert.equal(r.ok, true, r.error);
    assert.equal(STATE.status, "connected");
    assert.equal(STATE.tunnelKind, "dpi");
    assert.equal(api.lastProxy().proxyType, "manual");
    assert.equal(api.lastProxy().socksPort, 1081, "DPI живёт на своём порту, не на 1080");

    // проверка живости не должна ломать боевую настройку
    const armed = api.lastProxy();
    await T.verifyDpi();
    await clock.flush();
    assert.equal(api.lastProxy().proxyType, armed.proxyType);
    assert.equal(api.lastProxy().socksPort, armed.socksPort);
    assert.equal(STATE.proxyArmed, true);
  } finally { await ctx.teardown(); }
});

test("kill switch блокирует трафик, пока туннель не поднят", async () => {
  const ctx = await loadBackground({ storage: { servers: [VLESS_SERVER], killSwitch: true } });
  const { api, STATE, T, clock } = ctx;
  try {
    const host = createFakeHost(api, clock, {});
    ctx.host = host;
    host.hello();
    await clock.flush();
    const started = await T.startTunnel(VLESS_SERVER);
    assert.equal(started.ok, true, started.error);
    await clock.advance(3_200);
    assert.equal(STATE.status, "connected");
    assert.equal(api.blockedByKillSwitch(), false, "при живом туннеле блокировки нет");

    // рвём туннель: хост сообщает disconnected
    host.mode = "silent";
    host.probeOk = false;
    api.hostSend({ type: "status", status: "disconnected", reason: "туннель закрыт" });
    await clock.flush();
    assert.equal(api.blockedByKillSwitch(), true, "kill switch обязан блокировать трафик");
    assert.equal(api.lastProxy().proxyType, "none", "трафик не должен идти мимо туннеля");
  } finally { await ctx.teardown(); }
});

test("смена ноды атомарна: proxy.settings во время переключения не трогаем", async () => {
  const ctx = await loadBackground({ storage: { servers: [VLESS_SERVER, VLESS_SERVER_B] } });
  const { api, STATE, T, clock } = ctx;
  try {
    await connectAndArm(ctx, {});
    const before = api.proxyLog.length;
    const p = T.switchServer(VLESS_SERVER_B);
    await clock.advance(3_500);
    const r = await p;
    assert.equal(r.ok, true, r.error);
    // во время switching записей proxy.settings быть не должно
    const during = api.proxyLog.slice(before);
    await clock.advance(3_500);
    assert.equal(STATE.currentServer.id, "srv-b");
    assert.equal(STATE.proxyArmed, true);
    assert.equal(during.length, 0, "окно утечки при смене ноды: " + JSON.stringify(during.map((c) => c.value?.proxyType)));
  } finally { await ctx.teardown(); }
});
