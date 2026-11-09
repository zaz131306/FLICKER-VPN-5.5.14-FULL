// hold-proxy.test.mjs — режим «держать прокси и чинить на месте» (5.5.4.2).
//
// Требование пользователя: при обрыве туннеля прокси НЕ должен выкидываться
// браузеру. Расширение обязано оставить трафик на SOCKS и поднимать ноду
// заново, а вернуть прокси браузеру — только если починить не удалось
// (иначе вместо VPN получаем вечную дыру в интернет), и всегда — по кнопке.

import test from "node:test";
import assert from "node:assert/strict";
import { loadBackground, createFakeHost, connectAndArm, VLESS_SERVER, VLESS_SERVER_B } from "./bg-harness.mjs";

const SERVERS = [VLESS_SERVER, VLESS_SERVER_B];

/** Индекс последней записи proxy.settings на момент вооружения. */
function armedIndex(api) {
  let idx = -1;
  api.proxyLog.forEach((c, i) => { if (c.op === "set" && c.value?.proxyType === "manual") idx = i; });
  return idx;
}
function noneAfter(api, idx) {
  return api.proxyLog.slice(idx + 1).some((c) => c.op === "set" && c.value?.proxyType === "none");
}

/** Убить туннель: хост молчит, контрольный запрос не проходит, статистика stale. */
function killTunnel(ctx) {
  const { STATE, clock } = ctx;
  const host = ctx.host;
  host.mode = "silent";
  host.probeOk = false;
  host.alive = false;
  STATE.lastStatsAt = clock.now - 80_000;
}

test("hold: при обрыве прокси остаётся на туннеле, а не улетает браузеру", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, clock } = ctx;
  try {
    await connectAndArm(ctx, {});
    const idx = armedIndex(api);
    assert.ok(idx >= 0, "прокси вооружён");
    assert.equal(STATE.holdProxy, true, "режим удержания включён по умолчанию");

    killTunnel(ctx);
    await clock.advance(30_000);
    api.fireAlarm("keepalive");
    await clock.advance(30_000);
    api.fireAlarm("keepalive");
    await clock.advance(25_000);

    assert.equal(noneAfter(api, idx), false,
      "браузеру вернули прокси (proxyType none) — трафик ушёл напрямую");
    assert.equal(STATE.proxyArmed, true, "прокси должен остаться вооружённым");
    assert.equal(STATE.proxyMode, "holding", "ожидался режим удержания");
    assert.equal(api.lastProxy().proxyType, "manual");
    assert.ok(/gosuslugi\.ru/.test(api.lastProxy().passthrough || ""),
      "боевой passthrough (RU напрямую) должен остаться");
  } finally { await ctx.teardown(); }
});

test("hold: туннель возвращается на место, прокси за всё время не снимался", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, clock } = ctx;
  try {
    await connectAndArm(ctx, {});
    const idx = armedIndex(api);
    killTunnel(ctx);
    await clock.advance(30_000);
    api.fireAlarm("keepalive");
    await clock.advance(55_000);
    assert.equal(STATE.proxyMode, "holding");

    // хост ожил (тот же процесс, без нового hello)
    const host = ctx.host;
    host.mode = "healthy";
    host.probeOk = true;
    host.alive = true;

    await clock.advance(45_000);
    host.stats();
    await clock.advance(5_000);

    assert.equal(STATE.status, "connected", "туннель восстановлен");
    assert.equal(STATE.proxyArmed, true);
    assert.equal(STATE.proxyMode, "socks", "снова боевой режим");
    assert.equal(STATE.holdSince, null, "удержание снято после восстановления");
    assert.equal(noneAfter(api, idx), false,
      "за весь цикл обрыв→восстановление прокси ни разу не отдали браузеру");
  } finally { await ctx.teardown(); }
});

test("hold ограничен по времени: не починили — прокси честно возвращается браузеру", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, clock } = ctx;
  try {
    await connectAndArm(ctx, {});
    const idx = armedIndex(api);
    killTunnel(ctx);                       // хост мёртв навсегда
    // FIX(5.5.9): срок удержания теперь считается ПО ПРОГРЕССУ восстановления
    // (попытка/смена ноды/stats/подтверждение туннеля его продлевают), а вечной
    // дыры не даёт абсолютный потолок — 5 минут. Поэтому ждём дольше прежних
    // 120 c: 12 × 45 c = 540 c > 300 c.
    for (let i = 0; i < 12; i++) {
      await clock.advance(45_000);
      api.fireAlarm("keepalive");
    }
    assert.equal(noneAfter(api, idx), true,
      "если восстановить не удалось, прокси обязан вернуться браузеру (иначе вечная дыра)");
    assert.equal(STATE.proxyArmed, false);
    assert.ok(["released", "off"].includes(STATE.proxyMode), STATE.proxyMode);
    assert.equal(api.lastProxy().proxyType, "none");
  } finally { await ctx.teardown(); }
});

test("hold выключается тумблером — прежнее поведение (сразу отдаём прокси)", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS, holdProxy: false } });
  const { api, STATE, clock } = ctx;
  try {
    assert.equal(STATE.holdProxy, false, "настройка прочитана из storage");
    await connectAndArm(ctx, {});
    const idx = armedIndex(api);
    killTunnel(ctx);
    for (let i = 0; i < 4; i++) { await clock.advance(30_000); api.fireAlarm("keepalive"); }
    assert.equal(noneAfter(api, idx), true, "без удержания прокси возвращается браузеру");
    assert.equal(STATE.proxyArmed, false);
  } finally { await ctx.teardown(); }
});

test("кнопка «Вернуть прокси» сильнее удержания", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, T, clock } = ctx;
  try {
    await connectAndArm(ctx, {});
    assert.equal(STATE.proxyArmed, true);
    STATE.proxyReleasedByUser = true;
    await T.releaseProxy("по кнопке в popup", { byUser: true });
    await clock.flush();
    assert.equal(api.lastProxy().proxyType, "none");
    assert.equal(STATE.proxyArmed, false);
    assert.equal(STATE.proxyMode, "released");
    // и самовосстановление не воюет с пользователем
    await clock.advance(120_000);
    assert.equal(STATE.proxyArmed, false, "после явной команды не перевооружаемся");
  } finally { await ctx.teardown(); }
});
