// mode-off.test.mjs — FIX(5.5.12): режим маршрутизации «Ничего» (off).
//
// Что было в четвёртом отчёте пользователя:
//   09:23:04 [release] режим маршрутизации: off
//   09:23:10 [start]   той же ноды
//   при этом панель показывала «Маршрутизация: all».
//
// Единственное место, которое освобождает прокси с такой причиной, —
// обработчик setTunnelMode; отправляет его только popup.js (change на селекте).
// В Firefox селект меняет значение от колеса мыши и от стрелок: один случайный
// скролл вкладки «Дополнительно» выключал VPN. Дальше срабатывали три дефекта:
//   1. обработчик OFF освобождал прокси и ТУТ ЖЕ перезапускал туннель
//      (switchServer на ту же ноду) — «выключить VPN» рвало работающий туннель;
//   2. «connected» от хоста сбрасывал proxyReleasedByUser, и прокси вооружался
//      обратно, хотя пользователь выбрал прямой трафик;
//   3. режима OFF не было в applyProxyModeNow — он держался только на флаге,
//      который сбрасывался в трёх местах.
//
// Теперь OFF — авторитетное состояние: прокси не вооружается ни при каком
// «connected», туннель не перезапускается, пробы не гоняются (проба сама
// временно вооружает manual-прокси), а возврат на реальный режим снимает
// запрет и снова вооружает прокси.
//
// Запуск: node --test tests/
//   BG_DIR=../flicker-5.5.11/ext node --test tests/mode-off.test.mjs → RED

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadBackground, connectAndArm, VLESS_SERVER, VLESS_SERVER_B } from "./bg-harness.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const A = { ...VLESS_SERVER, id: "srv-a", name: "DE15", host: "de15.example.test", ping: 40 };
const B = { ...VLESS_SERVER_B, id: "srv-b", name: "FI1", host: "fi1.example.test", ping: 60 };

const jkinds = (STATE) => STATE.journal.map((j) => j.kind);
const jtail = (STATE) => JSON.stringify(STATE.journal.slice(-8));

test("OFF: прокси снят, туннель НЕ перезапускается", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { host } = await connectAndArm(ctx, { server: A });
    const { STATE, api, clock, T } = ctx;
    assert.equal(STATE.proxyArmed, true, "стартовали с вооружённым прокси");
    const starts = api.commands("start").length;

    const r = await api.fireRuntimeMessage({ action: "setTunnelMode", mode: "off" });
    await clock.advance(1000);
    await clock.flush();

    assert.equal(r.ok, true);
    assert.equal(STATE.tunnelMode, "off");
    assert.equal(STATE.proxyArmed, false, "прокси снят");
    assert.equal(T.statusPayload().proxyMode, "off-mode", "честный режим, а не «released» как авария");
    assert.equal(api.commands("start").length, starts, "туннель не перезапускался: " + jtail(STATE));
    assert.equal(host.startCalls, 1, "хост не получил второй start");
    assert.ok(jkinds(STATE).includes("release"), "в журнале есть причина освобождения");
    assert.ok(!jkinds(STATE).slice(-3).includes("start"), "после release старта нет: " + jtail(STATE));
  } finally { await ctx.teardown(); }
});

test("OFF авторитетен: «connected» + diagnose не вооружают прокси обратно", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { host } = await connectAndArm(ctx, { server: A });
    const { STATE, api, clock, T } = ctx;
    await api.fireRuntimeMessage({ action: "setTunnelMode", mode: "off" });
    await clock.advance(1000);
    await clock.flush();
    assert.equal(STATE.proxyArmed, false);

    api.resetProxyLog();
    host.sockListening = true;
    api.hostSend({ type: "status", status: "connected" });
    await clock.advance(4000);
    await clock.flush();
    api.hostSend({ type: "diagnose", data: { socksListening: true, tunnelActive: true, tunnelAlive: true, listenAddr: "127.0.0.1:1080", driver: "vless" } });
    await clock.advance(1000);
    await clock.flush();

    assert.equal(STATE.proxyArmed, false, "прокси не вернулся на туннель вопреки выбору пользователя");
    const armed = api.lastProxy();
    assert.ok(!armed || armed.proxyType !== "manual", "manual-прокси не выставлялся: " + JSON.stringify(armed));
  } finally { await ctx.teardown(); }
});

test("OFF: пробы живости не гоняются (иначе «выключенный VPN» всё равно тянет трафик)", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    await connectAndArm(ctx, { server: A });
    const { STATE, api, clock, T } = ctx;
    await api.fireRuntimeMessage({ action: "setTunnelMode", mode: "off" });
    await clock.advance(1000);
    await clock.flush();

    api.resetProxyLog();
    const diagnoseBefore = api.commands("diagnose").length;
    T.scheduleVerify();
    await clock.advance(10_000);
    await clock.flush();

    assert.equal(STATE.verifyRunning, false, "цикл подтверждения в OFF не запускается");
    assert.equal(api.commands("diagnose").length, diagnoseBefore, "diagnose не запрашивался");
    const armed = api.lastProxy();
    assert.ok(!armed || armed.proxyType !== "manual", "проба не вооружала manual-прокси: " + JSON.stringify(armed));
  } finally { await ctx.teardown(); }
});

test("повторная установка того же режима — no-op (туннель не рвётся)", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    await connectAndArm(ctx, { server: A });
    const { STATE, api, clock } = ctx;
    const starts = api.commands("start").length;

    const r = await api.fireRuntimeMessage({ action: "setTunnelMode", mode: "all" });
    await clock.advance(3000);
    await clock.flush();
    assert.equal(r.ok, true);
    const startsAfterFirst = api.commands("start").length;

    const r2 = await api.fireRuntimeMessage({ action: "setTunnelMode", mode: "all" });
    await clock.advance(3000);
    await clock.flush();

    assert.equal(r2.unchanged, true, "повтор помечен как no-op");
    assert.equal(api.commands("start").length, startsAfterFirst, "второй identical-запрос ноду не перезапускал");
    assert.equal(STATE.tunnelMode, "all");
    assert.ok(startsAfterFirst >= starts);
  } finally { await ctx.teardown(); }
});

test("возврат из OFF в «Всё через VPN»: прокси снова вооружён на туннеле", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { host } = await connectAndArm(ctx, { server: A });
    const { STATE, api, clock, T } = ctx;
    await api.fireRuntimeMessage({ action: "setTunnelMode", mode: "off" });
    await clock.advance(1000);
    await clock.flush();
    assert.equal(STATE.proxyArmed, false);

    const r = await api.fireRuntimeMessage({ action: "setTunnelMode", mode: "all" });
    await clock.advance(6000);
    host.stats();
    await clock.flush();

    assert.equal(r.ok, true);
    assert.equal(STATE.tunnelMode, "all");
    assert.equal(STATE.proxyReleasedByUser, false, "запрет на вооружение снят");
    assert.equal(STATE.proxyArmed, true, "прокси вернулся на туннель: " + jtail(STATE));
    assert.equal(api.lastProxy().socksPort, STATE.socksPort);
    assert.equal(T.statusPayload().tunnel.mode, "all");
  } finally { await ctx.teardown(); }
});

test("возврат из OFF без туннеля: расширение поднимает ноду само", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { host } = await connectAndArm(ctx, { server: A });
    const { STATE, api, clock } = ctx;
    await api.fireRuntimeMessage({ action: "setTunnelMode", mode: "off" });
    await clock.advance(1000);
    await clock.flush();

    // туннель упал, пока пользователь сидел в «Ничего»
    api.hostSend({ type: "status", status: "disconnected", reason: "узел недоступен" });
    await clock.advance(1000);
    await clock.flush();
    assert.equal(STATE.status, "disconnected");

    await api.fireRuntimeMessage({ action: "setTunnelMode", mode: "smart" });
    for (let i = 0; i < 10; i++) { await clock.advance(10_000); host.stats(); }
    await clock.flush();

    assert.equal(STATE.tunnelMode, "smart");
    assert.equal(STATE.status, "connected", "туннель поднят после возврата из OFF: " + jtail(STATE));
    assert.equal(STATE.proxyArmed, true, "и прокси вооружён");
  } finally { await ctx.teardown(); }
});

test("popup: случайный change селекта больше не выключает VPN (колесо + подтверждение)", () => {
  const extDir = process.env.BG_DIR ? path.resolve(process.env.BG_DIR) : path.resolve(HERE, "..", "ext");
  const src = readFileSync(path.join(extDir, "popup.js"), "utf8");
  assert.match(src, /addEventListener\("wheel"/, "колесо мыши над селектом перехвачено");
  assert.match(src, /mode === "off"/, "режим «Ничего» проверяется отдельно");
  assert.match(src, /confirm\(/, "перед выключением VPN спрашиваем подтверждение");
  assert.match(src, /lastKnownTunnelMode/, "есть значение для отката случайного изменения");
});
