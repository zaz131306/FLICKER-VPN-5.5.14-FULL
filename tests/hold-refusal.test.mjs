// hold-refusal.test.mjs — FIX(5.5.14): удержание запрещено на мёртвом конце.
//
// Шестой отчёт пользователя (5.5.13 в поле, хост 5.5.4):
//   header: узел «Диагностика (direct)», прокси вооружён на 127.0.0.1:1080,
//           при этом host SOCKS «не слушает»
//   22:04:09 verify: «туннель больше не подтверждён» → HOLD
//   22:04:17 probe: старт 600 серверов → 22:10:37 готово (6m20s)
//   22:00–22:06 браузер был прибит к порту, на котором НЕКТО НЕ СЛУШАЕТ,
//   потому что HOLD продлевался «прогрессом» пробного прогона.
//
// Требование пользователя: «прокси вообще не должен выкидываться браузеру» —
// но держать мёртвый порт равносильно выбросу: это и есть дыра в интернете.
// Удерживать можно только то, что способно вернуться.
//
// Правило 5.5.14: конец считается мёртвым, если транспорт локальный (direct),
// хост сказал nativeOnline=false, или diagnose сказал socksListening=false
// (свежесть 60 c). В этих случаях HOLD запрещён: прокси освобождается сразу,
// браузер выходит в интернет напрямую, в журнал пишется hold-refused.
//
// Запуск: node --test tests/
//   BG_DIR=../flicker-5.5.13/ext node --test tests/hold-refusal.test.mjs → RED

import test from "node:test";
import assert from "node:assert/strict";
import { loadBackground, connectAndArm, VLESS_SERVER, VLESS_SERVER_B } from "./bg-harness.mjs";

const A = { ...VLESS_SERVER, id: "srv-a", name: "DE15", host: "de15.example.test", ping: 40 };
const B = { ...VLESS_SERVER_B, id: "srv-b", name: "FI1", host: "fi1.example.test", ping: 60 };

const jkinds = (STATE) => STATE.journal.map((j) => j.kind);
const jtext = (STATE, kind) =>
  STATE.journal.filter((j) => j.kind === kind).map((j) => j.text).join(" | ");
const jtail = (STATE) => JSON.stringify(STATE.journal.slice(-8).map((j) => j.kind));
const lastProxyType = (api) => {
  const v = api.lastProxy();
  return v ? v.proxyType : (api.proxyLog.slice(-1)[0]?.op === "clear" ? "clear" : null);
};

async function settle(ctx, ms = 12_000, step = 1_000) {
  for (let t = 0; t < ms; t += step) {
    await ctx.clock.advance(step);
    await ctx.clock.flush();
  }
}

test("порт SOCKS мёртв → прокси освобождён сразу, HOLD не заводится", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { host } = await connectAndArm(ctx, { server: A });
    const { api, STATE, T, clock } = ctx;
    assert.equal(STATE.tunnelVerified, true, "нода подтверждена");
    assert.equal(lastProxyType(api), "manual", "прокси вооружён");

    api.hostSend({ type: "stats", bytesSent: 4096, bytesReceived: 8192, rtt: 40, dropped: 0 });
    await clock.flush();

    // как в отчёте: хост перестал слушать SOCKS, dial не проходит,
    // контрольный запрос браузера через SOCKS тоже не проходит
    host.socksListening = false;
    host.alive = false;
    host.probeOk = false;
    api.hostSend({ type: "diagnose", data: { socksListening: false, tunnelActive: false, tunnelAlive: false, listenAddr: "", driver: "vless" } });
    await clock.flush();
    assert.equal(STATE.lastSocksListening, false, "состояние порта SOCKS запомнено");

    for (let i = 0; i < 3; i++) {
      T.handleVerifyResult(false, { via: "browser-probe", error: "NetworkError when connecting to SOCKS proxy" });
      await settle(ctx, 4_000);
    }

    assert.ok(!/^holding/.test(STATE.proxyMode),
      "мёртвый порт не удерживается, proxyMode=" + STATE.proxyMode);
    assert.ok(jkinds(STATE).includes("hold-refused"), "в журнале отказ от удержания: " + jtail(STATE));
    assert.match(jtext(STATE, "hold-refused"), /не слушает|мёртв|SOCKS/i,
      "причина отказа объяснена: " + jtext(STATE, "hold-refused"));
    assert.equal(STATE.holdSince, null, "окна удержания нет");
    assert.equal(STATE.proxyArmed, false, "прокси браузера снят");
    assert.equal(lastProxyType(api), "none", "браузеру отдан прямой доступ, а не мёртвый порт");
  } finally { await ctx.teardown(); }
});

test("регрессия 5.5.4.2: SOCKS жив → HOLD по-прежнему заводится и чинит на месте", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { host } = await connectAndArm(ctx, { server: A });
    const { api, STATE, T, clock } = ctx;

    api.hostSend({ type: "stats", bytesSent: 4096, bytesReceived: 8192, rtt: 40, dropped: 0 });
    await clock.flush();
    assert.equal(lastProxyType(api), "manual", "прокси вооружён");

    // туннель порвался, но хост слушает SOCKS и может подняться на месте
    host.mode = "silent";
    host.alive = false;
    host.socksListening = true;
    host.probeOk = false;
    STATE.lastStatsAt = clock.now - 80_000;
    await T.releaseProxy("тест: обрыв туннеля", {});
    await settle(ctx, 3_000);

    assert.ok(jkinds(STATE).includes("hold-start"), "удержание началось: " + jtail(STATE));
    assert.equal(STATE.proxyMode, "holding", "прокси держится на туннеле");
    assert.equal(lastProxyType(api), "manual", "браузер по-прежнему смотрит в SOCKS");
    assert.ok(!jkinds(STATE).includes("hold-refused"), "отказа нет: " + jtail(STATE));
  } finally { await ctx.teardown(); }
});

test("пробный прогон не продлевает окно, когда конец мёртв", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { host } = await connectAndArm(ctx, { server: A });
    const { api, STATE, T, clock } = ctx;

    // обрыв при живом SOCKS — HOLD заведён честно
    host.mode = "silent";
    host.alive = false;
    host.socksListening = true;
    host.probeOk = false;
    STATE.lastStatsAt = clock.now - 80_000;
    await T.releaseProxy("тест: обрыв туннеля", {});
    await clock.flush();
    assert.equal(STATE.proxyMode, "holding", "окно удержания открыто");

    // теперь хост признался, что перестал слушать, и пошла проба 600 нод —
    // именно эта связка в отчёте держала браузер на мёртвом порту 6 минут
    host.socksListening = false;
    api.hostSend({ type: "diagnose", data: { socksListening: false, tunnelActive: false, tunnelAlive: false, listenAddr: "", driver: "vless" } });
    await clock.flush();
    assert.equal(STATE.lastSocksListening, false, "порт помечен мёртвым");
    STATE.probe = { ...(STATE.probe || {}), active: true, total: 600, mode: "full", done: 0 };
    const jlen = STATE.journal.length;

    // три цикла подтверждения при активной пробе: прогрессом это больше НЕ считается
    for (let i = 0; i < 3; i++) {
      const before = STATE.lastHoldProgressAt;
      STATE.probe.done = i * 200;
      T.handleVerifyResult(false, { via: "browser-probe", error: "NetworkError when connecting to SOCKS proxy" });
      await clock.flush();
      assert.equal(STATE.lastHoldProgressAt, before,
        "цикл " + i + ": проба не продлевает мёртвое окно (было " + before + ", стало " + STATE.lastHoldProgressAt + ")");
    }
    assert.equal(
      STATE.journal.slice(jlen).filter((j) => j.kind === "progress" && /пробой серверов/.test(j.text)).length, 0,
      "в журнале нет зачёта прогресса от пробы на мёртвом конце: " + jtail(STATE));

    // окно закрывается по отсутствию прогресса, браузер не остаётся на мёртвом порту
    await settle(ctx, 340_000, 5_000);
    assert.ok(!/^holding/.test(STATE.proxyMode), "удержание закончилось, proxyMode=" + STATE.proxyMode);
    assert.equal(STATE.holdSince, null, "окно удержания сброшено");
    assert.equal(STATE.proxyArmed, false, "прокси браузера снят — дыры нет");
  } finally { await ctx.teardown(); }
});
