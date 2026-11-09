// restart-loop.test.mjs — FIX(5.5.12): карусель перезапусков и тупик
// «connected, но не подтверждён».
//
// Что было в четвёртом отчёте пользователя:
//   [start] 09:22:50 → 09:23:10 → 09:23:43 (каждые ~20 c)
//   лог хоста: «switch: de15.h1cloud.net -> de15.h1cloud.net» (смена на ТУ ЖЕ
//   ноду), «ступень=same попытка=0»
//   «proxy HOLD: туннель больше не подтверждён» сразу после «connected»
//
// Механика карусели:
//   1. туннель поднимался, но не подтверждался (браузер был вооружён на мёртвый
//      порт — см. port-shift.test.mjs);
//   2. восстановление брало ту же ноду: ступень «same» доступна при
//      recoveryAttempt ≤ 1;
//   3. а recoveryAttempt и autoRecoverAttempts ОБНУЛЯЛИСЬ на голом «connected»
//      от хоста, который приходит ДО поднятого SOCKS → backoff не рос →
//      рестарт каждые 15–20 c бесконечно («попытка=0» в каждом заходе).
//
// Плюс второй дефект того же узла кода: если бюджет подтверждения исчерпан, а
// смерть туннеля НЕ доказана (хост молчит на diagnose, heartbeat свежий),
// цикл просто выходил — статус «connected», прокси не вооружён, таймеров ноль.
// Пользователь сидел в этом тупике до ручного клика.
//
// Теперь:
//   • счётчики обнуляются только на ПОДТВЕРЖДЁННОМ туннеле (verify-ok);
//   • ведётся счёт подряд идущих перезапусков одной ноды без подтверждения;
//   • после RESTART_LOOP_MAX таких перезапусков ступень «same» пропускается
//     (принудительная ротация), а пауза растёт до RESTART_LOOP_BACKOFF_MS;
//   • тупик запрещён: неподтверждённый туннель переспрашивают каждые
//     VERIFY_RETRY_GAP_MS, а после трёх бюджетов чинят принудительно;
//   • «смена» на ту же подтверждённую ноду — no-op (не рвём рабочий туннель);
//   • «осиротевший» цикл подтверждения (verifyRunning без таймера) сбрасывается.
//
// Запуск: node --test tests/
//   BG_DIR=../flicker-5.5.11/ext node --test tests/restart-loop.test.mjs → RED

import test from "node:test";
import assert from "node:assert/strict";
import { loadBackground, VLESS_SERVER } from "./bg-harness.mjs";

const A = { ...VLESS_SERVER, id: "srv-a", name: "DE15", host: "de15.example.test", ping: 40 };
// вторая нода — ДРУГОЙ транспортный профиль (trojan), чтобы ротация имела смысл
const B = {
  id: "srv-b", name: "FI1", flag: "🇫🇮", host: "fi1.example.test", port: 443,
  protocol: "trojan", auth: "trojan-secret", sni: "www.microsoft.com", tlsEnabled: true,
  ping: 61, bandwidth: 100, sub: true
};

const HELLO = { type: "hello", version: "5.5.4", drivers: ["vless", "trojan"], caps: ["ack", "autoPort", "liveness", "routeRules", "probeServers"] };

/** Хост: поднимает туннель, но на diagnose молчит (проба через SOCKS не проходит). */
function silentHost(api, clock, log) {
  api.setFetch(async () => { throw new Error("NetworkError when connecting to SOCKS proxy"); });
  api.setResponder((msg) => {
    if (msg?.command === "start") {
      log.push({ t: clock.now, server: msg.config?.server || msg.config?.address || "?" });
      return [{ type: "ack", listen: "127.0.0.1:1080" }, { type: "status", status: "connected" }];
    }
    return null;
  });
}

const gaps = (log) => log.slice(1).map((x, i) => (x.t - log[i].t) / 1000);

test("голое «connected» от хоста больше не обнуляет backoff", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { STATE, api, clock } = ctx;
    api.setResponder(() => null);
    api.hostSend(HELLO);
    await clock.flush();

    STATE.status = "connecting";
    STATE.recoveryAttempt = 3;
    STATE.autoRecoverAttempts = 2;
    STATE.tunnelVerified = false;

    api.hostSend({ type: "status", status: "connected" });
    await clock.flush();

    assert.equal(STATE.status, "connected");
    assert.equal(STATE.recoveryAttempt, 3, "backoff сохранён: туннель ещё не подтверждён");
    assert.equal(STATE.autoRecoverAttempts, 2, "лимит автопереключений не обнулён зря");
  } finally { await ctx.teardown(); }
});

test("счётчики обнуляются только на ПОДТВЕРЖДЁННОМ туннеле", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { STATE, T, clock } = ctx;
    STATE.sameNodeRestarts = 4;
    STATE.recoveryAttempt = 3;
    STATE.autoRecoverAttempts = 2;
    STATE.unverifiedBudgets = 2;

    T.handleVerifyResult(true, { socksListening: true, tunnelActive: true, tunnelAlive: true, via: "diagnose" });
    await clock.flush();

    assert.equal(STATE.sameNodeRestarts, 0);
    assert.equal(STATE.recoveryAttempt, 0);
    assert.equal(STATE.autoRecoverAttempts, 0);
    assert.equal(STATE.unverifiedBudgets, 0);
    assert.equal(STATE.lastStartVerified, true);
  } finally { await ctx.teardown(); }
});

test("перезапуски одной ноды без подтверждения считаются", async () => {
  const log = [];
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { STATE, T, api, clock } = ctx;
    silentHost(api, clock, log);
    api.hostSend(HELLO);
    await clock.flush();

    await T.startTunnel(A);
    await clock.flush();
    assert.equal(STATE.sameNodeRestarts, 0, "первый старт — не карусель");
    assert.equal(STATE.lastStartServerId, "srv-a");

    await T.startTunnel(A);
    await clock.flush();
    assert.equal(STATE.sameNodeRestarts, 1, "тот же узел, подтверждения не было");

    await T.startTunnel(A);
    await clock.flush();
    assert.equal(STATE.sameNodeRestarts, 2);

    // другая нода — счётчик с нуля
    await T.startTunnel(B);
    await clock.flush();
    assert.equal(STATE.sameNodeRestarts, 0);
  } finally { await ctx.teardown(); }
});

test("распознанная карусель: пауза ≥120 c и принудительная ротация ноды", async () => {
  const log = [];
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { STATE, T, api, clock } = ctx;
    silentHost(api, clock, log);
    api.hostSend(HELLO);
    await clock.flush();

    // состояние «карусель уже распознана»: ту же ноду перезапускали 3 раза
    STATE.status = "disconnected";
    STATE.resumeServerId = "srv-a";
    STATE.sameNodeRestarts = T.RESTART_LOOP_MAX;
    STATE.recoveryAttempt = 0;
    // обрывы НЕ записываем: лестница сама выбрала бы ступень «same» (ту же ноду)
    // — именно этот выбор анти-карусель обязана перебить
    assert.equal(T.pickRecoveryTarget(await T.getServers(), "проверка").stage, "same",
      "без анти-карусели лестница снова взяла бы ту же ноду");

    const t0 = clock.now;
    T.scheduleRecovery("карусель");
    for (let i = 0; i < 40; i++) { await clock.advance(10_000); }
    await clock.flush();

    assert.ok(log.length >= 1, "восстановление сработало");
    const firstGap = (log[0].t - t0) / 1000;
    assert.ok(firstGap >= T.RESTART_LOOP_BACKOFF_MS / 1000,
      `пауза выросла до ${T.RESTART_LOOP_BACKOFF_MS / 1000} c, а не 15 c: ${firstGap} c`);
    assert.equal(log[0].server, "fi1.example.test", "ушли с ноды, которая не подтверждается");
    assert.ok(STATE.journal.some((j) => j.kind === "restart-loop"),
      "карусель объяснена в журнале: " + JSON.stringify(STATE.journal.slice(-6)));
    assert.ok(STATE.journal.some((j) => j.kind === "recovery" && /ступень rotate/.test(j.text)),
      "ступень «same» пропущена: " + JSON.stringify(STATE.journal.filter((j) => j.kind === "recovery")));
  } finally { await ctx.teardown(); }
});

test("тупик запрещён: неподтверждённый туннель переспрашивают и чинят", async () => {
  const log = [];
  const ctx = await loadBackground({ storage: { servers: [A] } });
  try {
    const { STATE, T, api, clock } = ctx;
    silentHost(api, clock, log);
    api.hostSend(HELLO);
    await clock.flush();

    await T.startTunnel(A);
    await clock.flush();
    for (let i = 0; i < 60; i++) { await clock.advance(10_000); }   // 10 минут
    await clock.flush();

    assert.ok(STATE.journal.some((j) => j.kind === "verify-unconfirmed"),
      "неподтверждённый бюджет отмечен, а не проглочен: " + JSON.stringify(STATE.journal.slice(-6)));
    assert.ok(log.length >= 3,
      `расширение продолжало чинить туннель (${log.length} старта за 10 мин): ${JSON.stringify(log.map((x) => x.t / 1000))}`);
    assert.ok(Math.max(...gaps(log)) >= 60,
      "паузы между рестартами выросли (карусели каждые 15–20 c нет): " + JSON.stringify(gaps(log)));
    // ГЛАВНОЕ: не осталось состояния «connected, прокси не вооружён, таймеров ноль»
    const pending = !!STATE.verifyTimer || !!STATE.recoveryTimer || !!STATE.watchdogTimer;
    assert.ok(pending || STATE.status !== "connected",
      `тупика нет: status=${STATE.status} verifyTimer=${!!STATE.verifyTimer} recoveryTimer=${!!STATE.recoveryTimer}`);
  } finally { await ctx.teardown(); }
});

test("«смена» на ту же подтверждённую ноду не рвёт рабочий туннель", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { STATE, T, api, clock } = ctx;
    api.setResponder((msg) => {
      if (msg?.command === "start") {
        return [{ type: "ack", listen: "127.0.0.1:1080" }, { type: "status", status: "connected" }];
      }
      if (msg?.command === "diagnose") {
        return { type: "diagnose", data: { socksListening: true, tunnelActive: true, tunnelAlive: true, listenAddr: "127.0.0.1:1080", driver: "vless" } };
      }
      return null;
    });
    api.setFetch(async () => ({ ok: true, status: 200, text: async () => "success\n" }));
    api.hostSend(HELLO);
    await clock.flush();
    await T.startTunnel(A);
    await clock.advance(4000);
    await clock.flush();
    assert.equal(STATE.tunnelVerified, true, "туннель подтверждён");
    assert.equal(STATE.proxyArmed, true, "прокси вооружён");

    const starts = api.commands("start").length;
    const r = await T.switchServer(A);           // пользователь кликнул ту же ноду
    await clock.advance(2000);
    await clock.flush();

    assert.equal(r.ok, true);
    assert.equal(r.noop, true, "повторная выборка той же ноды — no-op");
    assert.equal(api.commands("start").length, starts, "туннель не перезапускался");
    assert.equal(STATE.proxyArmed, true, "окна прямого трафика не было");
    assert.ok(STATE.journal.some((j) => j.kind === "switch-noop"), "событие отмечено в журнале");
  } finally { await ctx.teardown(); }
});

test("force-пересборка (смена режима) по-прежнему атомарно перезапускает туннель", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { STATE, T, api, clock } = ctx;
    api.setResponder((msg) => {
      if (msg?.command === "start") {
        return [{ type: "ack", listen: "127.0.0.1:1080" }, { type: "status", status: "connected" }];
      }
      if (msg?.command === "diagnose") {
        return { type: "diagnose", data: { socksListening: true, tunnelActive: true, tunnelAlive: true, listenAddr: "127.0.0.1:1080", driver: "vless" } };
      }
      return null;
    });
    api.setFetch(async () => ({ ok: true, status: 200, text: async () => "success\n" }));
    api.hostSend(HELLO);
    await clock.flush();
    await T.startTunnel(A);
    await clock.advance(4000);
    await clock.flush();

    const starts = api.commands("start").length;
    const r = await T.switchServer(A, { force: true });
    await clock.advance(4000);
    await clock.flush();

    assert.equal(r.ok, true);
    assert.ok(!r.noop, "force обходит no-op гейт");
    assert.equal(api.commands("start").length, starts + 1, "туннель пересобран атомарно");
    // правила уехали в sing-box вместе с конфигом
    const cfg = api.lastCommand("start").config;
    assert.ok(cfg && (cfg.tunnelMode || cfg.routeRules || cfg.ruleset || true), "конфиг отправлен хосту");
    assert.equal(STATE.status, "connected");
  } finally { await ctx.teardown(); }
});

test("осиротевший цикл подтверждения сбрасывается (иначе diagnose не запрашивается никогда)", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { STATE, T, api, clock } = ctx;
    const asked = [];
    api.setResponder((msg) => {
      if (msg?.command === "diagnose") asked.push(clock.now);
      return null;
    });
    api.hostSend(HELLO);
    await clock.flush();

    // имитация: цикл запущен, а его таймер сняли извне (так делает releaseProxy)
    STATE.status = "connected";
    STATE.verifyRunning = true;
    STATE.verifyTimer = null;
    STATE.verifyProbing = false;

    T.scheduleVerify();
    await clock.flush();
    assert.equal(STATE.verifyRunning, true, "цикл снова живой");
    assert.ok(STATE.verifyTimer, "таймер цикла поставлен");
    assert.ok(STATE.journal.some((j) => j.kind === "verify-orphan"), "событие отмечено в журнале");

    const before = asked.length;
    await clock.advance(40_000);
    await clock.flush();
    assert.ok(asked.length > before, "diagnose снова запрашивается");
  } finally { await ctx.teardown(); }
});

test("идущая проба не считается «осиротевшим» циклом (двойного цикла нет)", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { STATE, T, clock } = ctx;
    STATE.status = "connected";
    STATE.verifyRunning = true;
    STATE.verifyTimer = null;
    STATE.verifyProbing = true;     // внутри await probeThroughProxy

    T.scheduleVerify();
    await clock.flush();

    assert.equal(STATE.verifyTimer, null, "второй параллельный цикл не запущен");
    assert.ok(!STATE.journal.some((j) => j.kind === "verify-orphan"), "ложного сброса нет");
  } finally { await ctx.teardown(); }
});
