// hold-progress.test.mjs — FIX(5.5.9): обрыв туннеля больше не возвращает прокси
// браузеру посреди починки.
//
// Что показала диагностика пользователя (расширение 5.5.8 + native host 5.5.4):
//   1. Текущая нода — «Диагностика (direct)»: статус connected, прокси вооружён,
//      а трафик идёт НАПРЯМУЮ. То есть «VPN работает» при отсутствии VPN.
//   2. «probe: старт 600 серверов (mode=full)»: пока хост жуёт пробу, diagnose
//      отвечает поздно → «туннель больше не подтверждён» → HOLD-окна по 15–25 c
//      на каждом переключении. Это не смерть туннеля.
//   3. Удержание считалось от ПЕРВОГО обрыва и не продлевалось: backoff 15→30→60 c
//      плюс бюджет вооружения до 45 c всегда длиннее holdMaxMs 120 c, поэтому
//      прокси возвращался браузеру прямо посреди восстановления. После возврата
//      lastArmedProxyValue обнулялся — удержание не могло включиться снова;
//      а canHold требовал status connected/connecting, хотя восстановление идёт
//      уже в disconnected.
//   4. «порт 127.0.0.1:1080 занят — SOCKS слушает 127.0.0.1:1081»: авто-порт
//      сработал штатно, но 1081 был дефолтом локального ciadpi — два прокси на
//      одном порту.
//
// Запуск: node --test tests/
//   BG_DIR=../ext557 node --test tests/hold-progress.test.mjs → RED (фиксов нет)

import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { loadBackground, connectAndArm, VLESS_SERVER, VLESS_SERVER_B } from "./bg-harness.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LIB = process.env.BG_DIR ? path.resolve(process.env.BG_DIR, "lib") : path.resolve(HERE, "..", "ext", "lib");
const DPI = await import(pathToFileURL(path.join(LIB, "dpi.js")).href);

const SERVERS = [VLESS_SERVER, VLESS_SERVER_B];
// узел из DEFAULT_SERVERS расширения: протокол direct, host 127.0.0.1
const DIAG = { id: "diag", name: "Диагностика (direct)", protocol: "direct", host: "127.0.0.1", port: 443, ping: 4 };
const FAST = { ...VLESS_SERVER, id: "srv-fast", name: "Быстрый", host: "fast.example.test", ping: 90 };

function armedIndex(api) {
  let idx = -1;
  api.proxyLog.forEach((c, i) => { if (c.op === "set" && c.value?.proxyType === "manual") idx = i; });
  return idx;
}
function noneAfter(api, idx) {
  return api.proxyLog.slice(idx + 1).some((c) => c.op === "set" && c.value?.proxyType === "none");
}
function killTunnel(ctx) {
  const { STATE, clock, host } = ctx;
  host.mode = "silent"; host.probeOk = false; host.alive = false;
  STATE.lastStatsAt = clock.now - 80_000;
}

// ============================================================ 3. удержание

test("hold: чистая логика — держим по ПРОГРЕССУ, а не по абсолютному таймеру", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { STATE, T, clock } = ctx;
  try {
    STATE.holdMaxMs = 15_000;                       // окно без прогресса
    const now = clock.now;
    STATE.holdSince = now - 200_000;                // держим уже 200 c
    STATE.lastHoldProgressAt = now - 5_000;         // но прогресс был 5 c назад
    assert.equal(T.holdStillWanted(now), true, "пока есть прогресс — держим, даже если прошло 200 c");
    assert.equal(T.holdStillWanted(now), true);
    assert.ok(T.holdRemainingMs(now) > 0 && T.holdRemainingMs(now) <= 15_000, "остаток — по окну без прогресса");

    STATE.lastHoldProgressAt = now - 16_000;        // прогресса нет 16 c > 15 c
    assert.equal(T.holdStillWanted(now), false, "без прогресса дольше окна — отпускаем");
    assert.equal(T.holdRemainingMs(now), 0);

    // абсолютный потолок: прогресс есть, но держим уже 700 c (> 300 c)
    STATE.lastHoldProgressAt = now;
    STATE.holdSince = now - 700_000;
    assert.equal(T.holdStillWanted(now), false, "потолок удержания защищает от вечной дыры");

    STATE.advanced = { ...(STATE.advanced || {}), holdUnbounded: true };
    assert.equal(T.holdStillWanted(now), true, "advanced.holdUnbounded — держать без потолка");
    STATE.advanced = { ...(STATE.advanced || {}), holdUnbounded: false, holdHardCapMs: 900_000 };
    STATE.holdSince = now - 700_000;
    assert.equal(T.holdStillWanted(now), true, "advanced.holdHardCapMs переопределяет потолок");
  } finally { await ctx.teardown(); }
});

test("hold: пока восстановление ДЕЛАЕТ ПРОГРЕСС, прокси не возвращается браузеру (было 120 c — обрыв посреди починки)", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, T, clock } = ctx;
  try {
    await connectAndArm(ctx, {});
    const idx = armedIndex(api);
    assert.ok(idx >= 0, "прокси вооружён");
    killTunnel(ctx);                    // хост молчит: настоящий обрыв
    STATE.holdMaxMs = 15_000;

    await T.releaseProxy("тест: обрыв туннеля", {});
    assert.equal(STATE.proxyMode, "holding", "удержание включилось");
    assert.ok(STATE.holdSince, "holdSince выставлен");

    // 12 циклов по 10 c = 120 c (ровно старый абсолютный срок), но каждый раз
    // есть РЕАЛЬНЫЙ прогресс: новая попытка восстановления / stats от хоста
    for (let i = 0; i < 12; i++) {
      await clock.advance(10_000);
      T.markHoldProgress(`попытка ${i + 1}`);
      assert.equal(T.holdStillWanted(clock.now), true, `итерация ${i}: держим`);
    }
    assert.equal(noneAfter(api, idx), false, "браузеру вернули прокси посреди восстановления");
    assert.equal(STATE.proxyMode, "holding");
    assert.ok((clock.now - STATE.holdSince) > 100_000, "прожили дольше старого срока 120 c");
  } finally { await ctx.teardown(); }
});

test("hold: без прогресса прокси честно возвращается, но ВОССТАНОВЛЕНИЕ ПРОДОЛЖАЕТСЯ и снимок сохраняется", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, T, clock } = ctx;
  try {
    await connectAndArm(ctx, {});
    const idx = armedIndex(api);
    STATE.holdMaxMs = 15_000;
    // никакого прогресса 20 c — окно исчерпано
    STATE.holdSince = clock.now - 20_000;
    STATE.lastHoldProgressAt = clock.now - 20_000;

    await T.releaseProxy("тест: без прогресса", {});
    assert.equal(STATE.proxyArmed, false, "прокси снят");
    assert.ok(noneAfter(api, idx), "браузеру вернули прокси — вечной дыры в интернет нет");
    assert.ok(STATE.lastArmedProxySnapshot, "снимок боевой настройки сохранён (иначе удержание не включится снова)");
    assert.ok(STATE.recovering || STATE.recoveryTimer, "после возврата прокси восстановление НЕ остановлено");
    assert.ok(STATE.journal.some((j) => j.kind === "release"), "возврат прокси записан в журнал");
  } finally { await ctx.teardown(); }
});

test("hold (defect B): восстановление идёт уже в disconnected — удержание не слетает", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, T, clock } = ctx;
  try {
    await connectAndArm(ctx, {});
    const idx = armedIndex(api);
    killTunnel(ctx);
    STATE.holdMaxMs = 15_000;
    // recoverFromDeadTunnel переводит статус в disconnected ДО того, как
    // отработает поздний releaseProxy: раньше canHold требовал connected/
    // connecting и прокси улетал браузеру в самый разгар починки
    STATE.status = "disconnected";
    STATE.recovering = true;

    await T.releaseProxy("тест: обрыв во время восстановления", {});
    assert.equal(STATE.proxyMode, "holding", "удержание включилось и в disconnected");
    assert.equal(STATE.proxyArmed, true, "прокси остался на туннеле");
    assert.equal(noneAfter(api, idx), false, "браузеру прокси не возвращали");
    assert.ok(STATE.journal.some((j) => j.kind === "hold-start"), "вход в удержание записан");
  } finally { await ctx.teardown(); }
});

test("hold (defect C): после возврата прокси следующий обрыв снова держится, а не сливает трафик", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, T, clock } = ctx;
  try {
    await connectAndArm(ctx, {});
    STATE.holdMaxMs = 15_000;
    // удержание исчерпано без прогресса -> прокси честно вернулся браузеру
    STATE.holdSince = clock.now - 20_000;
    STATE.lastHoldProgressAt = clock.now - 20_000;
    await T.releaseProxy("тест: первый возврат", {});
    assert.equal(STATE.proxyArmed, false);
    assert.equal(STATE.recoveryStage, "same", "лестница сброшена — новый обрыв начинаем заново");
    assert.ok(STATE.lastArmedProxySnapshot, "снимок боевой настройки сохранён (видно в отчёте)");
    const idxAfterFirst = armedIndex(api);

    // туннель удалось вернуть: прокси снова вооружён
    ctx.host.mode = "ok"; ctx.host.probeOk = true; ctx.host.alive = true;
    await T.startTunnel(VLESS_SERVER_B);
    await clock.advance(3_500);
    ctx.host.stats();
    await clock.flush();
    assert.equal(STATE.proxyArmed, true, "прокси снова вооружён");

    // и тут новый обрыв — удержание ОБЯЗАНО включиться снова
    killTunnel(ctx);
    const idx2 = armedIndex(api);
    await T.releaseProxy("тест: второй обрыв", {});
    assert.equal(STATE.proxyMode, "holding", "удержание включилось повторно");
    assert.ok(STATE.holdSince != null, "holdSince снова выставлен");
    assert.equal(noneAfter(api, idx2), false, "второго возврата прокси браузеру не было");
    assert.ok(idxAfterFirst >= 0);
    const kinds = STATE.journal.map((j) => j.kind);
    const lastRelease = kinds.lastIndexOf("release");
    const holdAfter = kinds.indexOf("hold-start", lastRelease + 1);
    assert.ok(lastRelease >= 0, "первый возврат записан в журнал: " + JSON.stringify(kinds));
    assert.ok(holdAfter > lastRelease,
      "после возврата прокси новый обрыв СНОВА вошёл в удержание: " + JSON.stringify(kinds));
  } finally { await ctx.teardown(); }
});

test("hold: когда прокси уже возвращён браузеру, статус «holding» не врёт", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, T, clock } = ctx;
  try {
    await connectAndArm(ctx, {});
    STATE.holdMaxMs = 15_000;
    STATE.holdSince = clock.now - 20_000;
    STATE.lastHoldProgressAt = clock.now - 20_000;
    await T.releaseProxy("тест: возврат", {});
    assert.equal(STATE.proxyArmed, false);
    // повторные вызовы watchdog не должны рисовать «держу прокси», когда держать нечего
    await T.releaseProxy("тест: повторный вызов", {});
    assert.notEqual(STATE.proxyMode, "holding", "держать нечего — статус не врёт");
    assert.equal(api.lastProxy().proxyType, "none");
  } finally { await ctx.teardown(); }
});

test("hold: stats от хоста и подтверждение туннеля — это прогресс (удержание продлевается)", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, T, clock } = ctx;
  try {
    const { host } = await connectAndArm(ctx, {});
    STATE.holdMaxMs = 15_000;
    await T.releaseProxy("тест: обрыв", {});
    const at = STATE.lastHoldProgressAt;
    assert.ok(at, "вход в удержание засчитан как прогресс");

    await clock.advance(10_000);
    host.mode = "ok";
    api.hostSend({ type: "stats", bytesSent: 10, bytesReceived: 20, rtt: 40, dropped: 0 });
    await clock.flush();
    assert.ok(STATE.lastHoldProgressAt > at, "stats от хоста продлил удержание");

    const at2 = STATE.lastHoldProgressAt;
    await clock.advance(10_000);
    T.handleVerifyResult(true, { via: "diagnose" });
    await clock.flush();
    assert.ok(STATE.lastHoldProgressAt > at2, "подтверждение туннеля продлило удержание");
    assert.equal(STATE.tunnelVerified, true);
    assert.equal(noneAfter(api, armedIndex(api)), false, "прокси не возвращался браузеру");
  } finally { await ctx.teardown(); }
});

// ============================================================ 2. проба хоста

test("проба 600 серверов: diagnose отвечает поздно — это НЕ смерть туннеля (без переключений и без HOLD-карусели)", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, T, clock } = ctx;
  try {
    await connectAndArm(ctx, {});
    const before = STATE.currentServer?.id;
    STATE.probe = { ...(STATE.probe || {}), active: true, total: 600, mode: "full" };

    for (let i = 0; i < 8; i++) {
      T.handleVerifyResult(false, { late: true });
      await clock.advance(4_000);
    }
    await clock.flush();
    assert.equal(STATE.verifyFails, 0, "пока хост занят пробой, неудачи diagnose не считаем");
    assert.equal(STATE.currentServer?.id, before, "ноду не переключаем посреди пробы");
    assert.equal(STATE.proxyArmed, true, "прокси остался вооружён");
    const msg = api.outgoing.find((m) => m?.type === "error" && /проверяет|проб/i.test(m.message || ""));
    assert.ok(msg, "в UI объяснено, что задержка из-за пробы: " + JSON.stringify(api.outgoing.slice(-3)));
    assert.match(msg.message, /НЕ обрыв|не обрыв/);
    assert.ok(STATE.journal.some((j) => /пробой/.test(j.text || "")), "событие в журнале");

    // проба закончилась — контроль живости снова работает штатно
    STATE.probe = { ...STATE.probe, active: false };
    T.handleVerifyResult(false, {});
    await clock.flush();
    assert.equal(STATE.verifyFails, 1, "после пробы неудачи снова считаются");
  } finally { await ctx.teardown(); }
});

// ============================================================ 1. direct-узел

test("direct/DPI-узел не выбирается автоподбором и честно помечается как НЕ VPN", async () => {
  const ctx = await loadBackground({ storage: { servers: [DIAG, FAST] } });
  const { api, STATE, T } = ctx;
  try {
    assert.equal(T.isLocalTransport(DIAG), true, "direct — локальный транспорт");
    assert.equal(T.isLocalTransport({ protocol: "dpi" }), true);
    assert.equal(T.isLocalTransport(FAST), false, "vless — настоящий VPN");

    // «Диагностика (direct)» имеет пинг 4 мс — раньше автовыбор брал именно её
    const best = await T.autoSelectBestServer([DIAG, FAST]);
    assert.ok(best, "автовыбор обязан вернуть ноду");
    assert.equal(best.id, "srv-fast", "автовыбор взял direct-узел: «VPN» без VPN");

    // подключение к direct-узлу больше не проходит молча
    api.outgoing.length = 0;
    T.warnDirectNode(DIAG);
    const err = api.outgoing.find((m) => m?.type === "error" && /НЕ VPN|не VPN/.test(m.message || ""));
    assert.ok(err, "пользователю сказано, что это не VPN: " + JSON.stringify(api.outgoing.map((m) => m?.message)));
    assert.ok(api.outgoing.some((m) => m?.type === "directNode"), "в UI ушло событие directNode");

    STATE.currentServer = DIAG;
    STATE.status = "connected";
    const st = T.statusPayload();
    assert.equal(st.currentIsLocal, true, "статус помечает локальный транспорт");
    assert.equal(st.vpnActive, false, "vpnActive=false: подключено ≠ VPN");
    assert.ok(STATE.journal.some((j) => j.kind === "direct"), "запись в журнале");
  } finally { await ctx.teardown(); }
});

// ============================================================ 4. порты

test("порт локального DPI не спорит с autoPort native host (1080 занят → хост на 1081)", async () => {
  assert.equal(DPI.FLICKER_DPI_PORT, 10880, "дефолт уведён из диапазона autoPort");
  assert.ok(!DPI.DPI_PORT_CANDIDATES.includes(1081) && !DPI.DPI_PORT_CANDIDATES.includes(1080),
    "кандидаты не пересекаются с портами хоста");

  const a = DPI.resolveDpiPort({ wanted: 1081, taken: [1081] });
  assert.equal(a.port, 10880, "1081 занят хостом — берём 10880");
  assert.equal(a.moved, true);
  assert.equal(a.wanted, 1081);

  const b = DPI.resolveDpiPort({ wanted: 10880, taken: [1080] });
  assert.equal(b.port, 10880, "конфликта нет — оставляем желаемый");
  assert.equal(b.moved, false);

  const c = DPI.resolveDpiPort({ wanted: 10880, taken: DPI.DPI_PORT_CANDIDATES });
  assert.equal(c.port, 10885, "все кандидаты заняты — берём последний и сообщаем");
  assert.equal(c.moved, true);

  const d = DPI.resolveDpiPort({});
  assert.equal(typeof d.port, "number");
});

test("startDpiTunnel уводит ciadpi с порта, который занял native host", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, T } = ctx;
  try {
    await connectAndArm(ctx, {});
    STATE.socksPort = 10880;                 // хост сдвинулся ровно на дефолт DPI
    api.outgoing.length = 0;
    await T.startDpiTunnel({ id: "dpi-local", name: "DPI-обход", protocol: "dpi", host: "127.0.0.1", port: 10880 });
    assert.notEqual(STATE.dpiPort, 10880, "два прокси на одном порту: ciadpi не поднимется");
    assert.equal(STATE.dpiPort, 10881);
    const warn = api.outgoing.find((m) => m?.type === "error" && /занят/.test(m.message || ""));
    assert.ok(warn, "сказали, почему порт сдвинут: " + JSON.stringify(api.outgoing.map((m) => m?.message)));
  } finally { await ctx.teardown(); }
});

// ============================================================ журнал и отчёт

test("отчёт об обрывах одним кликом: версии, удержание, ступень, журнал", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, T, clock } = ctx;
  try {
    await connectAndArm(ctx, {});
    STATE.holdMaxMs = 15_000;
    await T.releaseProxy("тест: обрыв для отчёта", {});
    await clock.flush();
    T.journal("probe", "probe: старт 600 серверов (mode=full)");

    const r = await api.fireRuntimeMessage({ action: "getBreakReport" });
    assert.equal(r.ok, true, JSON.stringify(r).slice(0, 200));
    const rep = r.report;
    assert.match(rep, /отчёт об обрывах/);
    assert.match(rep, /расширение: 5\.5\.\d+/, "версия расширения");
    assert.match(rep, /хост:/, "версия native host");
    assert.match(rep, /VPN активен/, "видно, VPN ли сейчас активен");
    assert.match(rep, /удержание:/, "параметры удержания");
    assert.match(rep, /восстановление:/, "ступень восстановления");
    assert.match(rep, /SOCKS порт:/, "порт, на который вооружён прокси");
    assert.match(rep, /журнал событий/, "журнал");
    assert.match(rep, /\[hold-start\]/, "вход в удержание записан");
    assert.ok(STATE.journal.length > 0 && STATE.journal.length <= 120, "журнал ограничен");
  } finally { await ctx.teardown(); }
});
