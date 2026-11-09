// direct-transport.test.mjs — FIX(5.5.14): локальный транспорт «Диагностика
// (direct)» больше не оставляет браузер на мёртвом SOCKS-порту, и HOLD не
// держит заведомо мёртвый конец.
//
// Шестой отчёт пользователя (5.5.13 + хост 5.5.4), 22:00:10 → 22:10:37:
//
//   шапка панели:  Статус туннеля: connected
//                  Прокси браузера: активен
//                  SOCKS5 порт: 1080 (прокси браузера вооружён на нём же)
//                  Сервер: Диагностика (direct)
//   срезы хоста:   Туннель активен: нет / SOCKS5: не слушает   (×11 подряд)
//   22:04:09       dbg: proxy HOLD: туннель больше не подтверждён
//                  dbg: proxy HOLD (жду подтверждения)
//   22:04:17       probe: старт 600 серверов (mode=full)  → 22:10:37 (6m20s)
//   22:06:06       switch: 127.0.0.1 -> 64.176.2.21 → port-shift → proxy=socks 1081
//
// То есть шесть минут браузер стучался в 127.0.0.1:1080, где никто не слушал,
// а панель говорила «connected / прокси активен». Ровно это пользователь
// описал как «похер какой сервер — ни ютуб, ни рутор не подрубает, выплевывает».
//
// Механика:
//   • драйвер direct у хоста SOCKS-слушатель НЕ поднимает;
//   • perRequestDecision возвращал socks5 127.0.0.1:activeProxyPort() с
//     завершающим null (fallback запрещён) → каждый запрос умирал;
//   • manual-путь вооружал тот же порт;
//   • подтверждение не проходило → releaseProxy → HOLD, а HOLD держит последний
//     вооружённый снимок, то есть тот же мёртвый порт;
//   • ветка «хост занят пробой серверов» звала markHoldProgress и продлевала
//     удержание на все 6 минут пробы.
//
// Теперь: direct = трафик напрямую (proxy снят, onRequest отдаёт DIRECT,
// подтверждение не гоняется), а HOLD запрещён, если конец заведомо мёртв
// (endpointDead): локальный транспорт, хост не на связи, или последний diagnose
// сказал socksListening=false.
//
// Запуск: node --test tests/
//   BG_DIR=../flicker-5.5.13/ext node --test tests/direct-transport.test.mjs → RED

import test from "node:test";
import assert from "node:assert/strict";
import {
  loadBackground, connectAndArm, createFakeHost, VLESS_SERVER, VLESS_SERVER_B
} from "./bg-harness.mjs";

const DIAG = { id: "diag", name: "Диагностика (direct)", protocol: "direct", host: "127.0.0.1", port: 443 };
const A = { ...VLESS_SERVER, id: "srv-a", name: "DE15", host: "de15.example.test", ping: 40 };
const B = { ...VLESS_SERVER_B, id: "srv-b", name: "FI1", host: "fi1.example.test", ping: 60 };

const jkinds = (STATE) => STATE.journal.map((j) => j.kind);
const jtail = (STATE) => JSON.stringify(STATE.journal.slice(-8).map((j) => j.kind + ":" + String(j.text).slice(0, 50)));
const lastProxyType = (api) => {
  const v = api.lastProxy();
  return v ? v.proxyType : (api.proxyLog.slice(-1)[0]?.op === "clear" ? "clear" : null);
};
const diagnose = (over = {}) => ({
  type: "diagnose",
  data: { socksListening: true, tunnelActive: true, tunnelAlive: true, listenAddr: "127.0.0.1:1080", driver: "vless", ...over }
});

test("direct: трафик идёт напрямую, а не в мёртвый SOCKS-порт", async () => {
  const ctx = await loadBackground({ storage: { servers: [DIAG, A] } });
  try {
    const { api, clock, T, STATE } = ctx;
    // честный хост для драйвера direct: слушателя нет, туннеля нет
    const host = createFakeHost(api, clock, { socksListening: false, alive: false });
    ctx.host = host;
    host.hello();
    await clock.flush();

    const st = await T.startTunnel(DIAG);
    assert.equal(st.ok, true, st.error);
    await clock.flush();
    await clock.advance(12_000);     // грация + несколько циклов подтверждения

    assert.equal(STATE.proxyMode, "local-direct", "честный режим: " + jtail(STATE));
    assert.equal(STATE.proxyArmed, false, "прокси не вооружён");
    assert.equal(lastProxyType(api), "none", "браузер не смотрит в мёртвый порт");

    // per-request: зарубежный сайт идёт НАПРЯМУЮ (прежде — socks5 на мёртвый порт
    // с завершающим null, то есть гарантированный обрыв запроса)
    const d1 = api.onRequestDecision("https://www.youtube.com/");
    assert.deepEqual(d1, { type: "direct" }, "onRequest отдаёт direct: " + JSON.stringify(d1));
    const d2 = api.onRequestDecision("https://rutracker.org/forum/index.php");
    assert.deepEqual(d2, { type: "direct" }, "onRequest отдаёт direct и для рутора");

    assert.ok(jkinds(STATE).includes("local-direct"), "в журнале честная причина: " + jtail(STATE));
    const sp = T.statusPayload();
    assert.equal(sp.currentIsLocal, true, "статус помечает локальный транспорт");
    assert.equal(sp.vpnActive, false, "VPN не активен");
    assert.ok(!sp.proxyEnabled, "панель больше не скажет «прокси активен»");
  } finally { await ctx.teardown(); }
});

test("direct: подтверждение не «чинит» то, чего нет (нет HOLD на мёртвом порту)", async () => {
  const ctx = await loadBackground({ storage: { servers: [DIAG, A] } });
  try {
    const { api, clock, T, STATE } = ctx;
    const host = createFakeHost(api, clock, { socksListening: false, alive: false });
    ctx.host = host;
    host.hello();
    await clock.flush();
    await T.startTunnel(DIAG);
    await clock.flush();
    await clock.advance(12_000);
    assert.equal(STATE.proxyMode, "local-direct");

    // хост раз за разом говорит «не слушаю» — расширение не должно уходить в HOLD
    for (let i = 0; i < 6; i++) {
      api.hostSend(diagnose({ socksListening: false, tunnelActive: false, tunnelAlive: false }));
      await clock.advance(4_000);
    }
    assert.notEqual(STATE.proxyMode, "holding", "HOLD на мёртвом порту: " + jtail(STATE));
    assert.equal(STATE.proxyArmed, false);
    assert.equal(lastProxyType(api), "none", "браузер остался на прямом трафике");
    assert.ok(!jkinds(STATE).includes("hold-start"), "удержание не начиналось: " + jtail(STATE));
  } finally { await ctx.teardown(); }
});

test("endpointDead: хост сказал «SOCKS не слушает» — HOLD запрещён, прокси возвращается сразу", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { host } = await connectAndArm(ctx, { server: A });
    const { api, clock, T, STATE } = ctx;
    assert.equal(STATE.proxyArmed, true, "стартуем с вооружённым прокси");

    // хост прямо сказал, что слушателя нет
    host.socksListening = false;
    host.alive = false;
    api.hostSend(diagnose({ socksListening: false, tunnelActive: false, tunnelAlive: false }));
    await clock.flush();
    assert.equal(STATE.lastSocksListening, false, "ответ хоста запомнен");

    // обрыв: до 5.5.14 здесь включался HOLD и браузер оставался на мёртвом порту
    await T.releaseProxy("туннель больше не подтверждён");
    await clock.flush();

    assert.notEqual(STATE.proxyMode, "holding",
      "на мёртвом конце удержания быть не должно: " + jtail(STATE));
    assert.equal(lastProxyType(api), "none",
      "браузер вернулся к прямому трафику сразу, а не через 5 минут удержания");
    assert.ok(jkinds(STATE).includes("hold-refused"),
      "отказ удержания виден в журнале: " + jtail(STATE));
    assert.equal(STATE.proxyEnabled, false);
    const sp = T.statusPayload();
    assert.ok(sp.proxyBlockedReason, "панель знает, почему прокси не вооружён: " + sp.proxyBlockedReason);
  } finally { await ctx.teardown(); }
});

test("проба серверов не продлевает удержание на мёртвом конце", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { host } = await connectAndArm(ctx, { server: A });
    const { api, clock, T, STATE } = ctx;

    // имитируем ситуацию из отчёта: HOLD уже идёт, хост жуёт пробу 600 серверов,
    // и при этом слушателя нет — каждый ответ diagnose говорит socksListening=false
    host.socksListening = false;
    host.alive = false;
    STATE.holdSince = clock.now;
    STATE.lastHoldProgressAt = clock.now;
    STATE.proxyMode = "holding";
    STATE.probe = { active: true, total: 600, done: 0 };

    api.hostSend(diagnose({ socksListening: false, tunnelActive: false, tunnelAlive: false }));
    await clock.flush();
    const before = STATE.lastHoldProgressAt;
    await clock.advance(30_000);
    T.handleVerifyResult(false, { socksListening: false, tunnelActive: false, tunnelAlive: false });
    await clock.flush();

    assert.equal(STATE.lastHoldProgressAt, before,
      "проба не должна продлевать удержание, когда слушателя нет: " + jtail(STATE));
  } finally { await ctx.teardown(); }
});

test("живой конец: HOLD по-прежнему работает (регрессия защиты от утечки)", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    await connectAndArm(ctx, { server: A });
    const { api, clock, STATE } = ctx;
    // diagnose молчит, но слушатель поднят — это «вот-вот вернётся», держать можно
    api.hostSend(diagnose({ socksListening: true, tunnelActive: true, tunnelAlive: true }));
    await clock.flush();
    assert.equal(STATE.lastSocksListening, true);

    api.hostSend({ type: "status", status: "disconnected", reason: "туннель закрыт" });
    await clock.flush();
    await clock.advance(1_000);

    assert.equal(STATE.proxyMode, "holding", "на живом конце удержание сохранено: " + jtail(STATE));
    assert.equal(STATE.proxyArmed, true, "прокси не отдан браузеру");
    assert.equal(lastProxyType(api), "manual", "браузер остался на туннеле");
    // hold-start пишется в releaseProxy; здесь удержание включил основной путь
    // applyProxyMode — поэтому смотрим на состояние, а не на вид записи
    assert.ok(STATE.holdSince != null, "удержание началось");
    assert.ok(!jkinds(STATE).includes("hold-refused"), "отказа удержания нет: " + jtail(STATE));
    assert.equal(STATE.lastSocksListening, true, "конец живой — слушатель на месте");
  } finally { await ctx.teardown(); }
});
