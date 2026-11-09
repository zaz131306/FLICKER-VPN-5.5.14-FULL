// soft-liveness.test.mjs — FIX(5.5.10): «SOCKS слушает, но контрольный dial
// отклонён» больше не значит «всё хорошо», если трафика нет вовсе.
//
// Второй отчёт пользователя (расширение 5.5.8, хост 5.5.4), дословно из лога:
//   10:38:30 liveness: контрольный dial через туннель не удался: socks5: connect
//            отклонён (код 0x1)
//   10:38:30 dbg: soft liveness: tunnelAlive=false проигнорирован (SOCKS слушает)
//   ... то же в 10:39:45, 10:40:10, 10:41:01, 10:42:15, 10:45:10, 10:46:43, 10:47:15
//   «Передано: ↑0.00 MB ↓0.00 MB»
// То есть восемь минут туннель не пропустил НИ БАЙТА, а расширение показывало
// CONNECTED и «туннель жив». Плюс в «Рейтинг нод» топ-1 и единственная
// «доверенная» нода — «Диагностика (direct)», которая VPN не является.
//
// Запуск: node --test tests/
//   BG_DIR=../flicker-5.5.9/ext node --test tests/soft-liveness.test.mjs → RED

import test from "node:test";
import assert from "node:assert/strict";
import { loadBackground, connectAndArm, VLESS_SERVER, VLESS_SERVER_B } from "./bg-harness.mjs";

const SERVERS = [VLESS_SERVER, VLESS_SERVER_B];
const DIAG = { id: "diag", name: "Диагностика (direct)", protocol: "direct", host: "127.0.0.1", port: 443 };

function armedIndex(api) {
  let idx = -1;
  api.proxyLog.forEach((c, i) => { if (c.op === "set" && c.value?.proxyType === "manual") idx = i; });
  return idx;
}
function noneAfter(api, idx) {
  return api.proxyLog.slice(idx + 1).some((c) => c.op === "set" && c.value?.proxyType === "none");
}
/** stats с нулевым трафиком: ровно как в логе пользователя (хост жив, байтов нет). */
function zeroStats(api) {
  api.hostSend({ type: "stats", bytesSent: 0, bytesReceived: 0, rtt: 40, dropped: 0 });
}

/**
 * Цикл diagnose в расширении привязан к watchdog (PROXY_WATCHDOG_MS = 25 c),
 * поэтому «прокручиваем» время шагом 10 c, пока не выполнится условие.
 * stats шлём каждый шаг — иначе watchdog объявит «хост молчит» и тест
 * проверит не soft liveness, а совсем другую ветку.
 */
async function runUntil(ctx, pred, { stepMs = 10_000, maxMs = 300_000, bytes = 0 } = {}) {
  const { api, clock } = ctx;
  let t = 0;
  while (t < maxMs && !pred()) {
    await clock.advance(stepMs);
    api.hostSend({ type: "stats", bytesSent: bytes, bytesReceived: bytes * 4, rtt: 200, dropped: 0 });
    await clock.flush();
    t += stepMs;
  }
  return { ok: pred(), elapsedMs: t };
}


test("мягкий режим: ОДИНОЧНЫЙ отказ dial — не приговор (поведение 5.5.4.3 сохранено)", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, clock } = ctx;
  try {
    const { host } = await connectAndArm(ctx, {});
    const idx = armedIndex(api);
    host.alive = false;                 // tunnelActive=false, tunnelAlive=false
    host.socksListening = true;         // но SOCKS слушает
    const r1 = await runUntil(ctx, () => STATE.softDeadStreak >= 1, { maxMs: 60_000 });
    assert.ok(r1.ok, "за 60 c не дождались ни одного diagnose с tunnelAlive=false");

    assert.equal(STATE.status, "connected", "один медленный dial не рвёт рабочий туннель");
    assert.equal(STATE.tunnelVerified, true, "в мягком режиме туннель остаётся подтверждённым");
    assert.equal(STATE.softDeadStreak, 1);
    assert.equal(STATE.recovering, false, "восстановление не запускали");
    assert.equal(noneAfter(api, idx), false, "прокси не возвращали браузеру");
  } finally { await ctx.teardown(); }
});

test("мягкий режим: серия отказов dial при НУЛЕВОМ трафике = нода мертва, уходим с неё", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, T, clock } = ctx;
  try {
    const { host } = await connectAndArm(ctx, {});
    const idx = armedIndex(api);
    const deadId = STATE.currentServer?.id;
    const startsBefore = ctx.host.startCalls;
    host.alive = false;
    host.socksListening = true;

    // diagnose приходит раз в ~25 c: ждём вердикта (3 отказа подряд + 45 c серии)
    const r2 = await runUntil(ctx, () => STATE.softDeadActAt != null, { maxMs: 300_000, bytes: 0 });
    assert.ok(r2.ok, "вердикт «нода мертва» не вынесен за 300 c (streak=" + STATE.softDeadStreak + ")");
    assert.ok(STATE.journal.some((j) => j.kind === "soft-dead"),
      "в журнале нет soft-dead: " + JSON.stringify(STATE.journal.map((j) => j.kind)));
    const msg = api.outgoing.find((m) => m?.type === "error" && /мёртвой|не пропускает трафик/i.test(m.message || ""));
    assert.ok(msg, "пользователю не объяснили вердикт: " + JSON.stringify(api.outgoing.map((m) => m?.message).slice(-4)));
    assert.match(msg.message, /0 байт/);
    assert.ok(T.deathsInWindow(deadId) >= 1, "нода учтена как обрыв: " + T.deathsInWindow(deadId));
    // после вердикта расширение подняло туннель заново (ротация): хост получил
    // новый start. resumeServerId к этому моменту уже может быть погашен —
    // восстановление успевает доехать, это штатно.
    assert.ok(ctx.host.startCalls > startsBefore,
      `после вердикта не было нового start (${startsBefore} → ${ctx.host.startCalls})`);
    // после вердикта туннель подняли заново (ушли с мёртвой ноды)
    const kinds = STATE.journal.map((j) => j.kind);
    const at = kinds.lastIndexOf("soft-dead");
    assert.ok(at >= 0, "soft-dead не записан в журнал");
    assert.ok(kinds.indexOf("start", at) > at,
      "после вердикта туннель не поднимали заново: " + JSON.stringify(kinds));
    // главное требование пользователя: прокси при этом НЕ уезжает браузеру
    assert.equal(noneAfter(api, idx), false, "прокси вернули браузеру посреди ротации ноды");
    assert.equal(T.sessionBytes(), 0, "трафика не было — критерий смерти сработал не зря");
  } finally { await ctx.teardown(); }
});

test("мягкий режим: трафик ИДЁТ — серия отказов dial ноду не убивает", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, clock } = ctx;
  try {
    const { host } = await connectAndArm(ctx, {});
    const idx = armedIndex(api);
    host.alive = false;
    host.socksListening = true;
    // байты идут: медленный dial на рабочей ноде — ровно тот случай, ради
    // которого мягкий режим вообще ввели в 5.5.4.3
    const r3 = await runUntil(ctx, () => STATE.softDeadStreak >= 4, { maxMs: 300_000, bytes: 1024 });
    assert.ok(r3.ok, "серия отказов не накопилась");
    assert.equal(STATE.status, "connected", "рабочий туннель с медленным dial порван");
    assert.equal(STATE.softDeadActAt, null, "вердикт вынесен зря");
    assert.equal(noneAfter(api, idx), false, "прокси не возвращали браузеру");
    assert.ok(STATE.softDeadStreak >= 3, "серия копится, но трафик её обезвреживает");
  } finally { await ctx.teardown(); }
});

test("мягкий режим: dial прошёл — счётчик серии обнуляется", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, clock } = ctx;
  try {
    const { host } = await connectAndArm(ctx, {});
    host.alive = false; host.socksListening = true;
    const r4 = await runUntil(ctx, () => STATE.softDeadStreak >= 2, { maxMs: 120_000 });
    assert.ok(r4.ok, "серия набиралась");
    host.alive = true;
    const r4b = await runUntil(ctx, () => STATE.softDeadStreak === 0, { maxMs: 120_000 });
    assert.ok(r4b.ok, "после успешного dial серия обнулена");
    assert.equal(STATE.softDeadSince, null);
    assert.equal(STATE.status, "connected");
  } finally { await ctx.teardown(); }
});

test("строгий режим: одиночный tunnelAlive=false по-прежнему приговор", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS, strictLiveness: true } });
  const { api, STATE, clock } = ctx;
  try {
    const { host } = await connectAndArm(ctx, {});
    assert.equal(STATE.strictLiveness, true, "строгий режим прочитан из storage");
    host.alive = false; host.socksListening = true;
    const r5 = await runUntil(ctx, () => STATE.tunnelVerified === false, { maxMs: 180_000 });
    assert.ok(r5.ok, "в строгом режиме туннель не подтверждён");
    // в строгом режиме приговор выносится СРАЗУ (tunnelVerified=false), поэтому
    // soft-механика не нужна и не должна срабатывать
    assert.equal(STATE.softDeadStreak, 0, "в строгом режиме soft-счётчик не ведётся");
    assert.equal(STATE.softDeadActAt, null);
  } finally { await ctx.teardown(); }
});

test("рейтинг: «Диагностика (direct)» больше не считается доверенной VPN-нодой", async () => {
  const ctx = await loadBackground({ storage: { servers: [DIAG, VLESS_SERVER, VLESS_SERVER_B] } });
  const { api, STATE } = ctx;
  try {
    // direct «идеален»: минимальный rtt, ноль ошибок — так он и выигрывал топ
    STATE.rating.pushSample(DIAG.id, { ok: true, rtt: 4, mbps: 0, tier: "free" });
    STATE.rating.markLatency(DIAG.id, 4);
    STATE.rating.pushSample(VLESS_SERVER.id, { ok: false, rtt: null, mbps: 0, tier: "free" });
    const r = await api.fireRuntimeMessage({ action: "getRatingSummary", limit: 10 });
    assert.equal(r.ok, true, JSON.stringify(r).slice(0, 200));
    const sm = r.summary;
    assert.ok(sm.nonVpn >= 1, "локальные транспорты учтены отдельно: " + JSON.stringify(sm));
    assert.equal(sm.total, 2, "в сводке только VPN-ноды");
    assert.equal(sm.trusted, 0, "direct не может быть «доверенной VPN-нодой»");
    // FIX(5.5.13): direct больше НЕ занимает место в топе. Пометки «← НЕ VPN»
    // оказалось мало: в дампе пользователя «Диагностика (direct)» стояла на
    // 2-м месте топа и вытесняла реальную ноду из видимой десятки.
    const diagRow = (r.top || []).find((n) => n.id === DIAG.id);
    assert.equal(diagRow, undefined, "локального транспорта в топе быть не должно");
    assert.ok(!(r.top || []).some((n) => n.nonVpn), "в топе вообще нет не-VPN строк");
    const vpnRow = (r.top || []).find((n) => n.id === VLESS_SERVER.id);
    assert.equal(vpnRow?.nonVpn, false);
    assert.ok(vpnRow?.host, "у строки топа есть адрес — иначе ноды подписки неотличимы");
  } finally { await ctx.teardown(); }
});

test("отчёт об обрывах содержит состояние soft liveness", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, clock } = ctx;
  try {
    const { host } = await connectAndArm(ctx, {});
    host.alive = false; host.socksListening = true;
    const r7 = await runUntil(ctx, () => STATE.softDeadStreak >= 2, { maxMs: 120_000 });
    assert.ok(r7.ok, "серия отказов dial не накопилась");
    const r = await api.fireRuntimeMessage({ action: "getBreakReport" });
    assert.equal(r.ok, true);
    assert.match(r.report, /soft liveness:/, "в отчёте нет soft liveness");
    assert.match(r.report, /отказов dial подряд=[1-9]/, "серия отказов не отражена");
    const st = r.status;
    assert.ok(st.softLiveness && st.softLiveness.streak >= 1, "в статусе нет softLiveness");
    assert.equal(st.softLiveness.noTraffic, true);
    assert.ok(st.softLiveness.needStreak === 3 && st.softLiveness.needMs === 45000, "пороги видны в статусе");
  } finally { await ctx.teardown(); }
});
