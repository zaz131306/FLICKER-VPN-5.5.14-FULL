// resume-direct.test.mjs — FIX(5.5.11): служебный «Диагностика (direct)» больше
// не поднимается как туннель, и старт не уходит в HOLD до подтверждения хоста.
//
// Отчёт пользователя с уже стоящей 5.5.10 (трафик шёл, обрывов не было), но:
//   09:08:51 [direct] выбран узел diag (direct) — это не VPN
//   09:08:51 [start]  diag direct 127.0.0.1:443      ← 28 секунд без VPN
//   09:09:19 [start]  sub-6da6d52c vless 87.242.119.253:443
//   09:09:24 [hold-start] туннель больше не подтверждён   ← через 5 c после старта
//   09:09:49 [verify-ok] diagnose
// Первая строка — прошлая сессия закончилась на «Диагностике», её id лежал в
// storage.session и восстанавливался как туннель (плюс дырка в pickRecoveryTarget:
// resume-ноду искали по полному списку, минуя фильтр локальных транспортов).
// Вторая — applyProxyModeNow() видел tunnelVerified=false сразу после start и
// уходил в HOLD, хотя хост ещё поднимал туннель.
//
// Запуск: node --test tests/
//   BG_DIR=../flicker-5.5.10/ext node --test tests/resume-direct.test.mjs → RED

import test from "node:test";
import assert from "node:assert/strict";
import { loadBackground, connectAndArm, createFakeHost, VLESS_SERVER, VLESS_SERVER_B } from "./bg-harness.mjs";

const SERVERS = [VLESS_SERVER, VLESS_SERVER_B];
const DIAG = { id: "diag", name: "Диагностика (direct)", protocol: "direct", host: "127.0.0.1", port: 443, ping: 4 };
const DPI_LOCAL = { id: "dpi-local", name: "DPI-обход", protocol: "dpi", host: "127.0.0.1", port: 10880 };

/** Запись сессии, которую расширение само кладёт в storage.session. */
function sessionRecord(serverId, extra = {}) {
  return {
    status: "connected",
    serverId,
    socksPort: 1080,
    tunnelKind: "native",
    dpiPort: 10880,
    proxyArmed: true,
    proxyMode: "socks",
    proxyValue: { proxyType: "manual", socks: "127.0.0.1:1080", passthrough: "<-loopback>" },
    killSwitchEnabled: false,
    killSwitchBlocked: false,
    proxyReleasedByUser: false,
    updatedAt: 0,          // виртуальные часы стартуют с нуля — запись «свежая»
    ...extra
  };
}

function armedIndex(api) {
  let idx = -1;
  api.proxyLog.forEach((c, i) => { if (c.op === "set" && c.value?.proxyType === "manual") idx = i; });
  return idx;
}
function noneAfter(api, idx) {
  return api.proxyLog.slice(idx + 1).some((c) => c.op === "set" && c.value?.proxyType === "none");
}
const kinds = (STATE) => STATE.journal.map((j) => j.kind);
const texts = (STATE) => STATE.journal.map((j) => `${j.kind}: ${j.text}`);

test("восстановление сессии: direct-узел НЕ поднимается как туннель, возвращаемся на последнюю VPN-ноду", async () => {
  const ctx = await loadBackground({
    storage: {
      servers: [DIAG, ...SERVERS],
      session: sessionRecord("diag"),
      lastVpnServerId: VLESS_SERVER_B.id
    }
  });
  const { STATE } = ctx;
  try {
    assert.equal(STATE.sessionRestored, true, "сессия восстановлена (прокси не сбрасываем)");
    assert.notEqual(STATE.resumeServerId, "diag", "direct-узел назначен целью восстановления");
    assert.notEqual(STATE.currentServer?.id, "diag", "текущий узел — direct: CONNECTED без VPN");
    assert.equal(STATE.currentServer?.id, VLESS_SERVER_B.id, "вернулись на последнюю VPN-ноду");
    assert.ok(kinds(STATE).includes("direct"), "в журнале нет записи о пропуске direct: " + JSON.stringify(texts(STATE)));
    assert.ok(texts(STATE).some((t) => /пропущен служебный узел diag/.test(t)), JSON.stringify(texts(STATE)));
  } finally { await ctx.teardown(); }
});

test("восстановление сессии: если последней VPN-ноды нет, direct всё равно не поднимаем", async () => {
  const ctx = await loadBackground({
    storage: { servers: [DIAG, ...SERVERS], session: sessionRecord("diag") }
  });
  const { STATE, api, clock } = ctx;
  try {
    assert.notEqual(STATE.resumeServerId, "diag");
    assert.equal(STATE.currentServer, null, "не делаем вид, что туннель на direct-узле есть");
    const host = createFakeHost(api, clock, {});
    host.hello();
    await clock.advance(40_000);
    await clock.flush();
    // восстановление обязано поднять VPN-ноду, а не служебный direct
    assert.ok(!texts(STATE).some((t) => /^start: diag /.test(t)),
      "восстановление подняло direct: " + JSON.stringify(texts(STATE)));
    if (STATE.currentServer) assert.notEqual(STATE.currentServer.protocol, "direct");
  } finally { await ctx.teardown(); }
});

test("pickRecoveryTarget: resume-дырка закрыта — direct целью не становится, dpi-режим сохранён", async () => {
  const ctx = await loadBackground({ storage: { servers: [DIAG, DPI_LOCAL, ...SERVERS] } });
  const { STATE, T } = ctx;
  try {
    STATE.resumeServerId = "diag";
    const r1 = T.pickRecoveryTarget([DIAG, VLESS_SERVER, VLESS_SERVER_B], "тест: resume на direct");
    assert.ok(r1.server, "цель возвращается всегда (тупик запрещён)");
    assert.notEqual(r1.server.protocol, "direct", "direct снова стал целью восстановления");
    assert.notEqual(r1.server.id, "diag");

    // dpi — отдельный пользовательский режим: если сидели в нём, в него и возвращаемся
    STATE.resumeServerId = "dpi-local";
    const r2 = T.pickRecoveryTarget([DIAG, DPI_LOCAL, VLESS_SERVER], "тест: resume в dpi");
    assert.equal(r2.server?.id, "dpi-local", "dpi-режим должен сохраняться");

    STATE.resumeServerId = VLESS_SERVER.id;
    const r3 = T.pickRecoveryTarget([DIAG, DPI_LOCAL, VLESS_SERVER, VLESS_SERVER_B], "тест: обычный resume");
    assert.equal(r3.server?.id, VLESS_SERVER.id, "прежняя нода приоритетна");
  } finally { await ctx.teardown(); }
});

test("resume после hello: direct-узел пропускается, запускается восстановление", async () => {
  const ctx = await loadBackground({ storage: { servers: [DIAG, ...SERVERS] } });
  const { api, STATE, clock } = ctx;
  try {
    STATE.status = "disconnected";
    STATE.resumeServerId = "diag";
    const host = createFakeHost(api, clock, {});
    host.hello();
    await clock.flush();
    assert.ok(!texts(STATE).some((t) => /^start: diag /.test(t)),
      "после hello подняли direct: " + JSON.stringify(texts(STATE)));
    assert.ok(STATE.recovering || STATE.recoveryTimer || texts(STATE).some((t) => /direct/.test(t)),
      "не запущено восстановление вместо direct");
    assert.ok(api.outgoing.some((m) => /Диагностика \(direct\)/.test(m?.message || "")),
      "пользователю не объяснили, почему узел пропущен");
  } finally { await ctx.teardown(); }
});

test("grace: сразу после start прокси не уходит в HOLD — ждём подтверждения хоста", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, T, clock } = ctx;
  try {
    await connectAndArm(ctx, {});
    const idx = armedIndex(api);
    // новый старт: хост ещё не подтвердил туннель (tunnelVerified=false — норма)
    STATE.tunnelVerified = false;
    STATE.lastStartAt = clock.now;
    const holdsBefore = STATE.journal.filter((j) => j.kind === "hold-start").length;
    await T.applyProxyMode();
    await clock.flush();
    assert.equal(STATE.journal.filter((j) => j.kind === "hold-start").length, holdsBefore,
      "сразу после старта ушли в HOLD: " + JSON.stringify(texts(STATE)));
    assert.equal(STATE.proxyMode, "socks", "режим прокси не должен меняться в грации");
    assert.equal(noneAfter(api, idx), false, "прокси вернули браузеру в окне грации");
    assert.ok(texts(STATE).some((t) => /grace|граци/i.test(t)), "в журнале нет записи о грации");

    // грация прошла, подтверждения так и нет — теперь HOLD штатен
    STATE.lastStartAt = clock.now - 30_000;
    STATE.tunnelVerified = false;
    await T.applyProxyMode();
    await clock.flush();
    assert.equal(STATE.proxyMode, "holding", "после окна грации удержание включается как прежде");
    assert.equal(noneAfter(api, idx), false, "и при этом прокси браузеру не отдали");
  } finally { await ctx.teardown(); }
});

test("последняя VPN-нода запоминается при подключении и лежит в storage", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, T } = ctx;
  try {
    await connectAndArm(ctx, { server: VLESS_SERVER_B });
    assert.equal(STATE.lastVpnServerId, VLESS_SERVER_B.id);
    const saved = await api.browser.storage.local.get("lastVpnServerId");
    assert.equal(saved.lastVpnServerId, VLESS_SERVER_B.id, "не сохранено в storage — после перезагрузки не вспомним");

    // DPI-обход — не VPN-нода: «последнюю VPN-ноду» он затирать не должен
    await T.startDpiTunnel({ id: "dpi-local", name: "DPI-обход", protocol: "dpi", host: "127.0.0.1", port: 10880 });
    assert.equal(STATE.lastVpnServerId, VLESS_SERVER_B.id,
      "DPI-режим перезаписал последнюю VPN-ноду — после перезагрузки вернёмся не туда");
  } finally { await ctx.teardown(); }
});

test("отчёт об обрывах: видна последняя VPN-нода и окно грации", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE } = ctx;
  try {
    await connectAndArm(ctx, {});
    const r = await api.fireRuntimeMessage({ action: "getBreakReport" });
    assert.equal(r.ok, true);
    assert.match(r.report, /последняя VPN-нода: /, "в отчёте нет последней VPN-ноды");
    assert.match(r.report, /грация после старта: /, "в отчёте нет окна грации");
    assert.equal(r.status.lastVpnServerId, STATE.currentServer?.id);
    assert.ok(r.status.startGraceLeftMs >= 0);
  } finally { await ctx.teardown(); }
});
