// recovery-ladder.test.mjs — FIX(5.5.5): лестница эскалации восстановления.
//
// Что было не так (и из-за чего «обрыв туннеля» выглядел нерешённым):
//   scheduleRecovery запоминал id ноды в момент постановки таймера и на КАЖДОЙ
//   попытке поднимал ОДИН И ТОТ ЖЕ сервер тем же конфигом. Если ноду режет DPI
//   или она лежит, пользователь получал бесконечный цикл
//   «Обрыв туннеля → восстанавливаю (до 60 c) → Обрыв туннеля → …».
//
// Теперь: обрывы считаются по нодам в скользящем окне 10 минут, и
//   ступень 1 (same)     — 1–2 попытки на прежней ноде (обрыв мог быть разовым);
//   ступень 2 (rotate)   — нода умерла повторно → другая нода, желательно с
//                          другим транспортным профилем;
//   ступень 3 (escalate) — ≥4 попыток или все ноды в обрывах → DPI-устойчивый
//                          профиль (TLS/443, ws/grpc, Reality, AmneziaWG).
//   Тупик «нечего пробовать» запрещён: цель возвращается всегда, если список непуст.
//
// Запуск: node --test tests/
//         BG_DIR=../ext554 node --test tests/recovery-ladder.test.mjs → RED (нет лестницы)

import test from "node:test";
import assert from "node:assert/strict";
import { loadBackground, VLESS_SERVER, VLESS_SERVER_B } from "./bg-harness.mjs";

const A = { ...VLESS_SERVER, id: "srv-a", name: "Нидерланды A", host: "nl1.example.test", ping: 42 };
const B = { ...VLESS_SERVER_B, id: "srv-b", name: "Германия B", host: "de1.example.test", ping: 55 };
const C = { ...VLESS_SERVER_B, id: "srv-c", name: "Финляндия C", host: "fi1.example.test", ping: 210 };

// «голый» WireGuard: порт 51820, без TLS — профиль, который DPI рвёт первым
const WG_A = {
  id: "wg-a", name: "WG голый A", host: "wg1.example.test", port: 51820, protocol: "wireguard",
  tlsEnabled: false, ping: 60, sub: true,
  wireguard: { privateKey: "PRIVPRIVPRIVPRIVPRIVPRIVPRIVPRIVPRIVPRIV123=", peerPublicKey: "PUBPUBPUBPUBPUBPUBPUBPUBPUBPUBPUBPUBPUB123=", allowedIPs: ["0.0.0.0/0"] }
};
const WG_B = { ...WG_A, id: "wg-b", name: "WG голый B", host: "wg2.example.test", ping: 80 };
// AmneziaWG — тот же WireGuard, но с обфускацией: устойчивый профиль
const AWG = {
  ...WG_A, id: "awg-1", name: "AmneziaWG свой", host: "awg.example.test", port: 54321, ping: 70,
  wireguard: { ...WG_A.wireguard, amnezia: { jc: 5, jmin: 10, jmax: 100, s1: 32, s2: 17, h1: 1, h2: 2, h3: 3, h4: 4 } }
};

test("ступень 1: разовый обрыв — пробуем ту же ноду", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B, C] } });
  const { STATE, T } = ctx;
  try {
    STATE.resumeServerId = "srv-a";
    STATE.recoveryAttempt = 0;
    T.noteTunnelDeath("srv-a", "разовый обрыв");
    const pick = T.pickRecoveryTarget(await T.getServers(), "разовый обрыв");
    assert.equal(pick.stage, "same", "первая попытка — прежняя нода");
    assert.equal(pick.server.id, "srv-a");
  } finally { await ctx.teardown(); }
});

test("ступень 2: нода оборвалась повторно — уходим на другую", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B, C] } });
  const { STATE, T } = ctx;
  try {
    STATE.resumeServerId = "srv-a";
    STATE.recoveryAttempt = 1;
    T.noteTunnelDeath("srv-a", "обрыв 1");
    const n = T.noteTunnelDeath("srv-a", "обрыв 2");
    assert.equal(n, 2, "обрывы считаются в окне");
    assert.equal(T.deathsInWindow("srv-a"), 2);
    const pick = T.pickRecoveryTarget(await T.getServers(), "обрыв 2");
    assert.equal(pick.stage, "rotate", "вторая смерть ноды → ротация");
    assert.notEqual(pick.server.id, "srv-a", "мёртвую ноду долбить нельзя");
    assert.ok(pick.note && /меняю/i.test(pick.note), "пользователю объясняют смену ноды: " + pick.note);
    assert.equal(T.pickRecoveryTarget(await T.getServers(), "x").server.id, pick.server.id, "выбор детерминирован");
  } finally { await ctx.teardown(); }
});

test("ступень 3: после серии неудач — DPI-устойчивый профиль", async () => {
  const ctx = await loadBackground({ storage: { servers: [WG_A, WG_B, AWG] } });
  const { STATE, T } = ctx;
  try {
    STATE.resumeServerId = "wg-a";
    STATE.recoveryAttempt = 4;                     // ≥ STAGE_ESCALATE_AFTER
    T.noteTunnelDeath("wg-a", "обрыв");
    const pick = T.pickRecoveryTarget(await T.getServers(), "обрыв");
    assert.equal(pick.stage, "escalate");
    assert.equal(pick.server.id, "awg-1", "AmneziaWG — устойчивый профиль, его и берём");
    assert.equal(T.isDpiResistant(AWG), true, "AWG-нода считается устойчивой к DPI");
    assert.equal(T.isDpiResistant(WG_A), false, "голый WG — неустойчив");
  } finally { await ctx.teardown(); }
});

test("тупик запрещён: даже когда все ноды в обрывах, цель возвращается", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B, C] } });
  const { STATE, T } = ctx;
  try {
    for (const id of ["srv-a", "srv-b", "srv-c"]) {
      T.noteTunnelDeath(id, "массовый обрыв");
      T.noteTunnelDeath(id, "массовый обрыв");
    }
    STATE.resumeServerId = "srv-a";
    STATE.recoveryAttempt = 5;
    const pick = T.pickRecoveryTarget([A, B, C], "массовый обрыв");
    assert.ok(pick.server, "null = «нечего пробовать» = пользователь без VPN навсегда");
    assert.ok(["srv-a", "srv-b", "srv-c"].includes(pick.server.id));
  } finally { await ctx.teardown(); }
});

test("пустой список не роняет восстановление", async () => {
  const ctx = await loadBackground({ storage: { servers: [] } });
  const { T } = ctx;
  try {
    const pick = T.pickRecoveryTarget([], "нет нод");
    assert.equal(pick.server, null);
    assert.equal(pick.stage, "none");
  } finally { await ctx.teardown(); }
});

test("стабильная сессия 2 мин обнуляет счётчики обрывов", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  const { STATE, T, clock } = ctx;
  try {
    T.noteTunnelDeath("srv-a", "обрыв");
    T.noteTunnelDeath("srv-a", "обрыв");
    STATE.recoveryStage = "rotate";
    STATE.suspectedDpi = true;
    STATE.status = "connected";
    T.armStabilityReset();
    await clock.advance(121_000);
    assert.equal(T.deathsInWindow("srv-a"), 0, "окно обрывов очищено");
    assert.equal(STATE.recoveryStage, "same");
    assert.equal(STATE.suspectedDpi, false);
  } finally { await ctx.teardown(); }
});

// ---------------------------------------------------------------------------
// Интеграция: полный цикл «обрыв → тупик на мёртвой ноде» больше не случается.
// Пинги у нод НЕ измерены (ping: null) — ровно так выглядит подписка сразу после
// «Обновить»: pickBestAlive не находит кандидатов, и старая логика уходила в
// вечный ретрай той же ноды. Здесь srv-a хост стабильно объявляет мёртвым,
// srv-b — живым. Ожидаем: расширение само уйдёт на srv-b и поднимет туннель.
// ---------------------------------------------------------------------------
test("при повторяющихся обрывах расширение само уходит на другую ноду и поднимается", async () => {
  const ctx = await loadBackground({
    storage: { servers: [{ ...A, ping: null }, { ...B, ping: null }] }
  });
  const { api, STATE, T, clock } = ctx;
  try {
    api.setResponder((msg) => {
      if (msg?.command === "start") {
        return [{ type: "ack", listen: "127.0.0.1:1080" }, { type: "status", status: "connected" }];
      }
      if (msg?.command === "diagnose") {
        const dead = STATE.currentServer?.id === "srv-a";   // srv-a не вытягивает туннель
        return {
          type: "diagnose",
          data: { socksListening: !dead, tunnelActive: !dead, tunnelAlive: !dead, listenAddr: "127.0.0.1:1080", driver: "vless" }
        };
      }
      return null;
    });
    api.setFetch(async () => {
      if (STATE.currentServer?.id === "srv-a") throw new Error("NetworkError when connecting to SOCKS proxy");
      return { ok: true, status: 200, text: async () => "success\n" };
    });

    api.hostSend({ type: "hello", version: "5.5.4", drivers: ["vless", "trojan", "wireguard"], caps: ["ack", "autoPort", "liveness", "routeRules", "probeServers"] });
    await clock.flush();

    const started = await T.startTunnel({ ...A, ping: null });
    assert.equal(started.ok, true, started.error);
    await clock.flush();

    let switched = false;
    for (let i = 0; i < 120 && !switched; i++) {
      await clock.advance(2000);
      if (STATE.status === "connected") {
        api.hostSend({ type: "stats", bytesSent: 1024 * (i + 1), bytesReceived: 4096 * (i + 1), rtt: 40, dropped: 0 });
      }
      await clock.flush();
      switched = STATE.currentServer?.id === "srv-b" && STATE.status === "connected" && STATE.tunnelVerified;
    }

    assert.equal(STATE.currentServer?.id, "srv-b", "восстановление должно уйти с мёртвой ноды на живую");
    assert.equal(STATE.status, "connected", "туннель обязан подняться, а не висеть в обрывах");
    assert.equal(STATE.tunnelVerified, true, "туннель подтверждён");
    assert.ok(T.deathsInWindow("srv-a") >= 1,
      "обрыв srv-a должен быть учтён: " + JSON.stringify(Object.fromEntries(STATE.deaths)));
    assert.notEqual(STATE.resumeServerId, "srv-a", "намерение не должно остаться на мёртвой ноде");
    const starts = api.commands("start").map((m) => m.config?.server);
    assert.ok(starts.includes("de1.example.test"), "был отправлен start на srv-b: " + JSON.stringify(starts));
    assert.equal(STATE.resumeServerId, null, "намерение восстановлено — доехали");
  } finally { await ctx.teardown(); }
});
