// ping-filter.test.mjs — потолок задержки (maxPingMs) и отсутствие тупиков.
//
// Претензия пользователя: «фильтра по пингам серверов нет — отсеивать большой
// пинг от 1000 до 4000, нахуй они нужны». Проверяем, что:
//   1. потолок применяется по умолчанию (1200 мс) и настраивается из UI;
//   2. автовыбор не берёт ноды с пингом выше потолка;
//   3. недопустимые значения отклоняются, а состояние не портится;
//   4. порог переживает перезапуск (storage);
//   5. если ВСЕ ноды медленные — это не молчаливый тупик: берём наименее
//      медленную и объясняем в UI, что сделать;
//   6. локальные транспорты (dpi/direct) и демо-ноды не становятся целью
//      восстановления — иначе «VPN» молча превращается в прямой трафик.
//
// Запуск: node --test tests/
//         BG_DIR=../ext554 node --test tests/ping-filter.test.mjs → RED (фильтра нет)

import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { loadBackground, VLESS_SERVER, VLESS_SERVER_B } from "./bg-harness.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LIB = process.env.BG_DIR ? path.resolve(process.env.BG_DIR, "lib") : path.resolve(HERE, "..", "ext", "lib");
const SUB = await import(pathToFileURL(path.join(LIB, "subscriptions.js")).href);

const FAST = { ...VLESS_SERVER, id: "srv-fast", name: "Быстрый", host: "fast.example.test", ping: 90 };
const MID = { ...VLESS_SERVER_B, id: "srv-mid", name: "Средний", host: "mid.example.test", ping: 900 };
const SLOW = { ...VLESS_SERVER_B, id: "srv-slow", name: "Медленный", host: "slow.example.test", ping: 2400 };
const VERY_SLOW = { ...VLESS_SERVER_B, id: "srv-vslow", name: "Очень медленный", host: "vslow.example.test", ping: 3800 };

const HELLO = { type: "hello", version: "5.5.7", drivers: ["vless", "trojan", "wireguard"], caps: ["ack", "autoPort", "liveness", "routeRules", "probeServers"] };

test("потолок задержки по умолчанию 1200 мс; неизмеренные и мёртвые не отсеиваются", async () => {
  const ctx = await loadBackground({ storage: { servers: [FAST, SLOW] } });
  const { STATE, T } = ctx;
  try {
    assert.equal(STATE.maxPingMs, 1200, "дефолт DEFAULT_MAX_PING_MS = 1200");
    assert.equal(SUB.isUsable(FAST, STATE.maxPingMs), true);
    assert.equal(SUB.isUsable(SLOW, STATE.maxPingMs), false, "2400 мс — мусор, не пригоден");
    assert.equal(T.isTooSlow({ ping: 1201 }), true);
    assert.equal(T.isTooSlow({ ping: 1200 }), false, "ровно потолок — проходит");
    assert.equal(T.isTooSlow({ ping: null }), false, "пинг не измерен — не «медленный»");
    assert.equal(T.isTooSlow({ ping: -2 }), false, "мёртвых скрывает hideDead/блок-лист");
    assert.equal(T.countSlow([FAST, MID, SLOW, VERY_SLOW]), 2);
  } finally { await ctx.teardown(); }
});

test("автовыбор не берёт ноды с пингом 2400/3800 мс", async () => {
  const ctx = await loadBackground({ storage: { servers: [SLOW, VERY_SLOW, MID, FAST] } });
  const { STATE, T } = ctx;
  try {
    assert.equal(STATE.maxPingMs, 1200);
    const best = await T.autoSelectBestServer([SLOW, VERY_SLOW, MID, FAST]);
    assert.ok(best, "автовыбор обязан вернуть ноду");
    assert.equal(best.id, "srv-fast");
    assert.equal(SUB.isUsable(best, STATE.maxPingMs), true);
  } finally { await ctx.teardown(); }
});

test("потолок задаётся из UI, отклоняет мусор и сохраняется в storage", async () => {
  const ctx = await loadBackground({ storage: { servers: [FAST, MID, SLOW] } });
  const { STATE, T, api } = ctx;
  try {
    const r1 = await api.fireRuntimeMessage({ action: "setMaxPing", maxPingMs: 400 });
    assert.equal(r1.ok, true, JSON.stringify(r1));
    assert.equal(STATE.maxPingMs, 400);
    assert.equal(r1.maxPingMs, 400);
    assert.equal(T.statusPayload().maxPingMs, 400, "видно в статусе и в «Диагностике»");
    const saved = await api.browser.storage.local.get("maxPingMs");
    assert.equal(saved.maxPingMs, 400, "переживает перезапуск");

    const best = await T.autoSelectBestServer([FAST, MID]);
    assert.equal(best.id, "srv-fast", "при потолке 400 узел с 900 мс отсеян");

    const bad1 = await api.fireRuntimeMessage({ action: "setMaxPing", maxPingMs: 10 });
    assert.equal(bad1.ok, false, "10 мс — вне диапазона 50…20000");
    assert.equal(STATE.maxPingMs, 400, "отклонённое значение не меняет состояние");
    const bad2 = await api.fireRuntimeMessage({ action: "setMaxPing", maxPingMs: 25000 });
    assert.equal(bad2.ok, false);
    assert.equal(STATE.maxPingMs, 400);
    const bad3 = await api.fireRuntimeMessage({ action: "setMaxPing", maxPingMs: "много" });
    assert.equal(bad3.ok, false);
    assert.equal(STATE.maxPingMs, 400);
  } finally { await ctx.teardown(); }
});

test("потолок читается из storage при старте", async () => {
  const ctx = await loadBackground({ storage: { servers: [FAST, MID], maxPingMs: 250 } });
  const { STATE, T } = ctx;
  try {
    assert.equal(STATE.maxPingMs, 250);
    const best = await T.autoSelectBestServer([FAST, MID]);
    assert.equal(best.id, "srv-fast");
  } finally { await ctx.teardown(); }
});

test("все ноды медленные — не молчаливый тупик: берём наименее медленную и объясняем", async () => {
  const ctx = await loadBackground({ storage: { servers: [SLOW, VERY_SLOW], maxPingMs: 1200 } });
  const { api, STATE, T, clock } = ctx;
  try {
    const PINGS = { "srv-slow": 2400, "srv-vslow": 3800 };
    api.setResponder((msg) => {
      if (msg?.command === "ping") return [{ type: "ping", serverId: msg.serverId, latency: PINGS[msg.serverId] ?? -1 }];
      return null;
    });
    api.hostSend(HELLO);
    await clock.flush();

    const p = T.autoSelectBestServer([{ ...SLOW, ping: null }, { ...VERY_SLOW, ping: null }]);
    await clock.advance(3000);
    const best = await p;

    assert.equal(STATE.maxPingMs, 1200);
    assert.ok(best, "null без единого слова в UI = пользователь сидит без VPN и не понимает почему");
    assert.equal(best.id, "srv-slow", "берём наименее медленную (2400 < 3800)");
    const hint = api.outgoing.find((m) => m?.type === "error" && /медленнее потолка|нет живых нод|живых нод с пингом/i.test(m.message || ""));
    assert.ok(hint, "в UI ушло объяснение: " + JSON.stringify(api.outgoing.map((m) => m?.message).slice(-3)));
  } finally { await ctx.teardown(); }
});

test("локальные транспорты и демо-ноды не становятся целью восстановления", async () => {
  const ctx = await loadBackground({ storage: { servers: [FAST, MID] } });
  const { STATE, T } = ctx;
  try {
    const locals = [
      { id: "dpi-local", name: "DPI-обход", protocol: "dpi", host: "127.0.0.1", port: 1081, ping: null },
      { id: "direct", name: "Напрямую", protocol: "direct", host: "127.0.0.1", port: 0, ping: null },
      { id: "demo-1", name: "Пример", protocol: "vless", host: "demo.example.test", port: 443, uuid: "x", demo: true, ping: 10 },
      FAST, MID
    ];
    STATE.resumeServerId = "srv-fast";
    T.noteTunnelDeath("srv-fast", "обрыв 1", "vless||tls|");
    T.noteTunnelDeath("srv-fast", "обрыв 2", "vless||tls|");
    STATE.recoveryAttempt = 1;
    const pick = T.pickRecoveryTarget(locals, "тест");
    assert.ok(pick.server, "цель обязана быть");
    assert.equal(pick.server.id, "srv-mid", "только настоящая VPN-нода");
    assert.notEqual(pick.server.protocol, "dpi", "DPI-режим нельзя включать молча вместо VPN");
    assert.notEqual(pick.server.protocol, "direct", "«напрямую» — это не VPN");
    assert.equal(!!pick.server.demo, false);

    // но если пользователь СИДЕЛ в DPI-режиме — возвращаем именно его
    STATE.resumeServerId = "dpi-local";
    STATE.recoveryAttempt = 0;
    STATE.deaths.clear();
    const dpiPick = T.pickRecoveryTarget(locals, "тест");
    assert.equal(dpiPick.server.id, "dpi-local");
  } finally { await ctx.teardown(); }
});
