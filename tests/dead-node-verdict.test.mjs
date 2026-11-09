// dead-node-verdict.test.mjs — FIX(5.5.14): мёртвая нода определяется по ДВУМ
// независимым подтверждениям, а не по правилу, которое никогда не срабатывает.
//
// Шестой отчёт пользователя (5.5.13 + хост 5.5.4):
//   22:06:47 liveness: контрольный dial через туннель не удался: socks5: connect
//            отклонён (код 0x1)
//   22:06:47 dbg: soft liveness: tunnelAlive=false проигнорирован (SOCKS слушает,
//            подряд 1, трафик есть)
//   22:07:34 liveness: … отклонён (код 0x1)      ← и снова ничего
//   22:10:37 probe: готово — 32 живых из 600
//   рейтинг: доверенных 0, мёртвых 50, без истории 1755
//
// Прежнее правило (5.5.10): 3 отказа dial подряд + 45 c + НУЛЕВОЙ трафик.
// На практике оно не срабатывало никогда:
//   • серия обнуляется при каждой смене ноды (softLivenessReset), а ноды
//     переключались каждые 20–40 c;
//   • «нулевого трафика» не бывает: контрольные запросы самого расширения идут
//     через туннель и дают байты. В отчёте «Передано ↑0.00 ↓0.00 MB» — и при
//     этом «трафик есть».
// В итоге расширение сидело на ноде, которая не пропускает трафик, и писало
// «Туннель жив». Пользователь это описал как «похер какой сервер — не подрубает».
//
// Теперь: на tunnelAlive=false от хоста сразу идёт СОБСТВЕННЫЙ контрольный
// запрос браузера через SOCKS. Прошёл — нода рабочая (dial хоста игнорируем,
// пишем об этом). Не прошёл — два независимых подтверждения, нода мёртвая,
// лестница уходит на другую. Прежний мягкий путь сохранён.
//
// Запуск: node --test tests/
//   BG_DIR=../flicker-5.5.13/ext node --test tests/dead-node-verdict.test.mjs → RED

import test from "node:test";
import assert from "node:assert/strict";
import { loadBackground, connectAndArm, VLESS_SERVER, VLESS_SERVER_B } from "./bg-harness.mjs";

const A = { ...VLESS_SERVER, id: "srv-a", name: "DE15", host: "de15.example.test", ping: 40 };
const B = { ...VLESS_SERVER_B, id: "srv-b", name: "FI1", host: "fi1.example.test", ping: 60 };

const jkinds = (STATE) => STATE.journal.map((j) => j.kind);
const jtext = (STATE, kind) =>
  STATE.journal.filter((j) => j.kind === kind).map((j) => j.text).join(" | ");
const jtail = (STATE) => JSON.stringify(STATE.journal.slice(-8).map((j) => j.kind));

/** Ответ хоста «SOCKS слушает, но контрольный dial отклонён» — как в отчёте. */
const dialRefused = () => ({
  type: "diagnose",
  data: { socksListening: true, tunnelActive: true, tunnelAlive: false, listenAddr: "127.0.0.1:1080", driver: "vless" }
});

async function settle(ctx, ms = 12_000, step = 1_000) {
  for (let t = 0; t < ms; t += step) {
    await ctx.clock.advance(step);
    await ctx.clock.flush();
  }
}

test("dial отклонён И запрос браузера не прошёл → нода мёртвая (без 45 c и при трафике)", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { host } = await connectAndArm(ctx, { server: A });
    const { api, STATE, clock } = ctx;
    assert.equal(STATE.tunnelVerified, true, "нода подтверждена");

    // трафик ЕСТЬ — прежнее правило требовало нулевого и потому молчало
    api.hostSend({ type: "stats", bytesSent: 5120, bytesReceived: 9216, rtt: 40, dropped: 0 });
    await clock.flush();
    assert.ok(STATE.bytesSent + STATE.bytesReceived > 0, "трафик ненулевой");

    // хост больше не проходит dial, и наш контрольный запрос через SOCKS тоже
    host.alive = false;
    host.probeOk = false;
    api.hostSend(dialRefused());
    await settle(ctx);

    assert.equal(STATE.softDeadStreak <= 1, true,
      "серия отказов НЕ набралась (прежнее правило не сработало бы): streak=" + STATE.softDeadStreak);
    assert.ok(jkinds(STATE).includes("soft-dead"), "нода признана мёртвой: " + jtail(STATE));
    assert.match(jtext(STATE, "soft-dead"), /контрольный запрос браузера через SOCKS не прошёл/,
      "в причине видно оба подтверждения: " + jtext(STATE, "soft-dead"));
    assert.equal(STATE.lastOwnProbeOk, false, "результат своей пробы запомнен");
  } finally { await ctx.teardown(); }
});

test("dial отклонён, но запрос браузера прошёл → нода рабочая, туннель не рвём", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { host } = await connectAndArm(ctx, { server: A });
    const { api, STATE, clock } = ctx;

    api.hostSend({ type: "stats", bytesSent: 1024, bytesReceived: 2048, rtt: 40, dropped: 0 });
    await clock.flush();

    // dial у хоста не проходит (медленная нода не укладывается в свой таймаут),
    // но реальный запрос через SOCKS работает
    host.alive = false;
    host.probeOk = true;
    api.hostSend(dialRefused());
    await settle(ctx);
    api.hostSend(dialRefused());
    await settle(ctx);

    assert.ok(!jkinds(STATE).includes("soft-dead"),
      "рабочую ноду не выбрасываем: " + jtail(STATE) + " " + jtext(STATE, "soft-dead"));
    assert.equal(STATE.lastOwnProbeOk, true, "своя проба прошла");
    assert.equal(STATE.status, "connected", "туннель остался подключён");
    assert.equal(STATE.proxyArmed, true, "прокси не снят");
  } finally { await ctx.teardown(); }
});

test("регрессия 5.5.10: одиночный отказ dial при живом SOCKS по-прежнему игнорируется", async () => {
  const ctx = await loadBackground({ storage: { servers: [A, B] } });
  try {
    const { host } = await connectAndArm(ctx, { server: A });
    const { api, STATE, clock } = ctx;

    host.alive = false;
    host.probeOk = true;              // наш запрос проходит → смерть не доказана
    api.hostSend(dialRefused());
    await settle(ctx, 6_000);

    assert.equal(STATE.status, "connected");
    assert.equal(STATE.tunnelVerified, true, "подтверждение не снято");
    assert.ok(!jkinds(STATE).includes("soft-dead"), "одиночный отказ не приговор: " + jtail(STATE));
    assert.ok(!jkinds(STATE).includes("tunnel-lost"), "обрыв не объявлен: " + jtail(STATE));
  } finally { await ctx.teardown(); }
});
