// tunnel-recovery.test.mjs — воспроизведение главного сценария 5.5.x:
//
//   «Туннель не работает — прокси возвращён браузеру» → соединения нет,
//    и обратно расширение не поднимается.
//
// Тесты написаны ПРОТИВ ОРИГИНАЛЬНОЙ 5.5.4: каждый из них на ней падает
// (это и есть баг-репорт), а на починенной копии — проходит.
//
// Запуск:
//   BG_DIR=../../ext554 node --test tests/          # оригинал (ожидаем RED)
//   node --test tests/                              # починенная ext/ (ожидаем GREEN)

import test from "node:test";
import assert from "node:assert/strict";
import {
  loadBackground, createFakeHost, connectAndArm, VLESS_SERVER, VLESS_SERVER_B
} from "./bg-harness.mjs";

const SERVERS = [VLESS_SERVER, VLESS_SERVER_B];

// ---------------------------------------------------------------------------
// 1. Хост 5.5.4 проверяет живость туннеля дольше, чем расширение готово ждать.
//    По INSTALL-INFO: 10 c на цель, три цели (1.1.1.1 / 8.8.8.8 / 9.9.9.9:443),
//    то есть до ~30 c. Расширение сдаётся за 12 c (PROXY_ARM_TIMEOUT_MS),
//    гасит туннель командой stop и снимает прокси.
// ---------------------------------------------------------------------------
test("медленный liveness хоста (3 цели × 10 c) не должен убивать живой туннель", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, T, clock } = ctx;
  try {
    const host = createFakeHost(api, clock, { diagnoseDelayMs: 15_000, probeOk: false });
    ctx.host = host;
    host.hello();
    await clock.flush();

    const started = await T.startTunnel(VLESS_SERVER);
    assert.equal(started.ok, true, started.error);
    await clock.flush();

    // хост думает 15 c, затем подтверждает: SOCKS слушает, туннель жив
    await clock.advance(20_000);

    assert.equal(STATE.status, "connected", "статус не должен падать в disconnected");
    assert.equal(STATE.tunnelVerified, true, "туннель подтверждён хостом");
    assert.equal(STATE.proxyArmed, true, "прокси обязан быть вооружён");
    assert.equal(api.commands("stop").length, 0,
      "расширение не имеет права гасить туннель, который хост ещё проверяет");
    assert.equal(api.lastProxy()?.proxyType, "manual", "браузер должен остаться на SOCKS5");
    assert.equal(api.lastProxy()?.socksPort, 1080);
  } finally { await ctx.teardown(); }
});

// ---------------------------------------------------------------------------
// 2. Тупик после освобождения прокси: статус «подключено»/resume-намерение есть,
//    а таймеров не осталось — расширение больше никогда ничего не спрашивает
//    у хоста и не поднимается само, даже когда хост снова здоров.
// ---------------------------------------------------------------------------
test("после смерти туннеля расширение восстанавливается само, когда хост снова отвечает", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, clock } = ctx;
  try {
    await connectAndArm(ctx, { host: {} });
    assert.equal(STATE.proxyArmed, true, "стартовое состояние: прокси вооружён");

    // туннель умер: хост молчит на diagnose, контрольный запрос не проходит,
    // статистика не обновляется
    const host = ctx.host;
    host.mode = "silent";
    host.probeOk = false;
    host.alive = false;
    STATE.lastStatsAt = clock.now - 80_000;

    await clock.advance(60_000);
    api.fireAlarm("keepalive");
    await clock.advance(1_000);
    api.fireAlarm("keepalive");
    await clock.advance(30_000);

    // хост снова отвечает (тот же процесс, нового hello не будет)
    host.mode = "healthy";
    host.probeOk = true;
    host.alive = true;

    await clock.advance(120_000);
    host.stats();
    await clock.advance(10_000);

    assert.equal(STATE.status, "connected",
      "туннель должен подняться заново без кликов пользователя");
    assert.equal(STATE.proxyArmed, true, "прокси должен вернуться на SOCKS5");
    assert.equal(api.lastProxy()?.proxyType, "manual");
  } finally { await ctx.teardown(); }
});

// ---------------------------------------------------------------------------
// 3. Контрольная проба через SOCKS переставляет browser.proxy.settings на
//    «пробную» конфигурацию и НЕ возвращает боевую: теряется passthrough
//    (RU-домены напрямую) либо браузер вообще уходит в системный прокси ОС.
// ---------------------------------------------------------------------------
test("проба живости возвращает браузеру боевую настройку прокси, а не пробную", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, STATE, T, clock } = ctx;
  try {
    await connectAndArm(ctx, {});
    const armed = api.lastProxy();
    assert.equal(armed.proxyType, "manual");
    assert.ok(/gosuslugi\.ru/.test(armed.passthrough || ""),
      "в боевой настройке RU-домены идут напрямую: " + armed.passthrough);

    // так watchdog/scheduleVerify проверяет живой туннель реальным запросом
    await T.probeThroughProxy(STATE.socksPort);
    await clock.flush();

    const after = api.lastProxy();
    assert.equal(after.proxyType, armed.proxyType,
      "после пробы proxyType остался от пробной настройки");
    assert.equal(after.socksPort, armed.socksPort);
    assert.equal(after.passthrough, armed.passthrough,
      "после пробы потерян список passthrough (split tunneling сломан)");
    assert.equal(STATE.proxyArmed, true, "прокси не должен сниматься пробой");
  } finally { await ctx.teardown(); }
});

// ---------------------------------------------------------------------------
// 4. Расширение представляется хосту версией 5.5.0, хотя само 5.5.4.
//    Хост гейтит по extVersion новое поведение (liveness 10 c × 3 цели,
//    autoPort, caps) — со «старым» расширением он работает по-старому.
// ---------------------------------------------------------------------------
test("announce.extVersion совпадает с версией из manifest.json", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS } });
  const { api, clock } = ctx;
  try {
    createFakeHost(api, clock, {});
    api.hostSend({ type: "hello", version: "5.5.4", drivers: ["vless"], caps: ["ack", "liveness"] });
    await clock.flush();
    const announce = api.lastCommand("announce");
    assert.ok(announce, "расширение обязано отправить announce после hello");
    assert.equal(announce.extVersion, api.manifest.version,
      `расширение говорит хосту, что оно ${announce.extVersion}, а в manifest ${api.manifest.version}`);
  } finally { await ctx.teardown(); }
});

// ---------------------------------------------------------------------------
// 5. Kill switch + мёртвый туннель = полная блокировка трафика навсегда:
//    recoverFromDeadTunnel уходит в activateKillSwitch, не запомнив намерение
//    и не назначив повтор. Дальше не поднимается ничего.
// ---------------------------------------------------------------------------
test("kill switch снимается сам, когда туннель удалось вернуть", async () => {
  const ctx = await loadBackground({ storage: { servers: SERVERS, killSwitch: true } });
  const { api, STATE, clock } = ctx;
  try {
    await connectAndArm(ctx, {});
    assert.equal(api.blockedByKillSwitch(), false);

    const host = ctx.host;
    host.mode = "silent";
    host.probeOk = false;
    host.alive = false;
    STATE.lastStatsAt = clock.now - 80_000;

    await clock.advance(60_000);
    api.fireAlarm("keepalive");
    await clock.advance(60_000);
    api.fireAlarm("keepalive");
    await clock.advance(30_000);
    assert.equal(api.blockedByKillSwitch(), true, "kill switch обязан блокировать трафик");

    host.mode = "healthy";
    host.probeOk = true;
    host.alive = true;

    await clock.advance(180_000);
    host.stats();
    await clock.advance(10_000);

    assert.equal(STATE.status, "connected", "туннель должен вернуться");
    assert.equal(api.blockedByKillSwitch(), false,
      "kill switch не снят — пользователь остался без интернета навсегда");
    assert.equal(STATE.proxyArmed, true, "трафик снова должен идти через SOCKS5");
  } finally { await ctx.teardown(); }
});
