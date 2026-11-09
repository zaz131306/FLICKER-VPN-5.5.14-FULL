// mode-norestart.test.mjs — FIX(5.5.13): смена режима маршрутизации не рвёт
// работающий туннель, если хост наших правил всё равно не получает.
//
// Что показал пятый дамп пользователя (5.5.12 + хост 5.5.4):
//   14:02:03 dbg: proxy=socks port=1081 kind=native passthrough=182   ← all → smart
//   14:02:03 dbg: switch: 193.124.35.241 -> 193.124.35.241           ← рестарт той же ноды
//   14:02:03 SOCKS5 слушает 127.0.0.1:1081
//   14:02:03 туннель: vless (193.124.35.241:443) connecting
//
// Атомарный рестарт делался «чтобы новые правила уехали в sing-box». Но
// composeConfig кладёт routeRules/tunnelMode в конфиг ТОЛЬКО если хост объявил
// cap routeRules/route-rules/routing. Хост 5.5.4 объявляет
// «ack, autoPort, diagnose, probe, liveness» — правил он не получает в
// принципе, маршрутизацию держит proxy.settings, который applyProxyMode()
// переустанавливает на месте, без разрыва (в дампе это строка passthrough=182
// ДО switch). То есть рестарт — чистая потеря: разрыв туннеля плюс окно
// прямого трафика из-за запоздалого stop-ack (см. stop-ack.test.mjs).
//
// Теперь: рестарт остался только для хоста, который правила принимает.
//
// Запуск: node --test tests/
//   BG_DIR=../flicker-5.5.12/ext node --test tests/mode-norestart.test.mjs → RED

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadBackground, connectAndArm, VLESS_SERVER } from "./bg-harness.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const A = { ...VLESS_SERVER, id: "srv-a", name: "DE15", host: "de15.example.test", ping: 40 };

// ровно те caps, что объявляет хост пользователя (пятый дамп, шапка)
const CAPS_554 = ["ack", "autoPort", "diagnose", "probe", "liveness"];
const CAPS_RULES = ["ack", "autoPort", "diagnose", "probe", "liveness", "routeRules"];

const jkinds = (STATE) => STATE.journal.map((j) => j.kind);
const jtail = (STATE) => JSON.stringify(STATE.journal.slice(-6).map((j) => j.kind));
const bypassCount = (api) => {
  const v = api.lastProxy();
  if (!v || v.proxyType !== "manual") return -1;
  return String(v.passthrough || "").split(",").filter(Boolean).length;
};
const directHandovers = (api, from = 0) =>
  api.proxyLog.slice(from).filter((c) => c.op === "clear" ||
    (c.value && (c.value.proxyType === "none" || c.value.proxyType === "system")));

test("хост без cap routeRules: режим меняется БЕЗ разрыва туннеля", async () => {
  const ctx = await loadBackground({ storage: { servers: [A] } });
  try {
    const { host } = await connectAndArm(ctx, { server: A });
    const { STATE, api, clock } = ctx;
    host.hello("5.5.4", CAPS_554);          // как у пользователя
    await clock.flush();
    assert.equal(STATE.nativeCaps.has("routeRules"), false);

    // стартовали в smart (по умолчанию) → переключаем в all и обратно
    const mark = api.proxyLog.length;
    const starts = host.startCalls;
    const r1 = await api.fireRuntimeMessage({ action: "setTunnelMode", mode: "all" });
    await clock.advance(1_000);
    assert.equal(r1.ok, true, JSON.stringify(r1).slice(0, 200));
    assert.equal(STATE.tunnelMode, "all");
    assert.equal(host.startCalls, starts, "туннель не перезапускался: " + jtail(STATE));
    assert.equal(api.commands("stop").length, 0, "хосту не посылали stop");
    assert.equal(STATE.status, "connected", "туннель жив");
    assert.equal(STATE.proxyArmed, true, "прокси вооружён");
    assert.ok(bypassCount(api) > 0 && bypassCount(api) < 20,
      "режим all: passthrough короткий, got " + bypassCount(api));
    assert.ok(jkinds(STATE).includes("tunnel-mode-noop"), "в журнале видно причину: " + jtail(STATE));

    const r2 = await api.fireRuntimeMessage({ action: "setTunnelMode", mode: "smart" });
    await clock.advance(1_000);
    assert.equal(r2.ok, true);
    assert.equal(host.startCalls, starts, "и обратно — тоже без рестарта");
    assert.ok(bypassCount(api) > 100, "режим smart: passthrough полный, got " + bypassCount(api));
    assert.equal(STATE.proxyArmed, true);
    assert.equal(directHandovers(api, mark).length, 0,
      "браузер ни разу не уходил напрямую: " + JSON.stringify(directHandovers(api, mark)));
  } finally { await ctx.teardown(); }
});

test("хост С cap routeRules: атомарный рестарт сохранён", async () => {
  const ctx = await loadBackground({ storage: { servers: [A] } });
  try {
    const { host } = await connectAndArm(ctx, { server: A });
    const { STATE, api, clock } = ctx;
    host.hello("5.5.4", CAPS_RULES);
    await clock.flush();
    assert.equal(STATE.nativeCaps.has("routeRules"), true);

    const mark = api.proxyLog.length;
    const starts = host.startCalls;
    const r = await api.fireRuntimeMessage({ action: "setTunnelMode", mode: "all" });
    await clock.advance(4_000);
    assert.equal(r.ok, true, JSON.stringify(r).slice(0, 200));
    assert.equal(host.startCalls, starts + 1, "правила уехали в sing-box атомарным рестартом");
    assert.equal(api.commands("stop").length, 1, "смена атомарная: один stop");
    assert.equal(STATE.status, "connected", "туннель поднят снова");
    assert.equal(STATE.proxyArmed, true);
    assert.equal(directHandovers(api, mark).length, 0,
      "во время пересборки браузер не уходил напрямую: " + JSON.stringify(directHandovers(api, mark)));
  } finally { await ctx.teardown(); }
});

test("advanced.forceRouteRules по-прежнему отправляет правила старому хосту", async () => {
  const ctx = await loadBackground({
    storage: { servers: [A], advanced: { forceRouteRules: true } }
  });
  try {
    const { host } = await connectAndArm(ctx, { server: A });
    const { api, STATE, T } = ctx;
    host.hello("5.5.4", CAPS_554);
    const composed = T.composeConfig(A);
    assert.equal(composed.ok, true, composed.error);
    assert.ok(composed.config.routeRules, "правила отправлены принудительно");
    assert.equal(composed.config.tunnelMode, STATE.tunnelMode);
    assert.ok(api.commands("start").length >= 1);
  } finally { await ctx.teardown(); }
});

test("статика: popup обновляется по «socksPort», панель показывает вооружённый порт", () => {
  const pop = readFileSync(path.join(HERE, "..", "ext", "popup.js"), "utf8");
  const opt = readFileSync(path.join(HERE, "..", "ext", "options.js"), "utf8");
  // FIX(5.5.13): reconcileSocksPort шлёт {type:"socksPort"}, а popup реагировал
  // только на {type:"status"} → в подвале висел старый 1080 при живом 1081.
  assert.match(pop, /msg\.type === "socksPort"/, "popup реагирует на сдвиг порта");
  assert.match(pop, /прокси на \$\{ap\}/, "подвал показывает фактически вооружённый порт");
  assert.match(opt, /прокси браузера вооружён на/, "шапка диагностики показывает вооружённый порт");
  assert.match(opt, /\$\{addr\.padEnd\(30\)\}/, "в топе рейтинга печатается host:port");
});
