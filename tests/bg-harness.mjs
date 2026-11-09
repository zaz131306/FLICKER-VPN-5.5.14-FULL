// bg-harness.mjs — стенд для прогона background.js (MV3 event page) в Node.
//
// Расширение живёт внутри Firefox: browser.*, fetch, таймеры. Здесь всё это
// подменяется управляемыми заглушками + виртуальными часами, чтобы сценарии
// «туннель упал / прокси освобождён» воспроизводились детерминированно и за
// миллисекунды, а не за минуты реального времени.
//
// Один вызов loadBackground() = одна свежая копия модуля (импорт с ?run=N).

import path from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
let runCounter = 0;

// ---------------------------------------------------------------- часы ----
export function createClock() {
  const real = {
    setTimeout: globalThis.setTimeout,
    clearTimeout: globalThis.clearTimeout,
    setInterval: globalThis.setInterval,
    clearInterval: globalThis.clearInterval,
    now: Date.now.bind(Date),
    immediate: globalThis.setImmediate
  };
  let t = 0;
  let seq = 1;
  const timers = new Map();

  const clock = {
    errors: [],
    get now() { return t; },
    pending() { return timers.size; },

    install() {
      globalThis.setTimeout = (fn, ms = 0, ...args) => {
        const id = seq++;
        timers.set(id, { at: t + Math.max(0, Number(ms) || 0), fn, args, every: 0 });
        return id;
      };
      globalThis.clearTimeout = (id) => { timers.delete(id); };
      globalThis.setInterval = (fn, ms = 0, ...args) => {
        const id = seq++;
        const every = Math.max(1, Number(ms) || 1);
        timers.set(id, { at: t + every, fn, args, every });
        return id;
      };
      globalThis.clearInterval = (id) => { timers.delete(id); };
      Date.now = () => t;
      return clock;
    },

    uninstall() {
      globalThis.setTimeout = real.setTimeout;
      globalThis.clearTimeout = real.clearTimeout;
      globalThis.setInterval = real.setInterval;
      globalThis.clearInterval = real.clearInterval;
      Date.now = real.now;
    },

    /** Промотать виртуальное время, выполнив все таймеры по порядку. */
    async advance(ms) {
      const target = t + ms;
      let guard = 0;
      while (guard++ < 50000) {
        let pick = null;
        for (const [id, tm] of timers) {
          if (tm.at <= target && (!pick || tm.at < pick.tm.at || (tm.at === pick.tm.at && id < pick.id))) {
            pick = { id, tm };
          }
        }
        if (!pick) break;
        t = pick.tm.at;
        if (pick.tm.every) pick.tm.at = t + pick.tm.every;
        else timers.delete(pick.id);
        try { pick.tm.fn(...pick.tm.args); } catch (e) { clock.errors.push(e); }
        await clock.flush();
      }
      t = target;
      await clock.flush();
      return clock;
    },

    /** Дать микрозадачам/промисам осесть (без реального ожидания). */
    async flush(rounds = 12) {
      for (let i = 0; i < rounds; i++) await new Promise(real.immediate);
    }
  };
  return clock;
}

// ------------------------------------------------------------- браузер ----
export function createBrowserStub(opts = {}) {
  const store = new Map(Object.entries(opts.storage || {}));
  const proxyLog = [];          // все вызовы proxy.settings.set/clear
  const notifications = [];
  const alarms = new Map();
  const alarmListeners = [];
  const runtimeListeners = [];   // FIX(5.5.5): доступ к runtime.onMessage из тестов
  const outgoing = [];           // FIX(5.5.8): что расширение послало в UI (broadcastUI)
  const native = {
    sent: [],                   // всё, что расширение отправило хосту
    port: null,
    onMessage: [],
    onDisconnect: [],
    responder: null             // (msg) => reply|null — «живой хост»
  };
  let proxyLevel = opts.levelOfControl ?? "controlled_by_this_extension";
  let webRequestBlocker = null;
  let onRequestListener = null;
  let proxyErrorListener = null;
  let fetchImpl = opts.fetchImpl || (async () => ({ ok: true, status: 200, text: async () => "success\n" }));

  const manifest = opts.manifest ||
    JSON.parse(readFileSync(path.resolve(opts.extDir || HERE, "manifest.json"), "utf8"));

  const port = {
    _flickerAlive: true,
    error: null,
    postMessage(msg) {
      native.sent.push(msg);
      if (msg?.command === "dbg") return;
      const reply = native.responder ? native.responder(msg) : null;
      if (reply) {
        // ответ хоста приходит асинхронно (как настоящий native messaging)
        Promise.resolve().then(() => {
          for (const item of [].concat(reply)) {
            for (const l of native.onMessage) l(typeof item === "function" ? item(msg) : item);
          }
        });
      }
    },
    disconnect() { port._flickerAlive = false; for (const l of native.onDisconnect) l(); },
    onMessage: { addListener: (l) => native.onMessage.push(l) },
    onDisconnect: { addListener: (l) => native.onDisconnect.push(l) }
  };
  native.port = port;

  const browser = {
    storage: {
      local: {
        async get(keys) {
          if (keys == null) return Object.fromEntries(store);
          if (typeof keys === "string") return store.has(keys) ? { [keys]: store.get(keys) } : {};
          const out = {};
          for (const k of keys) if (store.has(k)) out[k] = store.get(k);
          return out;
        },
        async set(obj) { for (const [k, v] of Object.entries(obj)) store.set(k, v); },
        async remove(keys) { for (const k of [].concat(keys)) store.delete(k); },
        async clear() { store.clear(); }
      }
    },
    proxy: {
      settings: {
        async set({ value }) { proxyLog.push({ op: "set", value }); },
        async clear() { proxyLog.push({ op: "clear" }); },
        async get() { return { levelOfControl: proxyLevel, value: proxyLog.filter((c) => c.op === "set").slice(-1)[0]?.value }; }
      },
      onRequest: { addListener: (l) => { onRequestListener = l; } },
      onError: { addListener: (l) => { proxyErrorListener = l; } }
    },
    runtime: {
      lastError: undefined,
      getURL: (p) => "moz-extension://fake/" + p,
      getManifest: () => manifest,
      connectNative: () => port,
      onMessage: { addListener: (l) => runtimeListeners.push(l) },
      // FIX(5.5.8): фиксируем broadcastUI, чтобы тесты видели сообщения в UI
      sendMessage: async (msg) => { outgoing.push(msg); return undefined; },
      getPlatformInfo: async () => ({ os: "win" })
    },
    notifications: { create: (o) => { notifications.push(o); return Promise.resolve("id"); } },
    alarms: {
      create: (name, info) => alarms.set(name, info),
      clear: (name) => alarms.delete(name),
      onAlarm: { addListener: (l) => alarmListeners.push(l) }
    },
    webRequest: {
      onBeforeRequest: { addListener: (l) => { webRequestBlocker = l; } }
    },
    tabs: { create: () => Promise.resolve({}) },
    i18n: { getMessage: (k) => k }
  };

  const api = {
    browser, native, notifications, alarms, manifest, store,
    get proxyLog() { return proxyLog; },
    lastProxy() { return proxyLog.filter((c) => c.op === "set").slice(-1)[0]?.value || null; },
    resetProxyLog() { proxyLog.length = 0; },
    setProxyLevel(v) { proxyLevel = v; },
    setFetch(fn) { fetchImpl = fn; },
    fetch: (url, init) => fetchImpl(url, init),
    setResponder(fn) { native.responder = fn; },
    /** Сообщение «от хоста» в расширение. */
    hostSend(msg) { for (const l of native.onMessage) l(msg); },
    hostDisconnect(err = "host crashed") { port.error = { message: err }; port.disconnect(); },
    commands(name) { return native.sent.filter((m) => m?.command === name); },
    lastCommand(name) { return native.sent.filter((m) => m?.command === name).slice(-1)[0] || null; },
    /** Сработал ли webRequest-блокировщик (kill switch) для URL. */
    /** Отправить сообщение так, как это делает popup, и дождаться ответа. */
    async fireRuntimeMessage(msg) {
      const l = runtimeListeners[0];
      if (!l) throw new Error("runtime.onMessage listener не зарегистрирован");
      return new Promise((resolve) => {
        let done = false;
        const sendResponse = (v) => { if (!done) { done = true; resolve(v); } };
        const keep = l(msg, { id: 1, url: "moz-extension://fake/popup.html" }, sendResponse);
        if (keep !== true && !done) { setTimeout(() => sendResponse(undefined), 0); }
      });
    },
    runtimeListeners,
    outgoing,
    blockedByKillSwitch(url = "https://example.com/") {
      if (!webRequestBlocker) return false;
      const r = webRequestBlocker({ url, type: "main_frame" });
      return !!(r && r.cancel);
    },
    onRequestDecision(url) { return onRequestListener ? onRequestListener(url) : null; },
    fireProxyError(message) { if (proxyErrorListener) proxyErrorListener({ message }); },
    fireAlarm(name) { for (const l of alarmListeners) l({ name }); }
  };
  return api;
}

// --------------------------------------------------------------- загрузка ----
export async function loadBackground(opts = {}) {
  const extDir = opts.extDir
    ? path.resolve(opts.extDir)
    : process.env.BG_DIR
      ? path.resolve(process.env.BG_DIR)
      : path.resolve(HERE, "..", "ext");
  const bgPath = opts.bgPath ? path.resolve(opts.bgPath) : path.join(extDir, "background.js");

  const clock = createClock().install();
  const api = createBrowserStub({
    ...opts,
    extDir,
    storage: { subsBootstrapped: true, ...(opts.storage || {}) },
    manifest: opts.manifest || JSON.parse(readFileSync(path.join(extDir, "manifest.json"), "utf8"))
  });

  const savedGlobals = {
    browser: globalThis.browser,
    navigator: globalThis.navigator,
    fetch: globalThis.fetch
  };
  globalThis.browser = api.browser;
  if (!globalThis.navigator) globalThis.navigator = {};
  try { Object.defineProperty(globalThis.navigator, "userAgent", { value: opts.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0", configurable: true }); } catch { /* ignore */ }
  globalThis.fetch = api.fetch;

  const spec = pathToFileURL(bgPath).href + "?run=" + (++runCounter);
  const mod = await import(spec);
  await mod.ready;
  await clock.flush();
  api.resetProxyLog();          // стартовый сброс прокси в зачёт не идёт

  const STATE = mod.__test.STATE;

  const ctx = {
    mod, STATE, api, clock, extDir, bgPath,
    T: mod.__test,
    async advance(ms) { return clock.advance(ms); },
    async teardown() {
      clock.uninstall();
      globalThis.browser = savedGlobals.browser;
      globalThis.fetch = savedGlobals.fetch;
      if (savedGlobals.navigator === undefined) delete globalThis.navigator;
    }
  };
  return ctx;
}

// ------------------------------------------------------- типовые сценарии ----
export const VLESS_SERVER = {
  id: "srv-a", name: "Нидерланды A", flag: "🇳🇱", host: "nl1.example.test", port: 443,
  protocol: "vless", uuid: "11111111-2222-3333-4444-555555555555",
  sni: "www.microsoft.com", fingerprint: "chrome", flow: "xtls-rprx-vision",
  reality: { publicKey: "PUBKEYPUBKEYPUBKEYPUBKEYPUBKEYPUBKEYPUBKEY123", shortId: "abcd1234" },
  ping: 42, bandwidth: 200, sub: true
};

export const VLESS_SERVER_B = { ...VLESS_SERVER, id: "srv-b", name: "Германия B", host: "de1.example.test", ping: 55 };

export const HELLO_554 = {
  type: "hello", version: "5.5.4", drivers: ["vless", "trojan", "wireguard"],
  caps: ["ack", "autoPort", "liveness", "routeRules", "probeServers"]
};

/**
 * createFakeHost — «живой» native host с переключаемым поведением.
 *
 *   mode = "healthy" — отвечает на start (ack + connected), на diagnose
 *                      («туннель жив»), шлёт stats.
 *   mode = "silent"  — молчит на diagnose (именно так выглядит медленный
 *                      liveness-обход 5.5.4: 3 цели × 10 c).
 *   diagnoseDelayMs  — насколько хост «задумывается» перед ответом diagnose
 *                      (виртуальное время).
 *   probeOk          — проходит ли контрольный HTTP-запрос через SOCKS.
 */
export function createFakeHost(api, clock, opts = {}) {
  const host = {
    mode: opts.mode || "healthy",
    diagnoseDelayMs: opts.diagnoseDelayMs ?? 0,
    diagnoseAskedAt: null,
    alive: opts.alive !== false,
    socksListening: opts.socksListening !== false,
    // FIX(5.5.12): какой адрес хост объявляет в ack.listen / diagnose.listenAddr.
    // autoPort: при занятом 1080 хост слушает 1081 — именно этот сдвиг расширение
    // раньше игнорировало и держало браузер на мёртвом порту.
    listenAddr: opts.listenAddr || "127.0.0.1:1080",
    probeOk: opts.probeOk !== false,
    startCalls: 0,
    stats(n = 1, everyMs = 1000) {
      for (let i = 0; i < n; i++) {
        api.hostSend({ type: "stats", bytesSent: 1024 * (i + 1), bytesReceived: 4096 * (i + 1), rtt: 40, dropped: 0 });
      }
    },
    hello(version = "5.5.4", caps = ["ack", "autoPort", "liveness", "routeRules", "probeServers"]) {
      api.hostSend({ type: "hello", version, drivers: ["vless", "trojan", "wireguard"], caps });
    }
  };

  api.setFetch(async () => {
    if (host.probeOk) return { ok: true, status: 200, text: async () => "success\n" };
    throw new Error("NetworkError when connecting to SOCKS proxy");
  });

  api.setResponder((msg) => {
    switch (msg?.command) {
      case "start": {
        host.startCalls++;
        // "silent" — хост не отвечает НИЧЕГО (ни ack, ни diagnose): именно так
        // выглядит мёртвый/зависший туннель в жизни
        if (host.mode === "dead-start" || host.mode === "silent") return null;
        return [
          { type: "ack", listen: host.listenAddr },
          { type: "status", status: "connected" }
        ];
      }
      case "diagnose": {
        if (host.mode === "silent") { host.diagnoseAskedAt = clock.now; return null; }
        const answer = () => ({
          type: "diagnose",
          data: {
            socksListening: host.socksListening,
            tunnelActive: host.alive,
            tunnelAlive: host.alive,
            listenAddr: host.listenAddr,
            driver: "vless"
          }
        });
        if (!host.diagnoseDelayMs) return answer();
        // «задумчивый» хост: ответ придёт позже (liveness 5.5.4 = 3 цели × 10 c)
        host.diagnoseAskedAt = clock.now;
        setTimeout(() => api.hostSend(answer()), host.diagnoseDelayMs);
        return null;
      }
      default:
        return null;
    }
  });

  /** Досрочно отдать накопленный ответ diagnose (если хост «думал»). */
  host.flushDiagnose = () => {
    if (host.pendingDiagnose) { const f = host.pendingDiagnose; host.pendingDiagnose = null; api.hostSend(f()); }
  };
  return host;
}

/** Живой хост: отвечает diagnose «всё хорошо» и шлёт stats. */
export function healthyHostResponder(listenAddr = "127.0.0.1:1080") {
  return (msg) => {
    if (msg?.command === "diagnose") {
      return { type: "diagnose", data: { socksListening: true, tunnelActive: true, tunnelAlive: true, listenAddr, driver: "vless" } };
    }
    return null;
  };
}

/**
 * Поднять расширение до состояния «подключено + прокси вооружён».
 */
export async function connectAndArm(ctx, { server = VLESS_SERVER, host: hostOpts = {} } = {}) {
  const { api, STATE, T, clock } = ctx;
  const host = createFakeHost(api, clock, hostOpts);
  ctx.host = host;
  host.hello();
  await clock.flush();

  const p = T.startTunnel(server);
  await clock.flush();
  const started = await p;
  if (!started?.ok) throw new Error("startTunnel не удался: " + (started?.error || "?"));
  await clock.flush();

  // первый же цикл проверки живости (3 c): diagnose → прокси вооружается
  await clock.advance(3200);
  host.stats();
  await clock.flush();
  return { ctx, host };
}

