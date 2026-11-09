// background.js — FLICKER VPN, service worker (Manifest V3, ESM).
//
// Сборка 5.5.4.1-fix1: починен сценарий «Туннель не работает — прокси
// возвращён браузеру» (6 дефектов, см. README-FIX.md). Все правки помечены
// комментарием FIX(5.5.5) и покрыты тестами tests/tunnel-recovery.test.mjs.
//
// Стек v4: TCP/443-маскировка (VLESS+Reality/Vision, Trojan, VMess, SS) и
// WireGuard-«матрёшка» через native host (движок sing-box); Hysteria 2 —
// скрытый запасной UDP-транспорт. Симуляции Fake-SNI/Mux/псевдо-REALITY и
// TUIC удалены (не влияли на провод / не имели реализации).
//
// Обязанности:
//  • подписки: автозагрузка источников, парсинг ссылок, слияние, GC;
//  • автопоиск: многоэтапные пробы через native host (probeServers),
//    двойной прогон (45 c), success rate < 50% → мёртв;
//  • подключение: compose -> validate -> NM start; kill switch; split tunneling;
//  • фон: alarm раз в 10 минут (созревшие подписки + quick-проба живых),
//    автопереключение с умершего текущего сервера;
//  • ошибки: человеческие сообщения (lib/errors.js).

import { PROTOCOLS, getProtocol, buildServerConfig, validateServerConfig, normalizeAmnezia, toSingBoxAmnezia, awgInvalidEntries } from "./lib/protocol.js";
import {
  DEFAULT_SOURCES, parseSubscription, normalizeSources, mergeServers,
  pruneStale, sortServers, countryFlag, isUsable
} from "./lib/subscriptions.js";
import { ERRORS, humanizeTunnelError, humanizeProbeError, hostOutdatedError } from "./lib/errors.js";
// v5: реестр источников, рейтинг нод и маршрутизация вынесены в lib/.
// Ни один из этих модулей не знает про browser.* — тот же код пойдёт в
// desktop-демон, поэтому здесь только «проводка».
import { TIER_WEIGHT, parseMetaSource, expandMetaSources, sourceStats, META_SOURCES } from "./lib/sources.js";
import {
  makeRatingStore, rankCandidates, pickBest as ratingPickBest, needsProbe,
  ratingSummary, fingerprintOf, SCORE_DEAD, SCORE_TRUSTED, MAX_RTT_MS
} from "./lib/rating.js";
// FIX(5.5.5): постоянный блок-лист «мусорных» нод. Ключ — отпечаток узла
// (host+port+protocol+credentials), а не id, поэтому подписка не может
// вернуть заблокированный узел под новым id.
import {
  makeBlocklist, nodeKey, verdictFromProbe, blocklistSummary,
  BLOCK_REASONS, BLOCK_REASON_LABEL, DEFAULT_MAX_PING_MS
} from "./lib/blocklist.js";
import {
  createRuleset, MODES as TUNNEL_MODES, DEFAULT_MODE as DEFAULT_TUNNEL_MODE,
  describeMode, toSingBoxRules, toPassthrough, normalizeDomain
} from "./lib/split-tunnel.js";
// FIX(5.5.6): контракт пробы с native host, выведенный из разбора
// flicker-host.exe (internal/probe). Два корня, которые чинит модуль:
//  HC-1 — этапы-метаданные (cloudflare/geoip на ip-api.com) больше не
//         выносят вердикт о живости узла;
//  HC-2 — расширению известны ВСЕ поля probe.Options хоста
//         (httpRetries, dial/tcp/quic/http/geoIp таймауты), и оно их
//         наконец передаёт вместо работы на дефолтах.
import {
  isVerdictStage, buildProbeOpts, probeWatchdogMs, fitTargetsToBudget,
  worstCasePerNodeMs, GEOIP_MAX_TARGETS, VERDICT_STAGES, PROBE_MSG_BYTE_BUDGET
} from "./lib/probe-opts.js";
import {
  DPI_PRESETS, DPI_DEFAULT_PORT, FLICKER_DPI_PORT, DPI_PROBE_URL,
  resolveDpiPort,   // FIX(5.5.9): локальный DPI не встаёт на порт native host
  DPI_PROBE_TIMEOUT_MS, buildDpiCommand, buildServiceInstall, validateDpiArgs,
  describeDpi,
  GOODBYEDPI_PRESETS, buildGoodbyeDpiCommand, buildGoodbyeDpiServiceInstall,
  buildGoodbyeDpiBlacklistBat, validateGoodbyeDpiArgs, describeGoodbyeDpi
} from "./lib/dpi.js";

const NATIVE_HOST_NAME = "com.flicker.vpn";
const SOCKS_HOST = "127.0.0.1";
const BLOCK_PORT = 59999; // закрытый порт вне restricted-списка Firefox (9 запрещён)
// FIX(5.5.5): версия бралась из зашитой константы и разошлась с manifest.json
// (5.5.0 против 5.5.4). Теперь версия всегда из манифеста, константа — только
// fallback.
//
// FIX(5.5.6), уточнение по разбору flicker-host.exe: прежний комментарий
// утверждал, что хост «по extVersion решает, какое поведение включить».
// Это не так, и повышение версии расширения безопасно:
//   • `hello` с полем caps приходит от хоста ПЕРЕД нашим `announce`, то есть
//     caps физически не могут зависеть от extVersion — хост её ещё не знает;
//   • строка "5.5.4" встречается в бинарнике ровно один раз и лежит в одном
//     кластере с hello/stats/alive/stage — это собственная версия хоста;
//   • функций сравнения версий в бинарнике нет (ни semver, ни CompareVersion,
//     ни versionLess — проверено по таблице символов);
//   • `ExtVersion json:"extVersion,omitempty"` — поле записи announce: хост его
//     хранит и отдаёт обратно (flicker-announce.json), а не сопоставляет.
// Версия по-прежнему уходит в announce — но как диагностика, не как гейт.
const VERSION_FALLBACK = "5.5.4";
const VERSION = (() => {
  try {
    const v = globalThis.browser?.runtime?.getManifest?.().version;
    return typeof v === "string" && v ? v : VERSION_FALLBACK;
  } catch { return VERSION_FALLBACK; }
})();

const STATE = {
  status: "disconnected", // disconnected | connecting | connected
  currentServer: null,
  currentProtocol: null,
  bytesSent: 0,
  bytesReceived: 0,
  currentSpeed: 0,
  lastSpeedSample: 0,
  nativePort: null,
  nativeOnline: false,
  nativeInfo: null,
  reconnectTimer: null,
  connectWatchdog: null,
  startAckResolver: null,
  proxyEnabled: false,
  proxyMode: "off",
  killSwitchEnabled: false,
  killSwitchBlocked: false,
  splitTunneling: false,
  excludedDomains: [],
  socksPort: 1080,
  autoSelectEnabled: false,
  hideDead: true,          // скрывать недоступные серверы в UI
  autoRefresh: true,       // авто-обновление пингов по расписанию
  lastRefreshAt: null,
  advanced: {},
  experimentalUdp: false,   // показывать/парсить Hysteria 2 (запасной UDP-стек)
  stats: { startedAt: null, droppedPackets: 0, rtt: 0, connectionQuality: "unknown" },
  serverPings: new Map(),
  pingWaiters: new Map(),

  // ---- подписки и автопоиск серверов (задачи 1, 3, 5) ----
  subscriptions: [],          // нормализованные источники (встроенные + свои)
  subsBootstrapped: false,    // первичная автозагрузка выполнена
  probe: {                    // состояние активного/последнего прогона проверок
    active: false, requestId: null, mode: null, pass: 0,
    total: 0, done: 0, alive: 0, startedAt: null, finishedAt: null,
    results: new Map()        // id -> последний Result из probeDone
  },
  probeTargets: new Map(),    // id -> server, участвующий в активном прогоне
  probeWatchdog: null,        // таймаут зависшей пробы
  autoSwitchEnabled: true,    // автопереключение с мёртвого текущего сервера
  probePasses: 2,             // сколько прогонов в цикле проверки (2 = ТЗ, 3 = усиленный фильтр)

  // ---- FIX(5.5.5): отбор нод по эффективности, а не по факту ответа ----
  // Потолок задержки: узел медленнее — не «живой сервер», а мусор. Уходит в
  // постоянный блок и больше не появляется в списке (даже из свежей подписки).
  maxPingMs: DEFAULT_MAX_PING_MS,
  blocklist: null,            // makeBlocklist() — реестр вердиктов
  blockedTotal: 0,            // сколько узлов в блоке (для UI)

  // ---- v5: рейтинг нод и маршрутизация ----
  rating: null,               // makeRatingStore() — история замеров по каждой ноде
  session: { serverId: null, startedAt: null, connectedAt: null,
             bytesSentAtStart: 0, bytesReceivedAtStart: 0, lastMbps: null, lastRtt: null },
  nativeVerified: false,      // хост ответил "hello" (nativeOnline — лишь «порт открыт»)
  nativeCaps: new Set(),      // возможности, объявленные хостом в hello
  nativeCompat: "ok",         // "old": hello от хоста 4.x (нет diagnose/announce/probe)
  resumeServerId: null,       // 5.5.4: намерение поднять туннель заново после смерти хоста
  autoRecoverAttempts: 0,     // 5.5.4: подряд идущие автопереключения (сброс на connected)
  nativeLastError: null,      // текст последней ошибки порта — для диагностики
  lastProxyError: null,       // последняя ошибка от browser.proxy.onError
  lastProxyErrorToastAt: 0,

  // ---- failsafe: прокси не вооружается вслепую (v5.3) ----
  proxyArmed: false,          // прокси ДЕЙСТВИТЕЛЬНО перехвачен под VPN
  tunnelVerified: false,      // хост подтвердил, что SOCKS слушает и туннель жив
  proxyReleasedByUser: false, // пользователь нажал «вернуть прокси» — не перевооружаем
  lastArmedProxyValue: null,  // FIX(5.5.5): боевая настройка proxy.settings (снимок для возврата после проб)
  holdProxy: true,            // FIX(5.5.4.2): при обрыве НЕ отдавать прокси браузеру, чинить на месте
  // FIX(5.5.5): сколько держим браузер на туннеле, пока чиним. Было жёстко
  // 60 c, после чего прокси честно возвращался браузеру (= IP наружу).
  // Теперь настраивается и по умолчанию вдвое больше: за 60 c медленная
  // бесплатная нода часто не успевала подняться, и пользователь получал
  // утечку на ровном месте.
  holdMaxMs: 120_000,
  // FIX(5.5.5): память о сессии, переживающая выгрузку MV3-страницы.
  // Без неё новая страница не знала, что туннель был поднят, и сбрасывала
  // прокси «на всякий случай» — ровно тот обрыв, который мы чиним.
  sessionRestored: false,
  diagnoseResolver: null,     // ждущий ответа diagnose (для askHostDiagnose)
  probeFailStreak: 0,         // подряд проваленных контрольных запросов через SOCKS
  lastHostVerdictAt: null,    // когда хост последний раз отвечал на diagnose
  // FIX(5.5.4.3): ВЕРНУТА СЕМАНТИКА 5.4.0. В 5.5.3 появилось условие
  //   ok = (socksListening || tunnelActive) && tunnelAlive !== false
  // и хостовый контрольный dial (tunnelAlive) стал ПРИГОВОРОМ: 10 c × 3 цели
  // у хоста 5.5.4 на бесплатной ноде регулярно не успевают → расширение
  // объявляло живой туннель мёртвым, слало stop и снимало прокси. В 5.4.0
  // такого условия не было, поэтому там ничего не рвалось.
  // strictLiveness=false (по умолчанию): tunnelAlive=false — предупреждение.
  // strictLiveness=true: прежнее поведение 5.5.x.
  strictLiveness: false,
  lastSoftWarnAt: 0,
  holdSince: null,            // с какого момента держим (ограничение HOLD_MAX_MS)
  // FIX(5.5.9): удержание продлевается ПО ПРОГРЕССУ восстановления, а не
  // абсолютным таймером от первого обрыва (иначе один цикл «backoff 15→30→60 c
  // + бюджет вооружения 45 c» всегда длиннее удержания и прокси возвращался
  // браузеру прямо посреди починки).
  lastHoldProgressAt: null,   // последний РЕАЛЬНЫЙ прогресс (stats/verify-ok/новая попытка/смена ноды)
  lastArmedProxySnapshot: null, // снимок боевой настройки: удержание должно уметь включиться СНОВА
  journal: [],                // кольцо последних событий — отчёт одним кликом
  journalAt: {},              // троттлинг повторяющихся записей
  directWarnAt: null,         // не спамим предупреждением о direct-узле (null = никогда)
  probeWarnAt: null,          // не спамим «хост занят пробой» (null = никогда)
  // FIX(5.5.10): учёт «SOCKS слушает, но контрольный dial отклонён».
  // В мягком режиме одиночное tunnelAlive=false — не приговор (у хоста 5.5.4
  // liveness-обход занимает до 30 c и на медленной бесплатной ноде не
  // укладывается в свой же таймаут). НО серия отказов при НУЛЕВОМ трафике —
  // это мёртвая нода, а не «медленная».
  softDeadStreak: 0,          // сколько diagnose подряд вернули tunnelAlive=false
  softDeadSince: null,        // с какого момента эта серия идёт
  softDeadActAt: null,        // когда последний раз выносили вердикт (кулдаун)
  // FIX(5.5.11): последняя НАСТОЯЩАЯ VPN-нода (не direct/dpi). Нужна, чтобы
  // после сессии на служебной «Диагностике» старт шёл на рабочий сервер, а не
  // в автоподбор по списку, где 27 живых из 600.
  lastVpnServerId: null,
  lastStartAt: null,          // когда последний раз послали хосту start
  // FIX(5.5.12): на каком порту прокси вооружён ФАКТИЧЕСКИ. Хост при занятом
  // 1080 уходит на 1081 (autoPort) и сообщает адрес в ack.listen и
  // diagnose.listenAddr. Без сверки браузер оставался на мёртвом порту, проба
  // не проходила, и нода перезапускалась каждые 15 c.
  armedPort: null,
  lastStartServerId: null,    // какую ноду поднимали в последний раз
  lastStartVerified: false,   // подтвердился ли тот старт
  sameNodeRestarts: 0,        // подряд идущие перезапуски одной ноды без подтверждения
  lastRestartAt: null,
  unverifiedBudgets: 0,       // сколько бюджетов подтверждения подряд исчерпано без вердикта
  lastVerifiedAt: null,
  lastStatsAt: null,
  verifyFails: 0,
  lastVerifyRequestAt: 0,     // FIX(5.5.5): троттлинг diagnose-запросов
  verifyTimer: null,
  verifyRunning: false,       // FIX(5.5.5): цикл подтверждения уже идёт
  verifyProbing: false,       // FIX(5.5.12): внутри итерации цикла идёт проба (await)
  watchdogTimer: null,
  // FIX(5.5.5): восстановление не должно заканчиваться тупиком
  recovering: false,          // защита от повторного входа в recoverFromDeadTunnel
  // FIX(5.5.8): лестница эскалации восстановления. scheduleRecovery запоминал
  // id ноды в момент постановки таймера и на КАЖДОЙ попытке поднимал ОДИН И ТОТ
  // ЖЕ сервер тем же конфигом. Если ноду режет DPI или она лежит, пользователь
  // получал бесконечный «Обрыв туннеля: прокси НЕ возвращён браузеру … (до 60 c)».
  deaths: new Map(),          // serverId -> [ts] обрывов внутри DEATH_WINDOW_MS
  recoveryStage: "same",      // same | rotate | escalate
  suspectedDpi: false,        // один транспортный профиль умирает на разных нодах
  lastRecovery: null,         // {at, attempt, stage, serverId, fromId, reason}
  lastRecoveryFp: new Map(),  // serverId -> транспортный профиль на момент обрыва
  stabilityTimer: null,       // сброс лестницы после стабильной сессии
  lastSlowHintAt: 0,          // троттлинг подсказки «все ноды медленные»
  awgUnsupported: false,      // хост не объявил caps amnezia — AWG не применяется
  awgUnsupportedWarned: false,
  recoveryTimer: null,        // отложенная попытка вернуть туннель
  recoveryAttempt: 0,         // номер попытки (для backoff)

  // ---- локальный DPI-обход (ByeDPI), не требует native host ----
  tunnelKind: "native",       // "native" | "dpi"
  dpiPort: FLICKER_DPI_PORT,
  dpiPresetId: "upstream-default",
  dpiArgs: "",                // пустая строка = брать из пресета
  gdPresetId: "gdp-ru-dnsredir", // v5.5: GoodbyeDPI — официальный RU-пресет
  gdArgs: "",
  probeInProgress: false,     // идёт проверка живости локального прокси
  probeRequestSeen: false,    // proxy.onRequest реально видел probe-запрос
  probePort: null,

  ruleset: null,              // createRuleset() — что через VPN, что напрямую
  tunnelMode: DEFAULT_TUNNEL_MODE,
  perRequestProxy: false,     // работает ли browser.proxy.onRequest (иначе manual)

  // ---- защита от утечки при смене ноды ----
  switching: false,           // идёт атомарная смена сервера: proxy.settings не трогаем
  // FIX(5.5.13): ждём ли мы «disconnected» как ответ на НАШ stop в ходе смены
  // ноды. switchServer сбрасывает switching сразу, как startTunnel вернул ack
  // ({pending:true}), а ответ на stop хост присылает ПОЗЖЕ — и он заставал
  // статус без защиты: status="disconnected" → applyProxyMode → proxy=none,
  // то есть браузер уходил напрямую посреди штатной смены ноды.
  pendingStopAck: false,
  pendingStopAckAt: 0,
  // FIX(5.5.13): последнее отключение было ЯВНЫМ («Отключить»). Без этой метки
  // нельзя отличить ответ хоста на наш stop от настоящего обрыва, а чинить
  // туннель после того, как пользователь его выключил, нельзя.
  stoppedByUser: false,
  // FIX(5.5.14): что последний раз сказал хост про SOCKS-слушатель. Нужно,
  // чтобы отличать «туннель вот-вот вернётся» (держать прокси) от «слушателя
  // нет и не будет» (держать нечего, браузер надо вернуть к прямому трафику).
  lastSocksListening: null,
  lastDiagnoseAt: 0,
  lastOwnProbeOk: null,       // результат НАШЕГО контрольного запроса через SOCKS
  lastOwnProbeAt: 0,
  ownProbeInFlight: false,
  // FIX(5.5.14): что последний раз сказал хост про SOCKS-слушатель. Нужно,
  // чтобы отличать «туннель вот-вот вернётся» (держать прокси) от «слушателя
  // нет и не будет» (держать нечего, браузер надо вернуть к прямому трафику).
  lastSocksListening: null,
  lastDiagnoseAt: 0,
  lastOwnProbeOk: null,       // результат НАШЕГО контрольного запроса через SOCKS
  lastOwnProbeAt: 0,
  ownProbeInFlight: false,
  // FIX(5.5.14): что последний раз сказал хост про SOCKS-слушатель. Нужно,
  // чтобы отличать «туннель вот-вот вернётся» (держать прокси) от «слушателя
  // нет и не будет» (держать нечего, браузер надо вернуть к прямому трафику).
  lastSocksListening: null,
  lastDiagnoseAt: 0,
  lastOwnProbeOk: null,       // результат НАШЕГО контрольного запроса через SOCKS
  lastOwnProbeAt: 0,
  ownProbeInFlight: false,
  bypassSystemProxy: true     // при выключенном VPN ставить proxyType:"none", а не clear()
};

// ================= Рейтинг нод (lib/rating.js) =================
//
// Хранилище — browser.storage.local под ключом "ratings". Инжектим load/save,
// чтобы rating.js оставался чистым модулем и переехал в desktop-демон без правок.
STATE.rating = makeRatingStore({
  load: async () => (await browser.storage.local.get("ratings")).ratings || null,
  save: async (data) => { await browser.storage.local.set({ ratings: data }); },
  // потолок задержки берём из настроек в момент пересчёта, а не при создании:
  // пользователь может изменить его без перезапуска расширения
  maxRtt: () => STATE.maxPingMs || DEFAULT_MAX_PING_MS
});

// Реестр постоянных блоков. Хранится отдельно от ratings: это вердикт, а не
// статистика, и сбрасываться вместе с историей замеров он не должен.
STATE.blocklist = makeBlocklist({
  load: async () => (await browser.storage.local.get("blockedNodes")).blockedNodes || null,
  save: async (data) => { await browser.storage.local.set({ blockedNodes: data }); }
});

// Правила маршрутизации пересобираются при смене режима/списков.
STATE.ruleset = createRuleset({ mode: STATE.tunnelMode });

/** rebuildRuleset — пересобрать правила из сохранённых настроек. */
async function rebuildRuleset(patch = {}) {
  const saved = await browser.storage.local.get([
    "tunnelMode", "extraBlocked", "extraDirect", "excludedDomains"
  ]);
  const mode = patch.mode || saved.tunnelMode || STATE.tunnelMode || DEFAULT_TUNNEL_MODE;
  const excluded = (patch.excludedDomains ?? saved.excludedDomains ?? [])
    .map((d) => String(d).trim().toLowerCase())
    .filter(Boolean)
    .map((d) => (d.startsWith("!") ? d : "!" + d));   // пользовательские исключения
  STATE.tunnelMode = mode;
  STATE.ruleset = createRuleset({
    mode,
    extraBlocked: saved.extraBlocked || [],
    extraDirect: saved.extraDirect || [],
    directDomains: excluded
  });
  return STATE.ruleset;
}

// ================= Native messaging =================

function connectNative() {
  if (STATE.nativePort) return STATE.nativePort;
  try {
    const port = browser.runtime.connectNative(NATIVE_HOST_NAME);
    // Некоторые сборки Firefox возвращают null вместо исключения, если манифест
    // native host не найден. Без проверки дальше падал TypeError
    // «Cannot set properties of null» — он тонул в catch и выглядел как сбой
    // native messaging, а не как «хост не установлен».
    if (!port) throw new Error("native host не найден: " + NATIVE_HOST_NAME);
    port._flickerAlive = true;
    STATE.nativePort = port;
    // Порт существует, но это ещё НЕ значит, что хост установлен: Firefox
    // создаёт Port сразу, а «No such native application» прилетает позже через
    // onDisconnect. Поэтому nativeOnline = «порт открыт», а nativeVerified
    // ставится только по сообщению hello.
    STATE.nativeOnline = true;
    STATE.nativeLastError = null;
    port.onMessage.addListener(onNativeMessage);
    port.onDisconnect.addListener(() => {
      const err = port.error?.message || browser.runtime.lastError?.message || "unknown";
      console.warn("[flicker] native disconnected:", err);
      port._flickerAlive = false;
      STATE.nativePort = null;
      STATE.nativeOnline = false;
      STATE.nativeVerified = false;
      STATE.nativeLastError = err;
      // КЛЮЧЕВОЕ: снимаем ожидание ack настоящей причиной. Без этого
      // startTunnel досиживал 2.5 c и показывал generic-сообщение
      // «Native host не ответил на команду start», а реальная причина
      // (No such native application / Access forbidden / Named pipe error)
      // оставалась только в консоли.
      if (STATE.startAckResolver) {
        const r = STATE.startAckResolver;
        STATE.startAckResolver = null;
        r({ type: "__portClosed", error: err });
      }
      clearTimeout(STATE.connectWatchdog);
      if (STATE.status !== "disconnected") handleTunnelLost("native host отключён: " + err);
      // активная проба умерла вместе с хостом — освобождаем состояние,
      // иначе STATE.probe.active навсегда заблокирует новые проверки
      abortActiveProbe("native host отключён во время проверки");
      broadcastUI({ type: "nativeStatus", online: false, verified: false, error: err });
      scheduleNativeReconnect();
    });
    console.log("[flicker] native port opened");
    broadcastUI({ type: "nativeStatus", online: true });
  } catch (e) {
    console.error("[flicker] native connect failed:", e);
    STATE.nativePort = null;
    STATE.nativeOnline = false;
    STATE.nativeVerified = false;
    STATE.nativeLastError = String(e?.message || e);
  }
  return STATE.nativePort;
}

// Экспоненциальный реконнект к native host (после краха/перезапуска хоста)
function scheduleNativeReconnect() {
  if (STATE.reconnectTimer) return;
  const delays = [1500, 3000, 6000, 12000, 20000];
  let i = 0;
  const tick = () => {
    STATE.reconnectTimer = null;
    if (STATE.nativePort || STATE.nativeOnline) return;
    connectNative();
    if (!STATE.nativePort && i < delays.length) {
      STATE.reconnectTimer = setTimeout(tick, delays[i++]);
    }
  };
  STATE.reconnectTimer = setTimeout(tick, delays[i++]);
}

function onNativeMessage(msg) {
  // ack для startTunnel: любой ответ хоста снимает ожидание
  if (STATE.startAckResolver) {
    const r = STATE.startAckResolver;
    STATE.startAckResolver = null;
    r(msg);
  }
  switch (msg.type) {
    case "hello": {
      STATE.nativeOnline = true;
      STATE.nativeVerified = true;
      STATE.nativeLastError = null;
      // возможности хоста: без явного объявления новые поля конфига НЕ шлём
      // (см. composeConfig). С 5.5.3 хост объявляет caps: ack/autoPort/liveness…
      STATE.nativeCaps = new Set(Array.isArray(msg.caps) ? msg.caps : []);
      // FIX(5.5.9): версия и возможности хоста пишутся в журнал — именно их
      // не хватало, чтобы понять, почему обрыв повторяется
      journal("host-hello", `host ${msg.version || "?"} caps=[${[...STATE.nativeCaps].join(",")}] drivers=[${(msg.drivers || []).join(",")}]`);
      markHoldProgress("native host ответил hello");
      // Версионный гейт: хост 4.x не знает announce/diagnose/probeServers —
      // работа с ним выглядела как «Туннель не подтверждён»/«неизвестная
      // команда». Не молчим, а прямо говорим, что переустановить.
      const hv = String(msg.version || "");
      const hMajor = parseInt(hv.split(".")[0], 10);
      STATE.nativeCompat = (hv && !Number.isNaN(hMajor) && hMajor < 5) ? "old" : "ok";
      STATE.nativeInfo = {
        version: msg.version, drivers: msg.drivers || [], caps: [...STATE.nativeCaps],
        compat: STATE.nativeCompat
      };
      if (STATE.nativeCompat === "old") {
        STATE.nativeLastError = hostOutdatedError(hv);
        broadcastUI({ type: "error", message: STATE.nativeLastError });
        broadcastUI({ type: "nativeStatus", online: true, verified: true, oldHost: true, info: STATE.nativeInfo });
        break;
      }
      // сообщаем хосту собственный URL — используется диагностикой и live-тестами
      sendToNative({
        command: "announce",
        url: browser.runtime.getURL("popup.html"),
        extVersion: VERSION
      });
      broadcastUI({ type: "nativeStatus", online: true, verified: true, info: STATE.nativeInfo });
      // 5.5.4: хост перезапустился (краш/антивирус) — если туннель был потерян
      // не по воле пользователя и kill switch не блокирует, поднимаем заново.
      if (STATE.resumeServerId && STATE.status === "disconnected" && !STATE.killSwitchBlocked) {
        const rid = STATE.resumeServerId;
        STATE.resumeServerId = null;
        getServers().then((list) => {
          const srv = list.find((s) => s.id === rid);
          // FIX(5.5.11): служебный direct-узел («Диагностика») VPN не является,
          // поднимать его «вместо туннеля» после перезапуска хоста нельзя —
          // пользователь получит CONNECTED без VPN. Идём общим путём
          // восстановления: оно выберет настоящую ноду.
          if (srv && srv.protocol === "direct") {
            journal("direct", `resume после hello: пропущен ${srv.id} (direct) — это не VPN`);
            broadcastUI({
              type: "error",
              message: "Восстановление: служебный узел «Диагностика (direct)» пропущен — это не VPN. Подбираю настоящую ноду."
            });
            scheduleRecovery("resume после hello: direct-узел не является VPN");
            return;
          }
          if (srv && STATE.status === "disconnected") {
            notify("FLICKER VPN", "Хост снова на связи — восстанавливаю туннель…");
            clearRecovery();     // FIX(5.5.5): hello опередил таймер — дубль не нужен
            startTunnel(srv).catch((e) => {
              console.warn("[flicker] resume fail:", e);
              scheduleRecovery("resume после hello не удался");
            });
          }
        }).catch(() => {});
      }
      break;
    }

    case "ack": {
      // 5.5.3: хост подтвердил start и сообщил фактический listen.
      // autoPort: если 1080 был занят, хост сдвинулся — вооружаем браузер
      // на правильный порт, иначе прокси уходил бы в мёртвый 1080.
      // FIX(5.5.12): listen из ack — источник правды о порте. Раньше сдвиг
      // только запоминался, а браузер оставался вооружён на мёртвый порт
      // (см. reconcileSocksPort).
      {
        const p = parseListenPort(msg.listen);
        if (p) {
          reconcileSocksPort(p, "ack")
            .catch((e) => console.warn("[flicker] reconcile ack:", e?.message || e));
        }
      }
      break;
    }

    case "status": {
      clearTimeout(STATE.connectWatchdog);
      if (msg.status === "connected") {
        if (STATE.status === "disconnected" && !STATE.switching) {
          // 5.5.3: запоздалый «connected» — watchdog/пользователь уже решили,
          // что подключение не состоялось. Гасим зомби-туннель: иначе он
          // держит SOCKS, а следующий старт конфликтует портами.
          console.warn("[flicker] поздний connected проигнорирован — отправляю stop");
          sendToNative({ command: "stop" });
          broadcastUI({ type: "status", status: STATE.status });
          break;
        }
        STATE.status = "connected";
        STATE.holdSince = null;          // FIX(5.5.4.2): туннель вернулся — удержание снято
        STATE.resumeServerId = null;     // доехали — намерение восстановлено
        // FIX(5.5.12): счётчики восстановления на голом «connected» НЕ
        // обнуляем — хост отвечает «connected» до того, как sing-box поднимет
        // SOCKS. Обнуление переехало в handleVerifyResult(ok). Иначе backoff
        // не рос: рестарт → connected → сброс → рестарт каждые 15 c.
        clearRecoveryTimer();            // таймер больше не нужен, счётчик оставляем
        armStabilityReset();             // FIX(5.5.8): обнулим счётчики обрывов, если продержимся 2 мин
        STATE.stats.startedAt = Date.now();
        // «connected» от хоста приходит РАНЬШЕ, чем sing-box реально поднимет
        // SOCKS-слушатель. Сбрасываем подтверждение и запрашиваем его заново:
        // прокси вооружится только после ответа diagnose.
        STATE.tunnelVerified = false;
        STATE.lastStatsAt = Date.now();
        STATE.proxyReleasedByUser = false;
        scheduleVerify();
        if (STATE.session?.serverId) {
          STATE.session.connectedAt = Date.now();
          STATE.session.bytesSentAtStart = STATE.bytesSent || 0;
          STATE.session.bytesReceivedAtStart = STATE.bytesReceived || 0;
        }
        releaseKillBlock();
        applyProxyMode();
        notify("FLICKER VPN", "Соединение установлено");
      } else if (msg.status === "connecting") {
        STATE.status = "connecting";
      } else {
        // FIX(5.5.13): ответ на НАШ stop в ходе смены ноды. Он штатно приходит
        // ПОСЛЕ того, как switching сброшен (startTunnel вернул {pending:true}),
        // и до 5.5.13 делал две беды:
        //   • status="connecting" → "disconnected" → applyProxyMode() → hold не
        //     положен (смена штатная: ни resumeServerId, ни recoveryTimer) →
        //     setProxyNone() → браузер ушёл напрямую посреди смены;
        //   • если новый туннель уже успел ответить «connected», то срабатывал
        //     handleTunnelLost("туннель закрыт") → свежий туннель объявлялся
        //     оборванным: минус в рейтинг, HOLD, восстановление.
        // В дампе пользователя это строки «dbg: proxy=none» в 14:00:04,
        // 14:01:42 и 14:02:17 — по одной почти на каждое переключение ноды.
        if (STATE.pendingStopAck && isStamp(STATE.pendingStopAckAt) &&
            (Date.now() - STATE.pendingStopAckAt) <= SWITCH_STOP_ACK_MS) {
          STATE.pendingStopAck = false;   // метка одноразовая: потреблена
          journal("switch-stop-ack",
            "ответ хоста на наш stop во время смены ноды проигнорирован: статус и прокси не тронуты");
          dbgNative({
            command: "dbg",
            text: "stop-ack: ответ на stop при смене ноды — статус " + STATE.status + ", прокси не трогаю"
          });
          broadcastUI({ type: "status", status: STATE.status });
          break;
        }
        // во время атомарной смены ноды «disconnected» от хоста — это ожидаемый
        // ответ на наш stop, а не обрыв; kill switch включать нельзя
        if (STATE.status === "connected" && !STATE.switching) {
          handleTunnelLost(msg.reason || "туннель закрыт");
        }
        if (!STATE.switching) STATE.status = "disconnected";
        STATE.stats.startedAt = null;
        // FIX(5.5.13): тупик. Хост сообщил «disconnected», когда мы уже не
        // «connected» (рукопожатие не состоялось): handleTunnelLost не вызван,
        // намерения и таймера нет, watchdog молчит — прокси уходил браузеру
        // НАВСЕГДА. Ставим восстановление ДО applyProxyMode, чтобы прокси
        // остался в HOLD, а не уехал в none.
        if (!STATE.switching && !STATE.stoppedByUser && !STATE.recoveryTimer &&
            !STATE.recovering && STATE.tunnelMode !== TUNNEL_MODES.OFF) {
          const scheduled = scheduleRecovery("хост сообщил disconnected (статус " +
            (msg.status || "?") + ")");
          if (scheduled) {
            journal("host-disconnect-recovery",
              "хост опустил туннель вне обрыва — восстановление запланировано, прокси держим");
          }
        }
        applyProxyMode();
      }
      broadcastUI({ type: "status", status: STATE.status });
      persistSession();      // FIX(5.5.5): статус переживает выгрузку страницы
      break;
    }

    case "stats":
      // FIX(5.5.9): stats от хоста — доказательство, что туннель жив:
      // продлеваем удержание (иначе прокси возвращается посреди починки)
      if (STATE.status === "connected") markHoldProgress("stats от хоста");
      // FIX(5.5.5): heartbeat от хоста — признак, что туннель жив. Если прокси
      // при этом снят (тупик версии 5.5.4: ни одного таймера не оставалось),
      // запрашиваем подтверждение и возвращаем браузер на SOCKS5.
      if (STATE.status === "connected" && !STATE.proxyArmed &&
          !STATE.proxyReleasedByUser && !STATE.killSwitchBlocked) {
        if (!STATE.tunnelVerified) requestVerify();
        else applyProxyMode();
      }
      STATE.bytesSent = msg.bytesSent || 0;
      STATE.bytesReceived = msg.bytesReceived || 0;
      STATE.stats.rtt = msg.rtt || 0;
      STATE.stats.droppedPackets = msg.dropped || 0;
      STATE.stats.connectionQuality = assessConnectionQuality(msg.rtt || 0, msg.dropped || 0);
      updateSessionStats(STATE.bytesSent, STATE.bytesReceived, STATE.stats.rtt);
      STATE.lastStatsAt = Date.now();   // heartbeat для watchdog
      STATE.verifyFails = 0;
      break;

    case "ping": {
      const waiter = STATE.pingWaiters.get(msg.serverId);
      if (waiter) {
        STATE.pingWaiters.delete(msg.serverId);
        waiter(msg.latency);
      }
      STATE.serverPings.set(msg.serverId, msg.latency);
      break;
    }

    case "probeResult":
      onProbeStage(msg);
      break;

    case "probeDone":
      // обработка асинхронная — не блокируем NM-цикл
      onProbeDone(msg).catch((e) => console.error("[flicker] probeDone:", e));
      break;

    case "openUiTab":
      // диагностический канал: хост просит открыть UI-вкладку (используется
      // live-тестами и утилитой flicker-ctl; в обычной работе не применяется)
      try {
        browser.tabs.create({ url: browser.runtime.getURL("popup.html") });
      } catch (e) {
        console.error("[flicker] openUiTab:", e);
      }
      break;

    case "diagnose": {
      STATE.nativeInfo = { ...(STATE.nativeInfo || {}), diagnose: msg };
      STATE.lastHostVerdictAt = Date.now();
      // FIX(5.5.5): снимаем ожидание askHostDiagnose() — ответ хоста и есть
      // источник правды о ЛОКАЛЬНОМ конце туннеля.
      if (STATE.diagnoseResolver) {
        const r = STATE.diagnoseResolver;
        STATE.diagnoseResolver = null;
        r(msg.data || msg);
      }
      // v5.3: ответ diagnose — источник правды о живости туннеля.
      // Хост отдаёт { tunnelActive, driver, socksListening, listenAddr, ... }.
      const d = msg.data || msg;
      // FIX(5.5.12): diagnose приходит чаще, чем ack, и тоже несет фактический
      // listenAddr. Сверяем порт ЗДЕСЬ и до вердикта о живости: иначе проба,
      // ушедшая на старый порт, объявляла мёртвым живой туннель.
      {
        const lp = parseListenPort(d && d.listenAddr);
        if (lp) {
          reconcileSocksPort(lp, "diagnose")
            .catch((e) => console.warn("[flicker] reconcile diagnose:", e?.message || e));
        }
      }
      // FIX(5.5.4.3): базовое подтверждение — как в 5.4.0: SOCKS слушает или
      // туннель активен. Контрольный dial хоста (tunnelAlive) в мягком режиме
      // приговором НЕ является: он слишком часто не укладывается в свой же
      // таймаут на медленных нодах, а рвёт из-за этого perfectly рабочий туннель.
      // FIX(5.5.14): запоминаем, что хост сказал про слушатель, — по этому
      // признаку endpointDead() отличает «туннель вот-вот вернётся» от
      // «держать нечего».
      if (d && typeof d.socksListening === "boolean") {
        STATE.lastSocksListening = d.socksListening;
        STATE.lastDiagnoseAt = Date.now();
      }
      // FIX(5.5.14): запоминаем, что хост сказал про слушатель, — по этому
      // признаку endpointDead() отличает «туннель вот-вот вернётся» от
      // «держать нечего».
      if (d && typeof d.socksListening === "boolean") {
        STATE.lastSocksListening = d.socksListening;
        STATE.lastDiagnoseAt = Date.now();
      }
      // FIX(5.5.14): запоминаем, что хост сказал про слушатель, — по этому
      // признаку endpointDead() отличает «туннель вот-вот вернётся» от
      // «держать нечего».
      if (d && typeof d.socksListening === "boolean") {
        STATE.lastSocksListening = d.socksListening;
        STATE.lastDiagnoseAt = Date.now();
      }
      const baseOk = !!(d && (d.socksListening === true || d.tunnelActive === true));
      const ok = STATE.strictLiveness ? (baseOk && d.tunnelAlive !== false) : baseOk;
      // FIX(5.5.10): в логе пользователя эта ветка 8 минут подряд писала
      // «tunnelAlive=false проигнорирован (SOCKS слушает)» при «Передано ↑0.00
      // ↓0.00» и «socks5: connect отклонён (код 0x1)». То есть туннеля не было
      // вовсе, а расширение показывало CONNECTED. Одиночный отказ по-прежнему
      // игнорируем (медленная нода), но серию отказов при НУЛЕВОМ трафике
      // считаем смертью ноды и уходим с неё.
      let softDeadHandled = false;
      if (baseOk && d && d.tunnelAlive === false && !STATE.strictLiveness) {
        const v = softLivenessNote();
        const now = Date.now();
        const cooled = STATE.softDeadActAt == null || now - STATE.softDeadActAt > SOFT_DEAD_COOLDOWN_MS;
        // FIX(5.5.14): второй независимый арбитр. Отдельный блок, а не звено
        // цепочки ниже: предупреждение в UI («dial не прошёл, но SOCKS слушает»)
        // должно остаться в любом случае.
        if (!v.dead && !STATE.ownProbeInFlight && !STATE.verifyProbing &&
            STATE.status === "connected" && STATE.tunnelKind !== "dpi" &&
            !isLocalTransport(STATE.currentServer)) {
          // Хост говорит «dial отклонён», но его одного мало: медленная нода не
          // укладывается в свой же таймаут (поэтому прежнее правило и было
          // мягким). Гоняем СОБСТВЕННЫЙ контрольный запрос через SOCKS:
          //   • прошёл    → нода рабочая, dial хоста игнорируем и пишем об этом;
          //   • не прошёл → два независимых подтверждения: нода мёртвая,
          //     лестница уходит на другую, не дожидаясь 45 c и «нулевого трафика».
          //     Прежнее правило на практике не срабатывало никогда: серия
          //     обнуляется при каждой смене ноды, а «нулевого трафика» не бывает —
          //     контрольные запросы расширения сами идут через туннель (в отчёте
          //     «Передано ↑0.00 ↓0.00 MB», но «трафик есть»).
          STATE.ownProbeInFlight = true;
          const portProbed = STATE.socksPort;
          const streakAtProbe = v.streak;
          probeThroughProxy(portProbed)
            .catch((e) => ({ ok: false, error: String(e?.message || e) }))
            .then((pr) => {
              STATE.ownProbeInFlight = false;
              STATE.lastOwnProbeOk = !!pr.ok;
              STATE.lastOwnProbeAt = Date.now();
              if (pr.ok) {
                dbgNative({
                  command: "dbg",
                  text: "soft liveness: dial хоста не прошёл, но контрольный запрос браузера через SOCKS прошёл — нода рабочая"
                });
                return;
              }
              // вердикт устарел: порт сдвинулся (autoPort), статус сменился,
              // пользователь уже ушёл на другую ноду
              if (portProbed !== STATE.socksPort || STATE.status !== "connected") return;
              if (isLocalTransport(STATE.currentServer)) return;
              declareSoftDead(
                `узел не пропускает трафик: контрольный dial хоста отклонён (${streakAtProbe}-й раз) ` +
                `И контрольный запрос браузера через SOCKS не прошёл: ${pr.error || "нет ответа"}`);
            });
        }
        // FIX(5.5.14): вердикт выносится общей функцией (см. declareSoftDead).
        // FIX(5.5.14): второй независимый арбитр. Отдельный блок, а не звено
        // цепочки ниже: предупреждение в UI («dial не прошёл, но SOCKS слушает»)
        // должно остаться в любом случае.
        if (!v.dead && !STATE.ownProbeInFlight && !STATE.verifyProbing &&
            STATE.status === "connected" && STATE.tunnelKind !== "dpi" &&
            !isLocalTransport(STATE.currentServer)) {
          // Хост говорит «dial отклонён», но его одного мало: медленная нода не
          // укладывается в свой же таймаут (поэтому прежнее правило и было
          // мягким). Гоняем СОБСТВЕННЫЙ контрольный запрос через SOCKS:
          //   • прошёл    → нода рабочая, dial хоста игнорируем и пишем об этом;
          //   • не прошёл → два независимых подтверждения: нода мёртвая,
          //     лестница уходит на другую, не дожидаясь 45 c и «нулевого трафика».
          //     Прежнее правило на практике не срабатывало никогда: серия
          //     обнуляется при каждой смене ноды, а «нулевого трафика» не бывает —
          //     контрольные запросы расширения сами идут через туннель (в отчёте
          //     «Передано ↑0.00 ↓0.00 MB», но «трафик есть»).
          STATE.ownProbeInFlight = true;
          const portProbed = STATE.socksPort;
          const streakAtProbe = v.streak;
          probeThroughProxy(portProbed)
            .catch((e) => ({ ok: false, error: String(e?.message || e) }))
            .then((pr) => {
              STATE.ownProbeInFlight = false;
              STATE.lastOwnProbeOk = !!pr.ok;
              STATE.lastOwnProbeAt = Date.now();
              if (pr.ok) {
                dbgNative({
                  command: "dbg",
                  text: "soft liveness: dial хоста не прошёл, но контрольный запрос браузера через SOCKS прошёл — нода рабочая"
                });
                return;
              }
              // вердикт устарел: порт сдвинулся (autoPort), статус сменился,
              // пользователь уже ушёл на другую ноду
              if (portProbed !== STATE.socksPort || STATE.status !== "connected") return;
              if (isLocalTransport(STATE.currentServer)) return;
              declareSoftDead(
                `узел не пропускает трафик: контрольный dial хоста отклонён (${streakAtProbe}-й раз) ` +
                `И контрольный запрос браузера через SOCKS не прошёл: ${pr.error || "нет ответа"}`);
            });
        }
        // FIX(5.5.14): вердикт выносится общей функцией (см. declareSoftDead).
        // FIX(5.5.14): второй независимый арбитр. Отдельный блок, а не звено
        // цепочки ниже: предупреждение в UI («dial не прошёл, но SOCKS слушает»)
        // должно остаться в любом случае.
        if (!v.dead && !STATE.ownProbeInFlight && !STATE.verifyProbing &&
            STATE.status === "connected" && STATE.tunnelKind !== "dpi" &&
            !isLocalTransport(STATE.currentServer)) {
          // Хост говорит «dial отклонён», но его одного мало: медленная нода не
          // укладывается в свой же таймаут (поэтому прежнее правило и было
          // мягким). Гоняем СОБСТВЕННЫЙ контрольный запрос через SOCKS:
          //   • прошёл    → нода рабочая, dial хоста игнорируем и пишем об этом;
          //   • не прошёл → два независимых подтверждения: нода мёртвая,
          //     лестница уходит на другую, не дожидаясь 45 c и «нулевого трафика».
          //     Прежнее правило на практике не срабатывало никогда: серия
          //     обнуляется при каждой смене ноды, а «нулевого трафика» не бывает —
          //     контрольные запросы расширения сами идут через туннель (в отчёте
          //     «Передано ↑0.00 ↓0.00 MB», но «трафик есть»).
          STATE.ownProbeInFlight = true;
          const portProbed = STATE.socksPort;
          const streakAtProbe = v.streak;
          probeThroughProxy(portProbed)
            .catch((e) => ({ ok: false, error: String(e?.message || e) }))
            .then((pr) => {
              STATE.ownProbeInFlight = false;
              STATE.lastOwnProbeOk = !!pr.ok;
              STATE.lastOwnProbeAt = Date.now();
              if (pr.ok) {
                dbgNative({
                  command: "dbg",
                  text: "soft liveness: dial хоста не прошёл, но контрольный запрос браузера через SOCKS прошёл — нода рабочая"
                });
                return;
              }
              // вердикт устарел: порт сдвинулся (autoPort), статус сменился,
              // пользователь уже ушёл на другую ноду
              if (portProbed !== STATE.socksPort || STATE.status !== "connected") return;
              if (isLocalTransport(STATE.currentServer)) return;
              declareSoftDead(
                `узел не пропускает трафик: контрольный dial хоста отклонён (${streakAtProbe}-й раз) ` +
                `И контрольный запрос браузера через SOCKS не прошёл: ${pr.error || "нет ответа"}`);
            });
        }
        // FIX(5.5.14): вердикт выносится общей функцией (см. declareSoftDead).
        if (v.dead && cooled) {
          softDeadHandled = declareSoftDead(
            `узел не пропускает трафик: контрольный dial через туннель отклонён ` +
            `${v.streak} раз подряд за ${Math.round(v.durMs / 1000)} c, передано 0 байт`);
        } else if (now - (STATE.lastSoftWarnAt || 0) > 60_000) {
          STATE.lastSoftWarnAt = now;
          console.warn("[flicker] хост: tunnelAlive=false, но SOCKS слушает — в мягком режиме продолжаю работать" +
                       (v.streak > 1 ? ` (подряд ${v.streak}, трафик ${v.noTraffic ? "нулевой" : "идёт"})` : ""));
          dbgNative({ command: "dbg", text: `soft liveness: tunnelAlive=false проигнорирован (SOCKS слушает, подряд ${v.streak}, трафик ${v.noTraffic ? "0" : "есть"})` });
          broadcastUI({
            type: "livenessWarn",
            message: v.noTraffic
              ? `Хост не проходит контрольную проверку через туннель (подряд ${v.streak}) и трафика пока НОЛЬ. ` +
                "Жду подтверждения; если так продолжится — сочту ноду мёртвой и сменю её. Строгий режим: настройки расширения."
              : "Хост не прошёл свою контрольную проверку через туннель (tunnelAlive=false), " +
                "но SOCKS слушает и трафик идёт — продолжаю работать. Строгий режим: настройки расширения."
          });
        }
      } else if (baseOk) {
        // dial прошёл — серия обнуляется, прежнее мягкое поведение сохранено
        softLivenessReset();
      }
      if (!softDeadHandled) handleVerifyResult(ok, d);
      broadcastUI({ type: "diagnose", data: msg.data || msg });
      break;
    }

    case "error": {
      console.error("[flicker] native error:", msg.message);
      // задача 7: показываем человеческое сообщение, а не стектрейс драйвера
      const human = humanizeTunnelError(msg.message, STATE.currentServer || undefined);
      broadcastUI({ type: "error", message: human, raw: String(msg.message || "").slice(0, 300) });
      if (STATE.status === "connecting") {
        STATE.status = "disconnected";
        handleTunnelLost(human);
      }
      break;
    }
  }
}

// dbg без реконнекта: не будит хост ради отладочной строки
function dbgNative(payload) {
  const p = STATE.nativePort;
  if (p && p._flickerAlive !== false) {
    try { p.postMessage(payload); } catch (e) { /* ignore */ }
  }
}

function sendToNative(payload) {
  let port = STATE.nativePort;
  if (!port || port._flickerAlive === false) port = connectNative();
  if (!port || port._flickerAlive === false) return false;
  try {
    port.postMessage(payload);
    return true;
  } catch (e) {
    console.error("[flicker] postMessage failed:", e);
    port._flickerAlive = false;
    STATE.nativePort = null;
    STATE.nativeOnline = false;
    return false;
  }
}

// ================= Proxy (manual socks5 / kill switch / off) =================

/**
 * applyProxyMode — применить маршрутизацию браузера к текущему состоянию.
 *
 * ИСПРАВЛЕНО (v5), три бага версии 4.0.x:
 *
 * 1. УТЕЧКА В СИСТЕМНЫЙ ПРОКСИ. При отключении и при смене сервера вызывался
 *    browser.proxy.settings.clear({}), а по MDN proxyType по умолчанию —
 *    "system", т.е. Firefox уходил в прокси операционной системы. Если в ОС
 *    задан HTTP-прокси (корпоративный, или leftover от другого VPN-клиента),
 *    весь трафик в это окно шёл через него в открытом виде. Теперь clear()
 *    не вызывается никогда: при выключенном туннеле ставим proxyType:"none"
 *    (напрямую, минуя системный прокси). Поведение "вернуть системный прокси"
 *    доступно тумблером bypassSystemProxy=false.
 *
 * 2. НЕАТОМАРНАЯ СМЕНА СЕРВЕРА. Переключение требовало disconnect → connect,
 *    и между ними маршрутизация снималась. Теперь во время STATE.switching
 *    эта функция не делает НИЧЕГО — окно утечки закрыто.
 *
 * 3. nonProxyHosts → passthrough. Свойство nonProxyHosts принадлежит Chrome;
 *    в Firefox список исключений называется passthrough (строка через запятую,
 *    поддерживает HOST, HOST:PORT, IP/PREFIX и <local>). Firefox молча
 *    игнорировал неизвестный ключ, поэтому «Исключения для доменов (мимо VPN)»
 *    в manual-режиме не работали вообще.
 */
// FIX(5.5.5): applyProxyMode вызывается из десятка мест БЕЗ await
// (onNativeMessage, handleVerifyResult, watchdog, сообщения из UI). Два
// параллельных вызова переставляли proxy.settings в произвольном порядке:
// ветка «pending-verify» доезжала ПОСЛЕ вооружения и затирала proxyMode и
// снимок боевой настройки, хотя прокси оставался вооружён. Watchdog после
// этого видел «не подтверждено» и снимал прокси с живого туннеля — ровно то
// самое «Туннель не работает — прокси возвращён браузеру».
// Теперь все применения маршрутизации идут строго очередью.
/**
 * buildManualValue — боевая manual-настройка прокси под текущий режим и списки.
 *
 * FIX(5.5.5): вынесено из applyProxyModeNow, потому что тот же самый расчёт
 * нужен пробе живости. Раньше проба собирала СВОЙ manual с passthrough только
 * для localhost и на время проверки теряла split-tunneling (~200 RU-доменов и
 * CIDR уезжали в VPN), а в per-request режиме и вовсе ставила proxyType:"system"
 * — то есть выпускала весь трафик напрямую.
 *
 * @param {object} [rs] ruleset (по умолчанию STATE.ruleset)
 * @returns {{value:object, count:number, truncated:boolean, effectiveMode:string}}
 */
function buildManualValue(rs = STATE.ruleset) {
  // Режим "blocked" без proxy.onRequest (не-Firefox или слушатель не
  // зарегистрировался) выразить нельзя — вырождаемся в "all", иначе
  // заблокированное ушло бы напрямую.
  const effectiveMode = rs.mode === TUNNEL_MODES.BLOCKED_ONLY ? TUNNEL_MODES.ALL : rs.mode;
  const rsForPass = effectiveMode === rs.mode ? rs : createRuleset({ mode: effectiveMode });
  const pass = toPassthrough(rsForPass, STATE.splitTunneling ? STATE.excludedDomains : []);
  return {
    value: {
      proxyType: "manual",
      socks: SOCKS_HOST,
      socksPort: activeProxyPort(),
      socksVersion: 5,
      proxyDNS: true,
      passthrough: pass.value
    },
    count: pass.count,
    truncated: pass.truncated,
    effectiveMode
  };
}

let proxyApplyChain = Promise.resolve();

/**
 * enqueueProxyApply (FIX 5.5.12) — поставить операцию над proxy.settings в ту
 * же очередь, в которой живёт applyProxyMode. Иначе перевооружение на новый
 * порт могло разминуться с applyProxyModeNow, и последнее слово осталось бы за
 * настройкой с мёртвым портом.
 */
function enqueueProxyApply(fn) {
  const run = proxyApplyChain.then(fn, fn).then(() => persistSession(), () => persistSession());
  proxyApplyChain = run.then(() => {}, () => {});
  return run;
}

function applyProxyMode() {
  // FIX(5.5.5): каждое изменение маршрутизации фиксируется в storage.session —
  // это единственная память, которая переживает выгрузку MV3-страницы (RC-1).
  return enqueueProxyApply(applyProxyModeNow);
}

/** parseListenPort — «127.0.0.1:1081» → 1081 (null, если не разобралось). */
function parseListenPort(addr) {
  if (addr == null || addr === "") return null;
  if (Number.isInteger(addr)) return addr > 0 && addr <= 65535 ? addr : null;
  const p = Number(String(addr).trim().split(":").pop());
  return Number.isInteger(p) && p > 0 && p <= 65535 ? p : null;
}

/**
 * reconcileSocksPort (FIX 5.5.12) — хост сказал, что SOCKS слушает НЕ там,
 * куда вооружён браузер (autoPort: 1080 был занят, хост ушёл на 1081).
 *
 * До 5.5.12 расширение только запоминало новый порт, а браузер продолжал
 * слать трафик на старый: контрольный запрос шёл в никуда, цикл подтверждения
 * объявлял «туннель больше не подтверждён», прокси освобождался, и нода
 * перезапускалась каждые 15 c. Теперь сдвиг порта:
 *   • сразу перевооружает прокси на фактический порт (без снятия и HOLD);
 *   • обнуляет счётчик неудач подтверждения — прежние были про мёртвый порт;
 *   • засчитывается как прогресс удержания (HOLD не истекает посреди починки).
 *
 * @param {number|string} port фактический порт/адрес от хоста
 * @param {string} via        откуда узнали («ack» | «diagnose»)
 * @returns {Promise<boolean>} true, если порт действительно уточнён
 */
async function reconcileSocksPort(port, via) {
  const p = parseListenPort(port);
  if (!p) return false;
  const wrongArmed = !!STATE.proxyArmed && STATE.armedPort != null &&
    Number(STATE.armedPort) !== p;
  if (p === STATE.socksPort && !wrongArmed) return false;

  const oldSock = STATE.socksPort;
  const oldArmed = STATE.armedPort;
  STATE.socksPort = p;
  STATE.verifyFails = 0;
  broadcastUI({ type: "socksPort", port: p });
  const note = `хост слушает ${p}` +
    (oldSock !== p ? ` (STATE было ${oldSock})` : "") +
    (wrongArmed ? `, прокси был вооружён на ${oldArmed} — перевооружаю` : "") +
    ` [${via || "?"}]`;
  console.warn("[flicker] SOCKS-порт:", note);
  journal("port-shift", note);
  dbgNative({ command: "dbg", text: "port-shift: " + note });
  markHoldProgress("уточнён порт SOCKS: " + p);

  if (wrongArmed) {
    await enqueueProxyApply(async () => {
      // во время атомарной смены ноды и в режиме «Ничего» прокси не трогаем
      if (STATE.switching || STATE.tunnelMode === TUNNEL_MODES.OFF) return;
      if (!STATE.proxyArmed) return;
      const built = buildManualValue();
      await browser.proxy.settings.set({ value: built.value });
      STATE.lastArmedProxyValue = built.value;
      STATE.armedPort = Number(built.value.socksPort) || p;
      STATE.proxyMode = "socks";
      dbgNative({
        command: "dbg",
        text: `proxy=socks port=${STATE.armedPort} (перевооружено после autoPort)`
      });
    });
  } else if (STATE.proxyArmed) {
    STATE.armedPort = p;
  }
  return true;
}

async function applyProxyModeNow() {
  // Во время атомарной смены ноды маршрутизацию не трогаем: иначе между
  // stop и start образуется окно, в котором трафик уходит мимо туннеля.
  if (STATE.switching) {
    dbgNative({ command: "dbg", text: "proxy: skipped (switching)" });
    return;
  }
  try {
    // FIX(5.5.12): режим маршрутизации «Ничего» — решение пользователя, и оно
    // авторитетнее любой автоматики. До этого «off» держался только на флаге
    // proxyReleasedByUser, который сбрасывался на «connected» и при каждом
    // успешном вооружении: прокси возвращался на туннель вопреки выбору.
    if (STATE.tunnelMode === TUNNEL_MODES.OFF) {
      await setProxyNone();
      STATE.proxyEnabled = false;
      STATE.proxyArmed = false;
      STATE.armedPort = null;
      STATE.lastArmedProxyValue = null;
      STATE.holdSince = null;
      STATE.lastHoldProgressAt = null;
      clearTimeout(STATE.watchdogTimer);
      STATE.watchdogTimer = null;
      STATE.proxyMode = "off-mode";
      dbgNative({ command: "dbg", text: "proxy=none (режим маршрутизации: off)" });
      return;
    }
    if (STATE.killSwitchBlocked) {
      // Трафик отменяется per-request в webRequest.onBeforeRequest; здесь важно
      // не оставить SOCKS и не отдать браузер системному прокси.
      await setProxyNone();
      STATE.proxyEnabled = false;
      STATE.proxyArmed = false;
      STATE.lastArmedProxyValue = null;
      STATE.proxyMode = "block";
      dbgNative({ command: "dbg", text: "proxy=block(onRequest)" });
      return;
    }

    // FIX(5.5.14): локальный транспорт direct. Слушателя нет, подтверждать
    // нечего, держать нечего — прокси снимается, трафик идёт напрямую, и панель
    // говорит об этом прямо. До этой правки расширение вооружало браузер на
    // порт, где никто не слушал, и уходило в HOLD на том же мёртвом снимке:
    // в отчёте пользователя 4 минуты «connected / Прокси браузера: активен»
    // при «SOCKS5: не слушает» и полностью мёртвом браузере.
    if (STATE.tunnelKind !== "dpi" && STATE.currentServer?.protocol === "direct") {
      STATE.tunnelVerified = true;      // подтверждать нечего: туннеля нет
      clearTimeout(STATE.verifyTimer);
      STATE.verifyTimer = null;
      STATE.verifyRunning = false;
      STATE.verifyFails = 0;
      if (STATE.proxyMode === "local-direct" && !STATE.proxyArmed) return;  // уже здесь
      await setProxyNone();
      STATE.proxyEnabled = false;
      STATE.proxyArmed = false;
      STATE.armedPort = null;
      STATE.lastArmedProxyValue = null;
      STATE.holdSince = null;
      STATE.lastHoldProgressAt = null;
      STATE.proxyMode = "local-direct";
      dbgNative({
        command: "dbg",
        text: "proxy=none (локальный транспорт direct: SOCKS-слушателя нет, трафик идёт напрямую — это НЕ VPN)"
      });
      journal("local-direct",
        "прокси снят: выбран локальный транспорт direct, трафик идёт напрямую (не VPN)");
      broadcastUI({
        type: "directNode",
        message: "Выбран служебный узел «Диагностика (direct)»: трафик идёт НАПРЯМУЮ, это не VPN. " +
                 "Прокси снят, чтобы не оставлять браузер на порту без слушателя."
      });
      return;
    }

    // FIX(5.5.14): локальный транспорт direct. Слушателя нет, подтверждать
    // нечего, держать нечего — прокси снимается, трафик идёт напрямую, и панель
    // говорит об этом прямо. До этой правки расширение вооружало браузер на
    // порт, где никто не слушал, и уходило в HOLD на том же мёртвом снимке:
    // в отчёте пользователя 4 минуты «connected / Прокси браузера: активен»
    // при «SOCKS5: не слушает» и полностью мёртвом браузере.
    if (STATE.tunnelKind !== "dpi" && STATE.currentServer?.protocol === "direct") {
      STATE.tunnelVerified = true;      // подтверждать нечего: туннеля нет
      clearTimeout(STATE.verifyTimer);
      STATE.verifyTimer = null;
      STATE.verifyRunning = false;
      STATE.verifyFails = 0;
      if (STATE.proxyMode === "local-direct" && !STATE.proxyArmed) return;  // уже здесь
      await setProxyNone();
      STATE.proxyEnabled = false;
      STATE.proxyArmed = false;
      STATE.armedPort = null;
      STATE.lastArmedProxyValue = null;
      STATE.holdSince = null;
      STATE.lastHoldProgressAt = null;
      STATE.proxyMode = "local-direct";
      dbgNative({
        command: "dbg",
        text: "proxy=none (локальный транспорт direct: SOCKS-слушателя нет, трафик идёт напрямую — это НЕ VPN)"
      });
      journal("local-direct",
        "прокси снят: выбран локальный транспорт direct, трафик идёт напрямую (не VPN)");
      broadcastUI({
        type: "directNode",
        message: "Выбран служебный узел «Диагностика (direct)»: трафик идёт НАПРЯМУЮ, это не VPN. " +
                 "Прокси снят, чтобы не оставлять браузер на порту без слушателя."
      });
      return;
    }

    // FIX(5.5.14): локальный транспорт direct. Слушателя нет, подтверждать
    // нечего, держать нечего — прокси снимается, трафик идёт напрямую, и панель
    // говорит об этом прямо. До этой правки расширение вооружало браузер на
    // порт, где никто не слушал, и уходило в HOLD на том же мёртвом снимке:
    // в отчёте пользователя 4 минуты «connected / Прокси браузера: активен»
    // при «SOCKS5: не слушает» и полностью мёртвом браузере.
    if (STATE.tunnelKind !== "dpi" && STATE.currentServer?.protocol === "direct") {
      STATE.tunnelVerified = true;      // подтверждать нечего: туннеля нет
      clearTimeout(STATE.verifyTimer);
      STATE.verifyTimer = null;
      STATE.verifyRunning = false;
      STATE.verifyFails = 0;
      if (STATE.proxyMode === "local-direct" && !STATE.proxyArmed) return;  // уже здесь
      await setProxyNone();
      STATE.proxyEnabled = false;
      STATE.proxyArmed = false;
      STATE.armedPort = null;
      STATE.lastArmedProxyValue = null;
      STATE.holdSince = null;
      STATE.lastHoldProgressAt = null;
      STATE.proxyMode = "local-direct";
      dbgNative({
        command: "dbg",
        text: "proxy=none (локальный транспорт direct: SOCKS-слушателя нет, трафик идёт напрямую — это НЕ VPN)"
      });
      journal("local-direct",
        "прокси снят: выбран локальный транспорт direct, трафик идёт напрямую (не VPN)");
      broadcastUI({
        type: "directNode",
        message: "Выбран служебный узел «Диагностика (direct)»: трафик идёт НАПРЯМУЮ, это не VPN. " +
                 "Прокси снят, чтобы не оставлять браузер на порту без слушателя."
      });
      return;
    }

    if (STATE.status === "connected") {
      // FAILSAFE: не перехватываем прокси, пока native host не подтвердил, что
      // SOCKS-слушатель поднят и туннель активен. Иначе при мёртвом туннеле
      // браузер остаётся без интернета, и вернуть его можно только отключением
      // расширения (именно так и было до 5.3).
      if (!STATE.tunnelVerified) {
        // FIX(5.5.11): первые секунды после start подтверждение ещё не могло
        // прийти — это штатный выход на режим, а не обрыв. Раньше здесь сразу
        // вызывался releaseProxy() и расширение уходило в HOLD на каждом старте
        // (в отчёте пользователя: [start] → через 5 c [hold-start] → через 25 c
        // [verify-ok]). Просто ждём diagnose, прокси не трогаем.
        if (isStamp(STATE.lastStartAt) && Date.now() - STATE.lastStartAt < START_GRACE_MS &&
            !STATE.recovering && STATE.holdSince == null) {
          if (!STATE.verifyTimer && !STATE.verifyRunning) scheduleVerify();
          dbgNative({
            command: "dbg",
            text: `proxy: грация после старта, жду подтверждения (${Math.max(0, Math.round((START_GRACE_MS - (Date.now() - STATE.lastStartAt)) / 1000))} c)`
          });
          journal("verify-grace", "жду подтверждения после старта — прокси не трогаю");
          return;
        }
        if (STATE.proxyArmed) await releaseProxy("туннель больше не подтверждён");
        else await setProxyNone();
        // FIX(5.5.4.2): если releaseProxy ушёл в удержание — снимок боевой
        // настройки и режим НЕ затираем. Иначе держать уже нечего, и следующий
        // обрыв выкинет прокси браузеру ровно как раньше.
        if (STATE.proxyMode === "holding") {
          if (!STATE.verifyTimer && !STATE.verifyRunning) scheduleVerify();
          dbgNative({ command: "dbg", text: "proxy HOLD (жду подтверждения)" });
          return;
        }
        STATE.proxyEnabled = false;
        STATE.lastArmedProxyValue = null;
        STATE.proxyMode = "pending-verify";
        dbgNative({ command: "dbg", text: "proxy=pending-verify (жду подтверждения хоста)" });
        if (!STATE.verifyTimer) scheduleVerify();
        return;
      }

      const rs = STATE.ruleset;

      // Основной путь — ДЕКЛАРАТИВНЫЙ: proxyType "manual" + passthrough.
      // Решение принимает сетевой стек браузера, а не наш JS, поэтому оно
      // работает даже когда MV3 event page выгружен. Это важно: proxy.onRequest
      // требует живого background-контекста на каждый запрос, и если страницу
      // не успели разбудить — запрос зависает и страницы не грузятся вовсе.
      //
      // proxy.onRequest нужен только для режима "blocked": там напрямую идёт
      // почти весь интернет, а перечислить его списком passthrough нельзя.
      if (STATE.perRequestProxy && rs.mode === TUNNEL_MODES.BLOCKED_ONLY) {
        const value = { proxyType: "system" };
        await browser.proxy.settings.set({ value });
        STATE.lastArmedProxyValue = value;   // FIX(5.5.5): снимок боевой настройки
        STATE.armedPort = null;              // FIX(5.5.12): per-request — порта в настройках нет
        STATE.proxyEnabled = true;
        STATE.proxyArmed = true;
        startWatchdog();
        STATE.proxyReleasedByUser = false;
        STATE.holdSince = null;      // FIX(5.5.4.2)
        STATE.proxyMode = "perRequest";
        dbgNative({ command: "dbg", text: "proxy=perRequest mode=" + rs.mode });
        return;
      }

      const built = buildManualValue(rs);
      const value = built.value;
      const pass = built;
      const effectiveMode = built.effectiveMode;
      await browser.proxy.settings.set({ value });
      STATE.lastArmedProxyValue = value;   // FIX(5.5.5): снимок боевой настройки
      STATE.armedPort = Number(value.socksPort) || activeProxyPort();  // FIX(5.5.12)
      STATE.proxyEnabled = true;
      STATE.proxyArmed = true;
      STATE.proxyReleasedByUser = false;
      STATE.holdSince = null;        // FIX(5.5.4.2)
      STATE.proxyMode = "socks";
      startWatchdog();
      if (effectiveMode !== rs.mode) {
        broadcastUI({
          type: "error",
          message: "Режим «Только заблокированное» недоступен без proxy.onRequest — включён полный туннель."
        });
      }
      if (pass.truncated) {
        console.warn(`[flicker] passthrough обрезан до ${pass.count} записей`);
      }
      dbgNative({
        command: "dbg",
        text: `proxy=socks port=${activeProxyPort()} kind=${STATE.tunnelKind} passthrough=${pass.count}${pass.truncated ? "(truncated)" : ""}`
      });
      return;
    }

    // Туннель выключен.
    // FIX(5.5.4.2): если мы В ПРОЦЕССЕ восстановления (обрыв, автопереключение,
    // откат на прежнюю ноду) — proxy.settings не трогаем вообще. Иначе каждое
    // неудачное переключение выкидывало браузер на прямую, и пользователь видел
    // «прокси возвращён браузеру» по нескольку раз за минуту.
    // FIX(5.5.14): …и то же самое в основном пути: на мёртвом конце HOLD
    // не включается, браузер возвращается к прямому трафику сразу.
    const wantHold = STATE.holdProxy && !STATE.proxyReleasedByUser &&
      STATE.lastArmedProxyValue && !STATE.killSwitchBlocked && !endpointDead() &&
      (STATE.resumeServerId || STATE.recoveryTimer || STATE.recovering);
    if (wantHold) {
      if (!STATE.holdSince) STATE.holdSince = Date.now();
      if (Date.now() - STATE.holdSince <= holdMaxMs()) {
        STATE.proxyMode = "holding";
        if (!STATE.recoveryTimer) scheduleRecovery("туннель выключен, чиню на месте");
        dbgNative({ command: "dbg", text: "proxy HOLD (tunnel off, восстанавливаю)" });
        return;
      }
    }
    STATE.holdSince = null;
    await setProxyNone();
    STATE.proxyEnabled = false;
    STATE.proxyArmed = false;
    STATE.armedPort = null;              // FIX(5.5.12)
    STATE.lastArmedProxyValue = null;
    STATE.tunnelVerified = false;
    clearTimeout(STATE.watchdogTimer);
    STATE.watchdogTimer = null;
    STATE.proxyMode = "off";
    dbgNative({ command: "dbg", text: "proxy=" + (STATE.bypassSystemProxy ? "none" : "system") });
  } catch (e) {
    console.error("[flicker] proxy set failed:", e);
    dbgNative({ command: "dbg", text: "proxy SET FAILED: " + (e?.message || e) });
    // Kill switch НЕ активируем от ошибки конфигурации прокси: только обрыв туннеля.
    // Самая частая причина в Firefox: proxy.settings требует разрешения на
    // приватные окна (ext-proxy.js). Говорим пользователю, что нажать.
    const pbHint = /private browsing/i.test(String(e?.message || e))
      ? " Разрешите приватные окна: about:addons → FLICKER VPN → «Разрешить в приватных окнах» — без этого Firefox не даёт управлять прокси."
      : "";
    broadcastUI({ type: "error", message: "Ошибка применения proxy: " + (e?.message || e) + pbHint });
  }
}

/**
 * setProxyNone — снять маршрутизацию VPN, НЕ отдавая браузер системному прокси.
 * При bypassSystemProxy=false восстанавливаем прежнее поведение версии 4
 * (clear → proxyType:"system"), оно нужно тем, кто сидит за корпоративным
 * прокси и без него вообще не имеет доступа в сеть.
 */
async function setProxyNone() {
  if (STATE.bypassSystemProxy) {
    await browser.proxy.settings.set({ value: { proxyType: "none" } });
  } else {
    await browser.proxy.settings.clear({});
  }
}

// ================= Failsafe прокси (v5.3) =================
//
// ГЛАВНОЕ ПРАВИЛО: расширение не имеет права оставить браузер без интернета.
//
// До 5.3 прокси перехватывался сразу по факту status === "connected", а
// «connected» приходит от native host до того, как sing-box реально поднял
// туннель и начал слушать SOCKS. Если туннель не поднялся (нода мертва,
// драйвер не загрузился, хост упал), Firefox продолжал слать весь трафик на
// 127.0.0.1:1080, где никто не отвечал — страницы не грузились ВООБЩЕ, и
// вернуть их можно было только отключением расширения.
//
// Теперь:
//   1. прокси НЕ вооружается, пока хост не подтвердит socksListening/tunnelActive;
//   2. пока подтверждения нет, стоит proxyType:"none" — браузер работает как обычно;
//   3. если подтверждение не пришло за PROXY_ARM_TIMEOUT_MS — вооружение отменяется;
//   4. после вооружения работает watchdog: нет подтверждения/статистики —
//      прокси освобождается автоматически, без участия пользователя;
//   5. есть ручная кнопка «вернуть прокси браузеру», которая работает всегда
//      (страница расширения не зависит от сети);
//   6. настройки трогаем только если они уже под нашим контролем
//      (levelOfControl === "controlled_by_this_extension").

/**
 * Сколько ждём подтверждения от хоста перед вооружением прокси.
 *
 * FIX(5.5.5): было 12 c — и это ГЛАВНАЯ причина «Туннель не работает — прокси
 * возвращён браузеру». Хост 5.5.4 проверяет живость туннеля сам: 10 c на цель,
 * три цели (1.1.1.1 / 8.8.8.8 / 9.9.9.9:443), то есть на ответ diagnose ему
 * нужно до ~30 c. Расширение сдавалось на 12-й секунде, отправляло хосту stop
 * (убивая туннель, который вот-вот поднялся бы) и снимало прокси.
 * Правило: JS-сторона не имеет права быть строже хоста.
 */
const PROXY_ARM_TIMEOUT_MS = 20_000;           // хост без caps:"liveness"
const PROXY_ARM_TIMEOUT_LIVENESS_MS = 45_000;  // хост 5.5.4+ (liveness 3 × 10 c)
/** Период опроса подтверждения, пока туннель не подтверждён. */
const VERIFY_POLL_MS = 3_000;
/** Период перепроверки живости туннеля. */
const PROXY_WATCHDOG_MS = 25_000;
/** Сколько провалов проверки подряд до автоматического освобождения прокси. */
const PROXY_FAIL_LIMIT = 3;
/** Если статистика от хоста молчит дольше этого — туннель считается мёртвым. */
const STATS_STALL_MS = 75_000;
/**
 * HOLD_MAX_MS (FIX 5.5.4.2) — сколько держим браузер на SOCKS мёртвого туннеля,
 * пытаясь поднять его заново, прежде чем честно вернуть прокси браузеру.
 * Без ограничения это превратилось бы в «интернета нет и непонятно почему».
 */
const HOLD_MAX_MS = 120_000;
// FIX(5.5.9): абсолютный потолок удержания. Пока восстановление делает прогресс,
// прокси держится на туннеле; но вечной дыры «браузер без интернета» быть не
// должно, поэтому после 5 минут прокси честно возвращается браузеру (или
// блокируется kill switch, если он включён). advanced.holdHardCapMs —
// переопределение, advanced.holdUnbounded = true — держать без потолка.
const HOLD_HARD_CAP_MS = 5 * 60 * 1000;
const JOURNAL_MAX = 120;
// FIX(5.5.10): вердикт «нода мертва» в мягком режиме живости.
// Условие строгое, чтобы не повторить ошибку, из-за которой мягкий режим
// вообще ввели: рвать РАБОЧИЙ туннель из-за одного медленного dial нельзя.
//   3 отказа подряд + 45 секунд серии + НОЛЬ байт трафика за всё время +
//   статус connected  =>  трафик не ходит вовсе, значит туннеля нет.
const SOFT_DEAD_STREAK = 3;
const SOFT_DEAD_MIN_MS = 45_000;
const SOFT_DEAD_COOLDOWN_MS = 60_000;
// FIX(5.5.11): грация после старта. Хост поднимает туннель не мгновенно
// (в отчёте: [start] → через 5 c «туннель больше не подтверждён» → HOLD →
// через 25 c [verify-ok]). В этом окне tunnelVerified=false — норма, а не обрыв,
// поэтому прокси не трогаем и просто ждём diagnose.
const START_GRACE_MS = 10_000;
// FIX(5.5.13): сколько ждём ответ хоста на наш stop при смене ноды. В дампе
// пользователя этот ответ приходил в том же тике (доли секунды), но порядок
// сообщений не гарантирован: ответ мог прийти и ПОСЛЕ «connected» новой ноды.
// Окно намеренно короткое — 10 c: проглоченный настоящим обрывом статус всё
// равно добирается вердиктом подтверждения (HOLD → восстановление), а держать
// метку дольше незачем.
const SWITCH_STOP_ACK_MS = 10_000;
// FIX(5.5.12): анти-карусель. В отчёте пользователя хост получал start той же
// ноды каждые ~20 c (switch: de15 -> de15, ступень=same, попытка=0): туннель
// поднимался, не подтверждался, восстановление снова брало ту же ноду, а
// счётчик попыток обнулялся на голом «connected», поэтому backoff не рос.
// После RESTART_LOOP_MAX неподтверждённых перезапусков одной ноды ступень
// «same» пропускается (принудительная ротация), а пауза между попытками
// растёт до RESTART_LOOP_BACKOFF_MS.
const RESTART_LOOP_MAX = 3;
const RESTART_LOOP_BACKOFF_MS = 120_000;
// FIX(5.5.12): как часто переспрашиваем подтверждение, когда бюджет исчерпан,
// но смерть туннеля НЕ доказана (хост молчит, heartbeat свежий).
const VERIFY_RETRY_GAP_MS = 30_000;
const JOURNAL_THROTTLE_MS = 20_000;
/** Пауза между попытками вернуть туннель (растёт вдвое, потолок ниже). */
const RECOVERY_RETRY_BASE_MS = 15_000;
const RECOVERY_RETRY_MAX_MS = 60_000;
// FIX(5.5.8): параметры лестницы эскалации восстановления
const DEATH_WINDOW_MS = 10 * 60 * 1000;   // окно учёта обрывов по ноде
const DEATHS_BEFORE_ROTATE = 2;           // обрывов одной ноды за окно → меняем ноду
const STAGE_ESCALATE_AFTER = 4;           // попыток → жёсткая эскалация (DPI-устойчивый профиль)
const STABLE_SESSION_MS = 120 * 1000;     // соединение держится столько → лестница обнуляется
/** Сколько подряд неподтверждённых проб нужно, чтобы признать unusable НОДУ. */
/**
 * PROBE_TARGETS — контрольные цели проверки живости (FIX 5.5.5).
 *
 * Была одна (detectportal.firefox.com). Её недоступность из-под конкретной ноды
 * читалась как «туннель мёртв», и расширение гасило рабочее соединение. Теперь
 * цели независимые и географически разные: вердикт «не проходит» требует
 * молчания ВСЕХ.
 */
const PROBE_TARGETS = [
  DPI_PROBE_URL,                        // detectportal.firefox.com/success.txt
  "https://cp.cloudflare.com/",         // anycast, отдаёт тело на 200
  "https://www.gstatic.com/generate_204" // минимальный ответ без тела
];
const NODE_UNUSABLE_STREAK = 2;
/** Таймаут ожидания ответа diagnose, когда он нужен как источник правды. */
const HOST_VERDICT_TIMEOUT_MS = 12_000;
/** Возраст записи сессии, после которого она уже не наша (сбрасываем прокси). */
const SESSION_MAX_AGE_MS = 6 * 3600 * 1000;
/** Ключ storage.local, под которым живёт память о сессии. */
const SESSION_KEY = "session";

/** holdMaxMs — действующее ограничение удержания прокси. */
function holdMaxMs() {
  return Number.isFinite(STATE.holdMaxMs) && STATE.holdMaxMs > 0 ? STATE.holdMaxMs : HOLD_MAX_MS;
}

// ================= FIX(5.5.9): удержание по прогрессу + журнал =================

/** Абсолютный потолок удержания (advanced.holdHardCapMs / holdUnbounded). */
function holdHardCapMs() {
  if (STATE.advanced?.holdUnbounded === true) return Infinity;
  const v = Number(STATE.advanced?.holdHardCapMs);
  return Number.isFinite(v) && v >= holdMaxMs() ? v : HOLD_HARD_CAP_MS;
}

/**
 * journal — кольцо последних событий. Нужно, чтобы разбор обрыва не требовал
 * от пользователя руками собирать диагностику: в попапе есть кнопка
 * «Скопировать отчёт», которая отдаёт весь журнал разом.
 */
function journal(kind, text) {
  try {
    const key = kind;
    const now = Date.now();
    // однотипные события пишем не чаще раза в JOURNAL_THROTTLE_MS (без спама)
    if (STATE.journalAt[key] != null && now - STATE.journalAt[key] < JOURNAL_THROTTLE_MS &&
        !/^(release|hold-start|stage|tunnel-lost|direct)$/.test(kind)) return;
    STATE.journalAt[key] = now;
    STATE.journal.push({ t: now, kind, text: String(text == null ? "" : text).slice(0, 400) });
    if (STATE.journal.length > JOURNAL_MAX) STATE.journal.splice(0, STATE.journal.length - JOURNAL_MAX);
  } catch { /* журнал не должен ломать восстановление */ }
}

/**
 * markHoldProgress — ЗАЧЁТ прогресса восстановления.
 * Продлевает удержание: пока что-то реально происходит (хост шлёт stats,
 * туннель подтверждён, началась новая попытка/смена ноды), прокси остаётся на
 * туннеле. Просто «мы снова попросили diagnose» прогрессом НЕ считается —
 * иначе удержание стало бы бесконечным.
 */
function markHoldProgress(what) {
  STATE.lastHoldProgressAt = Date.now();
  if (what) journal("progress", what);
}

/** Метка времени задана? (0 — валидное значение: Date.now() != 0 только в проде) */
function isStamp(v) { return Number.isFinite(v); }

/** Держим ли прокси сейчас: по прогрессу, с абсолютным потолком. */
function holdStillWanted(now = Date.now()) {
  if (!isStamp(STATE.holdSince)) return true;        // ещё не начали держать
  const progressAt = isStamp(STATE.lastHoldProgressAt) ? STATE.lastHoldProgressAt : STATE.holdSince;
  const sinceProgress = now - progressAt;
  const sinceStart = now - STATE.holdSince;
  if (sinceProgress > holdMaxMs()) return false;     // никакого прогресса — отпускаем
  if (sinceStart > holdHardCapMs()) return false;    // абсолютный потолок
  return true;
}

/**
 * endpointDead — FIX(5.5.14): держать прокси НЕ НА ЧЕМ.
 *
 * Удержание (HOLD) имеет смысл, пока SOCKS-слушатель вот-вот вернётся. Если
 * выбран локальный транспорт (direct — слушателя нет в принципе), если native
 * host не на связи, или если последний diagnose прямо сказал «не слушаю»
 * (свежий, не старше 60 c), то удержание оставляет браузер на МЁРТВОМ порту:
 * ни VPN, ни интернета, и панель при этом показывает «connected / прокси
 * активен». В отчёте пользователя ровно так прошли 22:00:10 → 22:06:06.
 *
 * @returns {string|null} причина, либо null если конец живой
 */
function endpointDead() {
  if (STATE.tunnelKind !== "dpi" && STATE.currentServer?.protocol === "direct") {
    return "локальный транспорт direct: SOCKS-слушателя нет";
  }
  if (STATE.nativeOnline === false) return "native host не на связи";
  if (STATE.lastSocksListening === false && isStamp(STATE.lastDiagnoseAt) &&
      (Date.now() - STATE.lastDiagnoseAt) <= 60_000) {
    return "хост сообщил, что SOCKS не слушает";
  }
  return null;
}

/**
 * endpointDead — FIX(5.5.14): держать прокси НЕ НА ЧЕМ.
 *
 * Удержание (HOLD) имеет смысл, пока SOCKS-слушатель вот-вот вернётся. Если
 * выбран локальный транспорт (direct — слушателя нет в принципе), если native
 * host не на связи, или если последний diagnose прямо сказал «не слушаю»
 * (свежий, не старше 60 c), то удержание оставляет браузер на МЁРТВОМ порту:
 * ни VPN, ни интернета, и панель при этом показывает «connected / прокси
 * активен». В отчёте пользователя ровно так прошли 22:00:10 → 22:06:06.
 *
 * @returns {string|null} причина, либо null если конец живой
 */
function endpointDead() {
  if (STATE.tunnelKind !== "dpi" && STATE.currentServer?.protocol === "direct") {
    return "локальный транспорт direct: SOCKS-слушателя нет";
  }
  if (STATE.nativeOnline === false) return "native host не на связи";
  if (STATE.lastSocksListening === false && isStamp(STATE.lastDiagnoseAt) &&
      (Date.now() - STATE.lastDiagnoseAt) <= 60_000) {
    return "хост сообщил, что SOCKS не слушает";
  }
  return null;
}

/**
 * endpointDead — FIX(5.5.14): держать прокси НЕ НА ЧЕМ.
 *
 * Удержание (HOLD) имеет смысл, пока SOCKS-слушатель вот-вот вернётся. Если
 * выбран локальный транспорт (direct — слушателя нет в принципе), если native
 * host не на связи, или если последний diagnose прямо сказал «не слушаю»
 * (свежий, не старше 60 c), то удержание оставляет браузер на МЁРТВОМ порту:
 * ни VPN, ни интернета, и панель при этом показывает «connected / прокси
 * активен». В отчёте пользователя ровно так прошли 22:00:10 → 22:06:06.
 *
 * @returns {string|null} причина, либо null если конец живой
 */
function endpointDead() {
  if (STATE.tunnelKind !== "dpi" && STATE.currentServer?.protocol === "direct") {
    return "локальный транспорт direct: SOCKS-слушателя нет";
  }
  if (STATE.nativeOnline === false) return "native host не на связи";
  if (STATE.lastSocksListening === false && isStamp(STATE.lastDiagnoseAt) &&
      (Date.now() - STATE.lastDiagnoseAt) <= 60_000) {
    return "хост сообщил, что SOCKS не слушает";
  }
  return null;
}

/** Сколько ещё держим прокси (для UI), мс; null — не держим. */
function holdRemainingMs(now = Date.now()) {
  if (!isStamp(STATE.holdSince)) return null;
  const progressAt = isStamp(STATE.lastHoldProgressAt) ? STATE.lastHoldProgressAt : STATE.holdSince;
  const a = holdMaxMs() - (now - progressAt);
  const b = holdHardCapMs() - (now - STATE.holdSince);
  return Math.max(0, Math.min(a, b));
}

/** Локальный транспорт: это НЕ VPN-туннель (трафик идёт напрямую/через ciadpi). */
function isLocalTransport(s) {
  return !!s && (s.protocol === "direct" || s.protocol === "dpi");
}

/**
 * warnDirectNode — «Диагностика (direct)» даёт статус connected и вооружённый
 * прокси, но трафик идёт НАПРЯМУЮ. По диагностике пользователя именно этот узел
 * был выбран, то есть «VPN подключён» при полном отсутствии VPN. Молчать нельзя.
 */
function warnDirectNode(server) {
  const now = Date.now();
  journal("direct", `выбран узел ${server?.id || "?"} (${server?.protocol}) — это не VPN`);
  if (STATE.directWarnAt != null && now - STATE.directWarnAt < 5 * 60 * 1000) return;
  STATE.directWarnAt = now;
  const m = server?.protocol === "dpi"
    ? "Включён DPI-обход (локально, без сервера): трафик не шифруется и IP не меняется — это обход блокировок, а не VPN."
    : `Выбран узел «${server?.name || server?.id}» (протокол direct) — это НЕ VPN: трафик идёт напрямую, IP не меняется. ` +
      "Выбери сервер из списка (вкладка «Серверы») или включи автовыбор.";
  console.warn("[flicker] " + m);
  broadcastUI({ type: "error", message: m });
  broadcastUI({ type: "directNode", serverId: server?.id || null, protocol: server?.protocol || null, message: m });
  notify("FLICKER VPN", m);
}

/** Хост сейчас занят пробой серверов: diagnose отвечает поздно, это не смерть. */
function probeRunning() {
  return !!(STATE.probe && STATE.probe.active);
}

// ============ FIX(5.5.10): мягкий режим живости больше не слепой ============

/** Сброс серии отказов dial (dial прошёл или пошёл трафик). */
function softLivenessReset() {
  STATE.softDeadStreak = 0;
  STATE.softDeadSince = null;
}

/** Суммарный трафик текущей сессии, байт. */
function sessionBytes() {
  return (Number(STATE.bytesSent) || 0) + (Number(STATE.bytesReceived) || 0);
}

/**
 * softLivenessNote — зачесть очередной verdict `tunnelAlive=false` и решить,
 * не стала ли серия доказательством смерти ноды.
 *
 * @returns {{dead:boolean, streak:number, durMs:number, noTraffic:boolean}}
 */
/**
 * declareSoftDead — FIX(5.5.14): общий вердикт «нода не пропускает трафик».
 *
 * Вынесен из обработчика diagnose, потому что подтверждений теперь два и они
 * приходят из разных мест:
 *   1. прежнее мягкое правило (3 отказа dial подряд + 45 c + нулевой трафик) —
 *      на практике не срабатывало никогда: серия обнуляется при каждой смене
 *      ноды, а «нулевого трафика» не бывает, потому что контрольные запросы
 *      расширения сами идут через туннель (в отчёте: «Передано ↑0.00 ↓0.00 MB»,
 *      но «трафик есть»);
 *   2. НОВОЕ: dial хоста отклонён И наш собственный контрольный запрос через
 *      SOCKS не прошёл — два независимых подтверждения, ждать 45 c незачем.
 *
 * @param {string} reason человекочитаемая причина
 * @returns {boolean} true, если вердикт вынесен (cooldown учтён внутри)
 */
function declareSoftDead(reason) {
  const now = Date.now();
  if (STATE.softDeadActAt != null && now - STATE.softDeadActAt <= SOFT_DEAD_COOLDOWN_MS) return false;
  STATE.softDeadActAt = now;
  console.warn("[flicker] soft liveness: " + reason);
  dbgNative({ command: "dbg", text: "soft liveness: DEAD " + reason });
  journal("soft-dead", reason);
  broadcastUI({
    type: "error",
    message: "⚠ " + reason + ". Считаю ноду мёртвой и ухожу на другую — прокси остаётся на туннеле, если он есть."
  });
  softLivenessReset();
  // две отметки обрыва (эта + внутри recoverFromDeadTunnel) дают
  // DEATHS_BEFORE_ROTATE, поэтому лестница сразу ротирует ноду,
  // а не пробует ту же самую снова
  const deadId = STATE.currentServer?.id || null;
  if (deadId) noteTunnelDeath(deadId, reason, transportFingerprint(STATE.currentServer));
  recoverFromDeadTunnel(reason).catch((e) => console.error("[flicker] soft-dead recover:", e));
  return true;
}

/**
 * declareSoftDead — FIX(5.5.14): общий вердикт «нода не пропускает трафик».
 *
 * Вынесен из обработчика diagnose, потому что подтверждений теперь два и они
 * приходят из разных мест:
 *   1. прежнее мягкое правило (3 отказа dial подряд + 45 c + нулевой трафик) —
 *      на практике не срабатывало никогда: серия обнуляется при каждой смене
 *      ноды, а «нулевого трафика» не бывает, потому что контрольные запросы
 *      расширения сами идут через туннель (в отчёте: «Передано ↑0.00 ↓0.00 MB»,
 *      но «трафик есть»);
 *   2. НОВОЕ: dial хоста отклонён И наш собственный контрольный запрос через
 *      SOCKS не прошёл — два независимых подтверждения, ждать 45 c незачем.
 *
 * @param {string} reason человекочитаемая причина
 * @returns {boolean} true, если вердикт вынесен (cooldown учтён внутри)
 */
function declareSoftDead(reason) {
  const now = Date.now();
  if (STATE.softDeadActAt != null && now - STATE.softDeadActAt <= SOFT_DEAD_COOLDOWN_MS) return false;
  STATE.softDeadActAt = now;
  console.warn("[flicker] soft liveness: " + reason);
  dbgNative({ command: "dbg", text: "soft liveness: DEAD " + reason });
  journal("soft-dead", reason);
  broadcastUI({
    type: "error",
    message: "⚠ " + reason + ". Считаю ноду мёртвой и ухожу на другую — прокси остаётся на туннеле, если он есть."
  });
  softLivenessReset();
  // две отметки обрыва (эта + внутри recoverFromDeadTunnel) дают
  // DEATHS_BEFORE_ROTATE, поэтому лестница сразу ротирует ноду,
  // а не пробует ту же самую снова
  const deadId = STATE.currentServer?.id || null;
  if (deadId) noteTunnelDeath(deadId, reason, transportFingerprint(STATE.currentServer));
  recoverFromDeadTunnel(reason).catch((e) => console.error("[flicker] soft-dead recover:", e));
  return true;
}

/**
 * declareSoftDead — FIX(5.5.14): общий вердикт «нода не пропускает трафик».
 *
 * Вынесен из обработчика diagnose, потому что подтверждений теперь два и они
 * приходят из разных мест:
 *   1. прежнее мягкое правило (3 отказа dial подряд + 45 c + нулевой трафик) —
 *      на практике не срабатывало никогда: серия обнуляется при каждой смене
 *      ноды, а «нулевого трафика» не бывает, потому что контрольные запросы
 *      расширения сами идут через туннель (в отчёте: «Передано ↑0.00 ↓0.00 MB»,
 *      но «трафик есть»);
 *   2. НОВОЕ: dial хоста отклонён И наш собственный контрольный запрос через
 *      SOCKS не прошёл — два независимых подтверждения, ждать 45 c незачем.
 *
 * @param {string} reason человекочитаемая причина
 * @returns {boolean} true, если вердикт вынесен (cooldown учтён внутри)
 */
function declareSoftDead(reason) {
  const now = Date.now();
  if (STATE.softDeadActAt != null && now - STATE.softDeadActAt <= SOFT_DEAD_COOLDOWN_MS) return false;
  STATE.softDeadActAt = now;
  console.warn("[flicker] soft liveness: " + reason);
  dbgNative({ command: "dbg", text: "soft liveness: DEAD " + reason });
  journal("soft-dead", reason);
  broadcastUI({
    type: "error",
    message: "⚠ " + reason + ". Считаю ноду мёртвой и ухожу на другую — прокси остаётся на туннеле, если он есть."
  });
  softLivenessReset();
  // две отметки обрыва (эта + внутри recoverFromDeadTunnel) дают
  // DEATHS_BEFORE_ROTATE, поэтому лестница сразу ротирует ноду,
  // а не пробует ту же самую снова
  const deadId = STATE.currentServer?.id || null;
  if (deadId) noteTunnelDeath(deadId, reason, transportFingerprint(STATE.currentServer));
  recoverFromDeadTunnel(reason).catch((e) => console.error("[flicker] soft-dead recover:", e));
  return true;
}

function softLivenessNote() {
  const now = Date.now();
  if (!isStamp(STATE.softDeadSince)) STATE.softDeadSince = now;
  STATE.softDeadStreak = (STATE.softDeadStreak || 0) + 1;
  const durMs = now - STATE.softDeadSince;
  const noTraffic = sessionBytes() <= 0;
  const dead = STATE.softDeadStreak >= SOFT_DEAD_STREAK && durMs >= SOFT_DEAD_MIN_MS &&
    noTraffic && STATE.status === "connected";
  return { dead, streak: STATE.softDeadStreak, durMs, noTraffic };
}

/** Состояние soft-liveness для статуса/отчёта. */
function softLivenessState(now = Date.now()) {
  return {
    streak: STATE.softDeadStreak || 0,
    sinceMs: isStamp(STATE.softDeadSince) ? Math.max(0, now - STATE.softDeadSince) : 0,
    noTraffic: sessionBytes() <= 0,
    needStreak: SOFT_DEAD_STREAK,
    needMs: SOFT_DEAD_MIN_MS
  };
}

/** armBudgetMs — сколько мы готовы ждать подтверждения от текущего хоста. */
function armBudgetMs() {
  const caps = STATE.nativeCaps;
  const liveness = !!(caps && typeof caps.has === "function" && (caps.has("liveness") || caps.has("liveness-3x10")));
  return liveness ? PROXY_ARM_TIMEOUT_LIVENESS_MS : PROXY_ARM_TIMEOUT_MS;
}

/**
 * activeProxyPort — порт SOCKS5, на который сейчас нужно направлять трафик.
 * Для VPN-туннеля это STATE.socksPort (слушает native host), для DPI-обхода —
 * порт ciadpi. Держим раздельно, чтобы режимы не дрались за одну настройку.
 */
function activeProxyPort() {
  return STATE.tunnelKind === "dpi" ? (STATE.dpiPort || FLICKER_DPI_PORT)
                                    : (STATE.socksPort || 1080);
}

/** ownsProxySetting — управляем ли мы сейчас настройками прокси. */
async function ownsProxySetting() {
  try {
    const cur = await browser.proxy.settings.get({});
    return cur?.levelOfControl === "controlled_by_this_extension";
  } catch { return false; }
}

/**
 * releaseProxy — вернуть прокси браузеру.
 * Единственная функция, которая снимает вооружение; вызывается и watchdog-ом,
 * и кнопкой пользователя, и при остановке туннеля.
 */
async function releaseProxy(reason, opts = {}) {
  // FIX(5.5.7) RC-5: во время атомарной смены узла proxy.settings не трогаем
  // ВООБЩЕ. Это прямо задекларировано в комментарии к полю STATE.switching
  // («идёт атомарная смена сервера: proxy.settings не трогаем»), но canHold
  // ниже содержал условие `!STATE.switching` — то есть вёл себя ровно
  // наоборот: на время смены удержание ВЫКЛЮЧАЛОСЬ, и функция проваливалась в
  // proxyType:"none". Браузер уходил напрямую в тот самый момент, когда
  // расширение переподключало ноду. Это второй самостоятельный источник
  // «возврата прокси браузеру», и он не зависит от liveness.
  //
  // Смена узла сама перевооружит прокси (applyProxyMode на новый порт), поэтому
  // здесь достаточно не мешать. Ограничение HOLD_MAX_MS сохраняется: если смена
  // так и не завершилась, прокси честно возвращается браузеру общим путём ниже.
  // Исключение — явная воля пользователя (opts.byUser / proxyReleasedByUser).
  if (STATE.switching && !opts.byUser && !STATE.proxyReleasedByUser &&
      STATE.lastArmedProxyValue && !STATE.killSwitchBlocked) {
    const nowSw = Date.now();
    if (!STATE.holdSince) { STATE.holdSince = nowSw; STATE.lastHoldProgressAt = nowSw; }
    if (holdStillWanted(nowSw)) {           // FIX(5.5.9): по прогрессу, не по абсолютному таймеру
      STATE.tunnelVerified = false;
      STATE.verifyFails = 0;
      clearTimeout(STATE.verifyTimer);
      STATE.verifyTimer = null;
      STATE.proxyMode = "holding";
      dbgNative({ command: "dbg", text: "proxy DEFERRED (switching): " + (reason || "-") });
      console.warn("[flicker] прокси НЕ возвращаю браузеру: идёт атомарная смена узла —", reason);
      broadcastUI({ type: "proxyHolding", reason: reason || null, since: STATE.holdSince });
      // scheduleRecovery здесь НЕ зовём: смена узла и есть восстановление,
      // второй параллельный поток только устроил бы гонку за STATE.switching.
      if (!STATE.watchdogTimer) startWatchdog();
      persistSession();
      return;
    }
    console.warn("[flicker] смена узла затянулась сверх удержания — освобождаю прокси");
  }

  // FIX(5.5.4.2): ДЕРЖИМ прокси вместо возврата браузеру.
  //
  // «Туннель не работает — прокси возвращён браузеру» означало: трафик ушёл
  // напрямую, а восстановление шло уже без маршрутизации. Теперь при обрыве не
  // по воле пользователя браузер остаётся на SOCKS туннеля, пока расширение
  // поднимает ноду заново (scheduleRecovery + watchdog). Держим не дольше
  // HOLD_MAX_MS: если починить не удалось, прокси честно возвращается браузеру,
  // чтобы не оставить человека без интернета навсегда.
  // FIX(5.5.9): три причины, по которым прокси всё-таки уезжал браузеру:
  //  (a) canHold требовал status connected/connecting — но восстановление идёт
  //      уже в disconnected, и любой поздний вызов освобождал прокси сразу;
  //  (b) после освобождения lastArmedProxyValue = null → удержание больше не
  //      могло включиться до успешного подключения (остаток аварии — напрямую);
  //  (c) срок считался от первого обрыва и не продлевался прогрессом.
  const recoveryInFlight = !!STATE.recovering || !!STATE.recoveryTimer ||
    (STATE.recoveryStage && STATE.recoveryStage !== "same");
  // держать можно только то, что ДЕРЖИТСЯ: прокси вооружён сейчас или его
  // боевая настройка ещё на руках (тогда возврат не состоялся)
  const haveLiveProxy = !!STATE.proxyArmed || !!STATE.lastArmedProxyValue;
  // FIX(5.5.14): удержание запрещено, если конец заведомо мёртв: держать
  // нечего, а браузер остаётся без интернета. Отказ удержания — событие, его
  // видно в журнале и в логе хоста.
  const deadEnd = endpointDead();
  if (deadEnd && STATE.holdProxy && haveLiveProxy && !opts.byUser &&
      !STATE.proxyReleasedByUser && !STATE.switching) {
    journal("hold-refused", "удержание отменено: " + deadEnd + " — возвращаю браузер к прямому трафику");
    dbgNative({ command: "dbg", text: "proxy: HOLD отменён (" + deadEnd + ") — мёртвый порт не держу" });
  }
  const canHold = STATE.holdProxy && !opts.byUser && !STATE.proxyReleasedByUser &&
    haveLiveProxy && !STATE.killSwitchBlocked && !STATE.switching && !deadEnd &&
    (STATE.status === "connected" || STATE.status === "connecting" || recoveryInFlight);
  if (canHold) {
    const now = Date.now();
    const firstHold = !STATE.holdSince;
    if (firstHold) {
      STATE.holdSince = now;
      STATE.lastHoldProgressAt = now;
      journal("hold-start", reason || "обрыв туннеля");
      console.warn(`[flicker] удержание прокси: окно без прогресса ${Math.round(holdMaxMs() / 1000)} c, ` +
                   `потолок ${Math.round(holdHardCapMs() / 1000)} c`);
    }
    if (holdStillWanted(now)) {
      clearTimeout(STATE.verifyTimer);
      STATE.verifyTimer = null;
      STATE.tunnelVerified = false;
      STATE.verifyFails = 0;
      STATE.proxyMode = "holding";
      dbgNative({ command: "dbg", text: "proxy HOLD: " + (reason || "-") });
      if (firstHold) {
        console.warn("[flicker] обрыв — держу прокси на туннеле и чиню на месте:", reason);
        notify("FLICKER VPN", "Обрыв туннеля. Прокси НЕ возвращён браузеру — восстанавливаю соединение…");
      }
      // FIX(5.5.9): одно сообщение, но с остатком удержания и ступенью
      // восстановления — в UI видно, что прокси держится и сколько ещё
      broadcastUI({
        type: "proxyHolding", reason: reason || null, since: STATE.holdSince,
        remainingMs: holdRemainingMs(now), progressAt: STATE.lastHoldProgressAt,
        stage: STATE.recoveryStage, attempt: STATE.recoveryAttempt || 0
      });
      scheduleRecovery(reason || "обрыв туннеля");
      if (!STATE.watchdogTimer) startWatchdog();
      persistSession();
      return;
    }
    console.warn("[flicker] держал прокси " + Math.round((now - STATE.holdSince) / 1000) +
                 " c без результата (без прогресса " +
                 Math.round((now - (isStamp(STATE.lastHoldProgressAt) ? STATE.lastHoldProgressAt : STATE.holdSince)) / 1000) + " c)");
    journal("hold-expired", `держал ${Math.round((now - STATE.holdSince) / 1000)} c, причина: ${reason || "-"}`);
    // FIX(5.5.5): удержание исчерпано. Если пользователь включил kill switch,
    // его воля «лучше без интернета, чем мимо VPN» сильнее удобства: блокируем
    // трафик вместо возврата браузеру и продолжаем чинить. Без kill switch
    // честно возвращаем прокси — вечной дыры в интернет быть не должно.
    if (STATE.killSwitchEnabled && !opts.byUser && !STATE.proxyReleasedByUser) {
      STATE.holdSince = null;
      activateKillSwitch("удержание исчерпано (" + Math.round(holdMaxMs() / 1000) +
                         " c) — трафик заблокирован вместо возврата браузеру");
      scheduleRecovery("kill switch: жду живую ноду");
      return;
    }
  }
  // FIX(5.5.9): снимок боевой настройки СОХРАНЯЕМ — иначе после этого возврата
  // удержание не сможет включиться снова и остаток аварии браузер просидит
  // напрямую (ровно то, на что жаловался пользователь).
  if (STATE.lastArmedProxyValue) STATE.lastArmedProxySnapshot = STATE.lastArmedProxyValue;
  STATE.holdSince = null;
  STATE.lastHoldProgressAt = null;
  STATE.recoveryStage = "same";       // следующий обрыв начинаем с чистой лестницы
  const wasArmed = STATE.proxyArmed;
  STATE.proxyArmed = false;
  STATE.armedPort = null;                // FIX(5.5.12)
  STATE.lastArmedProxyValue = null;
  STATE.tunnelVerified = false;
  STATE.verifyFails = 0;
  clearTimeout(STATE.verifyTimer);
  clearTimeout(STATE.watchdogTimer);
  STATE.verifyTimer = null;
  STATE.watchdogTimer = null;
  try {
    await browser.proxy.settings.set({ value: { proxyType: "none" } });
  } catch (e) {
    console.error("[flicker] releaseProxy failed:", e?.message || e);
  }
  STATE.proxyEnabled = false;
  STATE.proxyMode = "released";
  dbgNative({ command: "dbg", text: "proxy RELEASED: " + (reason || "-") });
  console.warn("[flicker] прокси освобождён:", reason || "без причины");
  broadcastUI({ type: "proxyReleased", reason: reason || null, wasArmed });
  journal("release", reason || "без причины");
  if (wasArmed && reason) {
    notify("FLICKER VPN", "Туннель не работает — прокси возвращён браузеру. " + reason);
  }
  // FIX(5.5.9): возврат прокси — НЕ конец работы. Чиним дальше, и как только
  // туннель вернётся, прокси снова вооружится (и снова сможет удерживаться).
  if (!opts.byUser && !STATE.proxyReleasedByUser && !STATE.killSwitchBlocked) {
    scheduleRecovery("после возврата прокси браузеру продолжаю восстановление");
  }
  persistSession();
}

/** Сколько diagnose-запросов в секунду достаточно (защита от флуда heartbeat-ом). */
const VERIFY_REQUEST_MIN_GAP_MS = 1_500;

/**
 * requestVerify — попросить хост подтвердить, что SOCKS слушает.
 *
 * FIX(5.5.5): с троттлингом. Stats от хоста приходит раз в секунду, и новый
 * хук самовосстановления на каждом таком сообщении просил бы diagnose —
 * native-канал забивался одинаковыми запросами.
 * @param {boolean} force — пропустить троттлинг (первый запрос цикла)
 */
function requestVerify(force = false) {
  const now = Date.now();
  if (!force && now - (STATE.lastVerifyRequestAt || 0) < VERIFY_REQUEST_MIN_GAP_MS) return false;
  STATE.lastVerifyRequestAt = now;
  return sendToNative({ command: "diagnose" });
}

/**
 * scheduleVerify — ждём подтверждения перед вооружением.
 * Если за PROXY_ARM_TIMEOUT_MS хост не ответил — не вооружаемся и сообщаем.
 */
function scheduleVerify() {
  // FIX(5.5.12): в режиме «Ничего» прокси снят по воле пользователя —
  // подтверждать нечего. Проба к тому же временно вооружала manual-прокси
  // (probeThroughProxy), то есть «выключенный VPN» всё равно тянул трафик.
  if (STATE.tunnelMode === TUNNEL_MODES.OFF) return;
  // FIX(5.5.12): «осиротевший» цикл подтверждения. verifyRunning взводится
  // здесь, а сбрасывается только в finish(); но таймер цикла снимают и извне
  // (releaseProxy — в трёх ветках, плюс обработчик сообщения releaseProxy).
  // После такого снятия флаг оставался true НАВСЕГДА: scheduleVerify() больше
  // ничего не запрашивал, diagnose не уходил, прокси не вооружался — тупик
  // «туннель не подтверждён, трафик напрямую» до ручного переподключения.
  if (STATE.verifyRunning && !STATE.verifyTimer && !STATE.verifyProbing) {
    console.warn("[flicker] цикл подтверждения осиротел (verifyRunning без таймера) — сбрасываю");
    journal("verify-orphan", "цикл подтверждения сброшен: таймер снят извне, флаг остался");
    STATE.verifyRunning = false;
  }
  // FIX(5.5.5): защита от второго параллельного цикла (retry — асинхронный,
  // и во время await verifyTimer обнулён).
  if (STATE.verifyRunning) return;
  clearTimeout(STATE.verifyTimer);
  STATE.verifyRunning = true;
  requestVerify(true);
  let tries = 0;

  const finish = () => {
    STATE.verifyRunning = false;
    STATE.verifyProbing = false;      // FIX(5.5.12)
    clearTimeout(STATE.verifyTimer);
    STATE.verifyTimer = null;
  };

  // повторяем, пока не получим подтверждение: первый diagnose может прийти
  // раньше, чем хост успел поднять SOCKS-слушатель, а у хоста 5.5.4 ответ
  // liveness занимает до 30 c
  const retry = async () => {
    STATE.verifyTimer = null;
    if (STATE.tunnelVerified || STATE.status !== "connected") { finish(); return; }
    tries++;
    if (tries % 2 === 1) {
      requestVerify();
    } else {
      // 5.5.3: чередуем diagnose с настоящей пробой через SOCKS. Молчание
      // хоста больше не приговор: если реальный запрос через прокси проходит,
      // туннель жив независимо от версии и состояния native-канала.
      // FIX(5.5.12): запоминаем порт пробы — если хост за это время уточнил
      // listen (autoPort), вердикт устарел и смертью туннеля не является.
      const portProbed = STATE.socksPort;
      STATE.verifyProbing = true;                 // FIX(5.5.12): цикл внутри await
      const pr = await probeThroughProxy(portProbed)
        .catch((e) => ({ ok: false, error: String(e?.message || e) }));
      STATE.verifyProbing = false;
      handleVerifyResult(pr.ok, {
        socksListening: pr.ok, via: "browser-probe", error: pr.error, probedPort: portProbed
      });
    }
    if (STATE.tunnelVerified || STATE.status !== "connected") { finish(); return; }

    // FIX(5.5.5): бюджет пересчитываем на каждой итерации. Сразу после
    // перезагрузки страницы hello от хоста ещё не пришёл и caps пустые —
    // фиксированные 20 c обрывали ожидание раньше, чем хост 5.5.4+ успевал
    // ответить на свой liveness-обход (3 цели × 10 c).
    const budget = armBudgetMs();
    if (tries * VERIFY_POLL_MS >= budget) {
      // Бюджет выбран. Последний независимый арбитр — реальный запрос через
      // SOCKS: если он проходит, туннель жив, и гасить его нельзя.
      const portConfirm = STATE.socksPort;
      STATE.verifyProbing = true;                 // FIX(5.5.12): цикл внутри await
      const confirm = await probeThroughProxy(portConfirm)
        .catch((e) => ({ ok: false, error: String(e?.message || e) }));
      STATE.verifyProbing = false;
      if (confirm.ok) {
        handleVerifyResult(true, { socksListening: true, via: "browser-probe-confirm", probedPort: portConfirm });
        finish();
        return;
      }
      // FIX(5.5.12): порт за время пробы уточнил хост — вердикт устарел,
      // спрашиваем заново уже на правильном порту (а не гасим туннель).
      if (portConfirm !== STATE.socksPort) {
        finish();
        journal("verify-stale", `проба на ${portConfirm} устарела: хост слушает ${STATE.socksPort}`);
        scheduleVerify();
        return;
      }
      finish();
      broadcastUI({
        type: "error",
        message: "Туннель не подтверждён: ни ответ хоста, ни контрольный запрос через SOCKS не прошли. " +
                 "Прокси НЕ перехвачен, браузер работает напрямую."
      });
      const whyUnconfirmed = "хост не подтвердил туннель за " + Math.round(budget / 1000) + " c";
      // FIX(5.5.12): ТУПИК ЗАПРЕЩЁН. Если смерть не доказана (хост молчит на
      // diagnose, но heartbeat свежий), прежний код просто выходил из цикла:
      // статус «connected», прокси не вооружён, таймеров ноль — пользователь
      // сидел так до ручного клика. Продолжаем спрашивать реже, а после
      // RESTART_LOOP_MAX неподтверждённых бюджетов чиним принудительно
      // (с анти-карусельной паузой и ротацией ноды).
      const recovered = await recoverIfConfirmedDead(whyUnconfirmed)
        .catch((e) => { console.error("[flicker] recover:", e); return false; });
      if (!recovered && STATE.status === "connected" && !STATE.tunnelVerified &&
          STATE.tunnelMode !== TUNNEL_MODES.OFF && !STATE.switching) {
        STATE.unverifiedBudgets = (STATE.unverifiedBudgets || 0) + 1;
        journal("verify-unconfirmed",
          `${whyUnconfirmed}; смерть не доказана — переспрашиваю, цикл ${STATE.unverifiedBudgets}/${RESTART_LOOP_MAX}`);
        markHoldProgress("жду подтверждения туннеля (смерть не доказана)");
        if (STATE.unverifiedBudgets >= RESTART_LOOP_MAX) {
          STATE.unverifiedBudgets = 0;
          // форсируем анти-карусель: дальше только ротация и длинная пауза
          STATE.sameNodeRestarts = Math.max(STATE.sameNodeRestarts || 0, RESTART_LOOP_MAX);
          await recoverFromDeadTunnel("туннель не подтверждается: " + whyUnconfirmed)
            .catch((e) => console.error("[flicker] recover:", e));
        } else {
          clearTimeout(STATE.verifyTimer);
          STATE.verifyTimer = setTimeout(() => {
            STATE.verifyTimer = null;
            if (STATE.status === "connected" && !STATE.tunnelVerified &&
                STATE.tunnelMode !== TUNNEL_MODES.OFF) scheduleVerify();
          }, VERIFY_RETRY_GAP_MS);
        }
      }
      return;
    }
    STATE.verifyTimer = setTimeout(retry, VERIFY_POLL_MS);
  };
  STATE.verifyTimer = setTimeout(retry, VERIFY_POLL_MS);
}

/** startWatchdog — периодическая перепроверка уже вооружённого прокси. */
function startWatchdog() {
  clearTimeout(STATE.watchdogTimer);
  const tick = () => {
    STATE.watchdogTimer = null;
    if (!STATE.proxyArmed) return;
    const stalled = STATE.lastStatsAt && (Date.now() - STATE.lastStatsAt > STATS_STALL_MS);
    if (stalled) {
      STATE.verifyFails++;
    } else {
      STATE.verifyFails = 0;
    }
    if (STATE.verifyFails >= PROXY_FAIL_LIMIT) {
      // FIX(5.5.5): приговор только после независимой проверки (запрос через
      // SOCKS). Молчание статистики само по себе туннель не убивает.
      recoverIfConfirmedDead("туннель не подаёт признаков жизни " + Math.round(STATS_STALL_MS / 1000) + "+ c (хост молчит)")
        .catch((e) => console.error("[flicker] recover:", e));
      return;
    }
    // для DPI-режима нет native host, которому можно послать diagnose:
    // живость проверяем реальным запросом через сам прокси
    if (STATE.tunnelKind === "dpi") verifyDpi().catch(() => {});
    else requestVerify();          // обновит tunnelVerified / lastVerifiedAt
    STATE.watchdogTimer = setTimeout(tick, PROXY_WATCHDOG_MS);
  };
  STATE.watchdogTimer = setTimeout(tick, PROXY_WATCHDOG_MS);
}

/**
 * handleVerifyResult — реакция на ответ diagnose от хоста.
 * @param {boolean} ok    хост подтвердил, что SOCKS слушает / туннель активен
 * @param {object} d      данные ответа
 */
function handleVerifyResult(ok, d) {
  // FIX(5.5.14): для локального транспорта direct вердикт подтверждения
  // бессмыслен: слушателя нет, diagnose всегда вернёт socksListening=false, и
  // расширение начинало «чинить» то, чего не существует (release → HOLD на
  // мёртвом порту). Состояние local-direct выставляется в applyProxyModeNow.
  if (STATE.tunnelKind !== "dpi" && STATE.currentServer?.protocol === "direct" &&
      STATE.proxyMode === "local-direct") {
    STATE.verifyFails = 0;
    return;
  }
  if (ok) {
    STATE.tunnelVerified = true;
    STATE.verifyFails = 0;
    STATE.lastVerifiedAt = Date.now();
    // FIX(5.5.12): вот ТЕПЕРЬ туннель настоящий — обнуляем счётчики
    // восстановления. Раньше они обнулялись на голом «connected» от хоста
    // (который приходит ДО поднятого SOCKS), из-за чего backoff не рос и одна
    // и та же нода перезапускалась каждые 15 c.
    STATE.autoRecoverAttempts = 0;
    STATE.recoveryAttempt = 0;
    STATE.sameNodeRestarts = 0;
    STATE.unverifiedBudgets = 0;
    STATE.lastStartVerified = true;
    markHoldProgress("туннель подтверждён хостом");   // FIX(5.5.9): зачёт прогресса
    journal("verify-ok", d?.via || "diagnose");
    clearTimeout(STATE.verifyTimer);
    STATE.verifyTimer = null;
    // FIX(5.5.4.2): туннель снова подтверждён — удержание закончено
    if (STATE.proxyMode === "holding") STATE.holdSince = null;
    if (STATE.status === "connected" && !STATE.proxyReleasedByUser &&
        (!STATE.proxyArmed || STATE.proxyMode === "holding")) {
      applyProxyMode();            // вооружаемся заново (и выходим из hold)
    }
  } else {
    STATE.tunnelVerified = false;
    // FIX(5.5.12): вердикт по пробе, ушедшей на ДРУГОЙ порт, — не вердикт о
    // туннеле (хост сдвинул SOCKS через autoPort, браузер ещё на старом).
    if (d && d.probedPort && Number(d.probedPort) !== Number(STATE.socksPort)) {
      STATE.verifyFails = 0;
      markHoldProgress(`проба на старый порт ${d.probedPort} — хост слушает ${STATE.socksPort}`);
      journal("verify-stale", `проба на ${d.probedPort} устарела: хост слушает ${STATE.socksPort}`);
      if (STATE.status === "connected" && !STATE.verifyTimer && !STATE.verifyRunning) scheduleVerify();
      return;
    }
    // FIX(5.5.12): режим «Ничего» — прокси снят по воле пользователя,
    // подтверждать нечего. Неудачи не считаем, ноду не перезапускаем.
    if (STATE.tunnelMode === TUNNEL_MODES.OFF) {
      STATE.verifyFails = 0;
      return;
    }
    // FIX(5.5.9): пока хост жуёт пробу сотен серверов (в логе пользователя —
    // «probe: старт 600 серверов (mode=full)»), diagnose отвечает поздно и
    // расширение объявляло «туннель больше не подтверждён» на каждом цикле.
    // Это не смерть туннеля: неудачи НЕ считаем, ноды не переключаем,
    // удержание продлеваем и один раз в 30 c объясняем в UI, что происходит.
    if (probeRunning()) {
      // FIX(5.5.14): продлевать удержание можно, только если есть что держать.
      // В отчёте 6-минутная проба 600 серверов продлевала HOLD на порту, где
      // никто не слушал: браузер сидел без интернета всё это время.
      if (!endpointDead()) markHoldProgress("хост занят пробой серверов — подтверждение задерживается");
      const nowP = Date.now();
      if (STATE.probeWarnAt == null || nowP - STATE.probeWarnAt > 30_000) {
        STATE.probeWarnAt = nowP;
        broadcastUI({
          type: "error",
          message: `Native host сейчас проверяет ${STATE.probe?.total || "?"} серверов — ответы о живости туннеля задерживаются. ` +
                   "Это НЕ обрыв: прокси удерживается на туннеле. Хочешь быстрее — отмени проверку."
        });
      }
      return;
    }
    if (STATE.proxyArmed) {
      STATE.verifyFails++;
      if (STATE.verifyFails >= PROXY_FAIL_LIMIT) {
        const reason = d && d.tunnelAlive === false
          ? "туннель не прошёл проверку живости (контрольный dial через туннель не удался)"
          : d && d.via === "browser-probe" && d.error
            ? "контрольный запрос через SOCKS не прошёл: " + d.error
            : "хост перестал подтверждать туннель (socksListening=false)";
        // FIX(5.5.5): одна серия неудачных diagnose — ещё не смерть. У хоста
        // 5.5.4 liveness-обход сам по себе занимает до 30 c и на медленной
        // бесплатной ноде легко даёт tunnelAlive=false, хотя SOCKS рабочий.
        if (d && d.via !== "browser-probe-confirm") {
          recoverIfConfirmedDead(reason).catch((e) => console.error("[flicker] recover:", e));
        } else {
          recoverFromDeadTunnel(reason);
        }
      }
    }
  }
}

// ================= Локальный DPI-обход (ByeDPI) =================
//
// Отдельный вид туннеля: внешний сервер не нужен, native host не нужен.
// ciadpi поднимает SOCKS5 на этом же компьютере, а FLICKER направляет на него
// трафик браузера. Работает даже когда native host мёртв — что и было главным
// блокером: без хоста расширение раньше не могло сделать вообще ничего.

/**
 * probeThroughProxy — проверить, что локальный SOCKS5 живой.
 *
 * Расширение не умеет открывать raw TCP-сокет, поэтому проверяем реальным
 * запросом. Запрос из background-страницы проходит через proxy.settings, так
 * что это честная проверка именно прокси, а не сети вообще.
 *
 * Самопроверка: параллельно ставим флаг и смотрим, увидел ли наш
 * proxy.onRequest этот URL. Если не увидел — значит запрос ушёл напрямую и
 * результат пробы ничего не доказывает; возвращаем verifiedVia=false, и
 * вызывающий обязан это учесть, а не поверить вслепую.
 *
 * @param {number} port
 * @returns {Promise<{ok:boolean, status?:number, error?:string, verifiedVia:boolean}>}
 */
async function probeThroughProxy(port) {
  const prevMode = STATE.proxyMode;
  STATE.probeInProgress = true;
  STATE.probeRequestSeen = false;
  STATE.probePort = port;

  // FIX(5.5.5) RC-3. ПРЕЖДЕ проба ставила proxyType:"system" и только при
  // успехе возвращалась к боевой manual-настройке. На это время (до 6 c на цель,
  // до 12 c на две) ВЕСЬ трафик браузера шёл мимо VPN — то есть проверка
  // живости сама и устраивала «возврат IP браузеру», причём на каждом цикле.
  //
  // Теперь проба не имеет права открывать окно прямого трафика:
  //   • боевой manual-прокси уже вооружён на этом же порту → запрос расширения
  //     и так идёт через SOCKS, настройки не трогаем ВООБЩЕ;
  //   • не вооружён (или вооружён per-request режим, для которого собственные
  //     запросы расширения идут мимо onRequest) → временно ставим боевой manual
  //     с ПОЛНЫМ passthrough. Это не прямой выход, а наоборот — весь трафик в
  //     туннель; утечки нет, split-tunneling восстанавливается в finally.
  const armed = STATE.lastArmedProxyValue;
  const armedOnThisPort = STATE.proxyArmed && armed?.proxyType === "manual" &&
    (!port || Number(armed.socksPort) === Number(port));

  const oneFetch = async (url) => {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), DPI_PROBE_TIMEOUT_MS);
    try {
      const res = await fetch(url, { signal: ctl.signal, cache: "no-store" });
      // Любой HTTP-статус означает, что соединение через прокси состоялось.
      // Даже 404/503 лучше, чем NetworkError: прокси живой.
      return { ok: true, status: res.status, url };
    } catch (e) {
      return { ok: false, error: String(e?.message || e), url };
    } finally {
      clearTimeout(timer);
    }
  };

  try {
    if (!armedOnThisPort) {
      const built = buildManualValue();
      if (port) built.value.socksPort = port;
      await browser.proxy.settings.set({ value: built.value });
    }
    // FIX(5.5.5) RC-2. Целей несколько. Одна недоступная/заблокированная URL
    // (detectportal.firefox.com регулярно не отвечает из-под отдельных нод)
    // больше не решает судьбу туннеля: пробуем следующую.
    let last = null;
    for (const url of PROBE_TARGETS) {
      last = await oneFetch(url);
      if (last.ok) return { ok: true, status: last.status, url: last.url, verifiedVia: true };
    }
    return { ok: false, error: last?.error || "ни одна контрольная цель не ответила", verifiedVia: true };
  } catch (e) {
    return { ok: false, error: "probe setup: " + String(e?.message || e), verifiedVia: false };
  } finally {
    STATE.probeInProgress = false;
    STATE.probePort = null;
    if (!armedOnThisPort) {
      // возвращаем ровно то, что было до пробы
      if (STATE.proxyArmed && STATE.lastArmedProxyValue) {
        try {
          await browser.proxy.settings.set({ value: STATE.lastArmedProxyValue });
        } catch (e) {
          console.error("[flicker] не удалось вернуть боевой прокси после пробы:", e?.message || e);
        }
      } else {
        try { await setProxyNone(); } catch { /* ignore */ }
        STATE.proxyMode = prevMode;
      }
    }
  }
}

/** dpiNotRunningError — что делать, если ciadpi не запущен. */
function dpiNotRunningError(port, reason) {
  const cmd = buildDpiCommand({ presetId: STATE.dpiPresetId, args: STATE.dpiArgs, port, win: true });
  // Firefox не даёт менять browser.proxy без разрешения на приватные окна
  // (прокси-настройка общая для приватного и обычного браузинга) — это не
  // «прокси мёртв», а «пробу не разрешили». Говорим прямо, что нажать.
  const denied = /private browsing/i.test(reason || "");
  const head = denied
    ? `Firefox не разрешил расширению менять настройки прокси (${reason}). ` +
      `Проверить DPI-прокси не удалось.`
    : `Локальный DPI-прокси не отвечает на 127.0.0.1:${port}.` +
      (reason ? ` (${reason})` : "");
  const deniedFix = denied
    ? `\n\nКак исправить: about:addons → FLICKER VPN → «Разрешить в приватных окнах», ` +
      `затем снова нажмите «Подключиться».`
    : "";
  return head + deniedFix +
    `\n\nЗапусти ByeDPI (скачать: github.com/hufrea/byedpi/releases, архив ` +
    `byedpi-*-x86_64-w64.zip, внутри ciadpi.exe — 129 КБ, лицензия MIT):\n\n` +
    `    ${cmd}\n\n` +
    `Или один раз установи его службой Windows (переживёт перезагрузку): ` +
    `service_install.bat от имени администратора.\n` +
    `Сервер и подписка не нужны.`;
}

/**
 * startDpiTunnel — поднять DPI-обход.
 * Native host не участвует: весь путь — проверка локального прокси и
 * вооружение browser.proxy на его порт.
 */
async function startDpiTunnel(server) {
  const wanted = Number(server?.port) || STATE.dpiPort || FLICKER_DPI_PORT;
  // FIX(5.5.9): native host умеет autoPort — при занятом 1080 он слушает 1081,
  // 1082… Если локальный ciadpi встанет на тот же порт, он не поднимется, а
  // браузеру мы вооружим порт, который никто не слушает (и трафик уйдёт
  // напрямую). Не спорим с хостом за порт.
  const picked = resolveDpiPort({ wanted, taken: [STATE.socksPort] });
  const port = picked.port;
  if (picked.moved) {
    const m = `Порт ${picked.wanted} занят SOCKS5 native host — DPI-обход поднят на ${port}.`;
    console.warn("[flicker] " + m);
    try { journal("dpi-port", m); } catch { /* journal определён ниже по файлу */ }
    broadcastUI({ type: "error", message: m });
  }
  STATE.tunnelKind = "dpi";
  STATE.dpiPort = port;
  STATE.currentServer = server;
  STATE.currentProtocol = "dpi";
  STATE.status = "connecting";
  softLivenessReset();   // FIX(5.5.10): новый режим — учёт отказов dial с нуля
  STATE.bytesSent = 0;
  STATE.bytesReceived = 0;
  STATE.lastSpeedSample = 0;
  STATE.tunnelVerified = false;
  STATE.proxyReleasedByUser = false;
  beginSession(server);
  broadcastUI({ type: "status", status: "connecting" });

  const probe = await probeThroughProxy(port);
  if (!probe.ok) {
    STATE.status = "disconnected";
    STATE.tunnelKind = "native";
    await releaseProxy(`DPI-прокси не отвечает на ${SOCKS_HOST}:${port}`);
    endSession(false, "dpi: прокси не отвечает");
    return { ok: false, error: dpiNotRunningError(port, probe.error) };
  }
  if (!probe.verifiedVia) {
    // Запрос не прошёл через proxy.onRequest — значит прокси мог и не
    // участвовать. Не делаем вид, что всё проверено.
    console.warn("[flicker] DPI-проба не подтверждена onRequest, верим на слово");
    broadcastUI({
      type: "error",
      message: "DPI-прокси ответил, но проверить маршрут не удалось (proxy.onRequest недоступен). Работает, но без контроля живости."
    });
  }

  STATE.tunnelVerified = true;
  STATE.lastVerifiedAt = Date.now();
  STATE.verifyFails = 0;
  STATE.status = "connected";
  STATE.stats.startedAt = Date.now();
  if (STATE.session?.serverId) {
    STATE.session.connectedAt = Date.now();
    STATE.session.bytesSentAtStart = 0;
    STATE.session.bytesReceivedAtStart = 0;
  }
  await applyProxyMode();       // вооружится: tunnelVerified === true
  startWatchdog();
  armStabilityReset();          // FIX(5.5.8): сброс лестницы обрывов после стабильной сессии
  broadcastUI({ type: "status", status: "connected" });
  notify("FLICKER VPN", `DPI-обход включён (127.0.0.1:${port}) — без сервера`);
  return { ok: true, kind: "dpi", port };
}

/** verifyDpi — watchdog-проверка для DPI-режима (вместо diagnose хосту). */
async function verifyDpi() {
  const probe = await probeThroughProxy(STATE.dpiPort || FLICKER_DPI_PORT);
  handleVerifyResult(probe.ok, { socksListening: probe.ok, kind: "dpi" });
  return probe;
}

// ================= Пер-запросная маршрутизация (v5) =================
//
// Firefox-специфичный browser.proxy.onRequest: решение принимается по каждому
// URL, поэтому объём правил не ограничен (в отличие от PAC, где лимит
// ~2048 символов — туда весь список доменов просто не влезает).
// Слушатель регистрируется СТАТИЧЕСКИ (требование MV3 event-pages), а реально
// маршрутизирует только когда соединение поднято.

/**
 * Допустимые значения proxy.ProxyInfo.type (MDN).
 *
 * "socks" — это и есть SOCKS v5. Значения "socks5" В СПЕЦИФИКАЦИИ НЕТ:
 * в версии 5.0.0–5.1.2 здесь возвращался именно "socks5", Firefox не мог
 * разобрать такой ProxyInfo, запрос падал, и у пользователя не грузилась
 * НИ ОДНА страница, пока расширение держало прокси. proxyDNS разрешён
 * только с "socks" и "socks4".
 */
export const PROXY_INFO_TYPES = new Set(["direct", "http", "https", "masque", "socks", "socks4"]);

/** DIRECT — единственный валидный способ сказать «без прокси». */
const DIRECT = { type: "direct" };

function perRequestDecision(url) {
  // Проверка живости локального прокси идёт ДО вооружения: направляем через
  // него только сам probe-URL, весь остальной трафик остаётся прямым. Так
  // окно возможного воздействия — один запрос на несколько секунд.
  if (STATE.probeInProgress && url === DPI_PROBE_URL) {
    STATE.probeRequestSeen = true;
    return [{
      type: "socks",
      host: SOCKS_HOST,
      port: STATE.probePort || activeProxyPort(),
      proxyDNS: true
    }, null];
  }
  // FIX(5.5.4.2): во время удержания (proxyMode === "holding") статус уже
  // "disconnected", но браузер намеренно оставлен на туннеле — маршрутизацию
  // не ломаем, иначе в режиме «Только заблокированное» трафик ушёл бы напрямую.
  // FIX(5.5.14): «Диагностика (direct)» — локальный транспорт: native host не
  // поднимает для него SOCKS-слушатель (в отчёте хост сам пишет «SOCKS5: не
  // слушает»). Направлять запросы на 127.0.0.1:1080 в этом состоянии означало
  // оставить браузер вообще без интернета, причём без fallback: завершающий null
  // в массиве запрещает откат на прокси браузера. Только DIRECT.
  if (STATE.tunnelKind !== "dpi" && STATE.currentServer?.protocol === "direct") return DIRECT;

  // FIX(5.5.14): «Диагностика (direct)» — локальный транспорт: native host не
  // поднимает для него SOCKS-слушатель (в отчёте хост сам пишет «SOCKS5: не
  // слушает»). Направлять запросы на 127.0.0.1:1080 в этом состоянии означало
  // оставить браузер вообще без интернета, причём без fallback: завершающий null
  // в массиве запрещает откат на прокси браузера. Только DIRECT.
  if (STATE.tunnelKind !== "dpi" && STATE.currentServer?.protocol === "direct") return DIRECT;

  // FIX(5.5.14): «Диагностика (direct)» — локальный транспорт: native host не
  // поднимает для него SOCKS-слушатель (в отчёте хост сам пишет «SOCKS5: не
  // слушает»). Направлять запросы на 127.0.0.1:1080 в этом состоянии означало
  // оставить браузер вообще без интернета, причём без fallback: завершающий null
  // в массиве запрещает откат на прокси браузера. Только DIRECT.
  if (STATE.tunnelKind !== "dpi" && STATE.currentServer?.protocol === "direct") return DIRECT;

  const routing = STATE.status === "connected" ||
    (STATE.holdProxy && STATE.proxyMode === "holding");
  if (!STATE.perRequestProxy || !routing) return DIRECT;
  // При активном kill switch запрос всё равно отменит webRequest-блокировка;
  // здесь важно НЕ отправить его в мёртвый туннель.
  if (STATE.killSwitchBlocked) return DIRECT;
  let host = "";
  try { host = new URL(url).hostname; } catch { return DIRECT; }
  if (!host) return DIRECT;
  if (STATE.ruleset.decide({ host }) !== "vpn") return DIRECT;

  // Массив с завершающим null: по MDN без него при недоступности прокси запрос
  // «отваливается» на прокси, заданный в браузере, — то есть трафик ушёл бы
  // мимо VPN. null запрещает этот fallback. Лучше ошибка, чем утечка.
  return [{
    type: "socks",                        // SOCKS v5
    host: SOCKS_HOST,
    port: activeProxyPort(),
    proxyDNS: true
  }, null];
}

function registerPerRequestProxy() {
  if (typeof browser === "undefined" || !browser.proxy?.onRequest?.addListener) {
    STATE.perRequestProxy = false;
    return false;
  }
  try {
    browser.proxy.onRequest.addListener(perRequestDecision, { urls: ["<all_urls>"] });
    STATE.perRequestProxy = true;
    return true;
  } catch (e) {
    console.warn("[flicker] proxy.onRequest недоступен, fallback на manual + passthrough:", e?.message || e);
    STATE.perRequestProxy = false;
    return false;
  }
}

/**
 * proxy.onError — единственный способ увидеть, что Firefox отверг наш ProxyInfo.
 * Без этого слушателя невалидный тип прокси приводил к молчаливому отказу всех
 * запросов: в консоли расширения пусто, у пользователя не грузится ничего.
 */
function registerProxyErrorListener() {
  if (typeof browser === "undefined" || !browser.proxy?.onError?.addListener) return;
  try {
    browser.proxy.onError.addListener((error) => {
      const msg = error?.message || String(error);
      STATE.nativeLastError = STATE.nativeLastError || null;
      STATE.lastProxyError = msg;
      console.error("[flicker] proxy.onError:", msg);
      dbgNative({ command: "dbg", text: "proxy.onError: " + msg });
      // Не спамим тостами: одно сообщение на серию ошибок
      const now = Date.now();
      if (now - (STATE.lastProxyErrorToastAt || 0) > 15_000) {
        STATE.lastProxyErrorToastAt = now;
        broadcastUI({ type: "error", message: "Ошибка прокси: " + msg });
      }
    });
  } catch (e) { console.warn("[flicker] proxy.onError недоступен:", e?.message || e); }
}

try {
  registerPerRequestProxy();
  registerProxyErrorListener();
} catch { STATE.perRequestProxy = false; }

// Kill switch: пер-запросная блокировка. Слушатель регистрируется СТАТИЧЕСКИ
// (требование MV3 event-pages): решение отменяет запрос только пока активен флаг.
try {
  browser.webRequest.onBeforeRequest.addListener(
    () => (STATE.killSwitchBlocked ? { cancel: true } : undefined),
    { urls: ["<all_urls>"] },
    ["blocking"]
  );
} catch (e) {
  console.error("[flicker] webRequest blocker:", e);
}

function releaseKillBlock() {
  if (!STATE.killSwitchBlocked) return;
  STATE.killSwitchBlocked = false;
}

function activateKillSwitch(reason) {
  console.warn("[flicker] kill switch activated:", reason);
  STATE.killSwitchBlocked = true;
  dbgNative({ command: "dbg", text: "killswitch block ON" });
  applyProxyMode();
  broadcastUI({ type: "killswitch", message: "Kill switch активирован — трафик заблокирован" });
  notify("FLICKER VPN", "Соединение потеряно. Kill switch активирован.");
}

/**
 * confirmTunnelDead (FIX 5.5.5) — последний арбитр перед приговором.
 *
 * Смерть туннеля больше не определяется по ОДНОМУ признаку (молчание stats,
 * одинокий diagnose с tunnelAlive=false, ошибка хостового dial). Проверяем
 * независимым способом: реальным HTTP-запросом через наш SOCKS. Если он
 * проходит — туннель жив, прокси не трогаем, счётчик провалов обнуляем.
 *
 * @returns {Promise<boolean>} true — туннель действительно мёртв
 */
/**
 * askHostDiagnose — спросить хост напрямую и дождаться ответа.
 *
 * FIX(5.5.5): раньше единственным «независимым арбитром» был HTTP-запрос во
 * внешний интернет. У пользователя VPN прямой выход как раз и заблокирован,
 * поэтому арбитр систематически отвечал «туннель мёртв» на ЖИВОМ туннеле —
 * расширение слало хосту stop и снимало прокси (RC-2). Ответ хоста о том,
 * слушает ли локальный SOCKS, — вот настоящий источник правды.
 *
 * @param {number} [timeoutMs]
 * @returns {Promise<object|null>} данные diagnose либо null (хост промолчал)
 */
function askHostDiagnose(timeoutMs = HOST_VERDICT_TIMEOUT_MS) {
  return new Promise((resolve) => {
    // предыдущего ждущего освобождаем: ответ придёт один на всех
    if (STATE.diagnoseResolver) {
      const prev = STATE.diagnoseResolver;
      STATE.diagnoseResolver = null;
      prev(null);
    }
    const done = (d) => { clearTimeout(timer); resolve(d); };
    const timer = setTimeout(() => {
      if (STATE.diagnoseResolver === done) { STATE.diagnoseResolver = null; resolve(null); }
    }, timeoutMs);
    STATE.diagnoseResolver = done;
    const sent = sendToNative({ command: "diagnose" });
    if (!sent) { STATE.diagnoseResolver = null; clearTimeout(timer); resolve(null); }
  });
}

/**
 * confirmTunnelDead — умер ли ЛОКАЛЬНЫЙ конец туннеля.
 *
 * ПРАВИЛО (FIX 5.5.5): внешний HTTP-запрос может туннель только ОПРАВДАТЬ,
 * но не имеет права его ОБВИНИТЬ. Обвинение — только за ответом хоста
 * (socksListening/tunnelActive), за молчанием хоста при протухшем heartbeat
 * или за закрытым native-портом.
 *
 * @returns {Promise<boolean>} true — туннель действительно мёртв
 */
async function confirmTunnelDead(reason) {
  if (STATE.status !== "connected") return true;
  if (STATE.switching) return false;               // идёт атомарная смена ноды

  // 1) ОПРАВДАНИЕ. Реальный запрос через наш SOCKS прошёл — туннель жив,
  //    что бы ни говорили косвенные признаки.
  try {
    const pr = await probeThroughProxy(activeProxyPort());
    if (pr?.ok) {
      console.warn("[flicker] туннель ЖИВ (подтверждено запросом через SOCKS), приговор отменён:", reason);
      STATE.probeFailStreak = 0;
      handleVerifyResult(true, { socksListening: true, via: "browser-probe-confirm" });
      return false;
    }
  } catch (e) {
    console.warn("[flicker] confirm probe:", e?.message || e);
  }

  // 2) ОБВИНЕНИЕ — только по хосту.
  const d = await askHostDiagnose();
  if (d) {
    const hostSaysDead = d.socksListening === false ||
      (d.tunnelActive === false && d.socksListening !== true);
    if (!hostSaysDead) {
      console.warn("[flicker] хост подтверждает SOCKS/tunnelActive — приговор отменён:", reason);
      handleVerifyResult(true, { socksListening: true, via: "host-diagnose" });
      return false;
    }
    dbgNative({ command: "dbg", text: "host verdict DEAD: " + JSON.stringify({
      socksListening: d.socksListening, tunnelActive: d.tunnelActive
    })});
    return true;
  }

  // 3) Хост молчит. Молчание само по себе не приговор: смотрим heartbeat.
  const statsFresh = !!STATE.lastStatsAt && (Date.now() - STATE.lastStatsAt) < STATS_STALL_MS;
  if (statsFresh) {
    console.warn("[flicker] хост молчит на diagnose, но heartbeat живой — туннель не гашу:", reason);
    return false;
  }
  dbgNative({ command: "dbg", text: "host silent + stats stale -> DEAD" });
  return true;
}

/**
 * confirmNodeUnusable — жив локальный SOCKS, но нода не пропускает трафик.
 *
 * Это ВТОРАЯ, отдельная неисправность: sing-box слушает, хост рапортует
 * «всё хорошо», а за пределами туннеля ничего не ходит (нода умерла, ключ
 * отозван, канал congested). Лечится не снятием прокси, а заменой ноды —
 * и обязательно БЕЗ возврата IP браузеру (удержание).
 *
 * Требует двух свидетелей: нашей пробы через SOCKS и (либо серии из
 * NODE_UNUSABLE_STREAK провалов, либо хостового tunnelAlive === false).
 *
 * @returns {Promise<boolean>}
 */
async function confirmNodeUnusable(reason) {
  if (STATE.status !== "connected" || STATE.switching) return false;
  if (STATE.tunnelKind !== "native") return false;   // DPI-режим чинится своим путём

  const d = await askHostDiagnose();
  const localOk = !!(d && (d.socksListening === true || d.tunnelActive === true));
  if (!localOk) return false;      // это уже local-dead — пусть решает confirmTunnelDead

  const pr = await probeThroughProxy(activeProxyPort())
    .catch((e) => ({ ok: false, error: String(e?.message || e) }));
  if (pr?.ok) {
    STATE.probeFailStreak = 0;
    handleVerifyResult(true, { socksListening: true, via: "browser-probe-confirm" });
    return false;
  }

  STATE.probeFailStreak++;
  // FIX(5.5.7) RC-4: в мягком режиме `tunnelAlive === false` БОЛЬШЕ НЕ СВИДЕТЕЛЬ.
  //
  // Это и была настоящая причина «обрыв туннеля + возврат прокси браузеру»,
  // которая пережила фиксы 5.5.5/5.5.6. Цепочка:
  //   1. Хост 5.5.4+ в checkAlive dial-ит сквозь туннель три захардкоженные
  //      цели 1.1.1.1:443 / 8.8.8.8:443 / 9.9.9.9:443, по 10 с на каждую.
  //      В хосте 4.0.0 функции checkAlive нет ВООБЩЕ (сравнение бинарников:
  //      checkAlive/liveness/tunnelAlive — 0 вхождений), поэтому старая
  //      связка такой болезни не знает.
  //   2. Все три — IP публичных DNS-резолверов на 443. Они регулярно
  //      блэкхолятся и провайдерами, и выходами VPN, а на медленной
  //      бесплатной ноде 10 с может просто не хватить. Итог: tunnelAlive=false
  //      при полностью ЖИВОМ туннеле и рабочем SOCKS.
  //   3. Здесь это поле раньше единолично объявляло ноду непригодной, в обход
  //      NODE_UNUSABLE_STREAK → смена узла → releaseProxy → proxyType:"none"
  //      → реальный IP наружу.
  //
  // Расширение 5.4.0 поле tunnelAlive не читает ни в одном месте (grep даёт 0
  // вхождений), и его diagnose судит только по socksListening/tunnelActive —
  // ровно поэтому 5.4.0 работает и с хостом 4.0.0, и с 5.5.4.
  //
  // «Мягкий liveness» 5.5.4.3 прикрыл лишь вычисление `ok` (строка ~523) и не
  // тронул это место. Теперь свидетельством считается только НАШ собственный
  // замер: серия из NODE_UNUSABLE_STREAK провалов запроса через SOCKS.
  // strictLiveness=true возвращает прежнее поведение для тех, кому оно нужно.
  const corroborated = STATE.strictLiveness && d.tunnelAlive === false;
  if (STATE.probeFailStreak < NODE_UNUSABLE_STREAK && !corroborated) {
    dbgNative({ command: "dbg", text: `node suspect ${STATE.probeFailStreak}/${NODE_UNUSABLE_STREAK}: ${pr.error || "probe fail"}` });
    return false;
  }
  STATE.probeFailStreak = 0;
  dbgNative({ command: "dbg", text: `node UNUSABLE: probe=${pr.error || "fail"} tunnelAlive=${d.tunnelAlive}` });
  console.warn("[flicker] локальный SOCKS жив, но нода не пропускает трафик — меняю узел:", reason);
  return true;
}

/**
 * recoverIfConfirmedDead — восстановить соединение, но только если неисправность
 * действительно подтверждена. Различает ДВЕ разные поломки:
 *   • local-dead (SOCKS/хост умер)  → recoverFromDeadTunnel по причине reason;
 *   • node-dead  (узел не пускает)  → то же восстановление, но смена ноды,
 *                                     прокси при этом удерживается.
 */
async function recoverIfConfirmedDead(reason) {
  if (STATE.switching || STATE.recovering) return false;
  if (await confirmTunnelDead(reason)) {
    await recoverFromDeadTunnel(reason);
    return true;
  }
  if (await confirmNodeUnusable(reason)) {
    await recoverFromDeadTunnel("узел не пропускает трафик через туннель: " + (reason || ""));
    return true;
  }
  return false;
}

/**
 * scheduleRecovery (FIX 5.5.5) — гарантия, что «прокси возвращён браузеру»
 * не является конечным состоянием.
 *
 * Раньше после releaseProxy не оставалось ни одного таймера: статус висел
 * «подключено» (или resumeServerId ждал своего hello), watchdog был погашен,
 * и расширение больше никогда ничего не спрашивало у хоста. Пользователь
 * сидел без VPN до ручного клика. Теперь попытка вернуть туннель ставится
 * всегда, с backoff 15 → 30 → 60 c, и живёт до явного «Отключить».
 */
function scheduleRecovery(reason) {
  if (STATE.recoveryTimer) return false;
  if (STATE.proxyReleasedByUser) return false;      // пользователь сам снял прокси
  const id = STATE.resumeServerId || STATE.currentServer?.id;
  if (!id) return false;
  const baseDelay = Math.min(
    RECOVERY_RETRY_BASE_MS * Math.pow(2, STATE.recoveryAttempt || 0),
    RECOVERY_RETRY_MAX_MS
  );
  // FIX(5.5.12): карусель — одну ноду перезапускали RESTART_LOOP_MAX раз
  // подряд без подтверждения. Долбить её каждые 15 c бесполезно: пауза растёт.
  const looping = (STATE.sameNodeRestarts || 0) >= RESTART_LOOP_MAX;
  const delay = looping ? Math.max(baseDelay, RESTART_LOOP_BACKOFF_MS) : baseDelay;
  STATE.recoveryAttempt = (STATE.recoveryAttempt || 0) + 1;
  STATE.recoveryTimer = setTimeout(async () => {
    STATE.recoveryTimer = null;
    if (STATE.status === "connected" || STATE.status === "connecting") {
      // FIX(5.5.12): backoff обнуляем только если туннель ПОДТВЕРЖДЁН.
      if (STATE.tunnelVerified) STATE.recoveryAttempt = 0;
      return;
    }
    if (STATE.proxyReleasedByUser) return;
    try {
      const servers = await getServers();
      // FIX(5.5.8): цель выбираем ЗДЕСЬ, а не в момент постановки таймера, и не
      // одну и ту же вечно: pickRecoveryTarget учитывает обрывы нод, потолок
      // задержки, блок-лист и ступень эскалации.
      let pick = pickRecoveryTarget(servers, reason);
      // FIX(5.5.12): принудительный уход со ступени «same», если нода
      // перезапускалась RESTART_LOOP_MAX раз подряд и так и не подтвердилась.
      // В отчёте пользователя хост получал start той же ноды каждые ~20 c
      // (switch: de15 -> de15, ступень=same, попытка=0).
      if (pick.stage === "same" && (STATE.sameNodeRestarts || 0) >= RESTART_LOOP_MAX) {
        const savedAttempt = STATE.recoveryAttempt;
        // ступень «same» доступна только при attempt ≤ 1 — поднимаем планку
        STATE.recoveryAttempt = Math.max(savedAttempt, 2);
        const rotated = pickRecoveryTarget(servers, reason + " | карусель перезапусков");
        STATE.recoveryAttempt = savedAttempt;
        if (rotated.server && rotated.server.id !== pick.server?.id) {
          journal("restart-loop",
            `нода ${pick.server?.id} не подтвердилась ${STATE.sameNodeRestarts} раз подряд — ухожу на ${rotated.server.id} (${rotated.stage})`);
          broadcastUI({
            type: "error",
            message: `Узел не подтверждается ${STATE.sameNodeRestarts} раз подряд — больше не перезапускаю его каждые 15 c, пробую другой (${rotated.stage}).`
          });
          pick = rotated;
        } else {
          journal("restart-loop",
            `нода ${pick.server?.id || "-"} не подтвердилась ${STATE.sameNodeRestarts} раз подряд, альтернатив нет — пауза ${Math.round(RESTART_LOOP_BACKOFF_MS / 1000)} c`);
        }
      }
      const srv = pick.server;
      if (!srv) {
        broadcastUI({ type: "error", message: "Восстановление: в списке нет ни одного сервера. Обновите подписку или добавьте свой." });
        scheduleRecovery("нет серверов для восстановления");
        return;
      }
      const fromId = STATE.resumeServerId || null;
      // FIX(5.5.9): новая попытка восстановления — это прогресс: удержание
      // продлевается, пока мы реально работаем, а не пока не истечёт таймер
      markHoldProgress(`попытка ${STATE.recoveryAttempt}: ${pick.stage} → ${srv.id}`);
      journal("recovery", `попытка ${STATE.recoveryAttempt} ступень ${pick.stage} нода ${srv.id}${pick.note ? " | " + pick.note : ""}`);
      if (pick.stage !== STATE.recoveryStage) {
        STATE.recoveryStage = pick.stage;
        broadcastUI({ type: "recoveryStage", stage: pick.stage, attempt: STATE.recoveryAttempt, note: pick.note || null, suspectedDpi: !!STATE.suspectedDpi });
        if (pick.note) notify("FLICKER VPN", pick.note);
        if (pick.stage === "escalate" && STATE.suspectedDpi) {
          broadcastUI({
            type: "error",
            message: "Похоже на DPI-блокировку: туннели одного профиля рвутся на разных нодах. " +
                     "Что помогает: ноды Reality/TLS-443, «матрёшка» (WG через VLESS), DPI-режим, " +
                     "свой сервер на AmneziaWG (конфиг можно вставить в карточке сервера)."
          });
        }
      }
      // намерение переводим на выбранную ноду — иначе следующий заход снова возьмёт мёртвую
      STATE.resumeServerId = srv.id;
      STATE.lastRecovery = { at: Date.now(), attempt: STATE.recoveryAttempt, stage: pick.stage, serverId: srv.id, fromId, reason: reason || null };
      broadcastUI({ type: "autoRecover", attempt: STATE.recoveryAttempt, stage: pick.stage, serverId: srv.id, fromId, reason: reason || null, note: pick.note || null });
      const r = await startTunnel(srv);
      if (!r?.ok) {
        noteTunnelDeath(srv.id, String(r?.error || "start не удался"), transportFingerprint(srv));
        scheduleRecovery("повтор не удался: " + (r?.error || "?"));
      }
    } catch (e) {
      console.warn("[flicker] recovery:", e?.message || e);
      scheduleRecovery("ошибка восстановления: " + (e?.message || e));
    }
  }, delay);
  return true;
}

/** FIX(5.5.12): снять таймер восстановления, НЕ обнуляя backoff. */
function clearRecoveryTimer() {
  clearTimeout(STATE.recoveryTimer);
  STATE.recoveryTimer = null;
}

function clearRecovery() {
  clearRecoveryTimer();
  STATE.recoveryAttempt = 0;
}

// ================= FIX(5.5.8): лестница эскалации восстановления =================

/** «Медленная» нода по текущему потолку задержки (неизмеренные не считаются). */
function isTooSlow(s) {
  const lim = Number(STATE.maxPingMs) || 0;
  if (lim <= 0) return false;
  return typeof s?.ping === "number" && s.ping > lim;
}
function countSlow(list) { return (list || []).filter(isTooSlow).length; }

/** Транспортный профиль: обрывы одного профиля на разных нодах = похоже на DPI. */
function transportFingerprint(s) {
  if (!s) return "none";
  const tr = (s.transport && (s.transport.type || s.transport.net)) || "";
  const tls = s.tlsEnabled || s.reality?.publicKey ? "tls" : "plain";
  const awg = s.protocol === "wireguard" && s.wireguard?.amnezia ? "awg" : "";
  return [s.protocol || "?", tr, tls, awg, s.detour ? "detour:" + (s.detour.protocol || "?") : ""].join("|");
}

/** Запомнить обрыв ноды (скользящее окно DEATH_WINDOW_MS). Возвращает число обрывов. */
function noteTunnelDeath(serverId, reason, fp) {
  if (!serverId) return 0;
  const now = Date.now();
  const arr = (STATE.deaths.get(serverId) || []).filter((t) => now - t <= DEATH_WINDOW_MS);
  arr.push(now);
  STATE.deaths.set(serverId, arr);
  if (fp) STATE.lastRecoveryFp.set(serverId, fp);
  // DPI-подозрение: >= DEATHS_BEFORE_ROTATE обрывов на >= 2 разных нодах ОДНОГО профиля
  try {
    const byFp = new Map();
    for (const [id, ts] of STATE.deaths) {
      if (ts.length < DEATHS_BEFORE_ROTATE) continue;
      const f = STATE.lastRecoveryFp.get(id);
      if (!f) continue;
      byFp.set(f, (byFp.get(f) || 0) + 1);
    }
    for (const [, n] of byFp) if (n >= 2) STATE.suspectedDpi = true;
  } catch { /* эвристика не должна ломать восстановление */ }
  if (reason) console.warn(`[flicker] обрыв ноды ${serverId} (${arr.length} за ${Math.round(DEATH_WINDOW_MS / 60000)} мин): ${reason}`);
  return arr.length;
}

function deathsInWindow(serverId) {
  if (!serverId) return 0;
  const now = Date.now();
  const all = STATE.deaths.get(serverId) || [];
  const arr = all.filter((t) => now - t <= DEATH_WINDOW_MS);
  if (arr.length !== all.length) STATE.deaths.set(serverId, arr);
  return arr.length;
}

function byPingAsc(list) {
  const val = (s) => (typeof s?.ping === "number" && s.ping >= 0 ? s.ping : (isTooSlow(s) ? 1e7 : 1e6));
  return (list || []).slice().sort((a, b) => val(a) - val(b));
}

/** DPI-устойчивый профиль: TLS/443 (ws/grpc/Reality) или AmneziaWG. */
function isDpiResistant(s) {
  const tr = (s?.transport && (s.transport.type || s.transport.net)) || "";
  const tls443 = !!(s && (s.tlsEnabled || s.reality?.publicKey) &&
    (Number(s.port) === 443 || tr === "ws" || tr === "grpc" || !!s.reality?.publicKey));
  return tls443 || !!(s && s.protocol === "wireguard" && s.wireguard?.amnezia);
}

/**
 * isAutoSelectable — какие ноды автовыбор вообще рассматривает.
 * PROBABLE_PROTOCOLS исторически не содержит wireguard: «голый» WG-handshake DPI
 * определяет и рвёт первым, поэтому автовыбор на таких нодах давал цикл обрывов.
 * AmneziaWG — исключение: обфускация как раз для того, чтобы выживать под DPI.
 */
function isAutoSelectable(s) {
  if (!s) return false;
  if (PROBABLE_PROTOCOLS.has(s.protocol)) return true;
  return s.protocol === "wireguard" && !!(s.wireguard && s.wireguard.amnezia);
}

/**
 * pickRecoveryTarget — какую ноду поднимать на очередной попытке восстановления.
 *   ступень 1 (same)     — 1–2 попытки на прежней ноде: обрыв мог быть разовым;
 *   ступень 2 (rotate)   — нода умирает повторно → другая нода, желательно с
 *                          ДРУГИМ транспортным профилем (иначе положат так же);
 *   ступень 3 (escalate) — >= STAGE_ESCALATE_AFTER попыток или все ноды в
 *                          обрывах → DPI-устойчивый профиль (TLS/443, AWG).
 * Тупик «нечего пробовать» запрещён: цель возвращается всегда, если список непуст.
 */
function pickRecoveryTarget(servers, reason) {
  const attempt = STATE.recoveryAttempt || 0;
  const resumeId = STATE.resumeServerId || STATE.currentServer?.id || null;
  // FIX(5.5.8): локальные транспорты и демо-ноды целями восстановления НЕ
  // являются. «direct» — это вообще не VPN, «dpi» — отдельный режим обхода без
  // сервера: молча перевести туда пользователя значит подменить ему VPN.
  // Исключение — если он в этом режиме и сидел (тогда возвращаем именно его).
  const list = (servers || []).filter((s) => s && s.id && !s.demo &&
    s.protocol !== "direct" &&
    (s.protocol !== "dpi" || s.id === resumeId));
  if (!list.length) return { server: null, stage: "none", note: "нет серверов" };
  // FIX(5.5.11): «дырка» в фильтре выше. Исключение для resume-ноды искали по
  // ПОЛНОМУ списку, поэтому direct снова становился целью восстановления
  // (именно так в отчёте пользователя на старте поднялся узел diag). Исключение
  // оставляем только для dpi — это отдельный пользовательский режим обхода,
  // а direct не является VPN ни в каком виде.
  const resumeRaw = (servers || []).find((s) => s && s.id === resumeId) || null;
  const resume = list.find((s) => s.id === resumeId) ||
    (resumeRaw && resumeRaw.protocol === "dpi" ? resumeRaw : null);
  const deaths = resumeId ? deathsInWindow(resumeId) : 0;
  const blocked = (s) => !!s.blocked || isServerDead(s) || isTooSlow(s) || deathsInWindow(s.id) >= DEATHS_BEFORE_ROTATE;

  // ступень 1
  if (resume && attempt <= 1 && deaths < DEATHS_BEFORE_ROTATE && !blocked(resume)) {
    return { server: resume, stage: "same", note: null };
  }

  const badFp = resume ? (STATE.lastRecoveryFp.get(resume.id) || transportFingerprint(resume)) : null;
  const pool = list.filter((s) => !blocked(s));

  // ступень 3: жёсткая эскалация
  if (attempt >= STAGE_ESCALATE_AFTER || (!pool.length && attempt >= 2)) {
    const src = pool.length ? pool : list;
    const resistant = src.filter(isDpiResistant);
    const pick = resistant.length
      ? (pickBestAlive(resistant) || byPingAsc(resistant)[0])
      : (pickBestAlive(src) || byPingAsc(src)[0]);
    if (pick) {
      return {
        server: pick, stage: "escalate",
        note: resistant.length
          ? "все ноды в обрывах — перехожу на DPI-устойчивый профиль (TLS/443 или AmneziaWG)"
          : "DPI-устойчивых нод в списке нет — пробую наименее проблемную"
      };
    }
  }

  // ступень 2: ротация
  if (pool.length) {
    const other = badFp ? pool.filter((s) => transportFingerprint(s) !== badFp) : pool;
    const cand = other.length ? other : pool;
    const pick = pickBestAlive(cand) || byPingAsc(cand)[0] || cand[0];
    if (pick) {
      return {
        server: pick, stage: "rotate",
        note: resume && pick.id !== resume.id
          ? `нода «${resume.name || resume.host}» оборвалась ${deaths} раз(а) за ${Math.round(DEATH_WINDOW_MS / 60000)} мин — меняю на «${pick.name || pick.host}»`
          : null
      };
    }
  }

  const fallback = pickBestAlive(list) || byPingAsc(list)[0] || resume || list[0];
  return { server: fallback || null, stage: "rotate", note: "свободных нод нет — пробую наименее проблемную" };
}

/** Сброс лестницы после стабильной сессии (иначе обрывы копятся вечно). */
function armStabilityReset() {
  clearTimeout(STATE.stabilityTimer);
  STATE.stabilityTimer = setTimeout(() => {
    STATE.stabilityTimer = null;
    if (STATE.status !== "connected") return;
    if (STATE.deaths.size || STATE.recoveryStage !== "same" || STATE.suspectedDpi) {
      STATE.deaths.clear();
      STATE.lastRecoveryFp.clear();
      STATE.recoveryStage = "same";
      STATE.suspectedDpi = false;
      STATE.awgUnsupportedWarned = false;
      console.warn("[flicker] сессия стабильна " + Math.round(STABLE_SESSION_MS / 1000) + " c — счётчики обрывов сброшены");
      broadcastUI({ type: "recoveryStage", stage: "same", reset: true });
    }
  }, STABLE_SESSION_MS);
}

function handleTunnelLost(reason) {
  console.warn("[flicker] tunnel lost:", reason);
  journal("tunnel-lost", reason || "?");
  // 5.5.4: обрыв не по воле пользователя — запоминаем намерение: когда хост
  // вернётся (hello), туннель будет поднят заново на той же ноде автоматически.
  if ((STATE.status === "connected" || STATE.status === "connecting") && STATE.currentServer?.id) {
    STATE.resumeServerId = STATE.currentServer.id;
    // FIX(5.5.8): учитываем обрыв — после DEATHS_BEFORE_ROTATE восстановление
    // уйдёт на другую ноду/профиль, а не будет долбить эту же
    noteTunnelDeath(STATE.currentServer.id, reason, transportFingerprint(STATE.currentServer));
  }
  endSession(true, reason);     // обрыв → минус в рейтинг текущей ноды
  STATE.status = "disconnected";
  STATE.currentSpeed = 0;
  if (STATE.killSwitchEnabled) {
    activateKillSwitch(reason);
  } else {
    applyProxyMode();
  }
  // FIX(5.5.5): если хост не вернётся сам (hello не будет), туннель всё равно
  // надо попробовать поднять — иначе «прокси возвращён браузеру» навсегда.
  scheduleRecovery("обрыв туннеля: " + reason);
}

/**
 * recoverFromDeadTunnel (5.5.4) — туннель признан мёртвым (liveness-удары,
 * контрольная проба, молчание статистики). Раньше здесь был тупик: прокси
 * освобождался, висело «Туннель не работает — прокси возвращён браузеру»,
 * а статус оставался «подключено» и ничего не переподключалось. Теперь:
 * гасим зомби на хосте, сбрасываем статус, минусуем ноду в рейтинг и —
 * если kill switch выключен — автоматически переключаемся на лучшего из
 * живых (не более 3 попыток подряд: дальше уже не угадаем, нужна свежая
 * подписка или выбор пользователя).
 */
async function recoverFromDeadTunnel(reason) {
  // FIX(5.5.5): защита от повторного входа — watchdog, keepalive-alarm и цикл
  // подтверждения могут сработать почти одновременно; два параллельных
  // восстановления рвали туннель и путали STATE.switching.
  if (STATE.recovering) return;
  STATE.recovering = true;
  try {
    const deadId = STATE.currentServer?.id || null;
    releaseProxy(reason);
    sendToNative({ command: "stop" });
    endSession(true, reason);
    STATE.status = "disconnected";
    STATE.currentSpeed = 0;
    STATE.tunnelVerified = false;
    // намерение поднять туннель заново запоминаем ВСЕГДА (в 5.5.4 ветка
    // kill switch выходила раньше, и восстановление становилось невозможным:
    // трафик заблокирован навсегда, повтор не назначен)
    if (deadId) {
      STATE.resumeServerId = deadId;
      // FIX(5.5.8): учёт обрывов для ротации нод и диагностики DPI
      noteTunnelDeath(deadId, reason, transportFingerprint(STATE.currentServer));
    }
    broadcastUI({ type: "status", status: STATE.status });

    if (STATE.killSwitchEnabled) {
      activateKillSwitch(reason);
      scheduleRecovery("kill switch: жду живую ноду");
      return;
    }
    if ((STATE.autoRecoverAttempts || 0) >= 3) {
      broadcastUI({
        type: "error",
        message: "Три сервера подряд не вытянули туннель. Обновите подписку " +
                 "(вкладка «Серверы» → «Обновить») или добавьте свой сервер."
      });
      scheduleRecovery("исчерпаны автопереключения");
      return;
    }
    STATE.autoRecoverAttempts = (STATE.autoRecoverAttempts || 0) + 1;
    const servers = await getServers();
    const next = pickBestAlive(servers, deadId);
    if (!next) {
      broadcastUI({
        type: "error",
        message: "Среди серверов подписки сейчас нет проверенно живых. Обновите подписку " +
                 "(вкладка «Серверы» → «Обновить») или добавьте свой сервер."
      });
      scheduleRecovery("нет проверенно живых нод");
      return;
    }
    notify("FLICKER VPN", `Сервер не вытянул — переключаюсь на «${next.name || next.host}»`);
    broadcastUI({ type: "autoSwitch", from: deadId, to: next.id, message: reason });
    const r = await switchServer(next);
    if (!r?.ok) {
      broadcastUI({ type: "error", message: "Автопереключение не удалось: " + (r?.error || "?") });
      // switchServer внутри мог вызвать stopTunnel и сбросить намерение —
      // возвращаем его, иначе восстановление закончится тупиком
      if (!STATE.resumeServerId) STATE.resumeServerId = deadId || next.id || null;
      scheduleRecovery("автопереключение не удалось");
    }
  } finally {
    STATE.recovering = false;
  }
}

function notify(title, message) {
  try {
    browser.notifications?.create({
      type: "basic",
      iconUrl: "icons/icon-128.png",
      title,
      message
    });
  } catch (e) { /* notifications опциональны */ }
}

/**
 * describeNativeFailure — человекочитаемая причина, по которой native host
 * не поднял туннель. В версии 4 здесь всегда было одно и то же сообщение
 * «Native host не ответил на команду start: проверьте установку
 * (native/install.sh)», которое (а) прятало настоящую причину от Firefox и
 * (б) на Windows отправляло запускать shell-скрипт для Linux.
 */
/**
 * nativeHostChecklist — что проверить, если native host не запускается.
 * Возвращает массив строк; используется и в тексте ошибки, и в diagnose,
 * и на странице настроек.
 */
export function nativeHostChecklist() {
  const ua = (typeof navigator !== "undefined" && navigator.userAgent) || "";
  const isWin = /Windows/i.test(ua);
  if (isWin) {
    return [
      "1. «Параметры → Приложения» — есть ли в списке «FLICKER VPN»? Если нет — запусти установщик FlickerVPN-Setup-5.5.4.exe (права администратора НЕ нужны: установка per-user).",
      "2. reg query \"HKCU\\Software\\Mozilla\\NativeMessagingHosts\\com.flicker.vpn\" /ve  — ключ должен существовать и указывать на com.flicker.vpn.json.",
      "3. Открой этот .json: \"name\" должен быть ровно com.flicker.vpn, \"path\" — вести на существующий .exe, \"allowed_extensions\" — содержать flicker-vpn@local.dev.",
      "4. Запусти хост вручную из cmd: %LOCALAPPDATA%\\flicker-vpn\\flicker-host.exe -version — должен напечатать «flicker-host 5.5.4». Если не запускается — мешает антивирус/SmartScreen (разреши приложение).",
      "5. Антивирус/SmartScreen мог заблокировать или удалить exe: файл скачан из интернета и помечен Mark-of-the-Web. Сними блокировку: свойства файла → «Разблокировать».",
      "6. netstat -ano | findstr :1080  — порт не должен быть занят; если занят, поменяй его на странице настроек расширения.",
      "7. После любого из пунктов полностью перезапусти Firefox (не только окно)."
    ];
  }
  return [
    "1. Установлен ли native host: native/install.sh (Linux) или native/install.ps1 (Windows).",
    "2. Файл манифеста должен лежать в ~/.mozilla/native-messaging-hosts/com.flicker.vpn.json и иметь \"path\" на существующий исполняемый файл с правом +x.",
    "3. Запусти хост вручную из терминала — падение при старте видно сразу.",
    "4. Проверь, что порт 1080 не занят: ss -lntp | grep 1080.",
    "5. Перезапусти Firefox."
  ];
}

function describeNativeFailure(reason) {
  const ua = (typeof navigator !== "undefined" && navigator.userAgent) || "";
  const isWin = /Windows/i.test(ua);
  const hint = isWin
    ? "Запустите установщик FlickerVPN-Setup-5.5.4.exe ещё раз: он ставится per-user (без прав администратора и без драйверов), сам перезаписывает манифест с ключом реестра и проверяет запуск хоста."
    : "Запустите native/install.sh (Linux) или native/install.ps1 (Windows) и перезапустите Firefox.";
  const r = String(reason || "");
  if (/no such native application|not found|не найден|does not exist/i.test(r)) {
    return `Native host «${NATIVE_HOST_NAME}» не зарегистрирован в системе. ${hint} Причина от Firefox: ${r}`;
  }
  if (/forbidden|access to the specified|разрешен|не разреш/i.test(r)) {
    return `Native host отказал расширению: guid не совпадает с allowed_extensions в его манифесте (ожидается flicker-vpn@local.dev). ${hint} Причина от Firefox: ${r}`;
  }
  if (/specified native messaging host|invalid|ошибк|malformed/i.test(r)) {
    return `Манифест native host повреждён или ссылается на отсутствующий исполняемый файл. ${hint} Причина от Firefox: ${r}`;
  }
  if (/communication error|pipe|closed|connection/i.test(r)) {
    return `Native host закрыл соединение сразу после старта — процесс запустился и упал. Чаще всего: процесс упал сразу после запуска, порт ${SOCKS_HOST}:${STATE.socksPort} занят, или антивирус заблокировал запуск. ${hint} Причина от Firefox: ${r}`;
  }
  // Firefox не смог запустить процесс хоста и не сообщил конкретики.
  // «An unexpected error occurred» — generic-ответ на: манифест указывает на
  // отсутствующий/неисполняемый файл, exe заблокирован антивирусом или
  // Mark-of-the-Web, процесс падает до записи первого кадра, либо хост пишет
  // невалидный native-messaging фрейм (нет 4-байтового префикса длины).
  if (/unexpected error|непредвиденн|неизвестн/i.test(r)) {
    return `Firefox не смог запустить процесс native host (generic-ошибка: ${r}). Это НЕ проблема расширения — до процесса дело не дошло.\n\n${hint}\n\nПроверь по шагам:\n${nativeHostChecklist().join("\n")}`;
  }
  if (r) return `Native host недоступен: ${r}. ${hint}\n\n${nativeHostChecklist().slice(0, 4).join("\n")}`;
  return `Native host не ответил на команду start за 2.5 c. Порт открылся, но хост молчит: процесс запустился и завис, либо отклонил конфиг. Проверьте права администратора, занятость порта ${SOCKS_HOST}:${STATE.socksPort} и лог хоста. ${hint}`;
}

// ================= Конфигурация туннеля =================

/**
 * FIX(5.5.13): получает ли хост наши правила маршрутизации вообще.
 *
 * composeConfig кладёт routeRules/tunnelMode в конфиг ТОЛЬКО при этом cap —
 * иначе Go-хост (5.5.4) не знает таких полей и молча их игнорирует. Значит
 * атомарный рестарт туннеля «чтобы правила уехали в sing-box» при таком хосте
 * не доставляет правил НИКУДА: маршрутизацию держит proxy.settings, который
 * переустанавливается на месте. Рестарт в этом случае — только разрыв и окно
 * прямого трафика (в дампе: «switch: 193.124.35.241 -> 193.124.35.241» на
 * смене режима all → smart).
 *
 * @returns {boolean}
 */
function nativeSupportsRouteRules() {
  const caps = STATE.nativeCaps || new Set();
  return caps.has("routeRules") || caps.has("route-rules") || caps.has("routing") ||
    STATE.advanced?.forceRouteRules === true;
}

function composeConfig(server) {
  const proto = getProtocol(server.protocol);
  if (!proto) return { ok: false, error: "Неизвестный протокол: " + server.protocol };

  // Нормализация + валидация (сначала build, потом validate)
  let cfg;
  try {
    cfg = buildServerConfig(server);
  } catch (e) {
    return { ok: false, error: String(e?.message || e) };
  }
  cfg.listen = `${SOCKS_HOST}:${STATE.socksPort}`;
  // v5: системные правила маршрутизации (в т.ч. CIDR, невыразимые в браузерном
  // прокси) шлём ТОЛЬКО если хост объявил поддержку в hello.caps.
  //
  // Почему не всегда: хост 4.0.0 не знает полей routeRules/tunnelMode. Go при
  // json.Unmarshal неизвестные поля по умолчанию игнорирует, но если там
  // включён DisallowUnknownFields или sing-box валидирует конфиг строго —
  // хост отклонит конфиг или упадёт, а пользователь увидит лишь «не ответил на
  // start». Цена ошибки слишком высока, поэтому по умолчанию не шлём.
  // Браузерная маршрутизация (proxy.onRequest) от этого не зависит и работает.
  //
  // Принудительно включить для проверки: advanced.forceRouteRules = true.
  // FIX(5.5.8): AmneziaWG (анти-DPI WireGuard: Jc/Jmin/Jmax/S1/S2/H1..H4).
  // ВАЖНО: upstream sing-box эти параметры НЕ поддерживает (в его
  // wireguard-outbound нет amnezia_wg), поэтому блок уходит хосту только если он
  // сам объявил caps amnezia/amneziawg/awg. Иначе — явное предупреждение, а не
  // видимость работающей обфускации: тихий игнор дал бы ровно те же обрывы.
  if (cfg.wireguard && cfg.wireguard.amnezia) {
    const c = STATE.nativeCaps || new Set();
    const hostAwg = c.has("amnezia") || c.has("amneziawg") || c.has("awg") || STATE.advanced?.forceAmnezia === true;
    if (hostAwg) {
      cfg.wireguard = { ...cfg.wireguard, amnezia_wg: toSingBoxAmnezia(cfg.wireguard.amnezia) };
    } else {
      cfg.wireguard = { ...cfg.wireguard, amnezia: undefined };
      STATE.awgUnsupported = true;
      if (!STATE.awgUnsupportedWarned) {
        STATE.awgUnsupportedWarned = true;
        const m = "AmneziaWG: native host не объявил поддержку (в hello.caps нет «amnezia»). Параметры сохранены в карточке сервера, " +
                  "но туннель пойдёт обычным WireGuard — DPI может его обрывать. Варианты: обновить native host, взять ноду " +
                  "Reality/TLS-443 («матрёшка»), включить DPI-режим или поднять свой сервер на AmneziaWG. " +
                  "Послать параметры принудительно: advanced.forceAmnezia = true.";
        console.warn("[flicker] " + m);
        broadcastUI({ type: "error", message: m });
      }
    }
  }

  // FIX(5.5.13): условие вынесено в nativeSupportsRouteRules() — оно же решает,
  // нужен ли атомарный рестарт туннеля при смене режима маршрутизации.
  if (nativeSupportsRouteRules()) {
    cfg.routeRules = toSingBoxRules(STATE.ruleset);
    cfg.tunnelMode = STATE.tunnelMode;
  }

  const validation = validateServerConfig(cfg);
  if (!validation.valid) return { ok: false, error: validation.errors.join("; ") };
  return { ok: true, config: cfg };
}

// ================= Подключение / отключение =================

async function startTunnel(server) {
  // FIX(5.5.13): любой старт — намерение держать туннель. Снимаем метку
  // «выключено пользователем», иначе следующий неожиданный «disconnected»
  // останется без восстановления.
  STATE.stoppedByUser = false;
  // DPI-обход не требует ни сервера, ни native host — отдельный путь
  if (server?.protocol === "dpi") return startDpiTunnel(server);

  // 5.5.3: со старым хостом (4.x) не стартуем: он не подтвердит туннель
  // (diagnose), и пользователь получит загадочный сброс вместо инструкции.
  if (STATE.nativeCompat === "old") {
    return { ok: false, error: hostOutdatedError(STATE.nativeInfo?.version) };
  }

  const composed = composeConfig(server);
  if (!composed.ok) return { ok: false, error: composed.error };

  STATE.currentServer = server;
  STATE.currentProtocol = composed.config.protocol;
  // FIX(5.5.9): «Диагностика (direct)» даёт connected и вооружённый прокси, но
  // трафик идёт НАПРЯМУЮ. По диагностике пользователя был выбран именно этот
  // узел — то есть «VPN работает» при отсутствии VPN. Говорим прямо.
  if (isLocalTransport(server)) warnDirectNode(server);
  softLivenessReset();   // FIX(5.5.10): новая нода — счётчик отказов dial с нуля
  STATE.lastStartAt = Date.now();   // FIX(5.5.11): отсчёт грации после старта
  // FIX(5.5.12): учёт карусели — сколько раз подряд поднимаем ОДНУ И ТУ ЖЕ
  // ноду, так и не дождавшись подтверждения туннеля.
  if (STATE.lastStartServerId === (server?.id || null) && !STATE.lastStartVerified) {
    STATE.sameNodeRestarts = (STATE.sameNodeRestarts || 0) + 1;
  } else {
    STATE.sameNodeRestarts = 0;
  }
  STATE.lastStartServerId = server?.id || null;
  STATE.lastStartVerified = false;
  STATE.lastRestartAt = Date.now();
  journal("start", `${server?.id || "?"} ${composed.config.protocol} ${server?.host || ""}:${server?.port || ""}`);
  STATE.status = "connecting";
  STATE.bytesSent = 0;
  STATE.bytesReceived = 0;
  STATE.lastSpeedSample = 0;
  beginSession(server);

  const sent = sendToNative({ command: "start", config: composed.config });
  if (!sent) {
    STATE.status = "disconnected";
    const reason = STATE.nativeLastError || ERRORS.NATIVE_MISSING;
    endSession(false, "native host недоступен: " + reason);
    return { ok: false, error: describeNativeFailure(reason) };
  }
  // Ждём любой ответ хоста (ack): молчание = хост не установлен/мёртв.
  const ack = await new Promise((resolve) => {
    STATE.startAckResolver = resolve;
    setTimeout(() => {
      if (STATE.startAckResolver === resolve) {
        STATE.startAckResolver = null;
        resolve(null);
      }
    }, 2500);
  });
  // ack === null → хост промолчал 2.5 c; ack.type === "__portClosed" → порт
  // закрылся, и в ack.error лежит НАСТОЯЩАЯ причина от Firefox
  if (!ack || ack.type === "__portClosed") {
    STATE.status = "disconnected";
    const reason = ack?.error || null;
    endSession(false, reason ? "native host: " + reason : "native host не ответил на start");
    return { ok: false, error: describeNativeFailure(reason) };
  }
  // watchdog: 20 c (рукопожатие у хоста живёт до 15 c — 5-секундный watchdog
  // версии 5.5.2 добивал медленные, но живые серверы посреди handshake).
  // При срабатывании гасим полустарт на хосте, чтобы поздний «connected»
  // не вооружил прокси задним числом.
  clearTimeout(STATE.connectWatchdog);
  STATE.connectWatchdog = setTimeout(() => {
    if (STATE.status === "connecting") {
      sendToNative({ command: "stop" });
      STATE.status = "disconnected";
      const reason = STATE.nativeLastError || "watchdog: статус подключения не пришёл за 20 c";
      endSession(false, reason);   // нода не подняла туннель → минус в рейтинг
      broadcastUI({ type: "error", message: describeNativeFailure(STATE.nativeLastError) });
      applyProxyMode();
    }
  }, 20_000);
  return { ok: true, pending: true };
}

async function stopTunnel(byUser = true) {
  // FIX(5.5.5): «не воскрешать» — это про ЯВНОЕ нажатие «Отключить».
  // Внутренние вызовы (откат при смене ноды, смерть текущего сервера)
  // намерение сбрасывать не должны: иначе авто-восстановление обрывалось
  // на первом же неудачном переключении и расширение вставало в тупик.
  if (byUser) {
    STATE.stoppedByUser = true;   // FIX(5.5.13): руками выключено — не воскрешать
    STATE.resumeServerId = null;
    STATE.proxyReleasedByUser = false;
    clearRecovery();
    await clearPersistedSession();   // FIX(5.5.5): «Отключить» — намерение явное
  }
  // FIX(5.5.13): явное/аварийное отключение — следующий «disconnected»
  // настоящий, глотать его нельзя (иначе статус залипнет в «connecting»).
  STATE.pendingStopAck = false;
  // для DPI-режима native host не задействован — слать stop некому
  if (STATE.tunnelKind !== "dpi") sendToNative({ command: "stop" });
  endSession(false);            // штатное закрытие → успешный замер с реальной скоростью
  STATE.status = "disconnected";
  STATE.tunnelVerified = false;
  STATE.tunnelKind = "native";
  STATE.currentSpeed = 0;
  STATE.stats.startedAt = null;
  releaseKillBlock();
  await applyProxyMode();
}

/**
 * switchServer — атомарная смена ноды (v5, исправление бага версии 4).
 *
 * Как было: popup.selectServer() только перерисовывал шапку (флаг, имя,
 * протокол, пинг), а туннель оставался на старой ноде. Пользователь видел
 * «подключено к B», хотя трафик шёл через A. Реальная смена требовала
 * disconnect → connect, и между ними applyProxyMode() снимал маршрутизацию —
 * окно, в котором трафик уходил в системный прокси или напрямую.
 *
 * Как стало: гасим старый туннель и поднимаем новый, proxy.settings не трогаем
 * (STATE.switching). Если новый не поднялся — откатываемся на прежнюю ноду,
 * а не оставляем пользователя без VPN.
 */
async function switchServer(server, opts = {}) {
  if (!server || (!server.host && !server.server)) {
    return { ok: false, error: "Не указан сервер" };
  }
  const prev = STATE.currentServer;

  // FIX(5.5.12): «смена» на ту же ноду, на которой мы уже сидим и которая
  // ПОДТВЕРЖДЕНА, — не смена, а лишний разрыв рабочего туннеля с окном прямого
  // трафика. В отчёте пользователя хост получал «switch: de15.h1cloud.net ->
  // de15.h1cloud.net» каждые ~20 c. Исключение — opts.force: setTunnelMode
  // обязан атомарно пересобрать туннель, чтобы новые правила уехали в sing-box.
  if (!opts.force && prev && server.id && prev.id === server.id &&
      STATE.status === "connected" && STATE.tunnelVerified) {
    journal("switch-noop", `уже на ${server.id} и туннель подтверждён — не рву`);
    dbgNative({ command: "dbg", text: `switch skipped: уже на ${server.host}, туннель подтверждён` });
    return { ok: true, noop: true, status: STATE.status };
  }

  // Туннель не поднят — это обычное подключение, окна утечки нет.
  if (STATE.status === "disconnected" || !prev) return startTunnel(server);

  STATE.switching = true;
  try {
    // уходим с прежней ноды по своей воле — это успешная сессия, а не обрыв
    endSession(false, "переключение на другой сервер");
    // статус меняем ДО отправки stop: иначе ответ хоста «disconnected» застанет
    // status === "connected" и будет истолкован как обрыв туннеля → ложный
    // kill switch посреди штатного переключения.
    STATE.status = "connecting";
    STATE.currentSpeed = 0;
    // FIX(5.5.13): этот stop — наш, штатный. Его «disconnected» придёт, когда
    // switching уже сброшен (startTunnel вернул pending), и без метки он ронял
    // статус в disconnected и отдавал прокси браузеру (dbg: proxy=none).
    STATE.pendingStopAck = true;
    STATE.pendingStopAckAt = Date.now();
    sendToNative({ command: "stop" });
    broadcastUI({ type: "status", status: "connecting" });
    dbgNative({ command: "dbg", text: `switch: ${prev.host} -> ${server.host}` });

    const res = await startTunnel(server);
    if (res.ok) return res;

    // FIX(5.5.13): старт не удался — «ожидаемого» disconnected больше нет.
    // Иначе настоящий обрыв в течение окна был бы проглочен, а статус остался
    // «connecting» до 20-секундного watchdog.
    STATE.pendingStopAck = false;

    // Откат: лучше остаться на прежней ноде, чем сидеть без VPN.
    console.warn("[flicker] switch failed, откат к", prev.name || prev.host, "—", res.error);
    const back = await startTunnel(prev);
    if (back.ok) {
      return {
        ok: false, rolledBack: true,
        error: `Не удалось переключиться на «${server.name || server.host}»: ${res.error || "?"}. Остался на прежнем сервере.`
      };
    }
    await stopTunnel(false);   // не пользователь: намерение восстановиться живо
    if (STATE.resumeServerId == null && (prev?.id || server?.id)) {
      STATE.resumeServerId = prev?.id || server?.id;
    }
    scheduleRecovery("смена сервера не удалась");
    if (STATE.killSwitchEnabled) activateKillSwitch("смена сервера не удалась, живых альтернатив нет");
    return { ok: false, error: res.error || "Смена сервера не удалась" };
  } finally {
    STATE.switching = false;
  }
}

// ============ Отбор нод по эффективности (FIX 5.5.5) ============
//
// ТРЕБОВАНИЕ: «поиск и проверка должны быть с валидацией по мере самых
// эффективных, а не самых говёных с пингом по 4000; такие сразу в блок и мусор
// без повторного вылезания в список».
//
// До 5.5.5 критерием «живой сервер» было `ping >= 0`, то есть «когда-то ответил».
// Узел с задержкой 4000 мс считался живым, попадал в список, в автовыбор и в
// автопереключение — и именно на нём туннель «отваливался через минуту».
// Рейтинг этого не исправлял: задержка входила в формулу как `1 - rtt/60`,
// то есть всё медленнее 60 мс оценивалось одинаково нулём, и узел со 100%
// успехов при rtt 4000 получал score ≈ 0.8 — «доверенный».
//
// Теперь три уровня защиты:
//   1. ЖЁСТКИЙ ПОТОЛОК `STATE.maxPingMs` (настраивается, по умолчанию 1200 мс):
//      `isUsable()` не считает такой узел живым — он не проходит ни в один
//      фильтр выбора и сортируется как непригодный.
//   2. ВЕРДИКТ (lib/blocklist.js → verdictFromProbe): пинг выше потолка,
//      серия провалов или нестабильность по окну проверок → постоянный блок.
//   3. ПОСТОЯННЫЙ БЛОК по отпечатку узла (host+port+protocol+credentials),
//      а не по id: подписка не может вернуть заблокированный узел ни под старым
//      id, ни под новым, и пробы на него больше не тратятся.

/** scoreOfServer — рейтинг ноды (для сортировки «самые эффективные первыми»). */
function scoreOfServer(s) {
  try { return STATE.rating?.get(s.id).score || 0; } catch { return 0; }
}

/** sortWithPolicy — сортировка списка с учётом потолка пинга и рейтинга. */
function sortWithPolicy(list) {
  return sortServers(list, { maxPing: STATE.maxPingMs, scoreOf: scoreOfServer });
}

/**
 * blockServerNode — вынести узлу постоянный вердикт.
 *
 * Пишет и в реестр блоков (по отпечатку), и в рейтинг (score → 0), чтобы узел
 * не прошёл ни через один из двух независимых фильтров.
 *
 * @returns {object|null} запись блока
 */
function blockServerNode(s, reason, info = {}) {
  if (!s || !s.id) return null;
  const key = nodeKey(s);
  if (!key) return null;                     // локальные транспорты не блокируем
  const rec = STATE.blocklist.add(s, reason, {
    serverId: s.id,
    label: info.label || s.name || s.host || s.id,
    host: s.host || null,
    ping: Number.isFinite(info.ping) ? info.ping : null,
    note: BLOCK_REASON_LABEL[reason] || reason
  });
  STATE.rating.block(s.id, reason);
  s.blocked = true;
  s.blockReason = reason;
  s.blockLabel = rec?.note || null;
  STATE.blockedTotal = STATE.blocklist.size();
  STATE.blocklist.flush().catch(() => {});
  ratingFlush(true).catch(() => {});
  return rec;
}

/**
 * applyProbeVerdict — классифицировать результат проверки и вынести вердикт.
 *
 * Вызывается ПОСЛЕ recordSample(): к этому моменту в рейтинге уже есть свежие
 * rtt/failStreak, по которым verdictFromProbe принимает решение.
 *
 * @param {object} s серверный объект (мутируется: ping/errClass/lastError/blocked)
 * @param {{alive:boolean, rtt?:number|null, mbps?:number|null}} res
 * @returns {{blocked:boolean, reason?:string, label?:string}}
 */
function applyProbeVerdict(s, res) {
  if (!s || !s.id) return { blocked: false };
  // Локальные транспорты (ByeDPI, «Диагностика») не являются внешними нодами:
  // задержка здесь — путь до собственного процесса, и блокировать их за это
  // нельзя. Иначе единственный бесплатный режим без сервера исчезал из списка.
  if (s.protocol === "direct" || s.protocol === "dpi") return { blocked: false };
  const entry = STATE.rating.get(s.id);
  const v = verdictFromProbe(s, entry, {
    alive: !!res.alive, rtt: res.rtt, maxPing: STATE.maxPingMs
  });
  if (!v.block) return { blocked: false };
  // вердикт есть, но ключа нет (например, узел без учётных данных) — не
  // помечаем заблокированным то, что реально заблокировать не удалось
  const rec = blockServerNode(s, v.block, { ping: v.ping, label: v.label });
  if (!rec) return { blocked: false };
  // в списке узел больше не «живой»: -2 = непригоден (UI показывает серым/скрывает)
  s.ping = -2;
  s.errClass = v.errClass || s.errClass || null;
  s.lastError = v.label || s.lastError || null;
  return { blocked: true, reason: v.block, label: v.label };
}

/**
 * pruneBlockedFromStorage — вычистить заблокированные узлы из хранилища.
 * Дорогая операция (считает отпечатки), поэтому вызывается на старте и после
 * пополнения подписки, а не на каждый getServers().
 * @returns {Promise<number>} сколько узлов удалено
 */
async function pruneBlockedFromStorage() {
  try {
    const all = await browser.storage.local.get("servers");
    const list = Array.isArray(all.servers) ? all.servers : [];
    if (!list.length) return 0;
    const kept = [];
    let dropped = 0;
    for (const srv of list) {
      if (srv.blocked || STATE.blocklist.has(srv)) { dropped++; continue; }
      kept.push(srv);
    }
    if (dropped) {
      await browser.storage.local.set({ servers: kept });
      STATE.blockedTotal = STATE.blocklist.size();
    }
    return dropped;
  } catch (e) {
    console.warn("[flicker] pruneBlocked:", e?.message || e);
    return 0;
  }
}

// ================= Пинг / авто-выбор =================

function pingServer(s, timeoutMs = 2500) {
  // старый хост (4.x) не знает команду ping — не дёргаем, статус неизвестен
  if (STATE.nativeCompat === "old") return Promise.resolve({ ...s, ping: -1 });
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      STATE.pingWaiters.delete(s.id);
      resolve({ ...s, ping: -1 }); // нет ответа: статус неизвестен (НЕ смерть)
    }, timeoutMs);
    STATE.pingWaiters.set(s.id, (latency) => {
      clearTimeout(timer);
      resolve({ ...s, ping: latency });
    });
    const ok = sendToNative({ command: "ping", server: s.host, port: s.port || 443, serverId: s.id });
    if (!ok) {
      clearTimeout(timer);
      STATE.pingWaiters.delete(s.id);
      resolve({ ...s, ping: -1 });
    }
  });
}

async function pingAllServers(servers) {
  return Promise.all(servers.map((s) => pingServer(s)));
}

async function autoSelectBestServer(servers) {
  // серверы без учётных данных, заблокированные и заведомо мёртвые не выбираются
  const pool = (servers || []).filter(
    // FIX(5.5.9): локальные транспорты (direct/dpi) не являются VPN-нодами и
    // автовыбором выбираться не должны: иначе «подключено» без VPN
    (s) => serverHasCredentials(s) && !s.blocked && !isServerDead(s) && !isLocalTransport(s)
  );
  if (!pool.length) return null;

  // FIX(5.5.5): «живой» = ответил И уложился в потолок задержки. Автовыбор
  // больше не берёт первый ответивший узел с пингом 4000 мс.
  let usable = pool.filter((s) => isUsable(s, STATE.maxPingMs));
  if (usable.length) return pickBestAlive(usable) || usable[0];

  // Измеренных нет — снимаем задержки и отбираем заново. UDP-пинг для HY2
  // бесполезен (серверы игнорируют мусорные дейтаграммы), поэтому он остаётся
  // только fallback-ом для узлов без сохранённой статистики.
  const results = await pingAllServers(pool);
  for (const srv of results) {
    const rtt = typeof srv.ping === "number" && srv.ping >= 0 ? srv.ping : null;
    if (rtt != null) {
      STATE.rating.markLatency(srv.id, rtt);
      applyProbeVerdict(srv, { alive: true, rtt });
    }
  }
  const visible = results.filter((x) => !x.blocked);
  await persistServers(sortWithPolicy(visible));
  usable = visible.filter((s) => isUsable(s, STATE.maxPingMs));
  if (usable.length) return pickBestAlive(usable) || usable[0];

  // FIX(5.5.8): под потолок задержки не попал НИКТО. Вернуть null — значит
  // оставить пользователя вообще без VPN; берём наименее медленного из
  // измеренных и честно говорим, что потолок стоит поднять.
  const measured = visible.filter((s) => typeof s.ping === "number" && s.ping >= 0 && !s.blocked);
  if (measured.length) {
    const least = byPingAsc(measured)[0];
    broadcastUI({
      type: "error",
      message: `Все измеренные ноды медленнее потолка ${STATE.maxPingMs} мс — беру наименее медленную ` +
               `(«${least.name || least.host}», ${Math.round(least.ping)} мс). Поднимите «Отсекать медленнее, мс» ` +
               `во вкладке «Серверы» или обновите подписку.`
    });
    return least;
  }
  // FIX(5.5.8): всё отбраковано/заблокировано по задержке. Молчаливый null
  // выглядит как «VPN сломался», поэтому говорим, что сделать (не чаще раза в 30 c).
  const now = Date.now();
  if (now - (STATE.lastSlowHintAt || 0) > 30_000) {
    STATE.lastSlowHintAt = now;
    broadcastUI({
      type: "error",
      message: `Автовыбор: живых нод с пингом ≤ ${STATE.maxPingMs} мс нет. ` +
               `Поднимите «Отсекать медленнее, мс» (вкладка «Серверы»), обновите подписку ` +
               `или добавьте свой сервер (например AmneziaWG — конфиг вставляется в карточке).`
    });
  }
  return null;
}

// ---------- Авто-обновление списка серверов ----------
// Пинг-свип: обновляет ping у всех серверов, сохраняет и рассылает в UI.
// direct-серверы не пингуем: это локальный TCP-транспорт, UDP-проба для них не смысла.
// Подписочные HY2-серверы тоже: UDP-пинг мусором для них бесполезен, живость
// определяет многоэтапная проба (runProbe → native probeServers).
async function refreshServers() {
  if (!STATE.nativeOnline) return null;
  const all = await getServers();
  // dpi и direct — локальные транспорты: UDP/TCP-пинг через native host для них
  // бессмыслен (dpi живёт в ciadpi, его проверяет verifyDpi)
  const local = (s) => s.protocol === "direct" || s.protocol === "dpi";
  const pingable = all.filter((s) => !local(s) && !s.sub);
  const rest = all.filter((s) => local(s) || s.sub);
  const results = [...(await pingAllServers(pingable)), ...rest];
  // FIX(5.5.5): свип задержки — такой же источник вердикта, как многоэтапная
  // проба. Узел, ответивший за 4000 мс, больше не считается «живым».
  let blockedHere = 0;
  for (const srv of results) {
    const rtt = typeof srv.ping === "number" && srv.ping >= 0 ? srv.ping : null;
    if (rtt == null) continue;
    STATE.rating.markLatency(srv.id, rtt);
    const v = applyProbeVerdict(srv, { alive: true, rtt });
    if (v.blocked) blockedHere++;
  }
  const visible = results.filter((x) => !x.blocked);
  await persistServers(sortWithPolicy(visible));
  if (blockedHere) {
    await pruneBlockedFromStorage();
    broadcastUI({ type: "blockedNodes", total: STATE.blockedTotal, added: blockedHere });
  }
  STATE.lastRefreshAt = Date.now();
  broadcastUI({ type: "serversUpdated", servers: sortWithPolicy(visible), at: STATE.lastRefreshAt });
  return visible;
}

// ================= Хранилище серверов =================

async function getServers() {
  const saved = await browser.storage.local.get("servers");
  // FIX(5.5.5): узлы с вынесенным вердиктом не возвращаются НИКУДА — ни в UI,
  // ни в автовыбор, ни в пробу. Флаг ставится в момент блока, поэтому проверка
  // дешёвая и не требует пересчёта отпечатков на каждый вызов.
  const list = (Array.isArray(saved.servers) ? saved.servers : []).filter((s) => !s.blocked);
  if (!list.length) return DEFAULT_SERVERS;

  // Встроенные ЛОКАЛЬНЫЕ транспорты (dpi, direct) обязаны быть доступны всегда.
  // Раньше DEFAULT_SERVERS использовался только как fallback для пустого
  // storage, то есть после первой же загрузки подписок dpi-local и diag
  // исчезали из списка — и единственный бесплатный режим без сервера становился
  // недостижим из UI. Подмешиваем их обратно, уважая явное удаление.
  let excluded = new Set();
  try {
    const ex = await browser.storage.local.get("excludedServerIds");
    excluded = new Set(ex.excludedServerIds || []);
  } catch { /* storage недоступен — не блокируем выдачу */ }

  const byId = new Map(list.map((s) => [s.id, s]));
  for (const def of DEFAULT_SERVERS) {
    if (byId.has(def.id) || excluded.has(def.id)) continue;
    // порт dpi-сервера держим синхронно с настройкой: пользователь мог его сменить
    const injected = def.protocol === "dpi" ? { ...def, port: STATE.dpiPort } : { ...def };
    list.push(injected);
  }
  return list;
}

async function persistServers(list) {
  await browser.storage.local.set({ servers: list });
}

// ================= Подписки (задача 1) =================
//
// Источники хранятся в storage.subscriptions; встроенные (Au1rxx,
// MatinGhanbari, jichang) присутствуют всегда и обновляются по расписанию
// (ежедневно/ежечасно), пользовательские URL добавляются из options.
// Скачивание — из service worker (host_permissions <all_urls> снимают CORS).

const FETCH_TIMEOUT_MS = 25_000;

// Кэш развёрнутых мета-источников: url → {lastFetchAt, lastCount, lastError}.
// Без него фоновое обслуживание (alarm 10 мин) заново тянуло бы все ~12
// производных URL каждый цикл. Хранится в storage.derivedSources.
let DERIVED_CACHE = new Map();

async function loadDerivedCache() {
  try {
    const saved = await browser.storage.local.get("derivedSources");
    const obj = saved.derivedSources;
    DERIVED_CACHE = new Map(obj && typeof obj === "object" ? Object.entries(obj) : []);
  } catch { DERIVED_CACHE = new Map(); }
  return DERIVED_CACHE;
}

async function persistDerivedCache() {
  try {
    await browser.storage.local.set({ derivedSources: Object.fromEntries(DERIVED_CACHE) });
  } catch (e) { /* не критично */ }
}

async function loadSubscriptions() {
  const saved = await browser.storage.local.get("subscriptions");
  STATE.subscriptions = normalizeSources(saved.subscriptions);
  return STATE.subscriptions;
}

async function persistSubscriptions() {
  await browser.storage.local.set({ subscriptions: STATE.subscriptions });
}

async function fetchSubscriptionText(url) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), FETCH_TIMEOUT_MS);
  try {
    const resp = await fetch(url, { signal: ctl.signal, redirect: "follow" });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const text = await resp.text();
    if (!text || text.length > 8 * 1024 * 1024) throw new Error("подписка пуста или слишком велика");
    return text;
  } finally {
    clearTimeout(timer);
  }
}

function sourceIsDue(src, now = Date.now()) {
  if (!src.enabled) return false;
  if (!src.lastFetchAt) return true;
  return now - src.lastFetchAt >= (src.refreshMinutes || 720) * 60_000;
}

/**
 * refreshSubscriptions — скачать подписки (все или только «созревшие»),
 * распарсить hysteria2://-ссылки, слить со списком серверов.
 * @returns {Promise<{ok:boolean, fetched:number, added:number, updated:number, total:number, perSource:object[], errors:string[]}>}
 */
async function refreshSubscriptions({ force = false } = {}) {
  const sources = STATE.subscriptions.length ? STATE.subscriptions : await loadSubscriptions();
  const now = Date.now();
  const perSource = [];
  const errors = [];
  let incoming = [];
  let fetched = 0;

  // v5: сначала tier "ru" (обновляются ежечасно и заточены под ТСПУ), затем
  // global, затем meta. При обрыве сети/таймаутах важные источники успевают
  // отработать раньше, а не по алфавиту.
  const ordered = [...sources].sort(
    (a, b) => (TIER_WEIGHT[b.tier] || 0) - (TIER_WEIGHT[a.tier] || 0)
  );

  // Мета-источники содержат не ноды, а URL других источников: скачиваем их
  // первыми и разворачиваем — новые списки подтягиваются без релиза приложения.
  const metaFetched = [];
  for (const src of ordered.filter((x) => x.tier === "meta" && x.enabled)) {
    if (!force && !sourceIsDue(src, now)) continue;
    try {
      const text = await fetchSubscriptionText(src.url);
      metaFetched.push({ url: src.url, text });
      src.lastFetchAt = Date.now();
      src.lastCount = parseMetaSource(text).length;
      src.lastError = null;
      fetched++;
      perSource.push({ id: src.id, name: src.name, meta: true, count: src.lastCount });
    } catch (e) {
      src.lastError = String(e?.message || e).slice(0, 200);
      src.lastFetchAt = Date.now();
      perSource.push({ id: src.id, name: src.name, meta: true, error: src.lastError });
      errors.push(`${src.name}: ${src.lastError}`);
    }
  }
  const derived = expandMetaSources(metaFetched);
  const knownUrls = new Set(ordered.map((x) => x.url));
  // подтягиваем lastFetchAt из кэша, чтобы sourceIsDue() работал и для
  // производных источников (иначе они тянулись бы каждый цикл)
  const derivedNew = derived
    .filter((d) => !knownUrls.has(d.url))
    .map((d) => ({ ...d, ...(DERIVED_CACHE.get(d.url) || {}) }));

  for (const src of [...ordered.filter((x) => x.tier !== "meta"), ...derivedNew]) {
    if (!force && !sourceIsDue(src, now)) {
      perSource.push({ id: src.id, skipped: true, lastCount: src.lastCount || 0 });
      continue;
    }
    if (!src.enabled) continue;
    try {
      const text = await fetchSubscriptionText(src.url);
      // HY2-ссылки парсим, только если источник помечен allowHY2 и включён
      // глобальный тумблер «Экспериментальные UDP-протоколы»
      const parsed = parseSubscription(text, src.id, {
        allowHY2: !!src.allowHY2 && STATE.experimentalUdp
      });
      src.lastFetchAt = Date.now();
      src.lastCount = parsed.servers.length;
      src.lastError = null;
      if (src.derivedFrom) {
        DERIVED_CACHE.set(src.url, {
          lastFetchAt: src.lastFetchAt, lastCount: src.lastCount, lastError: null
        });
      }
      fetched++;
      perSource.push({ id: src.id, name: src.name, count: parsed.servers.length, failed: parsed.failed.length });
      incoming.push(...parsed.servers);
      if (parsed.servers.length === 0) {
        errors.push(`${src.name}: HY2-ссылок не найдено (формат подписки изменился?)`);
      }
    } catch (e) {
      src.lastError = String(e?.message || e).slice(0, 200);
      src.lastFetchAt = Date.now(); // не долбить источник при каждой попытке
      if (src.derivedFrom) {
        DERIVED_CACHE.set(src.url, {
          lastFetchAt: src.lastFetchAt, lastCount: 0, lastError: src.lastError
        });
      }
      perSource.push({ id: src.id, name: src.name, error: src.lastError });
      errors.push(`${src.name}: ${src.lastError}`);
      console.warn("[flicker] subscription fetch failed:", src.id, src.lastError);
    }
  }
  await persistSubscriptions();
  await persistDerivedCache();

  // пользователь вручную удалил сервер → не возвращаем его из подписки
  const excl = await browser.storage.local.get("excludedServerIds");
  const excluded = new Set(excl.excludedServerIds || []);
  if (excluded.size) incoming = incoming.filter((s) => !excluded.has(s.id));

  // FIX(5.5.5) ГЛАВНОЕ для «мусор не вылезает обратно»: фильтр блок-листа
  // стоит НА ВХОДЕ, до слияния. Публичные бесплатные списки отдают одни и те же
  // мёртвые/черепаховые ноды каждый час, и раньше каждое обновление возвращало
  // их в список: mergeServers() брал узел из incoming как новый, а pruneStale()
  // удалял только то, что не встречалось 14 дней. Отбор идёт по ОТПЕЧАТКУ узла
  // (host+port+protocol+учётные данные), а не по id, поэтому смена id в подписке
  // заблокированный узел не спасает.
  const incomingTotal = incoming.length;
  const gated = STATE.blocklist.filterServers(incoming);
  incoming = gated.kept;
  const rejectedNow = gated.dropped.length;

  // дедупликация между источниками: первый встретившийся выигрывает,
  // но id у одинаковых host:port:auth совпадает — mergeServers их схлопнет
  const existing = await getServers();
  const { merged, added, updated } = mergeServers(existing, incoming, now);
  const pruned = pruneStale(merged, now).filter((x) => !x.blocked);
  const sorted = sortWithPolicy(pruned);
  await persistServers(sorted);

  // v5: отметить встреченные ноды в рейтинге; у сменивших учётные данные
  // история сбрасывается (иначе ротация пароля давала бы незаслуженный рейтинг)
  const resetCount = touchRatings(sorted);
  STATE.rating.gc(21);
  await ratingFlush(true);
  if (resetCount) {
    console.log(`[flicker] rating: сброшена история у ${resetCount} нод (сменились учётные данные)`);
  }
  if (fetched > 0) STATE.lastRefreshAt = now; // данные свежие — popup не дёргает лишнюю пробу

  if (rejectedNow) {
    await STATE.blocklist.flush().catch(() => {});
    console.log(`[flicker] подписка: отклонено заблокированных узлов — ${rejectedNow} из ${incomingTotal}`);
  }

  const result = {
    ok: true, fetched, added, updated,
    total: pruned.filter((s) => s.sub).length,
    // FIX(5.5.5): сколько пригодных (в пределах потолка задержки) и сколько в блоке
    usable: pruned.filter((s) => isUsable(s, STATE.maxPingMs)).length,
    blockedRejected: rejectedNow,
    blockedTotal: STATE.blockedTotal,
    maxPingMs: STATE.maxPingMs,
    perSource, errors,
    // v5: сводка для UI («источники: N, нод: M») и рейтинг-сводка
    sources: sourceStats(STATE.subscriptions),
    derivedSources: derivedNew.length,
    rating: ratingSummary(STATE.rating, sorted)
  };
  broadcastUI({ type: "subscriptionsUpdated", ...result, at: now });
  broadcastUI({ type: "serversUpdated", servers: sorted, at: now });
  return result;
}

// ================= Рейтинг нод: приём замеров (v5) =================
//
// Старая схема сводила результат проверки к бинарному ping = -2 («мёртв») или
// ping = задержка. Знание о том, что нода быстрая и стабильная, терялось, и
// каждый цикл прогрева заново молотил весь список.
// Здесь каждый замер уходит в lib/rating.js, а порядок выбора задаёт накопленный
// рейтинг. Поля ping/recent/checksOk сохраняются — их показывает текущий UI.

/** tierOf — приоритет источника, из которого пришла нода. */
function tierOf(server) {
  if (!server?.sub) return "custom";
  const src = STATE.subscriptions.find((x) => x.id === server.source);
  return src?.tier || "global";
}

/**
 * recordSample — один замер в рейтинг.
 * @param {object} server — серверный объект из хранилища
 * @param {{ok?:boolean, rtt?:number|null, mbps?:number|null, loss?:number|null, reason?:string|null}} sample
 */
function recordSample(server, sample) {
  if (!server?.id || !STATE.rating) return null;
  return STATE.rating.pushSample(server.id, { ...sample, tier: tierOf(server) });
}

/**
 * touchRatings — отметить ноды, встреченные в подписке, и сбросить историю тем,
 * у которых сменились учётные данные (ротация паролей на публичных нодах).
 */
function touchRatings(servers) {
  if (!STATE.rating) return 0;
  let reset = 0;
  for (const s of servers || []) {
    if (!s?.id) continue;
    const fp = fingerprintOf(s);
    const before = STATE.rating.get(s.id);
    const hadHistory = (before.samples?.length || 0) > 0 || before.okCount > 0;
    const e = STATE.rating.touch(s.id, { tier: tierOf(s), fingerprint: fp });
    if (hadHistory && (e.samples?.length || 0) === 0 && e.okCount === 0) reset++;
  }
  return reset;
}

/** ratingFlush — сохранить рейтинг (не чаще раза в N мс, чтобы не долбить storage). */
let lastRatingFlushAt = 0;
async function ratingFlush(force = false) {
  const now = Date.now();
  if (!force && now - lastRatingFlushAt < 5000) return;
  lastRatingFlushAt = now;
  try { await STATE.rating.flush(); } catch (e) { /* storage-сбой не критичен */ }
}

/** recordSampleById — замер по id (когда серверного объекта под рукой нет). */
function recordSampleById(id, sample) {
  if (!id || !STATE.rating) return null;
  const e = STATE.rating.pushSample(id, sample);   // tier уже проставлен через touch()
  ratingFlush(false);
  return e;
}

// ---- Сессионная статистика → рейтинг ----
//
// Реальная сессия — самый честный замер. Проба по HTTP может пройти, а под
// нагрузкой нода отваливается через минуту: это видно только по факту работы.
// Итог сессии пишется в рейтинг при закрытии туннеля.

function emptySession() {
  return { serverId: null, startedAt: null, connectedAt: null,
           bytesSentAtStart: 0, bytesReceivedAtStart: 0, lastMbps: null, lastRtt: null };
}

function beginSession(server) {
  STATE.session = { ...emptySession(), serverId: server?.id || null, startedAt: Date.now() };
  // FIX(5.5.11): запоминаем последнюю VPN-ноду. Служебный direct-узел и
  // DPI-обход не запоминаются: это не туннель, возвращаться на них нельзя.
  if (server && server.id && !isLocalTransport(server)) {
    STATE.lastVpnServerId = server.id;
    try { browser.storage.local.set({ lastVpnServerId: server.id }).catch(() => {}); }
    catch { /* storage-сбой не имеет права ронять туннель */ }
  }
}

/** updateSessionStats — пересчёт средней скорости сессии по накопленным байтам. */
function updateSessionStats(bytesSent, bytesReceived, rtt) {
  const ses = STATE.session;
  if (!ses?.serverId || !ses.connectedAt) return;
  const elapsedSec = Math.max(1, (Date.now() - ses.connectedAt) / 1000);
  const bytes = Math.max(0, (bytesSent - ses.bytesSentAtStart) + (bytesReceived - ses.bytesReceivedAtStart));
  ses.lastMbps = (bytes * 8) / elapsedSec / 1e6;
  if (typeof rtt === "number" && rtt > 0) ses.lastRtt = rtt;
}

/**
 * endSession — записать итог сессии в рейтинг. Идемпотентна.
 * @param {boolean} lost   true = туннель оборвался сам, false = закрыли штатно
 * @param {string|null} reason
 */
function endSession(lost = false, reason = null) {
  const ses = STATE.session;
  STATE.session = emptySession();
  if (!ses?.serverId) return null;
  if (lost) {
    return recordSampleById(ses.serverId, {
      ok: false, rtt: ses.lastRtt, reason: reason || "туннель оборвался"
    });
  }
  if (!ses.connectedAt) {
    return recordSampleById(ses.serverId, { ok: false, reason: reason || "не подключился" });
  }
  return recordSampleById(ses.serverId, {
    ok: true, rtt: ses.lastRtt, mbps: ses.lastMbps
  });
}

// ================= Автопоиск живых серверов (задачи 3–5) =================
//
// Расширение не может само говорить по QUIC/UDP — многоэтапная проверка
// выполняется в native host (Go, пакет internal/probe):
//   этап 1 TCP reachability → этап 2 QUIC prescan → этап 3 HTTP через туннель
//   → этап 4 медиана реальной задержки → (здесь) этап 5 двойной прогон.
// Здесь — оркестрация: запуск, стриминг статусов в UI, применение итогов,
// success rate < 50% → мёртв, авто-переключение текущего сервера.

const PASS2_DELAY_MS = 45_000;   // ТЗ: повторный тест через 45 секунд
const BOOTSTRAP_PROBE_CAP = 400; // первичная проба: не более N узлов (остальные добьёт фон)
const RECENT_WINDOW = 4;         // окно success rate
const MIN_SUCCESS_RATE = 0.5;    // ТЗ: < 50% → отсеиваем

function probeSpec(s) {
  const spec = {
    id: s.id,
    host: s.host,
    port: s.port || 443,
    protocol: s.protocol,
    auth: s.auth || "",
    sni: s.sni || "",
    obfsType: s.obfs?.type || "none",
    obfsPassword: s.obfs?.password || "",
    insecure: !!s.tls?.insecure,
    tlsEnabled: s.protocol === "hysteria2" ? true : !!s.tlsEnabled
  };
  if (s.protocol === "vless" || s.protocol === "vmess") {
    spec.uuid = s.uuid || "";
    if (s.flow) spec.flow = s.flow;
    if (s.fingerprint) spec.fingerprint = s.fingerprint;
    if (s.reality?.publicKey) {
      spec.realityPublicKey = s.reality.publicKey;
      spec.realityShortId = s.reality.shortId || "";
    }
  }
  if (s.cipher) spec.cipher = s.cipher;
  if (s.transport?.type) {
    spec.transportType = s.transport.type;
    spec.transportPath = s.transport.path || "";
    spec.transportHost = s.transport.host || "";
    spec.transportServiceName = s.transport.serviceName || "";
  }
  return spec;
}

const PROBABLE_PROTOCOLS = new Set(["vless", "trojan", "vmess", "shadowsocks", "hysteria2"]);

function probableServers(servers, ids = null) {
  return servers.filter((s) =>
    PROBABLE_PROTOCOLS.has(s.protocol) && !s.demo && !s.blocked && serverHasCredentials(s) &&
    (ids == null || ids.includes(s.id)));
}

/**
 * runProbe — запустить многоэтапную проверку в native host.
 * mode: "full" (TCP→QUIC→HTTP×3+cloudflare+GeoIP) | "quick" (QUIC→HTTP×1).
 * Ответ приходит стримом: probeResult по этапам + probeDone с итогами.
 *
 * FIX(5.5.6): фактический конвейер хоста (по разбору internal/probe):
 *   tcp → quic → http (www.gstatic.com/generate_204, www.cloudflare.com)
 *       → cloudflare (httpStatusThroughTunnel) → geoip (ip-api.com).
 * Вердикт о живости выносят только tcp/quic/http/sing (см. isVerdictStage);
 * cloudflare и geoip — метаданные. GeoIP запрашиваем лишь при малом числе
 * целей (GEOIP_MAX_TARGETS): ip-api.com ограничивает ~45 запросов/мин на IP,
 * и на массовом прогоне он отвечал status:"fail" пачками.
 *
 * @param {string} mode "full" | "quick"
 * @param {string[]|null} ids явный список узлов (обходит фильтр needsProbe)
 * @param {number} passNo номер прогона (1 = full, 2 = quick)
 * @param {object} [opts] {cap, force, geoIp}
 */
async function runProbe(mode = "full", ids = null, passNo = 0, opts = {}) {
  if (STATE.probe.active) {
    return { ok: false, error: "Проверка уже идёт — дождитесь окончания или отмените" };
  }
  const servers = await getServers();
  let targets = probableServers(servers, ids);
  if (mode === "quick" && ids == null) {
    // фоновая быстрая проверка: только живые/неизвестные + текущий сервер
    targets = targets.filter((s) => s.ping !== -2 || s.id === STATE.currentServer?.id);
  }
  // v5: доверенным нодам (рейтинг ≥ SCORE_TRUSTED при свежих замерах) повторная
  // проба не нужна. Именно это убирает львиную долю фоновых прогонов: раньше
  // каждый цикл молотил 400–600 узлов, теперь — только холодные и протухшие.
  // Явный список ids и force (клик пользователя) фильтр обходят.
  const probableTotal = targets.length;
  if (ids == null && !opts.force) {
    targets = targets.filter((s) => needsProbe(STATE.rating.get(s.id)));
  }
  if (!targets.length && probableTotal > 0) {
    const sum = ratingSummary(STATE.rating, servers);
    return {
      ok: true, skipped: probableTotal, started: false,
      reason: "Все узлы доверенные — повторная проверка не нужна",
      rating: sum
    };
  }
  // Лимит узлов за один прогон: bootstrap — 400, quick — 500, ручной
  // полный — 600. Остальные допроверяет фоновое обслуживание (alarm 10 мин).
  // Без лимита прогон 1400+ узлов занимает минуты и нагружает UI стримом.
  const cap = opts.cap || (mode === "quick" ? 500 : 600);
  if (targets.length > cap) {
    // приоритет: непроверенные и текущий сервер, затем давно проверенные
    targets.sort((a, b) => (a.lastCheckAt || 0) - (b.lastCheckAt || 0));
    targets = targets.slice(0, cap);
  }
  // FIX(5.5.6) HC-2: хост читает кадр native messaging через nm.Read и умеет
  // отвечать «nm: message too large». Порог из бинарника не читается, поэтому
  // просто не отправляем заведомо огромный кадр: большая подписка с Reality-
  // ключами и транспортами легко даёт сотни байт на узел, и вместо проверки
  // получали отказ хоста — все узлы зависали в `checking` до watchdog.
  const fit = fitTargetsToBudget(targets, probeSpec, PROBE_MSG_BYTE_BUDGET);
  if (fit.trimmed > 0) {
    console.warn("[flicker] probeServers: целей не влезло в кадр NM:", fit.trimmed,
      "(байт:", fit.bytes, ")");
    targets = fit.targets;
  }
  if (!targets.length) {
    return { ok: false, error: ERRORS.NO_SERVERS };
  }
  // FIX(5.5.6) HC-2: полный пакет opts. Все поля существуют в probe.Options
  // хоста (mode, concurrency, geoIp, httpRetries, dial/tcp/quic/http/geoIp
  // TimeoutMs). Раньше слали только три первых — проба шла на внутренних
  // дефолтах и без повторов HTTP, поэтому одиночный обрыв приговаривал узел,
  // а медленный узел обрывался по таймауту БЕЗ замера latencyMs и не попадал
  // под мгновенный блок (нужно было 4 провала подряд вместо одного замера).
  const probeOpts = buildProbeOpts({
    mode,
    targetCount: targets.length,
    geoIp: typeof opts.geoIp === "boolean" ? opts.geoIp : undefined
  });

  const requestId = "probe-" + Date.now() + "-" + Math.random().toString(36).slice(2, 8);
  const pass = passNo || (mode === "full" ? 1 : 2);
  STATE.probe = {
    active: true, requestId, mode, pass,
    total: targets.length, done: 0, alive: 0,
    startedAt: Date.now(), finishedAt: null,
    results: new Map()
  };
  STATE.probeTargets = new Map(targets.map((s) => [s.id, s]));
  for (const s of targets) s.checking = true;
  await persistServers(servers);
  broadcastUI({ type: "serversUpdated", servers, at: STATE.lastRefreshAt });
  broadcastUI({ type: "probeStarted", ...publicProbeState() });

  // watchdog: probeDone обязан прийти. FIX(5.5.6): запас считаем от реальных
  // таймаутов, которые мы сами задали (волны × худший узел), и берём максимум
  // с прежней оценкой 4 c/узел — иначе watchdog обрывал бы ещё живую пробу.
  clearTimeout(STATE.probeWatchdog);
  const watchdogMs = probeWatchdogMs(targets.length, probeOpts);
  STATE.probeWatchdog = setTimeout(() => {
    if (STATE.probe.active && STATE.probe.requestId === requestId) {
      sendToNative({ command: "probeCancel", requestId });
      abortActiveProbe("watchdog: native host не завершил проверку вовремя");
    }
  }, watchdogMs);

  if (STATE.nativeCompat === "old") {
    STATE.probe.active = false;
    for (const s of targets) delete s.checking;
    await persistServers(servers);
    return { ok: false, error: hostOutdatedError(STATE.nativeInfo?.version) };
  }

  const sent = sendToNative({
    command: "probeServers",
    requestId,
    servers: targets.map(probeSpec),
    opts: probeOpts
  });
  if (!sent) {
    STATE.probe.active = false;
    for (const s of targets) delete s.checking;
    await persistServers(servers);
    return { ok: false, error: ERRORS.NATIVE_MISSING };
  }
  return { ok: true, started: true, requestId, total: targets.length, mode, pass };
}

// abortActiveProbe — аварийное завершение зависшей пробы (смерть хоста,
// watchdog-таймаут): снимаем флаги checking, освобождаем STATE.probe.
async function abortActiveProbe(reason) {
  if (!STATE.probe.active) return;
  console.warn("[flicker] probe aborted:", reason);
  STATE.probe.active = false;
  STATE.probe.finishedAt = Date.now();
  const ids = [...STATE.probeTargets.keys()];
  STATE.probeTargets = new Map();
  try {
    const servers = await getServers();
    for (const s of servers) {
      if (ids.includes(s.id)) delete s.checking;
    }
    await persistServers(servers);
    broadcastUI({ type: "serversUpdated", servers, at: STATE.lastRefreshAt });
  } catch (e) { /* storage недоступен — не критично */ }
  broadcastUI({ type: "probeDone", ...publicProbeState(), cancelled: true, abortReason: reason });
}

function publicProbeState() {
  const p = STATE.probe;
  return {
    active: p.active, mode: p.mode, pass: p.pass, total: p.total,
    done: p.done, alive: p.alive, startedAt: p.startedAt, finishedAt: p.finishedAt
  };
}

// Стриминг этапов: UI показывает ⏳ → статус этапа по каждому серверу.
// Финальные стадии (http/fatal) сразу применяются к серверу, чтобы счётчики
// «живых/мёртвых» обновлялись ПО ХОДУ пробы, а не только в конце.
let lastStagePersistAt = 0;
function onProbeStage(msg) {
  if (!STATE.probe.active || msg.requestId !== STATE.probe.requestId) return;
  const stage = String(msg.stage == null ? "" : msg.stage).trim().toLowerCase();
  broadcastUI({
    type: "probeStage",
    id: msg.id,
    stage: msg.stage,
    ok: msg.ok,
    fatal: msg.fatal,
    latencyMs: msg.latencyMs,
    error: msg.error || null
  });

  // FIX(5.5.6) HC-1: вердикт о живости выносят ТОЛЬКО этапы, измеряющие сам
  // туннель/узел (tcp, quic, http, sing). Этапы cloudflare и geoip проверяют
  // сторонние сервисы из-за туннеля (www.cloudflare.com и ip-api.com
  // /json/?fields=status,country,countryCode,query) — их провал ничего не
  // говорит о качестве узла. У бесплатного ip-api.com лимит ~45 запросов/мин
  // на IP, и массовая проба с concurrency 12 упирается в него гарантированно.
  //
  // Прежнее условие `msg.fatal && !msg.ok` принимало этап с ЛЮБЫМ именем,
  // поэтому fatal-geoip, пришедший ПОСЛЕ успешного http, перезаписывал
  // вердикт: alive=false, ping=-2, failStreak++, и полностью рабочая нода
  // уезжала в постоянный блок, а в списке оставался мусор. Событие в UI
  // уходит как и раньше — этапы по-прежнему видны в логе пробы.
  if (!isVerdictStage(stage)) return;

  const definitive = stage === "http" || (!!msg.fatal && !msg.ok);
  if (!definitive) return;
  const s = STATE.probeTargets.get(msg.id);
  if (!s) return;
  delete s.checking;
  const alive = !!(msg.ok && stage === "http");
  const rtt = typeof msg.latencyMs === "number" && msg.latencyMs >= 0 ? msg.latencyMs : null;
  s.lastCheckAt = Date.now();
  if (alive) {
    s.ping = rtt != null ? rtt : (s.ping >= 0 ? s.ping : 0);
    s.errClass = null;
    s.lastError = null;
  } else if (!msg.ok) {
    s.ping = -2;
    s.errClass = msg.errClass || null;
    s.lastError = msg.error || s.lastError || null;
  }
  // v5: этап http/fatal — окончательный, его и пишем в рейтинг
  recordSample(s, {
    ok: alive,
    rtt,
    reason: msg.ok ? null : (msg.error || msg.errClass || null)
  });
  // FIX(5.5.5): счётчик замеров медленнее потолка и вердикт. ПОРЯДОК ВАЖЕН:
  // verdictFromProbe читает уже обновлённые rtt/failStreak из рейтинга.
  if (rtt != null) STATE.rating.markLatency(s.id, rtt);
  const stageVerdict = applyProbeVerdict(s, { alive, rtt });
  ratingFlush(false);
  if (stageVerdict.blocked) {
    broadcastUI({
      type: "nodeBlocked", id: s.id, reason: stageVerdict.reason,
      label: stageVerdict.label, total: STATE.blockedTotal
    });
  }
  // персистим и рассылаем не чаще раза в 15 секунд: полный список на 1000+
  // серверов — это мегабайты JSON на каждый цикл (storage + broadcast-клон
  // в popup); на слабых машинах 5-секундный ритм валил браузер в OOM.
  // ВАЖНО: мержим со всем списком — probeTargets содержит только участников
  // пробы, а persistServers перезаписывает хранилище целиком.
  const now = Date.now();
  if (now - lastStagePersistAt > 15000) {
    lastStagePersistAt = now;
    (async () => {
      try {
        const all = await getServers();
        const byId = new Map(all.map((x) => [x.id, x]));
        for (const t of STATE.probeTargets.values()) byId.set(t.id, t);
        // FIX(5.5.5): узлы с вердиктом из списка ВЫБЫВАЮТ, а не остаются серыми
        const merged = sortWithPolicy([...byId.values()].filter((x) => !x.blocked));
        await persistServers(merged);
        broadcastUI({ type: "serversUpdated", servers: merged, at: STATE.lastRefreshAt });
      } catch (e) { /* storage-сбой не роняет пробу */ }
    })();
  }
}

async function onProbeDone(msg) {
  const probe = STATE.probe;
  if (!probe.active || (msg.requestId && msg.requestId !== probe.requestId)) return;
  clearTimeout(STATE.probeWatchdog);

  const results = Array.isArray(msg.results) ? msg.results : [];
  const servers = await getServers();
  const byId = new Map(servers.map((s) => [s.id, s]));
  let alive = 0;
  let blockedNow = 0;

  for (const r of results) {
    const s = byId.get(r.id);
    if (!s) continue;
    delete s.checking;
    s.checksTotal = (s.checksTotal || 0) + 1;
    s.recent = [...(s.recent || []), r.alive ? 1 : 0].slice(-RECENT_WINDOW);
    s.lastCheckAt = Date.now();
    const rtt = r.latencyMs >= 0 ? r.latencyMs : null;
    if (r.alive) {
      // FIX(5.5.5): «живых» считаем по пригодности, а не по факту ответа —
      // узел за 4000 мс не должен увеличивать счётчик рабочих серверов
      if (rtt == null || rtt <= STATE.maxPingMs) alive++;
      s.checksOk = (s.checksOk || 0) + 1;
      s.ping = rtt != null ? rtt : (s.ping >= 0 ? s.ping : 0);
      s.errClass = null;
      s.lastError = null;
      recordSample(s, {
        ok: true,
        rtt,
        mbps: typeof r.mbps === "number" ? r.mbps : null
      });
      if (r.countryCode) {
        s.countryCode = r.countryCode;
        s.country = r.country;
        s.flag = countryFlag(r.countryCode);
      }
      if (r.exitIp) s.exitIp = r.exitIp;
    } else {
      s.ping = -2;
      s.errClass = r.errClass || null;
      s.lastError = r.error || humanizeProbeError(r.errClass, "", s);
      // сначала человекочитаемая ошибка, errClass — только как fallback:
      // в рейтинге причина нужна для диагностики пользователю
      recordSample(s, { ok: false, reason: r.error || r.errClass || null });
    }
    // FIX(5.5.5): вердикт по каждому итогу пробы — пинг-мусор, серия провалов
    // и нестабильность уходят в постоянный блок прямо здесь, а не «посеревшим»
    // остаются в списке до следующего обновления подписки.
    if (rtt != null) STATE.rating.markLatency(s.id, rtt);
    const v = applyProbeVerdict(s, { alive: !!r.alive, rtt });
    if (v.blocked) blockedNow++;
    probe.results.set(r.id, r);
  }

  // Этап 5 (двойной прогон): узлы с success rate < 50% по окну последних
  // проверок отсеиваются. FIX(5.5.5): это делает verdictFromProbe (reason
  // "flaky"), и узел при этом не просто сереет, а попадает в постоянный блок.
  const culled = blockedNow;

  // FIX(5.5.5): заблокированные ВЫБЫВАЮТ из списка — «мусор без повторного
  // вылезания». Порядок задаёт эффективность (рейтинг → задержка), а не
  // просто факт ответа.
  const sorted = sortWithPolicy([...byId.values()].filter((x) => !x.blocked));
  await persistServers(sorted);
  STATE.rating.rescore();
  await ratingFlush(true);

  probe.active = false;
  probe.done = results.length;
  probe.alive = sorted.filter((s) => isUsable(s, STATE.maxPingMs)).length;
  probe.finishedAt = Date.now();
  STATE.lastRefreshAt = probe.finishedAt;
  STATE.probeTargets = new Map();

  broadcastUI({ type: "serversUpdated", servers: sorted, at: STATE.lastRefreshAt });
  broadcastUI({
    type: "probeDone",
    ...publicProbeState(),
    alive: probe.alive,
    total: probe.total,
    pass: probe.pass,
    passes: STATE.probePasses,
    culled,
    cancelled: !!msg.cancelled,
    blocked: blockedNow,
    blockedTotal: STATE.blockedTotal,
    maxPingMs: STATE.maxPingMs,
    elapsedMs: msg.elapsedMs || (probe.finishedAt - probe.startedAt)
  });
  if (blockedNow) await pruneBlockedFromStorage();

  // Этап 5: повторные тесты через 45 секунд (двойной прогон по ТЗ;
  // probePasses=3 — усиленный фильтр: живые перепроверяются трижды)
  const nextPass = probe.pass + 1;
  if (!msg.cancelled && probe.pass < STATE.probePasses && nextPass <= STATE.probePasses) {
    const aliveIds = sorted.filter((s) => s.sub && isUsable(s, STATE.maxPingMs)).map((s) => s.id);
    if (aliveIds.length) {
      try {
        browser.alarms.create("probe-pass" + nextPass, { when: Date.now() + PASS2_DELAY_MS });
      } catch {
        setTimeout(() => runProbe("quick", aliveIds, nextPass).catch(() => {}), PASS2_DELAY_MS);
      }
    }
  }

  // Задача 5: текущий сервер умер → уведомление + автопереключение
  await autoSwitchIfCurrentDead(sorted);

  // Лучший живой — как выбранный по умолчанию (критерий задачи 6: свежая
  // установка → автовыбор берёт живой сервер из подписки)
  const savedSel = await browser.storage.local.get("selectedServer");
  const selStillValid = savedSel.selectedServer &&
    sorted.some((s) => s.id === savedSel.selectedServer &&
                       isUsable(s, STATE.maxPingMs) &&
                       STATE.rating.get(s.id).score >= SCORE_DEAD);
  if (!selStillValid) {
    const best = pickBestAlive(sorted);
    if (best) {
      await browser.storage.local.set({ selectedServer: best.id });
      broadcastUI({ type: "serverSelected", id: best.id });
    }
  }

  // Первичная загрузка завершена
  if (!STATE.subsBootstrapped) {
    STATE.subsBootstrapped = true;
    await browser.storage.local.set({ subsBootstrapped: true });
  }
}

/**
 * pickBestAlive — лучший из живых серверов.
 * v5: порядок задаёт накопленный рейтинг (доля успехов × скорость × задержка
 * × свежесть × штраф за серию провалов), а не одно последнее значение ping.
 * Ноды с рейтингом ниже SCORE_DEAD отсекаются, даже если последний одиночный
 * замер был успешным — именно они и «отваливаются через минуту».
 * @param {object[]} servers
 * @param {string|null} excludeId
 * @returns {object|null}
 */
function pickBestAlive(servers, excludeId = null) {
  const candidates = (servers || []).filter((s) =>
    s.id !== excludeId &&
    !s.demo &&
    !s.blocked &&
    isAutoSelectable(s) &&                 // FIX(5.5.8): + AmneziaWG-ноды
    serverHasCredentials(s) &&
    // FIX(5.5.5): isUsable() = ответил И не медленнее потолка И не заблокирован
    isUsable(s, STATE.maxPingMs) &&
    STATE.rating.get(s.id).score >= SCORE_DEAD);
  if (!candidates.length) return null;

  const ranked = rankCandidates(STATE.rating, candidates, {
    limit: candidates.length, minScore: 0, explore: 0
  });
  const known = ranked.filter((r) => r.known);
  if (known.length) return known[0].server;

  // fallback для нод без истории: стабильность → задержка (самые эффективные первыми)
  candidates.sort((a, b) => {
    const ra = (a.recent || []).reduce((x, y) => x + y, 0) / Math.max(1, (a.recent || []).length);
    const rb = (b.recent || []).reduce((x, y) => x + y, 0) / Math.max(1, (b.recent || []).length);
    if (rb !== ra) return rb - ra;      // стабильнее — выше
    return (a.ping || 0) - (b.ping || 0); // затем быстрее
  });
  return candidates[0];
}

async function autoSwitchIfCurrentDead(servers) {
  if (!STATE.autoSwitchEnabled) return;
  const cur = STATE.currentServer;
  if (!cur) return;
  if (STATE.status !== "connected" && STATE.status !== "connecting") return;
  const checked = (servers || []).find((s) => s.id === cur.id);
  if (!checked || checked.ping !== -2) return;

  endSession(true, "текущий сервер умер (автопереключение)");
  const best = pickBestAlive(servers, cur.id);
  if (best) {
    notify("FLICKER VPN", `Сервер «${cur.name || cur.host}» умер — переключаюсь на «${best.name || best.host}» (${best.ping} мс)`);
    broadcastUI({ type: "autoSwitch", from: cur.id, to: best.id, message: "Текущий сервер умер — автопереключение" });
    // через switchServer: в версии 4 здесь был «голый» startTunnel поверх
    // работающего туннеля, без stop и без защиты маршрутизации
    const res = await switchServer(best);
    if (!res.ok) {
      notify("FLICKER VPN", "Автопереключение не удалось: " + (res.error || "?"));
    }
  } else {
    notify("FLICKER VPN", ERRORS.NO_SERVERS);
    broadcastUI({ type: "error", message: ERRORS.NO_SERVERS });
    await stopTunnel(false);   // не пользователь: продолжаем пытаться
    if (STATE.resumeServerId == null && cur?.id) STATE.resumeServerId = cur.id;
    scheduleRecovery("текущий сервер умер, живых альтернатив нет");
    if (STATE.killSwitchEnabled) activateKillSwitch("текущий сервер умер, живых альтернатив нет");
  }
}

// ================= Первичная загрузка (задача 6) =================
// Свежая установка: скачать подписки → проверить → выбрать лучший живой.
// Работает без действий пользователя.

async function bootstrapSubscriptions() {
  const saved = await browser.storage.local.get("subsBootstrapped");
  if (saved.subsBootstrapped) {
    STATE.subsBootstrapped = true;
    return;
  }
  console.log("[flicker] первая установка: автозагрузка подписок…");
  try {
    const r = await refreshSubscriptions({ force: true });
    console.log(`[flicker] подписки: источников ${r.perSource.length}, серверов +${r.added}, ошибки: ${r.errors.length}`);
    if (r.added > 0 || r.total > 0) {
      const probe = await runProbe("full", null, 0, { cap: BOOTSTRAP_PROBE_CAP });
      if (!probe.ok) console.warn("[flicker] bootstrap probe:", probe.error);
    } else {
      STATE.subsBootstrapped = true;
      await browser.storage.local.set({ subsBootstrapped: true });
    }
  } catch (e) {
    console.warn("[flicker] bootstrap подписок не удался (нет сети?):", e?.message || e);
    // флаг НЕ ставим — повторим при следующем старте, когда сеть появится
  }
}

// ================= Фоновое обслуживание (задача 5) =================
// Alarm раз в 10 минут: обновить «созревшие» подписки + быстрая проверка
// живых и текущего сервера. Низкий приоритет: concurrency=3, quick-режим.

let maintenanceRunning = false;
async function backgroundMaintenance() {
  if (maintenanceRunning || STATE.probe.active) return;
  maintenanceRunning = true;
  try {
    if (!STATE.autoRefresh) return;
    const due = STATE.subscriptions.some((s) => sourceIsDue(s));
    if (due) await refreshSubscriptions({});
    const servers = await getServers();
    const hasProbable = probableServers(servers).length > 0;
    if (hasProbable && STATE.nativeOnline) {
      await runProbe("quick");
    }
  } catch (e) {
    console.warn("[flicker] maintenance:", e?.message || e);
  } finally {
    maintenanceRunning = false;
  }
}

// ================= Качество связи =================

// короткий детерминированный хеш строки (id пользовательских источников)
function fnvHex(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

function serversSummary(servers) {
  const subs = (servers || []).filter((s) => s.sub);
  return {
    total: (servers || []).length,
    subTotal: subs.length,
    alive: subs.filter((s) => isUsable(s, STATE.maxPingMs)).length,
    slow: subs.filter((s) => typeof s.ping === "number" && s.ping > STATE.maxPingMs).length,
    dead: subs.filter((s) => s.ping === -2).length,
    unknown: subs.filter((s) => s.ping == null || s.ping === -1).length,
    checking: subs.filter((s) => s.checking).length,
    lastCheckAt: subs.reduce((m, s) => Math.max(m, s.lastCheckAt || 0), 0) || null
  };
}

function assessConnectionQuality(rtt, dropped) {
  if (rtt <= 0) return "unknown";
  if (rtt < 50 && dropped < 1) return "excellent";
  if (rtt < 100 && dropped < 5) return "good";
  if (rtt < 200 && dropped < 10) return "fair";
  return "poor";
}

// ================= Сообщения от UI =================

function broadcastUI(msg) {
  try {
    const p = browser.runtime.sendMessage(msg);
    if (p && p.catch) p.catch(() => {});
  } catch (e) { /* popup закрыт */ }
}

/** goodbyedpiPayload — настройки второго DPI-движка (v5.5). */
function goodbyedpiPayload() {
  const preset = GOODBYEDPI_PRESETS.find((p) => p.id === STATE.gdPresetId) || GOODBYEDPI_PRESETS[0];
  const custom = STATE.gdArgs && STATE.gdArgs.trim() ? STATE.gdArgs.trim() : null;
  const effective = custom != null ? custom : preset.args;
  const v = validateGoodbyeDpiArgs(effective);
  return {
    description: describeGoodbyeDpi(),
    presets: GOODBYEDPI_PRESETS.map((p) => ({ id: p.id, name: p.name, args: p.args, note: p.note, origin: p.origin })),
    presetId: preset.id,
    customArgs: custom,
    effectiveArgs: effective,
    argsValid: v.ok,
    argsErrors: v.errors,
    argsWarnings: v.warnings,
    command: buildGoodbyeDpiCommand({ presetId: STATE.gdPresetId, args: custom, win: true }),
    serviceBat: buildGoodbyeDpiServiceInstall({ args: effective }),
    blacklistBat: buildGoodbyeDpiBlacklistBat()
  };
}

/** dpiStatusPayload — всё, что нужно UI для вкладки DPI-обхода. */
function dpiStatusPayload() {
  const args = STATE.dpiArgs && STATE.dpiArgs.trim() ? STATE.dpiArgs.trim() : null;
  const preset = DPI_PRESETS.find((p) => p.id === STATE.dpiPresetId) || DPI_PRESETS[0];
  const effectiveArgs = args != null ? args : preset.args;
  const v = validateDpiArgs(effectiveArgs + " --port " + STATE.dpiPort);
  return {
    port: STATE.dpiPort,
    defaultPort: DPI_DEFAULT_PORT,
    flickerPort: FLICKER_DPI_PORT,
    presetId: preset.id,
    presets: DPI_PRESETS.map((p) => ({ id: p.id, name: p.name, args: p.args, note: p.note, origin: p.origin })),
    customArgs: args,
    effectiveArgs,
    argsValid: v.ok,
    argsErrors: v.errors,
    argsWarnings: v.warnings,
    // ВАЖНО: передаём именно `args` (null, когда ручной правки нет), а не
    // STATE.dpiArgs. buildDpiCommand трактует пустую строку как «аргументов
    // нет намеренно» и тогда терял строку пресета — команда получалась
    // «ciadpi.exe --port NNNN» без стратегии обхода.
    command: buildDpiCommand({ presetId: STATE.dpiPresetId, args, port: STATE.dpiPort, win: true }),
    serviceBat: buildServiceInstall({ args: effectiveArgs, port: STATE.dpiPort }),
    activeArgsSource: args != null ? "custom" : "preset",
    description: describeDpi(),
    active: STATE.tunnelKind === "dpi" && STATE.status === "connected",
    // v5.5: второй движок — GoodbyeDPI (прозрачный системный фильтр).
    // В маршрутизации браузера не участвует: только команда/.bat для пользователя.
    goodbyedpi: goodbyedpiPayload()
  };
}

function statusPayload() {
  return {
    status: STATE.status,
    isConnected: STATE.status === "connected",
    currentServer: STATE.currentServer,
    currentProtocol: STATE.currentProtocol,
    bytesSent: STATE.bytesSent,
    bytesReceived: STATE.bytesReceived,
    currentSpeed: STATE.currentSpeed,
    proxyEnabled: STATE.proxyEnabled,
    proxyMode: STATE.proxyMode || "off",
    proxyArmed: STATE.proxyArmed,
    tunnelVerified: STATE.tunnelVerified,
    proxyReleasedByUser: STATE.proxyReleasedByUser,
    holdProxy: STATE.holdProxy,
    // FIX(5.5.9): что с удержанием и не сидим ли мы на «не-VPN» узле
    holdRemainingMs: holdRemainingMs(),
    holdProgressAt: STATE.lastHoldProgressAt,
    holdHardCapMs: holdHardCapMs() === Infinity ? null : holdHardCapMs(),
    armedSnapshot: !!STATE.lastArmedProxySnapshot,
    vpnActive: STATE.status === "connected" && !isLocalTransport(STATE.currentServer),
    currentIsLocal: isLocalTransport(STATE.currentServer),
    probeActive: probeRunning(),
    softLiveness: softLivenessState(),   // FIX(5.5.10): серия отказов dial
    // FIX(5.5.11): последняя VPN-нода и сколько осталось грации после старта
    lastVpnServerId: STATE.lastVpnServerId,
    startGraceLeftMs: isStamp(STATE.lastStartAt)
      ? Math.max(0, START_GRACE_MS - (Date.now() - STATE.lastStartAt)) : 0,
    // FIX(5.5.12): сверка порта и карусель перезапусков — видно в отчёте
    armedPort: STATE.armedPort,
    // FIX(5.5.14): почему прокси не вооружён, если статус «connected». Без этого
    // панель показывала «Прокси браузера: активен» при браузере, смотрящем в
    // мёртвый порт.
    proxyBlockedReason: endpointDead(),
    // FIX(5.5.14): почему прокси не вооружён, если статус «connected». Без этого
    // панель показывала «Прокси браузера: активен» при браузере, смотрящем в
    // мёртвый порт.
    proxyBlockedReason: endpointDead(),
    // FIX(5.5.14): почему прокси не вооружён, если статус «connected». Без этого
    // панель показывала «Прокси браузера: активен» при браузере, смотрящем в
    // мёртвый порт.
    proxyBlockedReason: endpointDead(),
    sameNodeRestarts: STATE.sameNodeRestarts || 0,
    lastStartServerId: STATE.lastStartServerId,
    restartLoop: (STATE.sameNodeRestarts || 0) >= RESTART_LOOP_MAX,
    probeTotal: STATE.probe?.total || 0,
    journalTail: STATE.journal.slice(-12),
    // FIX(5.5.8): что делает восстановление и почему (видно в «Диагностике»)
    recoveryStage: STATE.recoveryStage,
    recoveryAttempt: STATE.recoveryAttempt || 0,
    lastRecovery: STATE.lastRecovery,
    deaths: Object.fromEntries(STATE.deaths),
    suspectedDpi: !!STATE.suspectedDpi,
    awgUnsupported: !!STATE.awgUnsupported,
    strictLiveness: STATE.strictLiveness,
    holding: STATE.proxyMode === "holding",
    holdSince: STATE.holdSince,
    lastVerifiedAt: STATE.lastVerifiedAt,
    lastStatsAt: STATE.lastStatsAt,
    verifyFails: STATE.verifyFails,
    nativeOnline: STATE.nativeOnline,
    nativeVerified: STATE.nativeVerified,
    nativeLastError: STATE.nativeLastError,
    lastProxyError: STATE.lastProxyError,
    nativeInfo: STATE.nativeInfo,
    killSwitchEnabled: STATE.killSwitchEnabled,
    killSwitchBlocked: STATE.killSwitchBlocked,
    splitTunneling: STATE.splitTunneling,
    excludedDomains: STATE.excludedDomains,
    autoSelectEnabled: STATE.autoSelectEnabled,
    hideDead: STATE.hideDead,
    autoRefresh: STATE.autoRefresh,
    autoSwitchEnabled: STATE.autoSwitchEnabled,
    experimentalUdp: STATE.experimentalUdp,
    lastRefreshAt: STATE.lastRefreshAt,
    socksPort: STATE.socksPort,
    stats: { ...STATE.stats },
    probe: { ...publicProbeState(), passes: STATE.probePasses },
    subscriptions: {
      count: STATE.subscriptions.length,
      enabled: STATE.subscriptions.filter((s) => s.enabled).length,
      lastFetchAt: STATE.subscriptions.reduce((m, s) => Math.max(m, s.lastFetchAt || 0), 0) || null,
      stats: sourceStats(STATE.subscriptions)
    },
    // v5: режим маршрутизации — что через VPN, что напрямую
    switching: STATE.switching,
    bypassSystemProxy: STATE.bypassSystemProxy,
    tunnel: {
      mode: STATE.tunnelMode,
      description: describeMode(STATE.tunnelMode),
      perRequest: STATE.perRequestProxy,
      vpnDomains: STATE.ruleset?.vpnDomains?.length || 0,
      directDomains: STATE.ruleset?.directDomains?.length || 0,
      directCidrs: STATE.ruleset?.directCidrs?.length || 0
    },
    // v5: сколько нод с накопленной историей (детальная сводка — getRatingSummary)
    rating: { tracked: STATE.rating?.size?.() || 0 },
    // FIX(5.5.5): отбор по эффективности и постоянный блок мусорных нод
    maxPingMs: STATE.maxPingMs,
    holdMaxMs: holdMaxMs(),
    blocked: {
      total: STATE.blocklist?.size?.() || 0,
      byReason: blocklistSummary(STATE.blocklist?.all?.() || []).byReason,
      labels: BLOCK_REASON_LABEL
    },
    sessionRestored: STATE.sessionRestored,
    // v5.4: локальный DPI-обход
    tunnelKind: STATE.tunnelKind,
    dpi: dpiStatusPayload()
  };
}

browser.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      switch (msg.action) {
        case "getStatus":
          sendResponse(statusPayload());
          break;

        case "toggleConnect": {
          if (STATE.status !== "disconnected") {
            await stopTunnel();
            sendResponse({ ok: true, status: STATE.status });
            return;
          }
          // v5.5.2: «СБРОСИТЬ БЛОКИРОВКУ» обязан разблокировать ВСЕГДА.
          // Явное нажатие снимает kill-switch ДО попытки подключения: иначе
          // при неподключаемом выбранном сервере (например dpi-local без
          // ByeDPI) кнопка «залипает» и трафик заблокирован навсегда, хотя
          // пользователь явно попросил его пустить.
          if (STATE.killSwitchBlocked) {
            releaseKillBlock();
            await applyProxyMode();
            broadcastUI({ type: "killswitch", message: "Блокировка снята — подключаюсь…" });
          }
          let server = msg.config;
          if (STATE.autoSelectEnabled) {
            const best = await autoSelectBestServer(await getServers());
            if (!best) {
              const anySubs = (await getServers()).some((s) => s.sub);
              sendResponse({
                ok: false,
                error: anySubs
                  ? ERRORS.NO_SERVERS
                  : "Нет серверов с учётными данными для авто-выбора. Обновите подписку или добавьте свой."
              });
              return;
            }
            server = best;
          }
          if (!server || (!server.host && !server.server)) {
            sendResponse({ ok: false, error: "Выберите сервер" });
            return;
          }
          const res = await startTunnel(server);
          sendResponse(res.ok
            ? { ok: true, status: STATE.status, pending: true }
            : { ok: false, error: humanizeTunnelError(res.error, server) });
          break;
        }

        case "disconnect":
          await stopTunnel();
          sendResponse({ ok: true, status: STATE.status });
          break;

        // v5: атомарная смена сервера без окна утечки
        case "switchServer": {
          let target = msg.config;
          if (!target && msg.serverId) {
            target = (await getServers()).find((x) => x.id === msg.serverId) || null;
          }
          if (!target) {
            sendResponse({ ok: false, error: "Сервер не найден" });
            break;
          }
          const r = await switchServer(target);
          broadcastUI({
            type: "serverSwitched",
            ok: r.ok, to: target.id,
            toName: target.name || target.host,
            rolledBack: !!r.rolledBack, error: r.error || null
          });
          sendResponse(r.ok
            ? { ok: true, status: STATE.status, pending: true }
            : { ok: false, error: humanizeTunnelError(r.error, target), rolledBack: !!r.rolledBack });
          break;
        }

        // v5.3: аварийный возврат прокси браузеру. Работает всегда — страница
        // расширения не зависит от сети, в отличие от обычных сайтов.
        case "releaseProxy":
          STATE.proxyReleasedByUser = true;
          clearTimeout(STATE.verifyTimer);
          STATE.verifyTimer = null;
          STATE.holdSince = null;   // FIX(5.5.4.2): явное требование — не держим
          await releaseProxy(msg.reason || "по запросу пользователя", { byUser: true });
          sendResponse({ ok: true, proxyMode: STATE.proxyMode });
          break;

        case "retryVerify":
          STATE.proxyReleasedByUser = false;
          STATE.tunnelVerified = false;
          STATE.verifyFails = 0;
          scheduleVerify();
          sendResponse({ ok: true });
          break;

        // ---- v5.4: локальный DPI-обход ----
        case "getDpiConfig":
          sendResponse({ ok: true, dpi: dpiStatusPayload() });
          break;

        case "setDpiConfig": {
          if (msg.port != null) {
            const port = Number(msg.port);
            if (!Number.isInteger(port) || port < 1 || port > 65535) {
              sendResponse({ ok: false, error: "Порт должен быть 1–65535" });
              break;
            }
            if (port === STATE.socksPort) {
              // FIX(5.5.9): предлагаем конкретный свободный порт, а не абстрактный
              const alt = resolveDpiPort({ wanted: port, taken: [STATE.socksPort] }).port;
              sendResponse({
                ok: false,
                error: `Порт ${port} занят SOCKS5 native host (хост сдвинулся с 1080 через autoPort). Возьми свободный, например ${alt}.`
              });
              break;
            }
            STATE.dpiPort = port;
          }
          if (msg.presetId != null) {
            if (!DPI_PRESETS.some((p) => p.id === msg.presetId)) {
              sendResponse({ ok: false, error: "Неизвестный пресет: " + msg.presetId });
              break;
            }
            STATE.dpiPresetId = msg.presetId;
            STATE.dpiArgs = "";       // пресет сбрасывает ручную правку
          }
          if (msg.args != null) STATE.dpiArgs = String(msg.args);
          // v5.5: настройки GoodbyeDPI (независимы от ByeDPI)
          if (msg.gdPresetId != null) {
            if (!GOODBYEDPI_PRESETS.some((p) => p.id === msg.gdPresetId)) {
              sendResponse({ ok: false, error: "Неизвестный пресет GoodbyeDPI: " + msg.gdPresetId });
              break;
            }
            STATE.gdPresetId = msg.gdPresetId;
            STATE.gdArgs = "";
          }
          if (msg.gdArgs != null) STATE.gdArgs = String(msg.gdArgs);

          const eff = STATE.dpiArgs.trim()
            ? STATE.dpiArgs.trim()
            : (DPI_PRESETS.find((p) => p.id === STATE.dpiPresetId) || DPI_PRESETS[0]).args;
          const check = validateDpiArgs(eff + " --port " + STATE.dpiPort);

          await browser.storage.local.set({
            dpiPort: STATE.dpiPort, dpiPresetId: STATE.dpiPresetId, dpiArgs: STATE.dpiArgs,
            gdPresetId: STATE.gdPresetId, gdArgs: STATE.gdArgs
          });

          // если DPI-туннель активен — перечитываем порт без разрыва маршрутизации
          if (STATE.tunnelKind === "dpi" && STATE.status === "connected") {
            const re = await startDpiTunnel(STATE.currentServer);
            if (!re.ok) broadcastUI({ type: "error", message: re.error });
          }
          sendResponse({ ok: check.ok, dpi: dpiStatusPayload(), errors: check.errors, warnings: check.warnings });
          break;
        }

        case "probeDpi": {
          const port = Number(msg.port) || STATE.dpiPort;
          const r = await probeThroughProxy(port);
          sendResponse({
            ok: r.ok, status: r.status, error: r.error || null,
            verifiedVia: r.verifiedVia,
            hint: r.ok ? null : dpiNotRunningError(port, r.error)
          });
          break;
        }

        case "setStrictLiveness": {
          // FIX(5.5.4.3): тумблер «строгая проверка живости (tunnelAlive)»
          STATE.strictLiveness = msg.enabled === true;
          await browser.storage.local.set({ strictLiveness: STATE.strictLiveness });
          STATE.verifyFails = 0;
          sendResponse({ ok: true, strictLiveness: STATE.strictLiveness });
          break;
        }

        case "setMaxPing": {
          // FIX(5.5.5): потолок задержки для отбраковки нод
          const v = Number(msg.maxPingMs);
          if (!Number.isFinite(v) || v < 50 || v > 20000) {
            sendResponse({ ok: false, error: "Допустимый диапазон 50…20000 мс" });
            break;
          }
          STATE.maxPingMs = Math.round(v);
          await browser.storage.local.set({ maxPingMs: STATE.maxPingMs });
          // рейтинг пересчитывается с новым потолком: узлы, которые теперь
          // медленнее допустимого, теряют «доверенный» статус
          STATE.rating.rescore();
          await ratingFlush(true);
          const list = sortWithPolicy(await getServers());
          broadcastUI({ type: "serversUpdated", servers: list, at: STATE.lastRefreshAt });
          sendResponse({
            ok: true, maxPingMs: STATE.maxPingMs,
            usable: list.filter((x) => isUsable(x, STATE.maxPingMs)).length
          });
          break;
        }

        case "setHoldMax": {
          const v = Number(msg.holdMaxMs);
          if (!Number.isFinite(v) || v < 15000 || v > 600000) {
            sendResponse({ ok: false, error: "Допустимый диапазон 15…600 c" });
            break;
          }
          STATE.holdMaxMs = Math.round(v);
          await browser.storage.local.set({ holdMaxMs: STATE.holdMaxMs });
          sendResponse({ ok: true, holdMaxMs: STATE.holdMaxMs });
          break;
        }

        case "blockServer": {
          // ручная блокировка: узел больше не появится в списке
          const list = await getServers();
          const srv = list.find((x) => x.id === msg.id);
          if (!srv) { sendResponse({ ok: false, error: "Сервер не найден" }); break; }
          blockServerNode(srv, BLOCK_REASONS.MANUAL, { label: msg.reason || null });
          const rest = sortWithPolicy((await getServers()).filter((x) => !x.blocked));
          await persistServers(rest);
          broadcastUI({ type: "nodeBlocked", id: srv.id, reason: BLOCK_REASONS.MANUAL, total: STATE.blockedTotal });
          broadcastUI({ type: "serversUpdated", servers: rest, at: STATE.lastRefreshAt });
          sendResponse({ ok: true, total: STATE.blockedTotal });
          break;
        }

        case "unblockServer": {
          const key = String(msg.key || "");
          const id = msg.id ? String(msg.id) : null;
          let removed = false;
          if (key) removed = STATE.blocklist.remove(key);
          if (id) { STATE.rating.unblock(id); removed = true; }
          await STATE.blocklist.flush().catch(() => {});
          await ratingFlush(true);
          STATE.blockedTotal = STATE.blocklist.size();
          sendResponse({ ok: removed, total: STATE.blockedTotal });
          break;
        }

        case "clearBlocklist": {
          const n = STATE.blocklist.clear();
          await STATE.blocklist.flush().catch(() => {});
          // рейтинги разблокированных нод пересчитываются по их истории
          STATE.rating.rescore();
          await ratingFlush(true);
          STATE.blockedTotal = 0;
          sendResponse({ ok: true, cleared: n, total: 0 });
          break;
        }

        case "getBlocklist": {
          const all = STATE.blocklist.all().sort((a, b) => (b.blockedAt || 0) - (a.blockedAt || 0));
          sendResponse({
            ok: true, total: all.length, maxPingMs: STATE.maxPingMs,
            labels: BLOCK_REASON_LABEL,
            entries: all.map((e) => ({
              key: e.key, reason: e.reason, label: e.label, host: e.host,
              ping: e.ping, note: e.note, hits: e.hits || 0,
              blockedAt: e.blockedAt, serverId: e.serverId
            }))
          });
          break;
        }

        case "setHoldProxy": {
          // FIX(5.5.4.2): тумблер «держать прокси и чинить на месте»
          STATE.holdProxy = msg.enabled !== false;
          if (!STATE.holdProxy) STATE.holdSince = null;
          await browser.storage.local.set({ holdProxy: STATE.holdProxy });
          sendResponse({ ok: true, holdProxy: STATE.holdProxy });
          break;
        }

        case "setBypassSystemProxy": {
          STATE.bypassSystemProxy = msg.enabled !== false;
          await browser.storage.local.set({ bypassSystemProxy: STATE.bypassSystemProxy });
          await applyProxyMode();
          sendResponse({ ok: true, bypassSystemProxy: STATE.bypassSystemProxy });
          break;
        }

        case "getServers":
          sendResponse({ servers: await getServers() });
          break;

        case "loadExamples": {
          const list = await getServers();
          const have = new Set(list.map((s) => s.id));
          let added = 0;
          for (const ex of EXAMPLE_SERVERS) {
            if (!have.has(ex.id)) { list.push({ ...ex }); added++; }
          }
          if (added) await persistServers(list);
          sendResponse({ ok: true, added, servers: list });
          break;
        }

        case "saveServer": {
          const list = await getServers();
          const idx = list.findIndex((s) => s.id === msg.server.id);
          if (idx >= 0) list[idx] = { ...list[idx], ...msg.server };
          else list.push(msg.server);
          await persistServers(list);
          sendResponse({ ok: true, servers: list });
          break;
        }

        case "deleteServer": {
          const list = (await getServers()).filter((s) => s.id !== msg.serverId);
          await persistServers(list);
          // подписочный сервер удалён вручную → не возвращать его из подписки
          const deleted = await browser.storage.local.get("excludedServerIds");
          const excluded = new Set(deleted.excludedServerIds || []);
          excluded.add(msg.serverId);
          await browser.storage.local.set({ excludedServerIds: [...excluded] });
          sendResponse({ ok: true, servers: list });
          break;
        }

        case "getProtocols":
          sendResponse({ protocols: PROTOCOLS });
          break;

        case "setAdvanced": {
          STATE.advanced = msg.config || {};
          await browser.storage.local.set({ advanced: STATE.advanced });
          sendResponse({ ok: true });
          break;
        }

        case "setKillSwitch":
          STATE.killSwitchEnabled = !!msg.enabled;
          if (!STATE.killSwitchEnabled) releaseKillBlock();
          await browser.storage.local.set({ killSwitch: STATE.killSwitchEnabled });
          await applyProxyMode();
          sendResponse({ ok: true });
          break;

        case "setSplitTunneling":
          STATE.splitTunneling = !!msg.enabled;
          STATE.excludedDomains = msg.domains || [];
          await browser.storage.local.set({
            splitTunneling: STATE.splitTunneling,
            excludedDomains: STATE.excludedDomains
          });
          // пользовательские исключения теперь попадают в ruleset как "!domain"
          // и учитываются пер-запросно, а не только в fallback-режиме manual
          await rebuildRuleset({ excludedDomains: STATE.excludedDomains });
          await applyProxyMode();
          sendResponse({ ok: true, tunnel: statusPayload().tunnel });
          break;

        // ---- v5: режим маршрутизации ----
        case "setTunnelMode": {
          const mode = String(msg.mode || "");
          if (!Object.values(TUNNEL_MODES).includes(mode)) {
            sendResponse({ ok: false, error: "Неизвестный режим: " + mode });
            break;
          }
          const prevMode = STATE.tunnelMode;
          // FIX(5.5.12): повторная установка ТОГО ЖЕ режима — не событие.
          // Селект в popup меняет значение от колеса мыши и стрелок, и каждый
          // такой «change» перезапускал туннель атомарной сменой ноды.
          if (mode === prevMode) {
            sendResponse({ ok: true, unchanged: true, tunnel: statusPayload().tunnel });
            break;
          }
          STATE.tunnelMode = mode;
          await browser.storage.local.set({ tunnelMode: mode });
          await rebuildRuleset({ mode });
          journal("tunnel-mode", `${prevMode || "-"} → ${mode}`);
          if (mode === TUNNEL_MODES.OFF) {
            // «Ничего не через VPN» = расширение вообще не должно держать прокси
            STATE.proxyReleasedByUser = true;
            await releaseProxy("режим маршрутизации: off");
            // FIX(5.5.12): гасим цикл подтверждения — в режиме «Ничего»
            // подтверждать нечего, а проба временно вооружала manual-прокси,
            // то есть «выключенный VPN» всё равно тянул трафик через ноду.
            clearTimeout(STATE.verifyTimer);
            STATE.verifyTimer = null;
            STATE.verifyRunning = false;
            STATE.verifyProbing = false;
            STATE.verifyFails = 0;
            // FIX(5.5.12): доводим состояние до «off-mode» общим путём — UI и
            // отчёт показывают честную причину (выбор пользователя), а не
            // «прокси возвращён браузеру» как аварию.
            await applyProxyMode();
            // FIX(5.5.12): туннель НЕ перезапускаем. Прежний код после release
            // уходил в switchServer(та же нода): «выключить VPN» своими руками
            // рвало работающий туннель, а ответ «connected» сбрасывал
            // proxyReleasedByUser и вооружал прокси обратно. В журнале
            // пользователя: [release] режим маршрутизации: off → через 6 c
            // [start] той же ноды.
          } else {
            // FIX(5.5.12): выход из «Ничего» — снимаем запрет на вооружение,
            // иначе прокси не вернётся на туннель до ручного переподключения.
            STATE.proxyReleasedByUser = false;
            await applyProxyMode();
          }
          // правила уехали и в sing-box — пересобираем туннель атомарно,
          // чтобы на время пересборки трафик не уходил мимо VPN
          if (mode !== TUNNEL_MODES.OFF && STATE.status === "connected" && STATE.currentServer &&
              nativeSupportsRouteRules()) {
            const re = await switchServer(STATE.currentServer, { force: true });
            if (!re.ok) broadcastUI({ type: "error", message: re.error });
          } else if (mode !== TUNNEL_MODES.OFF && STATE.status === "connected" &&
                     STATE.currentServer) {
            // FIX(5.5.13): хост правил не получает (у 5.5.4 caps = ack, autoPort,
            // diagnose, probe, liveness) — маршрутизацию держит proxy.settings,
            // и applyProxyMode() выше уже переустановил его на месте: bypass-лист
            // поменялся без единого разрыва. Рвать работающий туннель незачем:
            // в дампе это выглядело как «switch: 193.124.35.241 -> 193.124.35.241»
            // с последующим «proxy=none».
            dbgNative({
              command: "dbg",
              text: `mode=${mode}: правила хосту не отправляются (нет cap routeRules) — туннель не рву, прокси: ${STATE.proxyMode}`
            });
            journal("tunnel-mode-noop",
              `режим ${mode}: хост без cap routeRules — рестарт не нужен, прокси переустановлен`);
          } else if (mode !== TUNNEL_MODES.OFF && STATE.status === "disconnected" &&
                     !STATE.switching && !STATE.recovering) {
            // FIX(5.5.12): режим включили, а туннеля нет — поднимаем, иначе
            // «Ничего → Всё» оставляло пользователя без VPN до ручного клика.
            // Намерение берём из последней настоящей VPN-ноды (5.5.11).
            if (!STATE.resumeServerId && STATE.lastVpnServerId) {
              STATE.resumeServerId = STATE.lastVpnServerId;
            }
            scheduleRecovery("возврат из режима «Ничего»: " + mode);
          }
          broadcastUI({ type: "tunnelMode", ...statusPayload().tunnel });
          sendResponse({ ok: true, tunnel: statusPayload().tunnel });
          break;
        }

        case "getTunnelMode":
          sendResponse({ ok: true, ...statusPayload().tunnel });
          break;

        // ---- v5: рейтинг нод ----
        case "getRatingSummary": {
          const servers = await getServers();
          // FIX(5.5.10): «Диагностика (direct)» всегда топ-1 по рейтингу — пинг до
          // 127.0.0.1 минимальный, ошибок нет (рваться нечему). В отчёте
          // пользователя именно она была единственной «доверенной» нодой, то есть
          // панель врала: доверенных VPN-нод не было вовсе. Сводку считаем только
          // по VPN-нодам, локальные транспорты помечаем отдельно.
          const vpnServers = servers.filter((s) => !isLocalTransport(s));
          // FIX(5.5.13): топ — только VPN-ноды. «Диагностика (direct)» в дампе
          // стояла на 2-м месте топа: подпись честная («← НЕ VPN»), но место в
          // рейтинге она занимала и вытесняла реальную ноду из видимой десятки.
          const ranked = rankCandidates(STATE.rating, vpnServers, { limit: Number(msg.limit) || 10, explore: 0 })
            .map((r) => {
              const e = STATE.rating.get(r.id);
              return {
                id: r.id, name: r.server?.name || r.server?.host, host: r.server?.host,
                port: r.server?.port,     // FIX(5.5.13): имена нод из подписки
                protocol: r.server?.protocol, tier: e.tier,
                score: Math.round(r.score * 1000) / 1000,
                mbps: e.mbps == null ? null : Math.round(e.mbps * 10) / 10,
                rtt: e.rtt == null ? null : Math.round(e.rtt),
                okCount: e.okCount, failCount: e.failCount, failStreak: e.failStreak,
                lastOkAt: e.lastOkAt,
                nonVpn: isLocalTransport(r.server)   // FIX(5.5.10): direct/dpi — не VPN
              };
            });
          sendResponse({
            ok: true,
            summary: {
              ...ratingSummary(STATE.rating, vpnServers),
              nonVpn: servers.length - vpnServers.length,
              totalAll: servers.length
            },
            top: ranked
          });
          break;
        }

        case "resetRating": {
          STATE.rating.clear();
          await STATE.rating.flush();
          sendResponse({ ok: true });
          break;
        }

        case "setAutoSelect":
          STATE.autoSelectEnabled = !!msg.enabled;
          await browser.storage.local.set({ autoSelect: STATE.autoSelectEnabled });
          sendResponse({ ok: true });
          break;

        case "setExperimentalUdp":
          STATE.experimentalUdp = !!msg.enabled;
          await browser.storage.local.set({ experimentalUdp: STATE.experimentalUdp });
          sendResponse({ ok: true, experimentalUdp: STATE.experimentalUdp });
          break;

        case "setSocksPort": {
          const port = Number(msg.port);
          if (!port || port < 1 || port > 65535) {
            sendResponse({ ok: false, error: "Некорректный порт" });
            return;
          }
          STATE.socksPort = port;
          await browser.storage.local.set({ socksPort: port });
          await applyProxyMode();
          sendResponse({ ok: true });
          break;
        }

        case "clearKillSwitch":
          releaseKillBlock();
          await applyProxyMode();
          sendResponse({ ok: true });
          break;

        case "pingServers": {
          const results = await refreshServers();
          sendResponse({ servers: results || [], at: STATE.lastRefreshAt });
          break;
        }

        // ---------- подписки и автопоиск серверов ----------
        case "getSubscriptions": {
          const subs = STATE.subscriptions.length ? STATE.subscriptions : await loadSubscriptions();
          const servers = await getServers();
          sendResponse({
            ok: true,
            subscriptions: subs,
            summary: serversSummary(servers),
            probe: publicProbeState()
          });
          break;
        }

        case "setSubscriptions": {
          // msg.custom: [url,...] — пользовательские источники;
          // msg.enabled: {id:bool}; msg.refreshMinutes: {id:n}
          const subs = STATE.subscriptions.length ? STATE.subscriptions : await loadSubscriptions();
          const next = [];
          for (const s of subs) {
            if (msg.enabled && Object.prototype.hasOwnProperty.call(msg.enabled, s.id)) {
              s.enabled = !!msg.enabled[s.id];
            }
            if (msg.refreshMinutes && Number(msg.refreshMinutes[s.id]) > 0) {
              s.refreshMinutes = Number(msg.refreshMinutes[s.id]);
            }
            next.push(s);
          }
          const keepIds = new Set(next.map((s) => s.id));
          for (const url of (msg.custom || [])) {
            const u = String(url || "").trim();
            if (!/^https?:\/\//i.test(u)) continue;
            const id = "custom-" + fnvHex(u);
            const prev = subs.find((s) => s.id === id);
            next.push(prev ? Object.assign(prev, { enabled: true }) : {
              id, name: u.replace(/^https?:\/\//, "").slice(0, 48), url: u,
              refreshMinutes: 720, builtin: false, enabled: true,
              note: "Пользовательский источник",
              lastFetchAt: null, lastCount: 0, lastError: null
            });
            keepIds.add(id);
          }
          // пользовательские источники, удалённые из списка, убираем
          STATE.subscriptions = normalizeSources(next.filter((s) => s.builtin || keepIds.has(s.id)));
          await persistSubscriptions();
          sendResponse({ ok: true, subscriptions: STATE.subscriptions });
          break;
        }

        case "refreshSubscriptions": {
          const r = await refreshSubscriptions({ force: !!msg.force });
          if (msg.probe !== false && (r.added > 0 || msg.force)) {
            // сразу проверяем новые/все серверы, чтобы «найдено X живых из Y»
            runProbe(msg.mode || "full").catch((e) => console.warn("[flicker] probe:", e));
          }
          sendResponse({ ok: r.ok, ...r });
          break;
        }

        case "probeServers": {
          // явный запрос из UI → force: прогоняем даже доверенные ноды
          const r = await runProbe(msg.mode || "full", msg.ids || null, 0, { force: !!msg.force });
          sendResponse(r);
          break;
        }

        case "checkAllServers": {
          const r = await runProbe("full", null, 0, { force: true });
          sendResponse(r);
          break;
        }

        case "cancelProbe": {
          if (STATE.probe.active) {
            sendToNative({ command: "probeCancel", requestId: STATE.probe.requestId });
            clearTimeout(STATE.probeWatchdog);
            await abortActiveProbe("отменено пользователем");
          }
          sendResponse({ ok: true });
          break;
        }

        case "setAutoSwitch": {
          STATE.autoSwitchEnabled = msg.enabled !== false;
          await browser.storage.local.set({ autoSwitch: STATE.autoSwitchEnabled });
          sendResponse({ ok: true, autoSwitch: STATE.autoSwitchEnabled });
          break;
        }

        case "setSettings": {
          if (msg.hideDead != null) STATE.hideDead = !!msg.hideDead;
          if (msg.autoRefresh != null) STATE.autoRefresh = !!msg.autoRefresh;
          if (msg.probePasses != null) {
            STATE.probePasses = Number(msg.probePasses) === 3 ? 3 : 2;
          }
          await browser.storage.local.set({
            hideDead: STATE.hideDead,
            autoRefresh: STATE.autoRefresh,
            probePasses: STATE.probePasses
          });
          sendResponse({ ok: true, hideDead: STATE.hideDead, autoRefresh: STATE.autoRefresh, probePasses: STATE.probePasses });
          break;
        }

        case "getBreakReport": {
          // FIX(5.5.9): весь разбор обрыва — одним текстом, чтобы не собирать
          // диагностику руками. Копируется в попапе кнопкой «Скопировать отчёт».
          const st = statusPayload();
          const srv = STATE.currentServer || {};
          const lines = [
            `FLICKER VPN — отчёт об обрывах (${new Date().toISOString()})`,
            `расширение: ${VERSION} | хост: ${STATE.nativeInfo?.version || "нет"} | compat: ${STATE.nativeCompat}`,
            `caps хоста: [${[...(STATE.nativeCaps || [])].join(", ")}]`,
            `драйверы: [${(STATE.nativeInfo?.drivers || []).join(", ")}]`,
            `статус: ${st.status} | прокси: ${st.proxyMode} | armed: ${st.proxyArmed} | verified: ${st.tunnelVerified}`,
            `VPN активен: ${st.vpnActive ? "да" : "НЕТ"} | текущий узел: ${srv.id || "-"} (${srv.protocol || "-"}) ${srv.host || ""}:${srv.port || ""}`,
            `локальный транспорт вместо VPN: ${st.currentIsLocal ? "ДА — трафик идёт напрямую/через ciadpi" : "нет"}`,
            `SOCKS порт: ${activeProxyPort()} (вооружён на: ${st.armedPort ?? "-"}) | потолок пинга: ${STATE.maxPingMs} мс`,
            `перезапуски одной ноды подряд без подтверждения: ${st.sameNodeRestarts} (карусель: ${st.restartLoop ? "ДА" : "нет"}) | нода последнего старта: ${st.lastStartServerId || "-"}`,
            `удержание: holdProxy=${STATE.holdProxy} holdMaxMs=${Math.round(holdMaxMs() / 1000)}c hardCap=${st.holdHardCapMs == null ? "∞" : Math.round(st.holdHardCapMs / 1000) + "c"} осталось=${st.holdRemainingMs == null ? "-" : Math.round(st.holdRemainingMs / 1000) + "c"}`,
            `восстановление: ступень=${st.recoveryStage} попытка=${st.recoveryAttempt} подозрение на DPI=${st.suspectedDpi ? "ДА" : "нет"}`,
            `последнее восстановление: ${st.lastRecovery ? JSON.stringify(st.lastRecovery) : "-"}`,
            `обрывы по нодам (10 мин): ${JSON.stringify(st.deaths)}`,
            `проба серверов: active=${st.probeActive} total=${st.probeTotal} alive=${st.probe?.alive ?? "-"} pass=${st.probe?.pass ?? "-"}`,
            `последняя VPN-нода: ${st.lastVpnServerId || "-"} | грация после старта: ${Math.round((st.startGraceLeftMs || 0) / 1000)} c (окно ${Math.round(START_GRACE_MS / 1000)} c)`,
            `soft liveness: отказов dial подряд=${st.softLiveness?.streak ?? 0} (нужно ${st.softLiveness?.needStreak ?? 3}), серия ${Math.round((st.softLiveness?.sinceMs ?? 0) / 1000)} c (нужно ${Math.round((st.softLiveness?.needMs ?? 45000) / 1000)} c), трафик ${(st.bytesSent || 0) + (st.bytesReceived || 0)} байт, strict=${STATE.strictLiveness ? "вкл" : "выкл"}`,
            `verifyFails: ${st.verifyFails} | lastVerifiedAt: ${st.lastVerifiedAt ? new Date(st.lastVerifiedAt).toISOString() : "-"} | lastStatsAt: ${st.lastStatsAt ? new Date(st.lastStatsAt).toISOString() : "-"}`,
            `kill switch: ${st.killSwitchEnabled ? "вкл" : "выкл"} (blocked=${st.killSwitchBlocked}) | последняя ошибка порта: ${st.nativeLastError || "-"}`,
            `AWG: ${st.awgUnsupported ? "хост не поддерживает (caps: amnezia нет)" : "не задействован"}`,
            "",
            "— журнал событий —",
            ...STATE.journal.slice(-60).map((j) => `${new Date(j.t).toISOString().slice(11, 19)} [${j.kind}] ${j.text}`)
          ];
          sendResponse({ ok: true, report: lines.join("\n"), status: st });
          break;
        }

        case "diagnose": {
          // Переподключаемся с нуля, чтобы получить СВЕЖУЮ ошибку, а не
          // закэшированное состояние. Раньше diagnose просто рапортовал
          // nativeOnline, который мог быть true при мёртвом хосте.
          const before = {
            online: STATE.nativeOnline,
            verified: STATE.nativeVerified,
            lastError: STATE.nativeLastError
          };
          try {
            if (STATE.nativePort) { STATE.nativePort._flickerAlive = false; }
          } catch { /* ignore */ }
          STATE.nativePort = null;
          STATE.nativeLastError = null;
          const port = connectNative();
          // даём Firefox время либо открыть канал, либо сообщить об ошибке
          await new Promise((res) => setTimeout(res, 1200));
          const sent = port ? sendToNative({ command: "diagnose" }) : false;

          sendResponse({
            ok: STATE.nativeVerified,
            native: STATE.nativeInfo,
            status: statusPayload(),
            probe: {
              portOpened: !!STATE.nativePort,
              messageSent: sent,
              helloReceived: STATE.nativeVerified,
              lastError: STATE.nativeLastError,
              before,
              socksPort: STATE.socksPort,
              extVersion: VERSION,
              hostName: NATIVE_HOST_NAME,
              checklist: nativeHostChecklist()
            }
          });
          break;
        }

        case "resetAll":
          await browser.storage.local.clear();
          STATE.advanced = {};
          STATE.experimentalUdp = false;
          STATE.killSwitchEnabled = false;
          releaseKillBlock();
          STATE.splitTunneling = false;
          STATE.excludedDomains = [];
          STATE.autoSelectEnabled = false;
          STATE.socksPort = 1080;
          STATE.autoSwitchEnabled = true;
          STATE.subsBootstrapped = false; // следующий старт — снова автозагрузка
          await loadSubscriptions();      // дефолтные источники
          await stopTunnel();
          sendResponse({ ok: true });
          break;

        default:
          sendResponse({ ok: false, error: "Unknown action: " + msg.action });
      }
    } catch (e) {
      console.error("[flicker] message handler error:", e);
      sendResponse({ ok: false, error: String(e?.message || e) });
    }
  })();
  return true; // async sendResponse
});

// ================= Сэмплинг скорости =================

function sampleSpeed() {
  if (STATE.status === "connected") {
    const delta = STATE.bytesReceived - STATE.lastSpeedSample;
    STATE.currentSpeed = +((Math.max(0, delta) / 1024 / 1024) * 8).toFixed(2); // Mbps
    STATE.lastSpeedSample = STATE.bytesReceived;
  } else {
    STATE.currentSpeed = 0;
    STATE.lastSpeedSample = STATE.bytesReceived;
  }
}

setInterval(sampleSpeed, 1000);

// ================= Серверы по умолчанию =================

// По умолчанию — только рабочий диагностический сервер: первый запуск
// обязан подключаться без лишних сущностей. Демо-витрина уезжает в EXAMPLE_SERVERS
// и добавляется кнопкой «Добавить примеры» (помечена demo: true, без учётных данных).
export const DEFAULT_SERVERS = [
  // v5.4: локальный обход DPI. Не сервер — ссылка на локальный SOCKS5 (ciadpi).
  // Работает без native host, без подписки и без внешнего VPN-сервера.
  { id: 'dpi-local', name: 'DPI-обход (локально, без сервера)', flag: '🛡',
    host: '127.0.0.1', port: FLICKER_DPI_PORT, protocol: 'dpi',
    ping: null, bandwidth: 0, builtin: true,
    note: 'Нужен запущенный ciadpi.exe из byedpi (MIT). Команду смотри в настройках.' },
  { id: 'diag', name: 'Диагностика (direct)', flag: '🧪', host: '127.0.0.1', port: 443, protocol: 'direct', ping: null, bandwidth: 100 }
];

// Примеры серверов (не подключаются без пароля/UUID; живут за кнопкой в popup)
export const EXAMPLE_SERVERS = [
  { id: 'nl1', name: 'Нидерланды #1', flag: '🇳🇱', host: 'nl1.flicker.local', port: 443, protocol: 'hysteria2', ping: null, bandwidth: 200, demo: true },
  { id: 'de2', name: 'Германия #2', flag: '🇩🇪', host: 'de2.flicker.local', port: 443, protocol: 'hysteria2', ping: null, bandwidth: 200, demo: true },
  { id: 'se1', name: 'Швеция', flag: '🇸🇪', host: 'se1.flicker.local', port: 443, protocol: 'vless', ping: null, bandwidth: 150, demo: true },
  { id: 'fi1', name: 'Финляндия', flag: '🇫🇮', host: 'fi1.flicker.local', port: 443, protocol: 'vless', ping: null, bandwidth: 150, demo: true },
  { id: 'gb1', name: 'Великобритания', flag: '🇬🇧', host: 'gb1.flicker.local', port: 443, protocol: 'hysteria2', ping: null, bandwidth: 180, demo: true },
  { id: 'tr1', name: 'Турция', flag: '🇹🇷', host: 'tr1.flicker.local', port: 443, protocol: 'hysteria2', ping: null, bandwidth: 150, demo: true },
  { id: 'sg1', name: 'Сингапур', flag: '🇸🇬', host: 'sg1.flicker.local', port: 443, protocol: 'hysteria2', ping: null, bandwidth: 200, demo: true },
  { id: 'jp1', name: 'Япония', flag: '🇯🇵', host: 'jp1.flicker.local', port: 443, protocol: 'vless', ping: null, bandwidth: 180, demo: true },
  { id: 'us1', name: 'США East (Нью-Йорк)', flag: '🇺🇸', host: 'us1.flicker.local', port: 443, protocol: 'hysteria2', ping: null, bandwidth: 250, demo: true },
  { id: 'us2', name: 'США West (Лос-Анджелес)', flag: '🇺🇸', host: 'us2.flicker.local', port: 443, protocol: 'vless', ping: null, bandwidth: 250, demo: true },
  { id: 'us3', name: 'США Central (Чикаго)', flag: '🇺🇸', host: 'us3.flicker.local', port: 443, protocol: 'hysteria2', ping: null, bandwidth: 220, demo: true },
  { id: 'us4', name: 'США South (Даллас)', flag: '🇺🇸', host: 'us4.flicker.local', port: 443, protocol: 'hysteria2', ping: null, bandwidth: 200, demo: true },
  { id: 'us5', name: 'США Southeast (Майами)', flag: '🇺🇸', host: 'us5.flicker.local', port: 443, protocol: 'vless', ping: null, bandwidth: 180, demo: true },
  { id: 'us6', name: 'США Northwest (Сиэтл)', flag: '🇺🇸', host: 'us6.flicker.local', port: 443, protocol: 'hysteria2', ping: null, bandwidth: 200, demo: true },
  { id: 'in1', name: 'Индия (Мумбаи)', flag: '🇮🇳', host: 'in1.flicker.local', port: 443, protocol: 'hysteria2', ping: null, bandwidth: 180, demo: true },
  { id: 'in2', name: 'Индия (Дели)', flag: '🇮🇳', host: 'in2.flicker.local', port: 443, protocol: 'hysteria2', ping: null, bandwidth: 160, demo: true },
  { id: 'in3', name: 'Индия (Бенгалуру)', flag: '🇮🇳', host: 'in3.flicker.local', port: 443, protocol: 'vless', ping: null, bandwidth: 150, demo: true },
  { id: 'in4', name: 'Индия (Ченнаи)', flag: '🇮🇳', host: 'in4.flicker.local', port: 443, protocol: 'hysteria2', ping: null, bandwidth: 140, demo: true },
  { id: 'in5', name: 'Индия (Хайдарабад)', flag: '🇮🇳', host: 'in5.flicker.local', port: 443, protocol: 'vless', ping: null, bandwidth: 150, demo: true },
  { id: 'id1', name: 'Индонезия (Джакарта)', flag: '🇮🇩', host: 'id1.flicker.local', port: 443, protocol: 'hysteria2', ping: null, bandwidth: 150, demo: true },
  { id: 'id2', name: 'Индонезия (Сурабая)', flag: '🇮🇩', host: 'id2.flicker.local', port: 443, protocol: 'vless', ping: null, bandwidth: 130, demo: true },
  { id: 'id3', name: 'Индонезия (Бандунг)', flag: '🇮🇩', host: 'id3.flicker.local', port: 443, protocol: 'hysteria2', ping: null, bandwidth: 140, demo: true },
  { id: 'id4', name: 'Индонезия (Денпасар)', flag: '🇮🇩', host: 'id4.flicker.local', port: 443, protocol: 'vless', ping: null, bandwidth: 120, demo: true },
];

// serverHasCredentials — хватает ли учётных данных для протокола.
export function serverHasCredentials(s) {
  if (!s) return false;
  switch (s.protocol) {
    case "vless":
    case "vmess":
      return !!s.uuid;
    case "trojan":
    case "shadowsocks":
    case "hysteria2":
      return !!s.auth;
    case "wireguard":
      return !!(s.wireguard && s.wireguard.privateKey && s.wireguard.peerPublicKey);
    case "dpi":
    case "direct":
      return true;              // локальные транспорты: учётные данные не нужны
    default:
      return true;
  }
}

export function isServerDead(s) {
  // локальные транспорты (direct, dpi) не зависят от внешних нод:
  // «мёртвыми» их помечать нельзя, иначе UI спрячет единственный рабочий вариант
  if (!s || s.protocol === "direct" || s.protocol === "dpi") return false;
  return s.ping === -2;
}

// ================= Память сессии (FIX 5.5.5, RC-1) =================
//
// Firefox MV3 выгружает фоновую страницу примерно через 30 секунд простоя и
// загружает заново при старте браузера. При этом:
//   • browser.storage.local  — ЖИВЁТ (это состояние браузера);
//   • browser.proxy.settings — ЖИВЁТ (настройка принадлежит браузеру);
//   • native host            — ЖИВЁТ, пока жив Firefox (и умирает вместе с ним);
//   • STATE, setTimeout-ы, слушатели — УМИРАЮТ вместе со страницей.
//
// До 5.5.5 новая страница стартовала с чистым STATE (status="disconnected",
// currentServer=null), видела «прокси под моим контролем» и сбрасывала его
// «на всякий случай»: proxyType:"none" → IP уходил браузеру при живом туннеле.
// Восстановление после этого не запускалось вовсе: resumeServerId был пуст.
// Это и есть главный источник «вылетает обрыв туннеля и возврат IP браузеру».
//
// Теперь состояние подключения фиксируется в storage и восстанавливается,
// а решение «сбросить прокси» принимается по ответу хоста, а не вслепую.

/** persistSession — зафиксировать текущее состояние подключения в storage. */
async function persistSession() {
  try {
    const armed = !!(STATE.proxyArmed && STATE.lastArmedProxyValue);
    await browser.storage.local.set({
      [SESSION_KEY]: {
        status: STATE.status,
        serverId: STATE.currentServer?.id || STATE.resumeServerId || null,
        socksPort: STATE.socksPort,
        tunnelKind: STATE.tunnelKind,
        dpiPort: STATE.dpiPort,
        proxyArmed: armed,
        proxyMode: STATE.proxyMode,
        proxyValue: armed ? STATE.lastArmedProxyValue : null,
        killSwitchEnabled: STATE.killSwitchEnabled,
        killSwitchBlocked: STATE.killSwitchBlocked,
        proxyReleasedByUser: STATE.proxyReleasedByUser,
        updatedAt: Date.now()
      }
    });
  } catch (e) { /* storage-сбой не имеет права ронять туннель */ }
}

/** clearPersistedSession — забыть сессию (явное «Отключить» пользователем). */
async function clearPersistedSession() {
  try { await browser.storage.local.remove(SESSION_KEY); } catch { /* ignore */ }
}

/**
 * restoreSessionAfterReload — восстановить память страницы после выгрузки.
 *
 * Прокси при этом НЕ трогаем: если запись свежая и настройка всё ещё наша,
 * браузер остаётся в туннеле, а мы всего лишь продолжаем наблюдение.
 *
 * @returns {Promise<boolean>} true — сессия восстановлена, сбрасывать прокси нельзя
 */
async function restoreSessionAfterReload() {
  let rec = null;
  try { rec = (await browser.storage.local.get(SESSION_KEY))[SESSION_KEY] || null; }
  catch { return false; }
  if (!rec || !rec.proxyArmed || !rec.proxyValue) return false;
  if (rec.status !== "connected" && rec.status !== "connecting") return false;
  if (rec.proxyReleasedByUser) return false;
  const age = Date.now() - (rec.updatedAt || 0);
  if (!Number.isFinite(age) || age > SESSION_MAX_AGE_MS) return false;
  // настройка прокси должна быть по-прежнему нашей: если её перехватило другое
  // расширение или пользователь, восстанавливать нечего
  if (!(await ownsProxySetting())) return false;

  STATE.status = rec.status;
  STATE.socksPort = Number(rec.socksPort) || STATE.socksPort;
  STATE.tunnelKind = rec.tunnelKind === "dpi" ? "dpi" : "native";
  STATE.dpiPort = Number(rec.dpiPort) || STATE.dpiPort;
  STATE.proxyArmed = true;
  STATE.proxyEnabled = true;
  STATE.lastArmedProxyValue = rec.proxyValue;
  STATE.proxyMode = rec.proxyMode || "socks";
  STATE.killSwitchEnabled = !!rec.killSwitchEnabled;
  STATE.killSwitchBlocked = !!rec.killSwitchBlocked;
  // Подтверждение запрашиваем заново — честно. Но heartbeat обнулять нельзя:
  // иначе watchdog немедленно приговорил бы туннель за «молчание статистики»,
  // которое вызвано нашей же выгрузкой, а не реальным обрывом.
  STATE.tunnelVerified = false;
  STATE.lastStatsAt = Date.now();
  STATE.sessionRestored = true;

  if (rec.serverId) {
    STATE.resumeServerId = rec.serverId;
    try {
      const list = await getServers();
      const srv = (list || []).find((x) => x.id === rec.serverId);
      if (srv) STATE.currentServer = srv;
      // FIX(5.5.11): в отчёте пользователя старт выглядел так:
      //   [direct] выбран узел diag (direct) — это не VPN
      //   [start]  diag direct 127.0.0.1:443     ← 28 секунд без VPN
      //   [start]  sub-6da6d52c vless ...
      // Прошлая сессия закончилась на «Диагностике», её id лежал в
      // storage.session и восстанавливался как туннель. Так нельзя: direct —
      // это не VPN. Возвращаемся на последнюю настоящую ноду, а если её нет —
      // оставляем выбор восстановлению (оно direct не берёт).
      if (srv && srv.protocol === "direct") {
        const vpnId = STATE.lastVpnServerId && STATE.lastVpnServerId !== srv.id ? STATE.lastVpnServerId : null;
        const vpn = vpnId ? (list || []).find((x) => x.id === vpnId && !isLocalTransport(x)) : null;
        STATE.currentServer = vpn || null;
        STATE.resumeServerId = vpn ? vpn.id : null;
        journal("direct", `при старте пропущен служебный узел ${srv.id} (direct)` +
                          (vpn ? ` — продолжаю на последней VPN-ноде ${vpn.id}` : " — подберу VPN-ноду заново"));
        broadcastUI({
          type: "error",
          message: "Прошлый туннель был на служебном узле «Диагностика (direct)» — это не VPN. " +
                   (vpn ? `Поднимаю «${vpn.name || vpn.host || vpn.id}».` : "Подбираю настоящую ноду.")
        });
      }
    } catch { /* resumeServerId достаточно для восстановления */ }
  }
  console.log("[flicker] сессия восстановлена после перезагрузки страницы:",
    rec.status, rec.serverId || "-", "возраст " + Math.round(age / 1000) + " c");
  return true;
}

// ================= Init =================

async function init() {
  const saved = await browser.storage.local.get([
    "killSwitch", "splitTunneling", "excludedDomains", "autoSelect", "holdProxy", "strictLiveness",
    "advanced", "socksPort", "hideDead", "autoRefresh", "maxPingMs", "holdMaxMs",
    "autoSwitch", "subsBootstrapped", "experimentalUdp", "probePasses",
    "tunnelMode", "bypassSystemProxy", "dpiPort", "dpiPresetId", "dpiArgs",
    "lastVpnServerId",   // FIX(5.5.11): последняя настоящая VPN-нода
    "gdPresetId", "gdArgs"
  ]);

  STATE.killSwitchEnabled = saved.killSwitch || false;
  STATE.splitTunneling = saved.splitTunneling || false;
  STATE.excludedDomains = saved.excludedDomains || [];
  STATE.autoSelectEnabled = saved.autoSelect || false;
  STATE.advanced = saved.advanced || {};
  STATE.socksPort = Number(saved.socksPort) || 1080;
  STATE.hideDead = saved.hideDead ?? true;
  STATE.autoRefresh = saved.autoRefresh ?? true;
  STATE.autoSwitchEnabled = saved.autoSwitch ?? true;
  STATE.subsBootstrapped = !!saved.subsBootstrapped;
  STATE.experimentalUdp = !!saved.experimentalUdp;
  STATE.probePasses = Number(saved.probePasses) === 3 ? 3 : 2;
  STATE.tunnelMode = Object.values(TUNNEL_MODES).includes(saved.tunnelMode)
    ? saved.tunnelMode : DEFAULT_TUNNEL_MODE;
  // по умолчанию true: не отдаём браузер системному прокси (защита от утечки)
  STATE.bypassSystemProxy = saved.bypassSystemProxy !== false;
  // FIX(5.5.4.2): по умолчанию ДЕРЖИМ прокси при обрыве (пользователь явно
  // просил не выкидывать трафик на прямую)
  STATE.holdProxy = saved.holdProxy !== false;
  // FIX(5.5.11): последняя VPN-нода — куда возвращаться после direct-сессии
  STATE.lastVpnServerId = typeof saved.lastVpnServerId === "string" ? saved.lastVpnServerId : null;
  // FIX(5.5.4.3): строгая проверка живости ВЫКЛЮЧЕНА по умолчанию (как в 5.4.0)
  STATE.strictLiveness = saved.strictLiveness === true;
  // FIX(5.5.5): потолок задержки для отбраковки нод и длительность удержания
  // прокси при обрыве — обе настройки переживают перезапуск.
  const mp = Number(saved.maxPingMs);
  STATE.maxPingMs = Number.isFinite(mp) && mp >= 50 && mp <= 20000 ? mp : DEFAULT_MAX_PING_MS;
  const hm = Number(saved.holdMaxMs);
  STATE.holdMaxMs = Number.isFinite(hm) && hm >= 15000 && hm <= 600000 ? hm : HOLD_MAX_MS;
  // v5.4: локальный DPI-обход. Порт по умолчанию 1081, а не 1080 — иначе ciadpi
  // и native host спорят за один порт.
  const dpiPort = Number(saved.dpiPort);
  STATE.dpiPort = dpiPort >= 1 && dpiPort <= 65535 ? dpiPort : FLICKER_DPI_PORT;
  STATE.dpiPresetId = DPI_PRESETS.some((p) => p.id === saved.dpiPresetId)
    ? saved.dpiPresetId : "upstream-default";
  if (typeof saved.gdPresetId === "string" &&
      GOODBYEDPI_PRESETS.some((p) => p.id === saved.gdPresetId)) {
    STATE.gdPresetId = saved.gdPresetId;
  }
  if (typeof saved.gdArgs === "string") STATE.gdArgs = saved.gdArgs;
  STATE.dpiArgs = typeof saved.dpiArgs === "string" ? saved.dpiArgs : "";

  await loadSubscriptions();

  // v5: поднимаем рейтинг нод и правила маршрутизации ДО connectNative(),
  // иначе первые же probeResult придут в неинициализированный store.
  try {
    await STATE.rating.hydrate();
    const restored = STATE.rating.size();
    if (restored) console.log(`[flicker] rating: восстановлено историй нод — ${restored}`);
  } catch (e) {
    console.warn("[flicker] rating hydrate failed:", e?.message || e);
  }
  // FIX(5.5.5): реестр постоянных блоков грузим ДО первой подписки/пробы,
  // иначе мусорные ноды успели бы попасть в список и в автовыбор.
  try {
    await STATE.blocklist.hydrate();
    STATE.blockedTotal = STATE.blocklist.size();
    if (STATE.blockedTotal) {
      console.log(`[flicker] blocklist: в постоянном блоке ${STATE.blockedTotal} узлов`);
      const removed = await pruneBlockedFromStorage();
      if (removed) console.log(`[flicker] blocklist: удалено из списка ${removed} узлов`);
    }
  } catch (e) {
    console.warn("[flicker] blocklist hydrate failed:", e?.message || e);
  }
  await rebuildRuleset({ mode: STATE.tunnelMode });
  await loadDerivedCache();

  // v5.3: если прошлая сессия умерла (краш, убийство процесса, перезагрузка),
  // настройка прокси могла остаться под нашим контролем — тогда Firefox
  // стартует, слетая на 127.0.0.1:1080, где никого нет, и страницы не грузятся.
  // Трогаем настройку ТОЛЬКО если она действительно наша.
  // FIX(5.5.5) RC-1: сначала пытаемся ВОССТАНОВИТЬ сессию, и только если
  // восстанавливать нечего — сбрасываем унаследованную настройку прокси.
  //
  // v5.3 делала сброс безусловно: «если прокси под нашим контролем, значит
  // прошлая сессия умерла». В MV3 это неверно — страница выгружается и
  // загружается постоянно, а туннель при этом жив. Безусловный сброс и давал
  // «обрыв туннеля + возврат IP браузеру» на ровном месте.
  //
  // v5.3-случай (крах/убийство процесса/перезагрузка) при этом не потерялся:
  // запись сессии либо отсутствует, либо протухла (SESSION_MAX_AGE_MS), либо
  // настройка уже не наша — тогда идём по прежнему пути сброса.
  const sessionRestored = await restoreSessionAfterReload();
  if (!sessionRestored) {
    try {
      if (await ownsProxySetting()) {
        await releaseProxy("сброс унаследованной настройки прокси при старте");
      }
    } catch (e) {
      console.warn("[flicker] startup proxy reset failed:", e?.message || e);
    }
  }

  connectNative();

  if (sessionRestored) {
    // Хост жив → diagnose подтвердит туннель, и работа продолжится как ни в чём
    // не бывало. Хост умер (перезапуск браузера убивает процесс native host) →
    // подтверждение не придёт, и scheduleRecovery поднимет туннель заново на
    // сохранённой ноде, НЕ снимая прокси: браузер всё это время в туннеле.
    scheduleVerify();
    startWatchdog();
    scheduleRecovery("восстановление сессии после перезагрузки страницы");
  }

  browser.alarms.create("keepalive", { periodInMinutes: 1 });
  // фоновое обслуживание (задача 5): раз в 10 минут — «созревшие» подписки
  // + быстрая проверка живых/текущего сервера, низкий приоритет
  browser.alarms.create("background-maintenance", { periodInMinutes: 10 });
  browser.alarms.onAlarm.addListener((a) => {
    if (a.name === "keepalive") {
      sampleSpeed();
      if (!STATE.nativePort) connectNative();
      // v5.3: резервный watchdog на будильнике — setTimeout умирает вместе с
      // выгруженной event page, а alarm будит её сам. Если прокси вооружён, но
      // статистика от хоста давно не приходила, освобождаем прокси.
      if (STATE.proxyArmed && STATE.lastStatsAt &&
          Date.now() - STATE.lastStatsAt > STATS_STALL_MS) {
        STATE.verifyFails++;
        if (STATE.verifyFails >= PROXY_FAIL_LIMIT) {
          // FIX(5.5.5): было releaseProxy() — статус оставался «подключено»,
          // watchdog гас, таймеров не оставалось, и расширение навсегда
          // застревало в «Туннель не работаем — прокси возвращён браузеру».
          // Теперь — общий путь восстановления (с независимым подтверждением).
          recoverIfConfirmedDead("watchdog: нет статистики от хоста")
            .catch((e) => console.error("[flicker] recover:", e));
        } else {
          requestVerify();
        }
      }
      // FIX(5.5.5): alarm — единственный, кто будит выгруженную MV3-страницу.
      // Если прокси снят не пользователем, а туннель должен работать —
      // возвращаемся в игру (setTimeout-ы вместе со страницей уже умерли).
      if (!STATE.proxyArmed && !STATE.proxyReleasedByUser && !STATE.recovering) {
        if (STATE.status === "connected") {
          requestVerify();
        } else if (STATE.resumeServerId || STATE.currentServer?.id) {
          scheduleRecovery("keepalive: туннель не поднят");
        }
      }
    } else if (a.name === "background-maintenance") {
      backgroundMaintenance().catch((e) => console.warn("[flicker] maintenance:", e));
    } else if (/^probe-pass(\d+)$/.test(a.name)) {
      // этап 5: повторный прогон живых через 45 секунд
      const passNo = Number(a.name.slice("probe-pass".length));
      browser.alarms.clear(a.name);
      (async () => {
        const servers = await getServers();
        const aliveIds = servers.filter((s) => s.sub && s.ping >= 0).map((s) => s.id);
        if (aliveIds.length) {
          await runProbe("quick", aliveIds, passNo);
        }
      })().catch((e) => console.warn("[flicker] pass" + passNo + ":", e));
    }
  });

  console.log(
    "[flicker] background ready, v" + VERSION +
    ", источников подписок: " + STATE.subscriptions.length +
    ", режим туннеля: " + STATE.tunnelMode +
    ", прокси: " + (STATE.perRequestProxy ? "per-request (ruleset)" : "manual (fallback)")
  );

  // свежая установка → автозагрузка подписок → проверка → автовыбор (задача 6)
  bootstrapSubscriptions().catch((e) => console.warn("[flicker] bootstrap:", e));
}

export const ready = init();

// exports для тестов
export const __test = {
  STATE,
  refreshSubscriptions,
  runProbe,
  onProbeDone,
  onProbeStage,
  pickBestAlive,
  autoSwitchIfCurrentDead,
  backgroundMaintenance,
  sourceIsDue,
  probeSpec,
  serversSummary,
  bootstrapSubscriptions,
  // v5
  rebuildRuleset,
  recordSample,
  recordSampleById,
  touchRatings,
  tierOf,
  beginSession,
  updateSessionStats,
  endSession,
  perRequestDecision,
  describeNativeFailure,
  nativeHostChecklist,
  releaseProxy,
  startTunnel,
  stopTunnel,
  probeThroughProxy,
  startDpiTunnel,
  verifyDpi,
  dpiStatusPayload,
  activeProxyPort,
  dpiNotRunningError,
  scheduleVerify,
  startWatchdog,
  handleVerifyResult,
  ownsProxySetting,
  onNativeMessage,
  connectNative,
  applyProxyMode,
  recoverFromDeadTunnel,
  recoverIfConfirmedDead,
  releaseProxy,
  confirmTunnelDead,
  scheduleRecovery,
  clearRecovery,
  // FIX(5.5.8): лестница эскалации восстановления + AmneziaWG
  pickRecoveryTarget,
  noteTunnelDeath,
  deathsInWindow,
  transportFingerprint,
  isDpiResistant,
  isAutoSelectable,
  isTooSlow,
  countSlow,
  byPingAsc,
  armStabilityReset,
  // FIX(5.5.9)
  holdStillWanted,
  holdRemainingMs,
  markHoldProgress,
  journal,
  isLocalTransport,
  warnDirectNode,
  probeRunning,
  handleVerifyResult,
  // FIX(5.5.10)
  softLivenessNote,
  softLivenessReset,
  softLivenessState,
  sessionBytes,
  noteTunnelDeath,
  deathsInWindow,
  isStamp,                  // FIX(5.5.11)
  // FIX(5.5.12): сверка порта, режим OFF, анти-карусель
  parseListenPort,
  reconcileSocksPort,
  enqueueProxyApply,
  clearRecoveryTimer,
  TUNNEL_MODES,
  RESTART_LOOP_MAX,
  RESTART_LOOP_BACKOFF_MS,
  VERIFY_RETRY_GAP_MS,
  buildManualValue,
  autoSelectBestServer,
  getServers,
  isServerDead,
  armBudgetMs,
  switchServer,
  setProxyNone,
  composeConfig,
  statusPayload,
  ratingFlush,
  loadDerivedCache,
  // FIX(5.5.5): отбор по эффективности и постоянный блок
  applyProbeVerdict,
  blockServerNode,
  pruneBlockedFromStorage,
  sortWithPolicy,
  scoreOfServer,
  isUsable,
  persistSession,
  restoreSessionAfterReload,
  askHostDiagnose,
  confirmNodeUnusable,
  buildManualValue,
  holdMaxMs
};

