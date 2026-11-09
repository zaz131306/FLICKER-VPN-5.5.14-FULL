/**
 * probe-opts.js — контракт с native host по многоэтапной пробе (FIX 5.5.6).
 *
 * Всё здесь выведено из статического разбора `flicker-host.exe` 5.5.4
 * (Go 1.27.3, модуль `flicker-vpn/native`, пакет `internal/probe`), а не
 * из догадок. Что именно известно про хост:
 *
 *  1. Структура `probe.Options` (поля видны в таблице типов бинарника по
 *     json-тегам): mode, concurrency, geoIp, skipTcp, skipQuic, skipHttp,
 *     httpRetries, dialTimeoutMs, tcpTimeoutMs, quicTimeoutMs,
 *     httpTimeoutMs, geoIpTimeoutMs. Расширение версий 5.4.0…5.5.5 слало
 *     только {mode, concurrency, geoIp} — то есть проба всегда шла на
 *     внутренних дефолтах хоста и БЕЗ повторов HTTP.
 *
 *  2. Конвейер пробы: tcp → quic → http (www.gstatic.com/generate_204,
 *     www.cloudflare.com) → cloudflare (httpStatusThroughTunnel) → geoip
 *     (geoIPThroughTunnel). GeoIP ходит на сторонний ip-api.com:
 *     `/json/?fields=status,country,countryCode,query`, ошибки
 *     `geoip status: %s` и `geoip json: %w`. Включается методом
 *     `probe.(*Options).geoIPEnabled` ← opts.geoIp.
 *
 *  3. Результат по узлу: alive, latencyMs, tcpMs, quicMs, errClass, error,
 *     stage, tlsEnabled, effectiveSni, exitIp, country, countryCode,
 *     packetEncoding, internalPort. Замер агрегируется `probe.median` —
 *     то есть хост уже берёт медиану, а не минимум.
 *
 * ── HC-1: этапы-метаданные не имеют права выносить вердикт ──────────────
 * cloudflare и geoip проверяют НЕ узел, а доступность сторонних сервисов
 * из-за туннеля. У бесплатного ip-api.com жёсткий лимит ~45 запросов в
 * минуту на IP; массовая проба с concurrency 12 и сотнями узлов упирается
 * в него гарантированно и возвращает status:"fail". Расширение 5.5.5
 * трактовало ЛЮБОЕ `fatal && !ok` как окончательный провал:
 *     const definitive = msg.stage === "http" || (msg.fatal && !msg.ok);
 *     const alive = !!(msg.ok && msg.stage === "http");
 * поэтому fatal-geoip, пришедший ПОСЛЕ успешного http, перезаписывал
 * вердикт на «мёртв», ставил ping = -2, наращивал failStreak и уводил
 * полностью рабочую ноду в постоянный блок. Отсюда «список сыпется и
 * остаётся мусор». Лечится белым списком этапов, измеряющих сам туннель.
 *
 * ── HC-2: явные таймауты дают замер вместо «таймаута без чисел» ─────────
 * Порог жёсткого блока в rating.js — MAX_RTT_MS (1200) × 2 = 2400 мс.
 * Если этап обрывается по дефолтному таймауту хоста, latencyMs не
 * приходит вовсе: узел на 4000 мс не попадает под мгновенный блок, а
 * копится в failStreak (нужно 4 провала подряд). Таймаут обязан быть
 * заметно выше потолка блока, чтобы мусорный узел УСПЕЛ измериться и был
 * заблокирован сразу и навсегда — ровно то, что требуется от отбора.
 */

/**
 * Этапы, которые измеряют сам туннель/узел и потому могут выносить вердикт.
 * Всё остальное (cloudflare, geoip, любые будущие этапы хоста) — метаданные:
 * показываем в UI, но на alive/рейтинг/блок не влияет.
 */
export const VERDICT_STAGES = Object.freeze(new Set(["tcp", "quic", "http", "sing"]));

/**
 * isVerdictStage — имеет ли этап право менять alive/рейтинг/блок узла.
 * Неизвестное имя этапа ⇒ false: молчаливое согласие с хостом здесь
 * опаснее отказа, потому что ценой ошибки является ложная блокировка.
 * @param {string} stage
 * @returns {boolean}
 */
export function isVerdictStage(stage) {
  return VERDICT_STAGES.has(String(stage == null ? "" : stage).trim().toLowerCase());
}

/**
 * GEOIP_MAX_TARGETS — потолок числа узлов, при котором вообще просим GeoIP.
 * ip-api.com (бесплатный тариф) ≈ 45 запросов/мин на IP. Ниже 20 узлов
 * укладываемся даже с учётом повторов; выше — начинаем получать
 * status:"fail" пачками и (до HC-1) ложно блокировать хорошие ноды.
 * GeoIP даёт только страну/флаг/exitIp, то есть косметику, — поэтому
 * пожертвовать им на больших прогонах безопасно.
 */
export const GEOIP_MAX_TARGETS = 20;

/**
 * Таймауты этапов по режиму, мс. Подобраны от порога жёсткого блока
 * (2400 мс) вверх с запасом ~2–3×, чтобы мусорный узел измерился, а не
 * «молча отвалился». httpRetries — повторы HTTP-проверки: одиночный
 * обрыв больше не приговаривает узел.
 */
export const STAGE_TIMEOUTS = Object.freeze({
  full: Object.freeze({
    dialTimeoutMs: 5_000,
    tcpTimeoutMs: 4_000,
    quicTimeoutMs: 8_000,
    httpTimeoutMs: 6_000,
    geoIpTimeoutMs: 5_000,
    httpRetries: 1
  }),
  quick: Object.freeze({
    dialTimeoutMs: 4_000,
    tcpTimeoutMs: 3_000,
    quicTimeoutMs: 6_000,
    httpTimeoutMs: 4_500,
    geoIpTimeoutMs: 4_000,
    httpRetries: 0
  })
});

/** Параллельность пробы по режиму (как было в 5.5.5, хост это принимает). */
export const PROBE_CONCURRENCY = Object.freeze({ full: 12, quick: 3 });

/**
 * geoIpWanted — просить ли у хоста этап GeoIP.
 * @param {string} mode "full" | "quick"
 * @param {number} targetCount сколько узлов в этом прогоне
 * @returns {boolean}
 */
export function geoIpWanted(mode, targetCount) {
  const n = Number(targetCount);
  return mode === "full" && Number.isFinite(n) && n > 0 && n <= GEOIP_MAX_TARGETS;
}

/**
 * buildProbeOpts — полный пакет opts для команды `probeServers`.
 * Только те поля, которые реально есть в `probe.Options` хоста: лишнее
 * отправлять нельзя, хост умеет отвечать `unknown option`.
 *
 * @param {object} p
 * @param {string} p.mode "full" | "quick"
 * @param {number} p.targetCount число узлов в прогоне
 * @param {boolean} [p.geoIp] явное переопределение (ручная проверка узла)
 * @returns {object} opts для sendToNative
 */
export function buildProbeOpts({ mode, targetCount, geoIp }) {
  const m = mode === "quick" ? "quick" : "full";
  const t = Object.assign({}, STAGE_TIMEOUTS[m]);
  return Object.assign(t, {
    mode: m,
    concurrency: PROBE_CONCURRENCY[m],
    geoIp: typeof geoIp === "boolean" ? geoIp : geoIpWanted(m, targetCount)
  });
}

/**
 * worstCasePerNodeMs — верхняя оценка длительности пробы одного узла.
 * Этапы идут последовательно, HTTP повторяется (1 + httpRetries) раз.
 * @param {object} opts
 * @returns {number}
 */
export function worstCasePerNodeMs(opts) {
  const o = opts || {};
  const n = (v) => (Number.isFinite(v) && v > 0 ? v : 0);
  return n(o.dialTimeoutMs) + n(o.tcpTimeoutMs) + n(o.quicTimeoutMs) +
    n(o.httpTimeoutMs) * (1 + n(o.httpRetries)) + n(o.geoIpTimeoutMs);
}

/**
 * probeWatchdogMs — запас на то, что хост обязан прислать probeDone.
 * Старая формула (5.5.5) `targets × 4000 + 180000` не знала про таймауты,
 * которые мы теперь явно задаём: при 600 узлах и concurrency 12 худший
 * случай длиннее, и watchdog обрывал бы ещё живую пробу. Берём максимум
 * из прежней оценки и честной (волны × худший узел), с общим потолком.
 *
 * @param {number} targetCount
 * @param {object} opts результат buildProbeOpts
 * @returns {number} мс
 */
export function probeWatchdogMs(targetCount, opts) {
  const n = Number(targetCount);
  const count = Number.isFinite(n) && n > 0 ? Math.ceil(n) : 1;
  const conc = Math.max(1, Number((opts || {}).concurrency) || 1);
  const waves = Math.ceil(count / conc);
  const legacy = count * 4_000 + 180_000;
  const derived = waves * worstCasePerNodeMs(opts) + 120_000;
  return Math.min(Math.max(legacy, derived), PROBE_WATCHDOG_CAP_MS);
}

/** Жёсткий потолок watchdog пробы: час. Дальше проба бессмысленна. */
export const PROBE_WATCHDOG_CAP_MS = 3_600_000;

/**
 * PROBE_MSG_BYTE_BUDGET — бюджет размера сообщения `probeServers`.
 * Хост читает кадр native messaging через `nm.Read` и умеет отвечать
 * `nm: message too large`; порог в бинарнике не читается, поэтому просто
 * не позволяем себе отправлять заведомо огромный кадр: если JSON целей
 * выходит за бюджет, прогон режется. Иначе одна большая подписка роняла
 * бы всю проверку целиком (узлы зависали в `checking` до watchdog).
 */
export const PROBE_MSG_BYTE_BUDGET = 2_000_000;

/**
 * fitTargetsToBudget — обрезать список целей под бюджет сообщения.
 * Цели уже отсортированы по приоритету вызывающим кодом; здесь важен
 * только факт «влезет / не влезет».
 *
 * @template T
 * @param {T[]} targets
 * @param {(t: T) => object} specFn та же функция, что кладётся в `servers`
 * @param {number} [budget] байты
 * @returns {{targets: T[], trimmed: number, bytes: number}}
 */
export function fitTargetsToBudget(targets, specFn, budget = PROBE_MSG_BYTE_BUDGET) {
  const list = Array.isArray(targets) ? targets : [];
  const fixed = 160; // command/requestId/opts — считаем константой
  let bytes = fixed;
  const out = [];
  let trimmed = 0;
  for (const t of list) {
    let size;
    try {
      size = JSON.stringify(specFn(t)).length + 1;
    } catch (e) {
      size = 512; // несериализуемая цель — берём с запасом
    }
    if (bytes + size > budget) { trimmed++; continue; }
    bytes += size;
    out.push(t);
  }
  return { targets: out, trimmed, bytes };
}
