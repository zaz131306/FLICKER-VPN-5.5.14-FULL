// lib/rating.js — пул нод с рейтингом вместо бинарного «жив/мёртв» (переработка v5).
//
// Проблема старой схемы: probeServers() в background.js (строки 594–950) каждый
// раз прозванивает ВЕСЬ список в 2 прогона по ~45 c, а результат — булево
// «жив/мёртв». Знание о том, что нода быстрая и стабильная, выбрасывается.
//
// Здесь — как в VpnHood Smart Proxies: каждая нода копит историю замеров,
// получает рейтинг, и подключение идёт сразу к лучшей. Полный прогон нужен
// только для холодного старта и для нод с протухшей историей.
//
// Модуль НЕ знает про browser.* : хранилище инжектится ({load, save}), поэтому
// один и тот же код работает и в расширении (browser.storage.local), и в
// desktop-демоне (файл/SQLite).

/** Половина веса замера в днях: через 7 дней старый замер весит вдвое меньше. */
const HALF_LIFE_DAYS = 7;
/** Сколько последних замеров держать на ноду. */
const MAX_SAMPLES = 12;
/** Целевые значения для нормировки (достижимый «хороший» результат). */
const TARGET_MBPS = 25;
const TARGET_RTT = 60;
/**
 * MAX_RTT_MS — жёсткий потолок задержки (FIX 5.5.5).
 *
 * До 5.5.5 задержка входила в рейтинг как `clamp01(1 - rtt/60)`: всё, что
 * медленнее 60 мс, давало НОЛЬ и переставало влиять на оценку. Нода с rtt 4000
 * и «удачными» проверками получала base ≈ 0.55·1 + 0.25·speed ≈ 0.8 — то есть
 * статус «доверенной» — и автовыбор спокойно подключался к ней, потому что
 * формально она «живая». Отсюда «валидация по самым говёным с пингом 4000».
 *
 * Теперь: полный кредит до TARGET_RTT, линейное затухание до нуля на MAX_RTT_MS,
 * а всё, что медленнее MAX_RTT_MS, — score 0 (ниже SCORE_DEAD) и постоянный блок.
 */
export const MAX_RTT_MS = 1200;
/** Рейтинг ниже этого — нода считается непригодной. */
export const SCORE_DEAD = 0.12;
/** Рейтинг выше этого — нода пригодна для автоподключения без доп. пробы. */
export const SCORE_TRUSTED = 0.55;
/** Нод без истории не выбрасываем: им даём нейтральный рейтинг. */
export const SCORE_COLD = 0.45;

const clamp01 = (v) => (Number.isFinite(v) ? Math.min(1, Math.max(0, v)) : 0);
const DAY = 86400000;

/** Пустая запись рейтинга. */
export function emptyEntry(id, now = Date.now()) {
  return {
    id,
    fingerprint: null,       // отпечаток учётных данных ноды; сменился → история сбрасывается
    tier: "global",          // ru | global | custom — множитель из sources.js
    samples: [],             // кольцевой буфер последних замеров
    okCount: 0,
    failCount: 0,
    failStreak: 0,           // подряд идущие провалы — главный сигнал «нода сдохла»
    lastSeenAt: null,        // когда вообще последний раз встречали в подписке
    lastOkAt: null,          // когда последний раз успешно работал
    lastFailAt: null,
    lastFailReason: null,
    rtt: null,               // EWMA, мс
    mbps: null,              // EWMA, Мбит/с
    loss: null,              // EWMA, 0..1
    // FIX(5.5.5): постоянный блок «мусорных» нод (см. lib/blocklist.js)
    blocked: false,          // нода в блоке — рейтинг 0, в список не возвращается
    blockReason: null,       // "latency" | "flaky" | "failures" | "manual"
    latencyStrikes: 0,       // подряд замеров медленнее потолка
    score: SCORE_COLD,
    scoredAt: null
  };
}

/**
 * makeRatingStore — фабрика хранилища рейтингов.
 * @param {{load:()=>Promise<object|null>, save:(o:object)=>Promise<void>,
 *          now?:()=>number, maxRtt?:number|(()=>number)}} io
 *   maxRtt — жёсткий потолок задержки. Может быть функцией: тогда настройка
 *   пользователя («отсекать медленнее N мс») подхватывается без пересоздания
 *   хранилища. По умолчанию MAX_RTT_MS.
 */
export function makeRatingStore(io = {}) {
  const now = io.now || (() => Date.now());
  const maxRtt = () => {
    const v = typeof io.maxRtt === "function" ? io.maxRtt() : io.maxRtt;
    return Number.isFinite(v) && v > 0 ? v : MAX_RTT_MS;
  };
  const state = { entries: new Map(), dirty: false };

  async function hydrate() {
    if (typeof io.load !== "function") return state;
    const raw = await io.load();
    const list = Array.isArray(raw?.entries) ? raw.entries : Array.isArray(raw) ? raw : [];
    state.entries = new Map(list.filter((e) => e && e.id).map((e) => [e.id, { ...emptyEntry(e.id), ...e }]));
    return state;
  }

  async function flush() {
    if (!state.dirty || typeof io.save !== "function") return;
    await io.save({ version: 1, updatedAt: now(), entries: exportEntries() });
    state.dirty = false;
  }

  function get(id) {
    let e = state.entries.get(id);
    if (!e) { e = emptyEntry(id, now()); state.entries.set(id, e); state.dirty = true; }
    return e;
  }

  function exportEntries() {
    return [...state.entries.values()].map((e) => ({ ...e, samples: e.samples.slice(-MAX_SAMPLES) }));
  }

  /**
   * touch — зафиксировать, что нода снова встретилась в подписке.
   * @param {string} id
   * @param {{tier?:string, fingerprint?:string}} [meta]
   *   fingerprint — отпечаток учётных данных (host/port/auth/uuid/ключи). Если он
   *   изменился, нода фактически ДРУГАЯ под тем же id: старая история замеров
   *   к ней не относится и сбрасывается в холодное состояние. Без этого
   *   ротация паролей на публичной ноде давала бы ей незаслуженный рейтинг.
   */
  function touch(id, meta = {}) {
    const e = get(id);
    if (meta.fingerprint) {
      if (e.fingerprint && e.fingerprint !== meta.fingerprint) resetEntry(e);
      e.fingerprint = meta.fingerprint;
    }
    e.lastSeenAt = now();
    if (meta.tier) e.tier = meta.tier;
    state.dirty = true;
    return e;
  }

  /**
   * pushSample — один замер (проба или реальная сессия).
   * @param {string} id
   * @param {{ok?:boolean, rtt?:number|null, mbps?:number|null, loss?:number|null,
   *          reason?:string|null, tier?:string, weight?:number}} s
   */
  function pushSample(id, s = {}) {
    const e = get(id);
    const t = now();
    if (s.tier) e.tier = s.tier;
    e.lastSeenAt = t;
    e.samples.push({ t, ok: !!s.ok, rtt: numOrNull(s.rtt), mbps: numOrNull(s.mbps), loss: numOrNull(s.loss) });
    if (e.samples.length > MAX_SAMPLES) e.samples.splice(0, e.samples.length - MAX_SAMPLES);

    if (s.ok) {
      e.okCount += 1;
      e.failStreak = 0;
      e.lastOkAt = t;
      e.rtt = ewma(e.rtt, s.rtt, 0.5);
      e.mbps = ewma(e.mbps, s.mbps, 0.4);
      e.loss = ewma(e.loss, s.loss ?? 0, 0.4);
    } else {
      e.failCount += 1;
      e.failStreak += 1;
      e.lastFailAt = t;
      e.lastFailReason = s.reason || e.lastFailReason || null;
      e.mbps = ewma(e.mbps, 0, 0.6);      // провал роняет оценку скорости резко
      e.loss = ewma(e.loss, 1, 0.6);
    }
    e.score = computeScore(e, t, { maxRtt: maxRtt() });
    e.scoredAt = t;
    state.dirty = true;
    return e;
  }

  /** Пересчитать все рейтинги (старение происходит само: score зависит от now()). */
  function rescore() {
    const t = now();
    for (const e of state.entries.values()) { e.score = computeScore(e, t, { maxRtt: maxRtt() }); e.scoredAt = t; }
    state.dirty = true;
  }

  /** Удалить записи, которые давно не встречались в подписках. */
  function gc(maxAgeDays = 21) {
    const cut = now() - maxAgeDays * DAY;
    let removed = 0;
    for (const [id, e] of state.entries) {
      const ref = e.lastSeenAt || e.lastOkAt || e.lastFailAt || 0;
      if (ref && ref < cut) { state.entries.delete(id); removed++; }
    }
    if (removed) state.dirty = true;
    return removed;
  }

  /**
   * block — вынести ноде постоянный вердикт (FIX 5.5.5).
   * Рейтинг обнуляется, нода исключается из автовыбора и из списка.
   */
  function block(id, reason = "manual") {
    const e = get(id);
    if (!e.blocked || e.blockReason !== reason) {
      e.blocked = true;
      e.blockReason = reason;
      e.score = 0;
      e.scoredAt = now();
      state.dirty = true;
    }
    return e;
  }

  /** unblock — снять вердикт (пользователь передумал / нода заменена). */
  function unblock(id) {
    const e = get(id);
    e.blocked = false;
    e.blockReason = null;
    e.latencyStrikes = 0;
    e.score = computeScore(e, now(), { maxRtt: maxRtt() });
    e.scoredAt = now();
    state.dirty = true;
    return e;
  }

  /** markLatency — зафиксировать замер медленнее потолка; вернёт запись. */
  function markLatency(id, rtt) {
    const e = get(id);
    const over = Number.isFinite(rtt) && rtt > maxRtt();
    e.latencyStrikes = over ? (e.latencyStrikes || 0) + 1 : 0;
    state.dirty = true;
    return e;
  }

  /** Ядро: все записи (для отладки/экспорта). */
  function all() { return exportEntries(); }
  function size() { return state.entries.size; }
  function clear() { state.entries = new Map(); state.dirty = true; }

  /** reset — сбросить историю одной ноды (например, пользователь сменил пароль). */
  function reset(id) {
    const e = get(id);
    resetEntry(e);
    state.dirty = true;
    return e;
  }

  return { hydrate, flush, get, touch, pushSample, rescore, gc, all, size, clear, reset,
           block, unblock, markLatency, maxRtt, now };
}

/**
 * Обнулить накопленную статистику записи (сохранив id/tier/fingerprint).
 * Вердикт блока НЕ сбрасывается: смена пароля на публичной ноде не делает
 * её быстрее — блок снимается только явно (blocklist.unblock / UI).
 */
function resetEntry(e) {
  const keep = { id: e.id, tier: e.tier, fingerprint: e.fingerprint,
                 blocked: e.blocked, blockReason: e.blockReason };
  Object.assign(e, emptyEntry(e.id), keep, { score: e.blocked ? 0 : SCORE_COLD, scoredAt: null });
}

function numOrNull(v) { return Number.isFinite(v) ? v : null; }

/**
 * fingerprintOf — отпечаток учётных данных серверного объекта.
 * Совпадает по составу полей с проверкой linkChanged в mergeServers(),
 * чтобы сброс рейтинга происходил ровно тогда же, когда сбрасывается ping.
 */
export function fingerprintOf(s) {
  if (!s || typeof s !== "object") return null;
  return JSON.stringify([
    s.host ?? null, s.port ?? null, s.auth ?? null, s.uuid ?? null,
    s.obfs?.password ?? null, s.reality?.publicKey ?? null,
    s.wireguard?.privateKey ?? null, s.cipher ?? null
  ]);
}

/** Экспоненциальное сглаживание; первое значение принимается как есть. */
function ewma(prev, next, alpha) {
  if (!Number.isFinite(next)) return prev ?? null;
  if (!Number.isFinite(prev)) return next;
  return prev * (1 - alpha) + next * alpha;
}

/**
 * latencyNorm — нормированная оценка задержки (FIX 5.5.5).
 *
 * Было: `clamp01(1 - rtt/60)` — любое rtt ≥ 60 мс давало 0, то есть 300 мс и
 * 4000 мс оценивались ОДИНАКОВО. Рейтинг не различал «приемлемо» и «мусор».
 *
 * Стало: полный кредит до target, затем линейное затухание до нуля на max.
 *   40 мс   → 1.00
 *   300 мс  → 0.79
 *   800 мс  → 0.35
 *   1200 мс → 0.00  (и дальше — жёсткий ноль, см. computeScore)
 *
 * @param {number|null} rtt  измеренная задержка, мс (EWMA)
 * @param {number} target    задержка, до которой штраф не начисляется
 * @param {number} max       задержка, на которой оценка падает в ноль
 */
export function latencyNorm(rtt, target = TARGET_RTT, max = MAX_RTT_MS) {
  if (!Number.isFinite(rtt) || rtt == null) return 0.5;   // неизвестно — нейтрально
  if (rtt <= target) return 1;
  if (max <= target) return 0;
  if (rtt >= max) return 0;
  return clamp01(1 - (rtt - target) / (max - target));
}

/**
 * computeScore — рейтинг ноды 0..1.
 *   55% — доля успешных замеров (с весовым затуханием старых);
 *   25% — скорость;
 *   20% — задержка (градуированно, см. latencyNorm);
 *   × штраф за серию провалов;
 *   × бонус за tier (ру-ноды优先, они ближе и лучше под ТСПУ);
 *   × ЖЁСТКИЙ НОЛЬ при rtt > maxRtt и при явно заблокированной ноде.
 *
 * @param {object} e запись рейтинга
 * @param {number} now
 * @param {{maxRtt?:number}} [opts] maxRtt — потолок задержки (по умолчанию MAX_RTT_MS)
 */
export function computeScore(e, now = Date.now(), opts = {}) {
  const maxRtt = Number.isFinite(opts.maxRtt) ? opts.maxRtt : MAX_RTT_MS;
  const samples = Array.isArray(e.samples) ? e.samples : [];
  if (!samples.length && !e.okCount && !e.failCount) return SCORE_COLD;

  // FIX(5.5.5): жёсткий потолок. Нода медленнее maxRtt непригодна независимо от
  // того, сколько раз она «успешно» ответила: именно такие узлы и давали
  // «пинг 4000» в списке и рвали туннель под нагрузкой.
  if (Number.isFinite(e.rtt) && e.rtt > maxRtt) return 0;
  // Явный блок (блок-лист lib/blocklist.js) — рейтинг обнуляется, чтобы нода не
  // прошла ни через один фильтр, даже если история у неё «хорошая».
  if (e.blocked) return 0;

  // Взвешенная доля успехов: свежий замер весит 1.0, недельной давности — 0.5.
  let wSum = 0, wOk = 0;
  for (const s of samples) {
    const ageDays = Math.max(0, (now - s.t) / DAY);
    const w = Math.exp(-ageDays / HALF_LIFE_DAYS);
    wSum += w;
    if (s.ok) wOk += w;
  }
  const successRate = wSum > 0 ? wOk / wSum : 0;

  const speedNorm = clamp01((e.mbps ?? 0) / TARGET_MBPS);
  const latNorm = latencyNorm(e.rtt, TARGET_RTT, maxRtt);

  let base = 0.55 * successRate + 0.25 * speedNorm + 0.20 * latNorm;

  // Серия провалов важнее средней статистики: 4 провала подряд = почти труп.
  const streak = Math.max(0, e.failStreak || 0);
  const penalty = 1 - Math.min(0.9, 0.25 * streak);

  // Протухшая история: нода давно не подтверждала работоспособность.
  const ref = e.lastOkAt || e.lastSeenAt || now;
  const staleness = Math.exp(-Math.max(0, (now - ref) / DAY) / (HALF_LIFE_DAYS * 2));

  const tierBoost = e.tier === "ru" ? 1.12 : e.tier === "meta" ? 0.95 : 1.0;

  return clamp01(base * penalty * staleness * tierBoost);
}

/**
 * rankCandidates — отсортировать ноды «лучшая первой» БЕЗ нового прогона проб.
 * Холодные ноды перемешиваются в середину, чтобы новые списки не голодали.
 * @param {ReturnType<makeRatingStore>} store
 * @param {object[]} servers — серверы из хранилища (нужен .id)
 * @param {{limit?:number, minScore?:number, explore?:number}} [opts]
 *   explore — сколько «неизвестных» нод подмешать в топ (default 2)
 * @returns {{id:string, score:number, known:boolean, server:object}[]}
 */
export function rankCandidates(store, servers, opts = {}) {
  const limit = opts.limit ?? 20;
  const minScore = opts.minScore ?? 0;
  const explore = opts.explore ?? 2;

  const scored = (servers || []).map((server) => {
    const e = store.get(server.id);
    const known = (e.samples?.length || 0) > 0 || e.okCount > 0 || e.failCount > 0;
    return { id: server.id, score: e.score, known, server };
  });

  const ok = scored.filter((c) => c.score >= minScore);
  const known = ok.filter((c) => c.known).sort((a, b) => b.score - a.score);
  const cold = ok.filter((c) => !c.known);

  // Детерминированная «случайность» для холодных: по id, чтобы не дёргалось
  // между запусками, но разные ноды получали шанс в разных сессиях.
  cold.sort((a, b) => (hashId(a.id) ^ store.now()) - (hashId(b.id) ^ store.now()));

  const out = [];
  const coldTake = cold.slice(0, explore);
  const knownTake = known.slice(0, Math.max(0, limit - coldTake.length));
  out.push(...knownTake, ...coldTake);
  return out.slice(0, limit).sort((a, b) => b.score - a.score);
}

function hashId(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < String(s).length; i++) { h ^= String(s).charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
  return h >>> 0;
}

/**
 * needsProbe — надо ли реально прозванивать ноду перед подключением.
 * Доверенным (SCORE_TRUSTED+) верим без пробы — это и убирает 45-секундные циклы.
 */
export function needsProbe(entry, maxAgeMs = 6 * 3600 * 1000) {
  if (!entry) return true;
  if ((entry.samples?.length || 0) === 0 && !entry.okCount && !entry.failCount) return true;
  const ref = entry.lastOkAt || entry.lastSeenAt || 0;
  if (!ref) return true;
  if (Date.now() - ref > maxAgeMs) return true;
  return entry.score < SCORE_TRUSTED;
}

/**
 * pickBest — быстрый выбор одной ноды для «подключиться немедленно».
 * Возвращает null, если доверенных нет (тогда нужен прогон проб).
 */
export function pickBest(store, servers, opts = {}) {
  const ranked = rankCandidates(store, servers, { ...opts, limit: 1, explore: 0 });
  const top = ranked[0];
  if (!top || !top.known || top.score < SCORE_TRUSTED) return null;
  return top;
}

/** Краткая сводка для UI. */
export function ratingSummary(store, servers) {
  const list = servers || [];
  let trusted = 0, dead = 0, cold = 0;
  for (const s of list) {
    const e = store.get(s.id);
    if (!e.samples?.length && !e.okCount && !e.failCount) cold++;
    else if (e.score >= SCORE_TRUSTED) trusted++;
    else if (e.score < SCORE_DEAD) dead++;
  }
  const avgMbps = list.length
    ? list.reduce((a, s) => a + (store.get(s.id).mbps || 0), 0) / Math.max(1, trusted || list.length)
    : 0;
  return { total: list.length, trusted, dead, cold, avgMbps: Math.round(avgMbps * 10) / 10 };
}
