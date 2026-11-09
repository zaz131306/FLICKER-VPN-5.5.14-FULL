// lib/blocklist.js — постоянный реестр «мусорных» нод (FIX 5.5.5).
//
// ЗАЧЕМ. До 5.5.5 отбраковка была мягкой и обратимой: неудачная проба ставила
// `ping = -2`, а следующее обновление подписки возвращало тот же узел обратно в
// список — `mergeServers()` брал его из `incoming` как новый, а `pruneStale()`
// удаляла только то, что не встречалось 14 дней. Публичные бесплатные списки
// отдают одни и те же мёртвые/черепаховые ноды каждый час, поэтому пользователь
// раз за разом видел «пинг 4000» и подключался к нему.
//
// ЧТО ЗДЕСЬ. Вердикт выносится ОДИН раз и хранится по отпечатку узла
// (host + port + protocol + учётные данные), а не по `id`. Это принципиально:
// `id` в подписочных списках производный и может меняться между обновлениями,
// а отпечаток — нет. Поэтому заблокированная нода не вернётся в список ни под
// старым id, ни под новым, и не будет тратить время пробы.
//
// Блок НЕ вечный слепок «плохой погоды»: он снимается, если у узла сменились
// учётные данные (это уже другая нода — отпечаток другой) или если пользователь
// явно разблокировал её в UI.
//
// Модуль не знает про browser.* : хранилище инжектится ({load, save}), как в
// rating.js — тот же код работает и в расширении, и в desktop-демоне.

import { fingerprintOf } from "./rating.js";

/** Причины блока — показываются в UI и пишутся в диагностику. */
export const BLOCK_REASONS = {
  LATENCY: "latency",     // стабильно медленнее потолка (пинг-мусор)
  FLAKY: "flaky",         // доля успехов ниже порога на нескольких прогонах
  FAILURES: "failures",   // серия провалов подряд: узел не поднимает туннель
  MANUAL: "manual"        // пользователь заблокировал сам
};

/** Человекочитаемое описание причины (для списка в UI). */
export const BLOCK_REASON_LABEL = {
  latency: "Слишком высокий пинг",
  flaky: "Нестабильный узел",
  failures: "Не поднимает туннель",
  manual: "Заблокирован вручную"
};

/**
 * Порог задержки по умолчанию, мс. Всё, что медленнее, — не «живой сервер»,
 * а мусор: на такой задержке TLS-рукопожатие и QUIC разваливаются, а автовыбор
 * получает узел, который «отваливается через минуту».
 */
export const DEFAULT_MAX_PING_MS = 1200;

/**
 * Сколько подряд замеров медленнее потолка нужно для вердикта.
 * Защита от одиночного всплеска: одна неудачная секунда не должна навсегда
 * вычёркивать рабочую ноду.
 */
export const LATENCY_STRIKES = 2;

/**
 * LATENCY_HARD_MULTIPLIER — во сколько раз выше потолка должен быть замер,
 * чтобы блок выносился СРАЗУ, без подтверждения вторым замером.
 *
 * Пинг 4000 мс при потолке 1200 мс — это 3.3×: не «всплеск», а откровенный мусор,
 * тратить на него ещё один прогон бессмысленно. А вот 1250 мс при потолке 1200 —
 * пограничное значение, его должен подтвердить второй замер.
 */
export const LATENCY_HARD_MULTIPLIER = 2;

/** Сколько подряд провалов пробы нужно для вердикта «не поднимает туннель». */
export const FAIL_STREAK_BLOCK = 4;

/** Доля успехов ниже которой узел считается нестабильным (по окну последних проверок). */
export const MIN_SUCCESS_RATE = 0.5;

/** Сколько последних проверок учитывать в доле успехов. */
export const RECENT_WINDOW = 4;

/** TTL записи блока по умолчанию: 0 = навсегда (вердикт снимается только явно). */
export const DEFAULT_BLOCK_TTL_DAYS = 0;

const DAY = 86400000;

/**
 * nodeKey — ключ блока. Отпечаток узла, инвариантный к `id` и к порядку полей.
 * @param {object} s серверный объект
 * @returns {string|null}
 */
export function nodeKey(s) {
  if (!s || typeof s !== "object") return null;
  // Локальные транспорты не блокируются никогда: это не внешние ноды.
  if (s.protocol === "direct" || s.protocol === "dpi") return null;
  const fp = fingerprintOf(s);
  if (!fp) return null;
  // fingerprintOf уже покрывает host/port/auth/uuid/ключи — добавляем протокол,
  // чтобы один и тот же host:port под разными протоколами не слипался.
  return (s.protocol || "?") + "|" + fp;
}

/**
 * makeBlocklist — фабрика реестра блоков.
 * @param {{load:()=>Promise<object|null>, save:(o:object)=>Promise<void>, now?:()=>number}} io
 */
export function makeBlocklist(io = {}) {
  const now = io.now || (() => Date.now());
  const state = { entries: new Map(), dirty: false };

  async function hydrate() {
    if (typeof io.load !== "function") return state;
    const raw = await io.load();
    const list = Array.isArray(raw?.entries) ? raw.entries : Array.isArray(raw) ? raw : [];
    state.entries = new Map(
      list.filter((e) => e && e.key).map((e) => [e.key, { ttlDays: DEFAULT_BLOCK_TTL_DAYS, ...e }])
    );
    gc();
    return state;
  }

  async function flush() {
    if (!state.dirty || typeof io.save !== "function") return;
    await io.save({ version: 1, updatedAt: now(), entries: all() });
    state.dirty = false;
  }

  /**
   * add — вынести вердикт. Идемпотентно: повторный блок той же причины
   * не обновляет blockedAt (иначе TTL никогда бы не истёк).
   * @param {object|string} serverOrKey
   * @param {string} reason одна из BLOCK_REASONS
   * @param {object} [info] {ping, label, serverId, note}
   */
  function add(serverOrKey, reason = BLOCK_REASONS.MANUAL, info = {}) {
    const key = typeof serverOrKey === "string" ? serverOrKey : nodeKey(serverOrKey);
    if (!key) return null;
    const prev = state.entries.get(key);
    const e = {
      key,
      reason,
      blockedAt: prev?.blockedAt || now(),
      hits: (prev?.hits || 0) + 1,          // сколько раз подписка пыталась вернуть узел
      lastSeenAt: now(),
      serverId: info.serverId || prev?.serverId || null,
      label: info.label || prev?.label || null,
      host: info.host || prev?.host || null,
      ping: Number.isFinite(info.ping) ? info.ping : (prev?.ping ?? null),
      note: info.note || null,
      ttlDays: Number.isFinite(info.ttlDays) ? info.ttlDays : DEFAULT_BLOCK_TTL_DAYS
    };
    state.entries.set(key, e);
    state.dirty = true;
    return e;
  }

  /** hasKey — заблокирован ли узел с таким ключом. */
  function hasKey(key) {
    if (!key) return false;
    const e = state.entries.get(key);
    if (!e) return false;
    if (expired(e)) { state.entries.delete(key); state.dirty = true; return false; }
    return true;
  }

  /** has — заблокирован ли этот серверный объект. */
  function has(server) { return hasKey(nodeKey(server)); }

  function expired(e) {
    const ttl = Number(e?.ttlDays);
    if (!Number.isFinite(ttl) || ttl <= 0) return false;   // 0 = навсегда
    return now() - (e.blockedAt || 0) > ttl * DAY;
  }

  /** remove — снять блок с одного узла. */
  function remove(serverOrKey) {
    const key = typeof serverOrKey === "string" ? serverOrKey : nodeKey(serverOrKey);
    if (!key) return false;
    const had = state.entries.delete(key);
    if (had) state.dirty = true;
    return had;
  }

  /** clear — очистить реестр целиком (кнопка «Разблокировать всё»). */
  function clear() {
    const n = state.entries.size;
    state.entries = new Map();
    state.dirty = true;
    return n;
  }

  /** Удалить записи с истёкшим TTL. */
  function gc() {
    let removed = 0;
    for (const [key, e] of state.entries) {
      if (expired(e)) { state.entries.delete(key); removed++; }
    }
    if (removed) state.dirty = true;
    return removed;
  }

  function all() { return [...state.entries.values()]; }
  function size() { return state.entries.size; }

  /**
   * filterServers — исключить заблокированные узлы из списка.
   * Используется на ВХОДЕ (свежая подписка) и на ВЫХОДЕ (список для UI/проб),
   * поэтому мусор не появляется ни там, ни там.
   * @param {object[]} servers
   * @returns {{kept:object[], dropped:object[]}}
   */
  function filterServers(servers) {
    const kept = [];
    const dropped = [];
    for (const s of servers || []) {
      if (has(s)) {
        const key = nodeKey(s);
        const e = state.entries.get(key);
        if (e) { e.hits = (e.hits || 0) + 1; e.lastSeenAt = now(); state.dirty = true; }
        dropped.push(s);
      } else {
        kept.push(s);
      }
    }
    return { kept, dropped };
  }

  return { hydrate, flush, add, has, hasKey, remove, clear, gc, all, size, filterServers, now };
}

/**
 * verdictFromProbe — вынести вердикт по результату одной проверки.
 *
 * Чистая функция: не трогает хранилище, возвращает решение, которое применяет
 * вызывающий. Именно здесь живёт правило «пинг 4000 → сразу в блок»:
 *
 *   • alive && rtt > maxPing           → блок LATENCY (мусор, не «живой сервер»);
 *   • latencyStrikes >= LATENCY_STRIKES→ блок LATENCY (подтверждено дважды);
 *   • failStreak >= FAIL_STREAK_BLOCK  → блок FAILURES;
 *   • доля успехов < MIN_SUCCESS_RATE
 *     при полном окне                  → блок FLAKY;
 *   • иначе                            → вердикта нет.
 *
 * @param {object} srv серверный объект (читает .recent, .ping, .latencyStrikes)
 * @param {object} entry запись рейтинга (читает .failStreak, .rtt)
 * @param {{alive:boolean, rtt?:number|null, maxPing?:number}} res
 * @returns {{block:null|string, ping:number|null, errClass:string|null, label:string|null}}
 */
export function verdictFromProbe(srv, entry, res = {}) {
  const maxPing = Number.isFinite(res.maxPing) ? res.maxPing : DEFAULT_MAX_PING_MS;
  const rtt = Number.isFinite(res.rtt) ? res.rtt : null;

  const strikes = Number(srv?.latencyStrikes || entry?.latencyStrikes || 0);

  // 1) Жёсткий потолок задержки. Выше maxPing узел в любом случае НЕ пригоден
  //    (isUsable() его отсекает), а постоянный блок выносится, когда это
  //    однозначный мусор: либо задержка выше потолка в LATENCY_HARD_MULTIPLIER
  //    раз, либо потолок пробит LATENCY_STRIKES замеров подряд.
  if (res.alive && rtt != null && rtt > maxPing) {
    const egregious = rtt > maxPing * LATENCY_HARD_MULTIPLIER;
    if (egregious || strikes >= LATENCY_STRIKES) {
      return {
        block: BLOCK_REASONS.LATENCY, ping: rtt, errClass: "latency",
        label: egregious
          ? `Пинг ${Math.round(rtt)} мс — в ${(rtt / maxPing).toFixed(1)}× выше потолка ${maxPing} мс`
          : `Пинг ${Math.round(rtt)} мс > ${maxPing} мс: ${strikes} замера подряд`
      };
    }
    // пограничный замер: узел непригоден, но вердикт ждёт подтверждения
    return { block: null, ping: rtt, errClass: "latency", label: null };
  }

  // 2) Подтверждённая медлительность по EWMA-задержке из рейтинга: текущий
  //    замер мог не прийти (rtt == null), но накопленная оценка выше потолка.
  if (strikes >= LATENCY_STRIKES) {
    const r = rtt ?? entry?.rtt ?? null;
    return {
      block: BLOCK_REASONS.LATENCY, ping: r, errClass: "latency",
      label: `Пинг ${r == null ? "?" : Math.round(r)} мс: ${strikes} замера подряд выше ${maxPing} мс`
    };
  }

  // 3) Серия провалов: узел вообще не поднимает туннель.
  if (Number(entry?.failStreak || 0) >= FAIL_STREAK_BLOCK) {
    return {
      block: BLOCK_REASONS.FAILURES, ping: null, errClass: "dead",
      label: `${entry.failStreak} провалов подряд`
    };
  }

  // 4) Нестабильность по окну последних проверок.
  const recent = Array.isArray(srv?.recent) ? srv.recent : [];
  if (recent.length >= RECENT_WINDOW) {
    const window = recent.slice(-RECENT_WINDOW);
    const rate = window.reduce((a, b) => a + b, 0) / window.length;
    if (rate < MIN_SUCCESS_RATE) {
      return {
        block: BLOCK_REASONS.FLAKY, ping: null, errClass: "flaky",
        label: `Успех ${Math.round(rate * 100)}% за последние ${window.length} проверок`
      };
    }
  }

  return { block: null, ping: null, errClass: null, label: null };
}

/** Сводка для UI: сколько в блоке и по каким причинам. */
export function blocklistSummary(list) {
  const out = { total: 0, byReason: {} };
  for (const e of list || []) {
    out.total++;
    const r = e.reason || "manual";
    out.byReason[r] = (out.byReason[r] || 0) + 1;
  }
  return out;
}
