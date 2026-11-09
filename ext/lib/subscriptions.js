// lib/subscriptions.js — источники подписок и их разбор (задача 1).
//
// Основной стек — TCP/443 (VLESS+Reality, Trojan, VMess, SS). Hysteria 2
// (UDP/QUIC) — запасной: его источники по умолчанию ВЫКЛЮЧЕНЫ, парсинг hy2
// включается опцией allowHY2 (настройки → «Экспериментальные UDP»).
//
// Встроенные источники живут в lib/sources.js (v5):
//  • tier "ru"     — igareck/vpn-configs-for-russia (BLACK VLESS / SS+All /
//                    Reality white-lists) и w1770946466/Auto_proxy; обновление
//                    каждый час, приоритет при выборе ноды.
//  • tier "global" — Au1rxx (1843 ссылки), peasoft/NoMoreWalls (413),
//                    SS-Collector (b64), MatinGhanbari vless/trojan (289/266).
//  • tier "meta"   — peasoft sources.list: не ноды, а URL 13 восходящих
//                    источников; разворачивается в рантайме.
//  • удалён hysteria350/free-jichang — отдаёт HTTP 403 (проверено 2026-10-15).
//
// Отбор нод больше не бинарный: см. lib/rating.js (рейтинг вместо «жив/мёртв»).
// Что гнать через VPN — см. lib/split-tunnel.js (главный выигрыш по скорости).
//
// Подписка может быть plain-текстом или base64-блобом (v2ray-формат).

import { parseHY2Links } from "./hy2-parser.js";
import { parseShareLinks, splitWireGuardConfs, parseWireGuardConf } from "./share-parser.js";

// Реестр источников вынесен в lib/sources.js (v5): там же проверенные URL,
// счётчики ссылок по состоянию на 2026-10-15, tier-приоритеты и мета-источники.
// Здесь остаётся только логика разбора подписок.
export { DEFAULT_SOURCES, META_SOURCES, TIER_WEIGHT, parseMetaSource, expandMetaSources,
         allBuiltinSources, sourceStats, REMOTE_DIRECT_LISTS } from "./sources.js";
import { DEFAULT_SOURCES, META_SOURCES } from "./sources.js";

/** Все встроенные источники: обычные + мета (списки списков). */
const BUILTIN_SOURCES = [...DEFAULT_SOURCES, ...META_SOURCES];

// base64-алфавит с возможными пробелами/переводами строк
const B64_RE = /^[A-Za-z0-9+/=\s]+$/;

/**
 * decodeSubscriptionText — подписка может прийти plain-текстом или base64.
 * Возвращает текст со ссылками (best effort).
 */
export function decodeSubscriptionText(raw) {
  if (typeof raw !== "string" || !raw.trim()) return "";
  const trimmed = raw.trim();
  // уже текст со ссылками?
  if (trimmed.includes("://")) return trimmed;
  // base64-блоб?
  if (B64_RE.test(trimmed) && trimmed.length >= 16) {
    try {
      let bin;
      if (typeof atob === "function") {
        bin = atob(trimmed.replace(/\s+/g, ""));
      } else {
        bin = Buffer.from(trimmed.replace(/\s+/g, ""), "base64").toString("binary");
      }
      const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
      const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      if (text.includes("://")) return text;
    } catch { /* не base64 — вернём исходный текст */ }
  }
  return trimmed;
}

const SHARE_RE = /(?:vless|trojan|vmess|ss):\/\/[^\s"'<>]+/gi;
const WG_RE = /wireguard:\/\/[^\s"'<>]+/gi;
const HY2_RE = /(?:hysteria2|hy2):\/\/[^\s"'<>]+/gi;

function trimLink(link) {
  return link.replace(/[),;.'"<>]+$/, "");
}

/**
 * extractShareLinks — ссылки TCP/443-стека (+ wireguard) из текста.
 * @param {string} text
 * @param {{allowHY2?:boolean}} [opts] — включать ли hysteria2/hy2
 */
export function extractShareLinks(text, opts = {}) {
  if (!text) return [];
  const out = [];
  for (const re of [SHARE_RE, WG_RE]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      const link = trimLink(m[0]);
      if (link.length > 8) out.push(link);
    }
  }
  if (opts.allowHY2) {
    HY2_RE.lastIndex = 0;
    let m;
    while ((m = HY2_RE.exec(text)) !== null) {
      const link = trimLink(m[0]);
      if (link.length > 8) out.push(link);
    }
  }
  return out;
}

/**
 * parseSubscription — полный разбор текста подписки одного источника.
 * @returns {{servers:object[], failed:object[], linkCount:number}}
 */
export function parseSubscription(rawText, sourceId, opts = {}) {
  const text = decodeSubscriptionText(rawText);
  const links = extractShareLinks(text, opts);
  const share = links.filter((l) => !/^(hysteria2|hy2):\/\//i.test(l));
  const hy2 = links.filter((l) => /^(hysteria2|hy2):\/\//i.test(l));

  const r1 = parseShareLinks(share, { source: sourceId || "custom" });
  const r2 = hy2.length ? parseHY2Links(hy2, { source: sourceId || "custom" }) : { servers: [], failed: [] };

  // FIX(5.5.8): конфиги WireGuard/AmneziaWG текстом ([Interface]/[Peer]).
  // Свой сервер (например от bivlked/amneziawg-installer) отдаёт именно .conf,
  // а не ссылку — раньше такой текст просто выбрасывался.
  const confServers = [];
  const confFailed = [];
  for (const block of splitWireGuardConfs(text)) {
    const r = parseWireGuardConf(block, { source: sourceId || "custom" });
    if (r?.ok && r.server) confServers.push(r.server);
    else confFailed.push({ raw: block.slice(0, 120), error: r?.error || "conf: разбор не удался" });
  }

  return {
    servers: [...r1.servers, ...r2.servers, ...confServers],
    failed: [...r1.failed, ...r2.failed, ...confFailed],
    linkCount: links.length + confServers.length + confFailed.length
  };
}

/**
 * normalizeSources — слияние сохранённых источников с дефолтами:
 * встроенные всегда присутствуют (обновляются url/note из кода),
 * пользовательские сохраняются как есть.
 */
export function normalizeSources(saved) {
  const out = [];
  const savedById = new Map((Array.isArray(saved) ? saved : []).map((s) => [s.id, s]));
  // ВАЖНО: обходим BUILTIN_SOURCES, а не только DEFAULT_SOURCES — иначе
  // мета-источники не попадают в storage.subscriptions и никогда не опрашиваются.
  for (const def of BUILTIN_SOURCES) {
    const s = savedById.get(def.id);
    out.push({
      ...def,
      url: def.url, // URL встроенного источника фиксирован кодом
      enabled: s && s.enabled != null ? !!s.enabled : def.enabled,
      refreshMinutes: Number(s?.refreshMinutes) > 0 ? Number(s.refreshMinutes) : def.refreshMinutes,
      lastFetchAt: s?.lastFetchAt ?? null,
      lastCount: s?.lastCount ?? 0,
      lastError: s?.lastError ?? null
    });
    savedById.delete(def.id);
  }
  for (const s of savedById.values()) {
    if (s && typeof s.url === "string" && /^https?:\/\//i.test(s.url)) {
      out.push({
        id: s.id,
        name: s.name || s.url.replace(/^https?:\/\//, "").slice(0, 48),
        url: s.url,
        refreshMinutes: Number(s.refreshMinutes) > 0 ? Number(s.refreshMinutes) : 720,
        builtin: false,
        enabled: s.enabled !== false,
        allowHY2: !!s.allowHY2,
        note: s.note || "Пользовательский источник",
        lastFetchAt: s?.lastFetchAt ?? null,
        lastCount: s?.lastCount ?? 0,
        lastError: s?.lastError ?? null
      });
    }
  }
  return out;
}

/**
 * mergeServers — слияние свежих подписочных серверов с сохранёнными.
 * Сохраняет накопленную статистику (пинги, проверки, страна) существующих,
 * обновляет поля из ссылки (пароль/sni/ключи могли измениться).
 * @returns {{merged:object[], added:number, updated:number}}
 */
export function mergeServers(existing, incoming, now = Date.now()) {
  const byId = new Map();
  for (const s of existing || []) byId.set(s.id, s);
  let added = 0;
  let updated = 0;
  for (const inc of incoming || []) {
    const prev = byId.get(inc.id);
    if (!prev) {
      byId.set(inc.id, { ...inc, addedAt: now, lastSeenAt: now, checksOk: 0, checksTotal: 0, recent: [] });
      added++;
      continue;
    }
    // Поля, накопленные проверками, не приходят из подписки — если их слепо
    // перезаписать свежим объектом (ping:null и т.п.), статистика теряется.
    // Поэтому link-поля берём из inc, а измерения сохраняем из prev.
    // Пробы теряют смысл только при смене credentials/адреса; смена sni — нет.
    const creds = (s) => JSON.stringify([s.auth, s.uuid, s.obfs?.password, s.reality?.publicKey, s.wireguard?.privateKey, s.host, s.port]);
    const linkChanged = creds(prev) !== creds(inc);

    const keepName = prev.name && prev.name !== "deleted";
    byId.set(inc.id, {
      ...prev,
      ...inc,
      // имя: пользовательское/прежнее важнее автоматически сгенерированного
      name: keepName ? prev.name : inc.name,
      // измерения: сбрасываются только если изменились учётные данные ссылки
      ping: linkChanged ? null : (prev.ping ?? null),
      lastCheckAt: linkChanged ? null : (prev.lastCheckAt ?? null),
      checksOk: linkChanged ? 0 : (prev.checksOk || 0),
      checksTotal: linkChanged ? 0 : (prev.checksTotal || 0),
      recent: linkChanged ? [] : (prev.recent || []),
      country: linkChanged ? undefined : prev.country,
      countryCode: linkChanged ? undefined : prev.countryCode,
      exitIp: linkChanged ? undefined : prev.exitIp,
      flag: linkChanged ? "🌍" : (prev.flag || "🌍"),
      errClass: linkChanged ? undefined : prev.errClass,
      lastError: linkChanged ? undefined : prev.lastError,
      // источник: первый встретившийся выигрывает (не перезаписываем
      // при встрече того же узла в следующей подписке)
      source: prev.source || inc.source,
      addedAt: prev.addedAt || now,
      lastSeenAt: now,
      selected: prev.selected
    });
    updated++;
  }
  return { merged: [...byId.values()], added, updated };
}

/**
 * pruneStale — удаляет подписочные серверы, которые не встречались
 * в источниках дольше maxAgeMs (по умолчанию 14 дней).
 * Пользовательские (sub !== true) и демо не трогает.
 */
export function pruneStale(servers, now = Date.now(), maxAgeMs = 14 * 24 * 3600 * 1000) {
  return (servers || []).filter((s) => !(s.sub && s.lastSeenAt && now - s.lastSeenAt > maxAgeMs));
}

/**
 * isUsable — пригоден ли узел для подключения (FIX 5.5.5).
 *
 * Единый критерий «живой сервер». Раньше им было `ping >= 0`, то есть
 * «когда-то ответил», — и узел с пингом 4000 мс считался живым, попадал в
 * автовыбор и в список наравне с 40 мс. Теперь «живой» = ответил И уложился
 * в потолок задержки И не заблокирован.
 *
 * @param {object} s
 * @param {number} [maxPing] потолок задержки, мс
 */
export function isUsable(s, maxPing = Infinity) {
  if (!s || s.demo || s.blocked) return false;
  const p = typeof s.ping === "number" ? s.ping : null;
  if (p == null || p < 0) return false;
  return p <= maxPing;
}

/**
 * sortServers — живой список для UI.
 *
 * FIX(5.5.5): порядок задаёт ЭФФЕКТИВНОСТЬ, а не факт ответа.
 *   0 — пригодные (ответили в пределах потолка задержки): по рейтингу,
 *       затем по задержке;
 *   2 — непроверенные;
 *   3 — непригодные: мёртвые ИЛИ медленнее потолка (живой, но мусор);
 *   4 — заблокированные вердиктом (в UI не показываются вовсе);
 *   5 — демо.
 * Мёртвые не удаляем — серыми в UI, если пользователь снял «скрывать мёртвых».
 *
 * @param {object[]} servers
 * @param {{maxPing?:number, scoreOf?:(s:object)=>number}} [opts]
 */
export function sortServers(servers, opts = {}) {
  const maxPing = Number.isFinite(opts.maxPing) ? opts.maxPing : Infinity;
  const scoreOf = typeof opts.scoreOf === "function" ? opts.scoreOf : () => 0;
  const rank = (s) => {
    if (s.demo) return 5;
    if (s.blocked) return 4;
    const p = typeof s.ping === "number" ? s.ping : null;
    if (p != null && p >= 0) return p <= maxPing ? 0 : 3;
    if (p === -2) return 3;
    return 2;                                    // -1 / null — неизвестно
  };
  return [...(servers || [])].sort((a, b) => {
    // «Диагностика (direct)» всегда сверху как рабочий инструмент
    if (a.protocol === "direct" && b.protocol !== "direct") return -1;
    if (b.protocol === "direct" && a.protocol !== "direct") return 1;
    const ra = rank(a);
    const rb = rank(b);
    if (ra !== rb) return ra - rb;
    if (ra === 0) {
      // внутри пригодных — самые эффективные первыми
      const sa = scoreOf(a), sb = scoreOf(b);
      if (sb !== sa) return sb - sa;
    }
    const pa = typeof a.ping === "number" && a.ping >= 0 ? a.ping : 1e9;
    const pb = typeof b.ping === "number" && b.ping >= 0 ? b.ping : 1e9;
    if (pa !== pb) return pa - pb;
    return (a.name || "").localeCompare(b.name || "");
  });
}

// Флаг страны по ISO-коду (региональные индикаторы Unicode)
export function countryFlag(code) {
  if (!code || !/^[A-Za-z]{2}$/.test(code)) return "🌍";
  const up = code.toUpperCase();
  return String.fromCodePoint(...[...up].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}
