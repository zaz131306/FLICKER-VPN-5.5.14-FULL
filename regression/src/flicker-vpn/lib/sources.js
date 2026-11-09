// lib/sources.js — реестр источников бесплатных нод (переработка v5, задача 1).
//
// Зачем отдельный модуль: DEFAULT_SOURCES разросся и перемешался с логикой
// парсинга в subscriptions.js. Здесь — только ДАННЫЕ: проверенные URL, их
// приоритет и ожидаемый состав. Логика разбора осталась в subscriptions.js.
//
// Все URL прогнаны живым HTTP-запросом 2026-10-30; поле `links` — фактическое
// число распознанных ссылок на момент проверки, `mix` — состав по протоколам.
// Мёртвые источники удалены: `jichang` (HTTP 403), `ebrasha` (HTTP 404,
// заменён на SS-Collector 2026-10-30).
//
// Классы источников (tier) — чем выше, тем раньше источник опрашивается и тем
// выше вес его нод при равных замерах:
//   "ru"     — РФ-специфичные: обход белых списков ТСПУ, обновление каждый час;
//   "global" — мировые агрегаторы: большой объём, свежесть ниже;
//   "meta"   — сам нод не содержит, содержит URL других источников
//              (разворачивается в рантайме, см. expandMetaSources).

export const TIER_WEIGHT = { ru: 3, global: 2, meta: 1, custom: 2 };

// РФ-агрегатор igareck/vpn-configs-for-russia: profile-update-interval=1,
// т.е. ноды пересобираются каждый час. Отсюда берём короткий refreshMinutes.
const IGARECK = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main";
const MATIN = "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs";
const PEASOFT = "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master";

export const DEFAULT_SOURCES = [
  // ==================== tier: ru (приоритет) ====================
  {
    id: "ru-black-vless",
    name: "RU · BLACK VLESS (обход белых списков)",
    url: `${IGARECK}/BLACK_VLESS_RUS.txt`,
    refreshMinutes: 60,
    builtin: true,
    enabled: true,
    tier: "ru",
    links: 98,
    mix: {"vless": 98},
    verifiedAt: "2026-10-30",
    note: "VLESS Reality, заточен под ТСПУ; обновление каждый час"
  },
  {
    id: "ru-black-vless-mobile",
    name: "RU · BLACK VLESS mobile",
    url: `${IGARECK}/BLACK_VLESS_RUS_mobile.txt`,
    refreshMinutes: 60,
    builtin: true,
    enabled: true,
    tier: "ru",
    links: 139,
    mix: {"vless": 63, "trojan": 50, "vmess": 26},
    verifiedAt: "2026-10-30",
    note: "То же, но отфильтровано под мобильные сети (41 КБ)"
  },
  {
    id: "ru-black-all",
    name: "RU · BLACK SS+All",
    url: `${IGARECK}/BLACK_SS%2BAll_RUS.txt`,
    refreshMinutes: 60,
    builtin: true,
    enabled: true,
    tier: "ru",
    links: 114,
    mix: {"trojan": 70, "vmess": 36, "hy2": 8},
    verifiedAt: "2026-10-30",
    note: "Trojan + Hysteria2 + VMess для обхода блокировок"
  },
  {
    id: "ru-white-reality",
    name: "RU · VLESS Reality (white lists)",
    url: `${IGARECK}/Vless-Reality-White-Lists-Rus-Mobile.txt`,
    refreshMinutes: 60,
    builtin: true,
    enabled: true,
    tier: "ru",
    links: 57,
    mix: {"vless": 48, "trojan": 9},
    verifiedAt: "2026-10-30",
    note: "Reality-ноды, проверенные на РФ-мобильных"
  },
  {
    id: "ru-auto-proxy",
    name: "RU · Auto_proxy (long-term)",
    url: "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription1",
    refreshMinutes: 240,
    builtin: true,
    enabled: true,
    tier: "ru",
    links: 69,
    mix: {"vless": 18, "trojan": 3, "vmess": 17, "ss": 28, "hy2": 3},
    verifiedAt: "2026-10-30",
    note: "«Долгоживущие» ноды — реже отваливаются"
  },

  // ==================== tier: global ====================
  {
    id: "au1rxx",
    name: "Au1rxx · free-vpn-subscriptions (verified)",
    url: "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt",
    refreshMinutes: 1440,
    builtin: true,
    enabled: true,
    tier: "global",
    links: 1751,
    mix: {"vless": 1002, "trojan": 234, "vmess": 210, "ss": 134, "hy2": 171},
    verifiedAt: "2026-10-30",
    note: "Крупнейший проверенный агрегатор; узлы прогоняются HTTP-трафиком"
  },
  {
    id: "peasoft",
    name: "peasoft · NoMoreWalls",
    url: `${PEASOFT}/list_raw.txt`,
    refreshMinutes: 360,
    builtin: true,
    enabled: true,
    tier: "global",
    links: 433,
    mix: {"vless": 260, "trojan": 59, "vmess": 32, "ss": 52, "hy2": 30},
    verifiedAt: "2026-10-30",
    note: "Смешанный plain-список"
  },
  {
    id: "sscollector",
    name: "SS-Collector · subscription-all (b64)",
    url: "https://raw.githubusercontent.com/lagzian/SS-Collector/main/configs/subscription-all.b64",
    refreshMinutes: 720,
    builtin: true,
    enabled: true,
    tier: "global",
    links: 335,
    mix: {"vless": 233, "trojan": 52, "ss": 50},
    verifiedAt: "2026-10-30",
    note: "Замена мёртвого EbraSha (404 на 2026-10-30); base64-агрегатор SS/VMess/VLESS"
  },
  {
    id: "matin-vless",
    name: "MatinGhanbari · VLESS",
    url: `${MATIN}/vless.txt`,
    refreshMinutes: 60,
    builtin: true,
    enabled: true,
    tier: "global",
    links: 226,
    mix: {"vless": 226},
    verifiedAt: "2026-10-30",
    note: "Только VLESS (включая Reality/Vision), источник обновляется каждые 15 мин"
  },
  {
    id: "matin-trojan",
    name: "MatinGhanbari · Trojan",
    url: `${MATIN}/trojan.txt`,
    refreshMinutes: 60,
    builtin: true,
    enabled: true,
    tier: "global",
    links: 223,
    mix: {"trojan": 223},
    verifiedAt: "2026-10-30",
    note: "Только Trojan (TCP/443)"
  },

  // ==================== выключены по умолчанию ====================
  {
    id: "matin-vmess",
    name: "MatinGhanbari · VMess (много, но слабо)",
    url: `${MATIN}/vmess.txt`,
    refreshMinutes: 240,
    builtin: true,
    enabled: false,
    tier: "global",
    links: 2650,
    mix: {"vmess": 2650},
    verifiedAt: "2026-10-30",
    note: "2386 нод, но VMess без маскировки режется DPI — включать только если TCP/443-стек не работает"
  },
  {
    id: "matin-hy2",
    name: "MatinGhanbari · Hysteria 2 (UDP)",
    url: `${MATIN}/hysteria2.txt`,
    refreshMinutes: 60,
    builtin: true,
    enabled: false,
    allowHY2: true,
    tier: "global",
    links: 188,
    mix: {"hy2": 188},
    verifiedAt: "2026-10-30",
    note: "UDP/QUIC — запасной транспорт, нужен разрешённый UDP"
  }
];

/**
 * META_SOURCES — файлы, содержащие не ноды, а URL других источников.
 * Разворачиваются в рантайме: один запрос даёт доступ к десяткам списков,
 * причём состав обновляется без релиза приложения.
 *
 * peasoft/NoMoreWalls sources.list на 2026-10-15 содержит 13 записей, среди них:
 *   ripaojiedian/freenode (sub + clash), zhangkaiitugithub/passcro,
 *   shaoyouvip/free, lagzian/SS-Collector, Surfboardv2ray/TGParse (hy2),
 *   snakem982/proxypool, gitlab free9999/ipupdate (3 зеркала).
 */
export const META_SOURCES = [
  {
    id: "meta-peasoft",
    name: "peasoft · sources.list (мета)",
    url: `${PEASOFT}/sources.list`,
    refreshMinutes: 1440,
    builtin: true,
    enabled: true,
    tier: "meta",
    note: "13 восходящих источников одним файлом"
  }
];

/**
 * REMOTE_DIRECT_LISTS — списки для split tunneling: что пускать МИМО VPN.
 * Грузятся split-tunnel.js, не являются источниками нод.
 */
export const REMOTE_DIRECT_LISTS = [
  {
    id: "ru-white-cidr",
    name: "RU · белые CIDR (VK, Yandex, CDNvideo, Beeline)",
    url: `${IGARECK}/WHITE-CIDR-RU-checked.txt`,
    kind: "cidr-config",   // это не список CIDR, а конфиг нод с маршрутизацией по CIDR
    refreshMinutes: 60,
    note: "38 конфигов, обновляется ежечасно"
  },
  {
    id: "peasoft-abpwhite",
    name: "peasoft · abpwhite ( AdBlock -синтаксис)",
    url: `${PEASOFT}/abpwhite.txt`,
    kind: "abp-domain",
    refreshMinutes: 720,
    note: "22 домена-исключения (в т.ч. Alibaba CDN), формат ||domain^"
  }
];

const LINE_RE = /^\s*(https?:\/\/\S+)\s*$/;

/**
 * parseMetaSource — разобрать содержимое мета-источника в список URL.
 * Поддерживает и «голые» URL по строке, и clash-формат `proxy-providers`
 * с отступом (`  url: https://...`).
 * @param {string} text
 * @returns {string[]}
 */
export function parseMetaSource(text) {
  if (!text) return [];
  const out = new Set();
  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    // clash-стиль: "- url: https://..." или "url: https://..."
    const m = line.match(/(?:^|[\s:])(https?:\/\/[^\s"'#,}]+)/);
    if (m) { out.add(m[1]); continue; }
    const bare = line.match(LINE_RE);
    if (bare) out.add(bare[1]);
  }
  return [...out];
}

/**
 * expandMetaSources — превратить записи мета-источников в обычные источники.
 * Не ходит в сеть сам: принимает готовый текст (загрузку делает вызывающий).
 * @param {{url:string,text:string}[]} fetched — скачанные тела мета-источников
 * @returns {object[]} источники, готовые для normalizeSources()
 */
export function expandMetaSources(fetched) {
  const out = [];
  for (const { url, text } of fetched || []) {
    const parent = META_SOURCES.find((m) => m.url === url);
    const urls = parseMetaSource(text);
    urls.forEach((u, i) => {
      const host = u.replace(/^https?:\/\//, "").split("/")[0];
      out.push({
        id: `meta:${host}:${i}`,
        name: host,
        url: u,
        refreshMinutes: 360,
        builtin: false,
        enabled: true,
        tier: "global",
        derivedFrom: parent?.id || url,
        note: "Из мета-источника"
      });
    });
  }
  return out;
}

/** Все встроенные источники, упорядоченные по приоритету опроса. */
export function allBuiltinSources() {
  const all = [...DEFAULT_SOURCES, ...META_SOURCES];
  return all.sort((a, b) => (TIER_WEIGHT[b.tier] || 0) - (TIER_WEIGHT[a.tier] || 0));
}

/**
 * sourceStats — сводка для UI («источники: N, нод: M, обновлено …»).
 * @param {object[]} sources — нормализованные источники с lastCount
 */
export function sourceStats(sources) {
  const list = Array.isArray(sources) ? sources : [];
  const enabled = list.filter((s) => s.enabled !== false);
  return {
    total: list.length,
    enabled: enabled.length,
    alive: enabled.filter((s) => Number(s.lastCount) > 0).length,
    failed: enabled.filter((s) => s.lastError).length,
    links: enabled.reduce((a, s) => a + (Number(s.lastCount) || 0), 0),
    byTier: enabled.reduce((acc, s) => {
      const t = s.tier || "custom";
      acc[t] = (acc[t] || 0) + 1;
      return acc;
    }, {})
  };
}
