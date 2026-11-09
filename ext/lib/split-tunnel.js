// lib/split-tunnel.js — маршрутизация «что гнать через VPN, а что напрямую».
//
// ГЛАВНЫЙ ВЫИГРЫШ по скорости на бесплатных нодах. Сегодня весь трафик (работа,
// видео, российские сервисы) уходит через одну перегруженную чужую ноду. Если
// через неё гнать только то, что реально заблокировано, нагрузка на ноду падает
// в разы, а значит растёт и скорость, и время жизни ноды.
//
// Модуль чистый (без browser.*): решение принимает, применяет вызывающий —
// либо sing-box через toSingBoxRules(), либо браузер через toPacScript().

// ---------------------------------------------------------------------------
// Режимы
// ---------------------------------------------------------------------------
export const MODES = {
  ALL: "all",              // всё через VPN (как сейчас; медленно на бесплатной ноде)
  SMART: "smart",          // зарубежное через VPN, российское напрямую — ПО УМОЛЧАНИЮ
  BLOCKED_ONLY: "blocked", // через VPN только явно заблокированные ресурсы
  OFF: "off"               // VPN выключен
};

export const DEFAULT_MODE = MODES.SMART;

// ---------------------------------------------------------------------------
// Встроенные списки
// ---------------------------------------------------------------------------

/** Российские сервисы: идут НАПРЯМУЮ (VPN им не нужен и только мешает). */
export const RU_DIRECT_DOMAINS = [
  // Госуслуги и государство
  "gosuslugi.ru", "gov.ru", "kremlin.ru", "government.ru", "nalog.ru", "gosuslugi.mos.ru",
  "mos.ru", "spb.ru", "zdrav.ru", "sudrf.ru", "arbitr.ru", "pravo.gov.ru",
  // Поиск, почта, экосистемы
  "yandex.ru", "yandex.net", "yandex.com", "ya.ru", "yastatic.net", "yandex.st",
  "mail.ru", "vk.ru", "vk.com", "vkontakte.ru", "vk.me", "userapi.com", "vk-cdn.net",
  "ok.ru", "odnoklassniki.ru", "mycdn.me", "rambler.ru", "lenta.ru", "gazeta.ru",
  "rbc.ru", "rbkcrypto.ru", "kommersant.ru", "vedomosti.ru", "tass.ru", "ria.ru",
  "iz.ru", "kp.ru", "mk.ru", "rbc.com",
  // Маркетплейсы и банки
  "ozon.ru", "ozon.com", "wildberries.ru", "wb.ru", "wbbasket.ru", "avito.ru", "avito.st",
  "yoomoney.ru", "qiwi.com", "qiwi.ru", "tinkoff.ru", "tbank.ru", "sberbank.ru",
  "sber.ru", "sberbank.com", "vtb.ru", "alfabank.ru", "raiffeisen.ru", "gazprombank.ru",
  "mvideo.ru", "eldorado.ru", "dns-shop.ru", "citilink.ru", "lamoda.ru", "detmir.ru",
  // Транспорт, доставка, связь
  "rzd.ru", "tutu.ru", "yandex.taxi", "eda.yandex.ru", "delivery-club.ru",
  "kuper.ru", "samokat.ru", "sbermarket.ru", "cdek.ru", "boxberry.ru", "pochta.ru",
  "mts.ru", "beeline.ru", "megafon.ru", "tele2.ru", "yota.ru", "sbermobile.ru",
  // CDN и прочая инфраструктура РФ
  "cdnvideo.ru", "selectel.ru", "timeweb.ru", "reg.ru", "rbc-cdn.ru", "sbp.ru",
  "mir.ru", "mirconnect.ru", "2gis.ru", "2gis.com", "drom.ru", "drive2.ru", "auto.ru",
  "cian.ru", "domclick.ru", "hh.ru", "superjob.ru", "aviasales.ru", "tutu.travel",
  // v5.5: сайты, доступные только с российских IP (список Amnesia VPN,
  // github.com/te4a/amnesia-list). bitwarden.com из их списка НЕ добавлен:
  // это глобальный сервис, его прямой трафик — утечка мимо VPN.
  "edumsko.ru", "egais.ru", "emias.info", "emias.ru", "invitro.ru",
  "lemanapro.ru", "my.mos.ru", "myfin.by", "nix.ru", "sibmama.ru"
];

/**
 * Ресурсы, доступ к которым из РФ ограничен/замедлен: через VPN ОБЯЗАТЕЛЬНО.
 * Список пополняется в UI; здесь — стартовый набор.
 */
export const BLOCKED_DOMAINS = [
  // Соцсети и мессенджеры
  "instagram.com", "facebook.com", "fb.com", "fbcdn.net", "fb.watch", "facebook.net",
  "whatsapp.com", "whatsapp.net", "threads.net", "threads.com",
  "twitter.com", "x.com", "twimg.com", "t.co", "pscp.tv", "periscope.tv",
  "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media",
  "signal.org", "signal.com", "signal.art", "signal-cdn.org", "signal-messenger.org",
  "telegram.org", "telegram.me", "telegram.dog", "tdesktop.com", "telesco.pe",
  "viber.com", "line.me", "wechat.com", "weixin.qq.com",
  // Видео и стриминг
  "youtube.com", "youtu.be", "youtube-nocookie.com", "googlevideo.com", "ytimg.com",
  "googleusercontent.com", "twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net",
  "vimeo.com", "dailymotion.com", "netflix.com", "nflxvideo.net", "nflximg.net",
  "hulu.com", "disneyplus.com", "hbomax.com", "max.com", "peacocktv.com",
  // Медиа
  "meduza.io", "meduza.zone", "novayagazeta.ru", "theins.ru", "proekt.media",
  "holod.media", "sverstka.ru", "vazhnoe.net", "bellingcat.com", "occrp.org",
  "dw.com", "bbc.com", "bbc.co.uk", "bbci.co.uk", "reuters.com", "apnews.com",
  "nytimes.com", "wsj.com", "ft.com", "theguardian.com", "washingtonpost.com",
  "radiosvoboda.org", "svoboda.org", "currenttime.tv", "rferl.org",
  "idmeduza.io", "doxa.team", "ovdinfo.org", "ovd.in", "memorial.ru",
  // Инструменты и прочее
  "torproject.org", "tor.me", "vpn.net", "riseup.net", "archive.org", "archive.ph",
  "soundcloud.com", "spotify.com", "scdn.co", "anchor.fm", "patreon.com",
  "change.org", "amnesty.org", "hrw.org", "rsf.org"
];

/** Подсети РФ и соседей — напрямую (для режима SMART). */
export const RU_DIRECT_CIDRS = [
  "5.3.31.0/24", "5.8.32.0/19", "5.42.64.0/18", "5.45.80.0/22", "5.61.212.0/22",
  "31.13.128.0/17", "37.9.64.0/18", "37.144.0.0/14", "46.8.0.0/16", "46.17.40.0/21",
  "62.76.0.0/16", "77.37.128.0/17", "77.88.0.0/16", "78.155.192.0/18", "79.137.128.0/17",
  "80.64.0.0/20", "80.87.192.0/19", "81.19.64.0/19", "83.69.192.0/18", "84.21.64.0/19",
  "85.140.0.0/15", "86.62.64.0/18", "87.226.0.0/17", "87.250.224.0/19", "88.212.128.0/18",
  "89.108.64.0/18", "90.156.128.0/17", "91.77.0.0/16", "91.194.216.0/23", "92.53.64.0/18",
  "93.158.128.0/18", "94.100.176.0/20", "95.24.0.0/13", "95.163.0.0/16", "109.207.8.0/21",
  "128.140.0.0/18", "141.8.128.0/18", "147.45.0.0/16", "176.57.208.0/20", "178.154.128.0/17",
  "185.5.72.0/22", "185.12.92.0/22", "185.16.96.0/22", "185.32.186.0/24", "185.71.76.0/22",
  "185.114.136.0/22", "185.169.60.0/22", "188.43.0.0/17", "193.24.196.0/22", "194.67.0.0/18",
  "195.19.0.0/17", "212.109.0.0/19", "213.87.0.0/16", "217.20.144.0/20", "217.66.0.0/18"
];

/**
 * Домены, которые нельзя отдавать в VPN даже в режиме ALL — иначе ломаются
 * локальная сеть, банки с 3-D Secure и корпоративный доступ.
 */
export const ALWAYS_DIRECT_DOMAINS = [
  "localhost", "local", "lan", "home", "internal", "intranet",
  "router", "keenetic", "mikrotik", "tplinkwifi.net", "speedport.ip"
];

// ---------------------------------------------------------------------------
// Матчинг
// ---------------------------------------------------------------------------

/** Привести домен к нижнему регистру и отбросить точку в конце / схему / порт. */
export function normalizeDomain(input) {
  if (typeof input !== "string") return "";
  let d = input.trim().toLowerCase();
  if (!d) return "";
  d = d.replace(/^[a-z0-9+.-]+:\/\//, "");   // http://host/path -> host/path
  d = d.split("/")[0].split("?")[0].split("#")[0];
  d = d.replace(/:\d+$/, "");                // host:8080 -> host
  d = d.replace(/^\./, "").replace(/\.$/, "");
  // userinfo
  if (d.includes("@")) d = d.split("@").pop();
  return d;
}

/**
 * domainMatches — подходит ли домен под правило.
 * Правило: "example.com" (домен и все поддомены), ".example.com" (только поддомены),
 * "*.example.com" (один уровень), "!example.com" (исключение).
 */
export function domainMatches(domain, rule) {
  const d = normalizeDomain(domain);
  if (!d) return false;
  let r = String(rule || "").trim().toLowerCase();
  if (!r) return false;
  if (r.startsWith("!")) return false;                 // исключения обрабатывает matches()
  if (r.startsWith("*.")) {
    const base = r.slice(2);
    const prefix = d.slice(0, -(base.length + 1));
    return d.endsWith("." + base) && !prefix.includes(".");
  }
  if (r.startsWith(".")) return d.endsWith(r);
  if (r.includes("*")) {
    const re = new RegExp("^" + r.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[a-z0-9-]*") + "$");
    return re.test(d);
  }
  return d === r || d.endsWith("." + r);
}

function ipToLong(ip) {
  const p = String(ip).split(".");
  if (p.length !== 4) return null;
  let v = 0;
  for (const x of p) {
    const n = Number(x);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    v = v * 256 + n;
  }
  return v >>> 0;
}

/** cidrMatch — IPv4. Возвращает false для не-IPv4 (IPv6 пока не маршрутизируем). */
export function cidrMatch(ip, cidr) {
  const [net, bitsRaw] = String(cidr).split("/");
  const base = ipToLong(net);
  const target = ipToLong(ip);
  if (base == null || target == null) return false;
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((base & mask) >>> 0) === ((target & mask) >>> 0);
}

// ---------------------------------------------------------------------------
// Набор правил
// ---------------------------------------------------------------------------

/**
 * createRuleset — собранный набор правил.
 * @param {{
 *   mode?:string,
 *   vpnDomains?:string[], directDomains?:string[],
 *   vpnCidrs?:string[], directCidrs?:string[],
 *   extraBlocked?:string[], extraDirect?:string[]
 * }} [cfg]
 */
export function createRuleset(cfg = {}) {
  const mode = cfg.mode || DEFAULT_MODE;
  const vpnDomains = uniq([...BLOCKED_DOMAINS, ...(cfg.extraBlocked || []), ...(cfg.vpnDomains || [])]);
  const directDomains = uniq([
    ...ALWAYS_DIRECT_DOMAINS, ...RU_DIRECT_DOMAINS,
    ...(cfg.extraDirect || []), ...(cfg.directDomains || [])
  ]);
  const vpnCidrs = uniq(cfg.vpnCidrs || []);
  const directCidrs = uniq([...RU_DIRECT_CIDRS, ...(cfg.directCidrs || [])]);

  // "!rule" в списках — исключения, вынимаем их в отдельный набор
  const denyVpn = directDomains.filter((d) => d.startsWith("!"));
  const allowVpn = vpnDomains.filter((d) => !d.startsWith("!"));

  /**
   * decide — главный вход: куда отправить запрос.
   * @param {{host?:string, ip?:string}} target
   * @returns {"vpn"|"direct"}
   */
  function decide(target = {}) {
    if (mode === MODES.OFF) return "direct";
    const host = normalizeDomain(target.host);
    const ip = typeof target.ip === "string" ? target.ip.trim() : "";

    // Приватные/служебные адреса — всегда напрямую, VPN их сломает.
    if (ip && isPrivateIp(ip)) return "direct";

    // Жёстко-прямые имена работают в ЛЮБОМ режиме, включая ALL: иначе отваливаются
    // роутер, принтеры, NAS и localhost. Сюда же — NETBIOS-имена без точки.
    if (host && (!host.includes(".") || ALWAYS_DIRECT_DOMAINS.some((r) => domainMatches(host, r)))) {
      return "direct";
    }

    // Явные исключения имеют приоритет над всем.
    if (host && denyVpn.some((r) => domainMatches(host, r.slice(1)))) return "direct";

    if (host && allowVpn.some((r) => domainMatches(host, r))) return "vpn";
    if (ip && vpnCidrs.some((c) => cidrMatch(ip, c))) return "vpn";

    if (mode === MODES.ALL) return "vpn";

    if (host && directDomains.some((r) => domainMatches(host, r))) return "direct";
    if (ip && directCidrs.some((c) => cidrMatch(ip, c))) return "direct";

    // SMART: всё нероссийское — через VPN. BLOCKED_ONLY: всё не из списка — напрямую.
    return mode === MODES.BLOCKED_ONLY ? "direct" : "vpn";
  }

  return { mode, vpnDomains: allowVpn, directDomains, vpnCidrs, directCidrs, decide };
}

function uniq(a) {
  const s = new Set();
  for (const x of a || []) {
    const v = String(x || "").trim().toLowerCase();
    if (v) s.add(v);
  }
  return [...s];
}

function isPrivateIp(ip) {
  return (
    cidrMatch(ip, "10.0.0.0/8") || cidrMatch(ip, "172.16.0.0/12") ||
    cidrMatch(ip, "192.168.0.0/16") || cidrMatch(ip, "127.0.0.0/8") ||
    cidrMatch(ip, "169.254.0.0/16") || cidrMatch(ip, "100.64.0.0/10") ||
    ip === "::1" || ip.startsWith("fc") || ip.startsWith("fd") || ip.startsWith("fe80")
  );
}

// ---------------------------------------------------------------------------
// Парсеры внешних списков
// ---------------------------------------------------------------------------

/**
 * parseList — универсальный разбор текстового списка в домены/CIDR.
 * Понимает: plain-домены, `||domain^` (AdBlock), `DOMAIN,x` / `IP-CIDR,x/24,`
 * (clash), `*.domain` и комментарии `#`.
 * @returns {{domains:string[], cidrs:string[]}}
 */
export function parseList(text) {
  const domains = new Set();
  const cidrs = new Set();
  for (const rawLine of String(text || "").split(/\r?\n/)) {
    let line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    line = line.split("#")[0].trim();
    if (!line) continue;

    // clash: DOMAIN-SUFFIX,example.com,REJECT  /  IP-CIDR,1.2.3.0/24,no-resolve
    const clash = line.match(/^(?:DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|IP-CIDR6?|SRC-IP),([^,]+)/i);
    if (clash) {
      const v = clash[1].trim();
      (v.includes("/") ? cidrs : domains).add(v.toLowerCase());
      continue;
    }
    // AdBlock: ||example.com^
    const abp = line.match(/^\|\|([^\^|]+)\^?/);
    if (abp) { domains.add(abp[1].trim().toLowerCase()); continue; }
    // IP-CIDR в открытую
    const cidrOnly = line.match(/^(\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2})$/);
    if (cidrOnly) { cidrs.add(cidrOnly[1]); continue; }
    // остальное считаем доменом/маской
    const v = line.replace(/^[|*]+/, "").replace(/[\^]+$/, "").toLowerCase();
    if (v && !v.includes(" ")) (v.includes("/") ? cidrs : domains).add(v);
  }
  return { domains: [...domains], cidrs: [...cidrs] };
}

// ---------------------------------------------------------------------------
// Адаптеры вывода
// ---------------------------------------------------------------------------

/**
 * toSingBoxRules — правила маршрутизации для sing-box (движок native-хоста).
 * Прямые сети идут в outbound "direct", остальное — в "vpn".
 */
export function toSingBoxRules(ruleset) {
  const rules = [];
  const directCidr = [...ruleset.directCidrs];
  const directDomain = ruleset.directDomains.filter((d) => !d.startsWith("!")).map(stripDot);

  rules.push({ outbound: "direct", ip_is_private: true });
  if (directDomain.length) rules.push({ outbound: "direct", domain_suffix: directDomain });
  if (directCidr.length) rules.push({ outbound: "direct", ip_cidr: directCidr });

  const vpnDomain = ruleset.vpnDomains.map(stripDot);
  if (vpnDomain.length) rules.push({ outbound: "vpn", domain_suffix: vpnDomain });
  if (ruleset.vpnCidrs.length) rules.push({ outbound: "vpn", ip_cidr: ruleset.vpnCidrs });

  rules.push({ outbound: ruleset.mode === MODES.OFF ? "direct" : "vpn" });
  return rules;
}

const stripDot = (d) => (d.startsWith(".") ? d.slice(1) : d);

/** Предел длины строки passthrough — Firefox хранит её в network.proxy.no_proxies_on. */
export const PASSTHROUGH_MAX = 8000;

/**
 * toPassthrough — список исключений для browser.proxy.settings (proxyType: "manual").
 *
 * ВАЖНО: в Firefox это свойство называется `passthrough` (строка через запятую),
 * а НЕ `nonProxyHosts` — это имя из Chrome, и Firefox его молча игнорирует.
 * Именно поэтому «Split Tunneling» в версии 4.0.x не работал в manual-режиме.
 *
 * Формат Firefox (MDN → proxy.settings → passthrough):
 *   HOST_NAME[:PORT] | IP_LITERAL[:PORT] | IP_LITERAL/PREFIX (CIDR) | <local>
 * `<local>` покрывает все имена без точки — принтеры, NAS, NETBIOS.
 * Хосты localhost / 127.0.0.1 / [::1] Firefox не проксирует никогда, но
 * дублируем их явно — так было в версии 4 и этого ждут тесты.
 *
 * @param {object} ruleset — результат createRuleset()
 * @param {string[]} [extra] — дополнительные исключения (пользовательские)
 * @returns {{value:string, truncated:boolean, count:number}}
 */
export function toPassthrough(ruleset, extra = []) {
  const parts = ["<local>", "localhost", "127.0.0.1", "[::1]"];
  if (ruleset.mode !== MODES.ALL) {
    for (const d of ruleset.directDomains) {
      if (d.startsWith("!") || d.includes("*")) continue;   // маски passthrough не понимает
      parts.push(stripDot(d));
    }
    for (const c of ruleset.directCidrs) parts.push(c);
  }
  for (const d of extra || []) {
    const v = normalizeDomain(d);
    if (v) parts.push(v);
  }

  // Собираем с контролем длины: обрезать нужно с хвоста, но так, чтобы
  // служебные имена (<local>, localhost) и пользовательские исключения остались.
  const head = parts.slice(0, 4);
  const userExtra = (extra || []).map(normalizeDomain).filter(Boolean);
  const tail = parts.slice(4).filter((x) => !userExtra.includes(x));
  const keep = [...head, ...userExtra];
  let value = keep.join(",");
  let used = keep.length;
  for (const item of tail) {
    const next = value + "," + item;
    if (next.length > PASSTHROUGH_MAX) break;
    value = next;
    used++;
  }
  return { value, count: used, truncated: used < parts.length };
}

/**
 * toPacScript — PAC для браузерного режима (расширение без native-хоста).
 * Позволяет плагину работать самостоятельно: Firefox сам решает, куда слать
 * каждый запрос. Это убирает дублирование ответственности за маршрутизацию
 * между расширением и native-хостом.
 * @param {string} proxy — строка прокси, напр. "SOCKS5 127.0.0.1:1080"
 */
export function toPacScript(ruleset, proxy = "SOCKS5 127.0.0.1:1080") {
  const vpn = ruleset.vpnDomains.map(stripDot);
  const direct = ruleset.directDomains.filter((d) => !d.startsWith("!")).map(stripDot);
  const mode = ruleset.mode;
  return `function FindProxyForURL(url, host) {
  var h = (host || "").toLowerCase();
  var VPN = "PROXY ${proxy}; DIRECT";
  var DIR = "DIRECT";
  function inList(list, h) {
    for (var i = 0; i < list.length; i++) {
      var d = list[i];
      if (h === d || h.slice(-d.length - 1) === "." + d) return true;
    }
    return false;
  }
  if (isPlainHostName(host) || shExpMatch(host, "*.local")) return DIR;
  if (isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
      isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
      isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
      isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")) return DIR;
  ${JSON.stringify(vpn).length ? `if (inList(${JSON.stringify(vpn)}, h)) return VPN;` : ""}
  ${JSON.stringify(direct).length ? `if (inList(${JSON.stringify(direct)}, h)) return DIR;` : ""}
  ${mode === MODES.ALL ? "return VPN;" : mode === MODES.OFF ? "return DIR;" :
      mode === MODES.BLOCKED_ONLY ? "return DIR;" : "return VPN;"}
}`;
}

/**
 * describe — человекочитаемое описание режима для UI.
 */
export function describeMode(mode) {
  switch (mode) {
    case MODES.ALL:
      return "Весь трафик через VPN. Надёжнее всего, но на бесплатной ноде — медленно.";
    case MODES.SMART:
      return "Зарубежные сайты через VPN, российские напрямую. Оптимально для бесплатных нод.";
    case MODES.BLOCKED_ONLY:
      return "Через VPN только заблокированные ресурсы. Максимальная скорость, минимальный расход ноды.";
    case MODES.OFF:
      return "VPN выключен, весь трафик напрямую.";
    default:
      return "";
  }
}
