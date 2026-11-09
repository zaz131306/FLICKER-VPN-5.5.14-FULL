// lib/hy2-parser.js — парсер ссылок Hysteria 2 (задача 2).
//
// Формат: hysteria2://password@server:port?obfs=salamander&obfs-password=xxx&sni=xxx#name
// Также принимается алиас схемы hy2:// (так публикует Au1rxx).
//
// Извлекаются ОБЯЗАТЕЛЬНЫЕ поля:
//   password (auth)     — userinfo до '@'; режим userpass = "username:password" целиком;
//   server, port        — порт по умолчанию 443;
//   obfs                — обычно salamander;
//   obfs-password;
//   sni                 — если есть (алиасы: sni, peer);
//   insecure            — 1/true/yes (алиас: skip-cert-verify).
//
// Ошибка в формате ведёт к таймауту вместо понятной ошибки, поэтому парсер
// строгий: любые отклонения возвращают {ok:false, error:"..."} с причиной.

// FNV-1a: детерминированный короткий id сервера (host:port:auth:obfs-pass)
export function fnv1aHex(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

const HY2_SCHEME_RE = /^(hysteria2|hy2):\/\//i;

// Валидное ли это имя хоста для SNI (отсекает мусор вроде "https://t.me/xxx",
// который реально встречается в подписках Au1rxx).
function isValidHostname(h) {
  if (!h || h.length > 253) return false;
  if (/^[0-9.]+$/.test(h)) return true;           // IPv4
  if (h.includes(":")) return false;               // IPv6 в SNI не используется
  if (h.includes("://") || h.includes("/")) return false;
  return /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$/.test(h);
}

function tryDecode(v) {
  try {
    return decodeURIComponent(v);
  } catch {
    return v; // битый percent-encoding — оставляем как есть
  }
}

function parseBoolParam(v) {
  const s = String(v ?? "").toLowerCase();
  return s === "1" || s === "true" || s === "yes" || s === "on";
}

// Разбор host:port с поддержкой IPv6-литералов [::1]:443
function splitHostPort(hp, defaultPort) {
  if (!hp) return { host: "", port: defaultPort };
  if (hp.startsWith("[")) {
    const end = hp.indexOf("]");
    if (end < 0) return { host: "", port: defaultPort };
    const host = hp.slice(1, end);
    const rest = hp.slice(end + 1);
    const port = rest.startsWith(":") ? parseInt(rest.slice(1), 10) : defaultPort;
    return { host, port };
  }
  const idx = hp.lastIndexOf(":");
  if (idx < 0) return { host: hp, port: defaultPort };
  const port = parseInt(hp.slice(idx + 1), 10);
  if (!Number.isFinite(port)) return { host: hp, port: defaultPort };
  return { host: hp.slice(0, idx), port };
}

/**
 * parseHY2Link — разбор одной ссылки.
 * @param {string} link — hysteria2://… или hy2://…
 * @param {object} [meta] — {source: "matin"} — метаданные для сервера
 * @returns {{ok:true, server:object}|{ok:false, error:string}}
 */
export function parseHY2Link(link, meta = {}) {
  if (typeof link !== "string") return { ok: false, error: "ссылка не строка" };
  const raw = link.trim().replace(/\r$/, "");
  if (!raw) return { ok: false, error: "пустая ссылка" };
  if (!HY2_SCHEME_RE.test(raw)) {
    return { ok: false, error: "не HY2-ссылка (ожидался hysteria2:// или hy2://)" };
  }

  // 1. Отделяем фрагмент (имя) — первый '#'
  let rest = raw.replace(HY2_SCHEME_RE, "");
  let fragment = "";
  const hashIdx = rest.indexOf("#");
  if (hashIdx >= 0) {
    fragment = rest.slice(hashIdx + 1);
    rest = rest.slice(0, hashIdx);
  }

  // 2. Отделяем query
  let query = "";
  const qIdx = rest.indexOf("?");
  if (qIdx >= 0) {
    query = rest.slice(qIdx + 1);
    rest = rest.slice(0, qIdx);
  }
  rest = rest.replace(/\/+$/, ""); // "host:port/" — встречающийся мусор

  // 3. userinfo@host:port
  const atIdx = rest.lastIndexOf("@");
  let userinfo = "";
  let hostport = rest;
  if (atIdx >= 0) {
    userinfo = rest.slice(0, atIdx);
    hostport = rest.slice(atIdx + 1);
  }

  const auth = tryDecode(userinfo); // password ИЛИ "username:password" (userpass)
  const { host, port } = splitHostPort(tryDecode(hostport), 443);

  if (!host) return { ok: false, error: "не указан сервер" };
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, error: `некорректный порт: ${hostport}` };
  }
  if (!auth) return { ok: false, error: "не указан пароль (auth пуст)" };

  // 4. Query-параметры (ключи регистронезависимы)
  const params = {};
  for (const kv of query.split("&")) {
    if (!kv) continue;
    const eq = kv.indexOf("=");
    const k = (eq < 0 ? kv : kv.slice(0, eq)).toLowerCase();
    const v = eq < 0 ? "" : tryDecode(kv.slice(eq + 1).replace(/\+/g, " "));
    if (k) params[k] = v;
  }

  // SNI: sni | peer; мусорные значения (URL и т.п.) отбрасываются
  let sni = params.sni || params.peer || "";
  if (sni && !isValidHostname(sni)) sni = "";

  // obfs
  const obfsType = (params.obfs || "").toLowerCase();
  const obfsPassword = params["obfs-password"] ?? params.obfspassword ?? params["obfs-pass"] ?? "";
  let obfs = { type: "none", password: "" };
  if (obfsType === "salamander" && obfsPassword) {
    obfs = { type: "salamander", password: obfsPassword };
  } else if (obfsType && obfsType !== "none" && obfsType !== "salamander") {
    return { ok: false, error: `неподдерживаемый obfs: ${obfsType}` };
  } else if (obfsType === "salamander" && !obfsPassword) {
    return { ok: false, error: "obfs=salamander без obfs-password" };
  }

  // insecure / skip-cert-verify: в бесплатных подписках сертификат почти всегда
  // самоподписанный, поэтому ОТСУТСТВИЕ флага трактуем как insecure=true
  // (иначе «живой» по пробам узел не подключится из-за валидации сертификата).
  const insecureRaw = params.insecure ?? params["skip-cert-verify"] ?? params.allowinsecure;
  const insecure = insecureRaw == null ? true : parseBoolParam(insecureRaw);

  // alpn / mux / пропускная способность — необязательные, но полезные
  const alpn = params.alpn ? params.alpn.split(",").map((s) => s.trim()).filter(Boolean) : undefined;
  const upMbps = parseInt(params.up, 10);
  const downMbps = parseInt(params.down, 10);

  // 5. Имя: фрагмент; чистим рекламные хвосты вида "… | ⚡ channel"
  let name = tryDecode(fragment).trim();
  name = name.split("|")[0].trim();
  if (!name || /^[\s\p{Emoji}]+$/u.test(name)) name = host;
  if (name.length > 64) name = name.slice(0, 64);

  const id = "sub-" + fnv1aHex(`${host.toLowerCase()}:${port}:${auth}:${obfs.password}`);

  const server = {
    id,
    name,
    host,
    port,
    protocol: "hysteria2",
    auth,                       // password или "user:pass" (userpass-режим)
    sni,
    obfs,
    tls: { verify: !insecure, insecure },
    // подписочные серверы подключаются строго по своему SNI —
    // глобальный Fake-SNI их не переопределяет
    fakeSni: { enabled: false },
    congestion: {
      type: "bbr",
      ...(Number.isFinite(upMbps) && upMbps > 0 ? { upMbps } : {}),
      ...(Number.isFinite(downMbps) && downMbps > 0 ? { downMbps } : {})
    },
    ...(alpn ? { alpn } : {}),
    source: meta.source || "custom",
    sub: true,
    demo: false,
    flag: "🌍",
    ping: null
  };
  return { ok: true, server };
}

/**
 * parseHY2Links — пакетный разбор; собирает и успехи, и причины отказов.
 * @param {string[]} links
 * @param {object} [meta]
 * @returns {{servers:object[], failed:{link:string,error:string}[]}}
 */
export function parseHY2Links(links, meta = {}) {
  const servers = [];
  const failed = [];
  const seen = new Set();
  for (const link of links || []) {
    const r = parseHY2Link(link, meta);
    if (!r.ok) {
      failed.push({ link: String(link).slice(0, 120), error: r.error });
      continue;
    }
    if (seen.has(r.server.id)) continue; // дубликаты host:port:auth — один сервер
    seen.add(r.server.id);
    servers.push(r.server);
  }
  return { servers, failed };
}
