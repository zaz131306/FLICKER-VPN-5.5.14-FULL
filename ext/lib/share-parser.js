// lib/share-parser.js — парсер ссылок TCP/443-стека (VLESS+Reality, Trojan,
// VMess, Shadowsocks, WireGuard).
//
// Форматы:
//   vless://uuid@host:port?security=reality&pbk=..&sid=..&fp=chrome&flow=xtls-rprx-vision&sni=..#name
//   trojan://password@host:port?sni=..&allowInsecure=1#name
//   vmess://base64({add,port,id,net,type,host,path,tls,sni,scy,...})#name
//   ss://base64(method:password)@host:port#name   (SIP002)
//   wireguard://privateKey@endpoint:port?publickey=..&allowedips=..&address=..&psk=..&mtu=..&reserved=0,0,0#name
//
// WireGuard-«матрёшка» (detour через VLESS/Trojan) настраивается в UI:
// публичных WG-подписок не существует — это схема для собственного сервера.

import { fnv1aHex } from "./hy2-parser.js";

// ---------- общие утилиты ----------

function tryDecode(v) {
  try {
    return decodeURIComponent(v);
  } catch {
    return v;
  }
}

function isValidHostname(h) {
  if (!h || h.length > 253) return false;
  if (/^[0-9.]+$/.test(h)) return true;
  if (h.includes("://") || h.includes("/") || h.includes(" ")) return false;
  return /^[A-Za-z0-9]([A-Za-z0-9-_.]*[A-Za-z0-9])?$/.test(h) || h.includes(":"); // IPv6
}

function splitHostPort(hp, defaultPort = 443) {
  if (!hp) return { host: "", port: defaultPort };
  if (hp.startsWith("[")) {
    const end = hp.indexOf("]");
    if (end < 0) return { host: "", port: defaultPort };
    const host = hp.slice(1, end);
    const rest = hp.slice(end + 1);
    return { host, port: rest.startsWith(":") ? parseInt(rest.slice(1), 10) : defaultPort };
  }
  const idx = hp.lastIndexOf(":");
  if (idx < 0) return { host: hp, port: defaultPort };
  const port = parseInt(hp.slice(idx + 1), 10);
  if (!Number.isFinite(port)) return { host: hp, port: defaultPort };
  return { host: hp.slice(0, idx), port };
}

function parseQuery(query) {
  const params = {};
  for (const kv of String(query || "").split("&")) {
    if (!kv) continue;
    const eq = kv.indexOf("=");
    const k = (eq < 0 ? kv : kv.slice(0, eq)).toLowerCase();
    // ВНИМАНИЕ: '+' НЕ заменяем на пробел — в base64-ключах (pbk/publickey)
    // это литеральный символ; пробелы в ссылках кодируются как %20.
    const v = eq < 0 ? "" : tryDecode(kv.slice(eq + 1));
    if (k) params[k] = v;
  }
  return params;
}

function parseBoolParam(v) {
  const s = String(v ?? "").toLowerCase();
  return s === "1" || s === "true" || s === "yes" || s === "on";
}

function cleanName(fragment, fallback) {
  let name = tryDecode(fragment || "").trim();
  name = name.split("|")[0].trim();
  if (!name) name = fallback;
  return name.length > 64 ? name.slice(0, 64) : name;
}

function baseCommon(id, name, host, port, protocol, source) {
  return {
    id, name, host, port, protocol,
    source: source || "custom",
    sub: true, demo: false,
    flag: "🌍", ping: null
  };
}

// ---------- транспорт v2ray (общий для vless/trojan/vmess) ----------

function parseTransport(params) {
  const net = (params.type || params.net || "").toLowerCase();
  switch (net) {
    case "ws":
      return { type: "ws", path: params.path || "/", host: params.host || "" };
    case "grpc":
      return { type: "grpc", serviceName: params.servicename || params.path || "" };
    case "http":
    case "h2":
      return { type: "http", path: params.path || "/", host: params.host || "" };
    case "httpupgrade":
      return { type: "httpupgrade", path: params.path || "/", host: params.host || "" };
    case "tcp":
      if ((params.headerType || params.type2 || "") === "http") {
        return { type: "http", path: params.path || "/", host: params.host || "" };
      }
      return null;
    default:
      return null; // raw tcp
  }
}

const FP_VALID = new Set(["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "chrome_psk", "chrome_psk_shuffle", "chrome_padding_psk_shuffle", "chrome_pq", "chrome_pq_psk"]);

// ---------- VLESS ----------

export function parseVLESSLink(link, meta = {}) {
  const raw = String(link || "").trim();
  const m = /^vless:\/\/([^#]*)(?:#(.*))?$/.exec(raw);
  if (!m) return { ok: false, error: "не vless-ссылка" };
  let body = m[1];
  const fragment = m[2] || "";

  let query = "";
  const qIdx = body.indexOf("?");
  if (qIdx >= 0) { query = body.slice(qIdx + 1); body = body.slice(0, qIdx); }

  const atIdx = body.lastIndexOf("@");
  if (atIdx < 0) return { ok: false, error: "vless: нет uuid@host" };
  const uuid = tryDecode(body.slice(0, atIdx));
  const { host, port } = splitHostPort(tryDecode(body.slice(atIdx + 1)), 443);
  if (!uuid) return { ok: false, error: "vless: пустой uuid" };
  if (!host) return { ok: false, error: "vless: не указан сервер" };
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { ok: false, error: "vless: некорректный порт" };

  const p = parseQuery(query);
  const security = (p.security || "").toLowerCase();
  if (security && !["none", "tls", "reality"].includes(security)) {
    return { ok: false, error: "vless: неизвестный security=" + security };
  }
  const reality = security === "reality" || !!p.pbk;
  let sni = p.sni || p.peer || "";
  if (sni && !isValidHostname(sni)) sni = "";
  if (!sni && (security === "tls" || reality)) sni = host;

  const fp = FP_VALID.has((p.fp || "").toLowerCase()) ? p.fp.toLowerCase() : (reality ? "chrome" : "");
  const flow = (p.flow || "").toLowerCase() === "xtls-rprx-vision" ? "xtls-rprx-vision" : "";

  const id = "sub-" + fnv1aHex(`vless|${host.toLowerCase()}:${port}:${uuid}:${p.pbk || ""}:${flow}`);
  const server = {
    ...baseCommon(id, cleanName(fragment, host), host, port, "vless", meta.source),
    uuid,
    flow,
    fingerprint: fp,
    sni,
    tlsEnabled: security === "tls" || reality,
    tls: { verify: !parseBoolParam(p.allowinsecure ?? p.insecure), insecure: parseBoolParam(p.allowinsecure ?? p.insecure) },
    transport: parseTransport(p),
    packetEncoding: p.packetencoding || undefined
  };
  if (reality) {
    if (!p.pbk) return { ok: false, error: "vless+reality: нет pbk" };
    server.reality = { publicKey: p.pbk, shortId: p.sid || "" };
    if (p.spx) server.spiderX = p.spx;
  }
  return { ok: true, server };
}

// ---------- Trojan ----------

export function parseTrojanLink(link, meta = {}) {
  const raw = String(link || "").trim();
  const m = /^trojan:\/\/([^#]*)(?:#(.*))?$/.exec(raw);
  if (!m) return { ok: false, error: "не trojan-ссылка" };
  let body = m[1];
  const fragment = m[2] || "";

  let query = "";
  const qIdx = body.indexOf("?");
  if (qIdx >= 0) { query = body.slice(qIdx + 1); body = body.slice(0, qIdx); }

  const atIdx = body.lastIndexOf("@");
  if (atIdx < 0) return { ok: false, error: "trojan: нет password@host" };
  const password = tryDecode(body.slice(0, atIdx));
  const { host, port } = splitHostPort(tryDecode(body.slice(atIdx + 1)), 443);
  if (!password) return { ok: false, error: "trojan: пустой пароль" };
  if (!host) return { ok: false, error: "trojan: не указан сервер" };
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { ok: false, error: "trojan: некорректный порт" };

  const p = parseQuery(query);
  let sni = p.sni || p.peer || "";
  if (sni && !isValidHostname(sni)) sni = "";
  if (!sni) sni = host;

  const insecure = parseBoolParam(p.allowinsecure ?? p.insecure);
  const id = "sub-" + fnv1aHex(`trojan|${host.toLowerCase()}:${port}:${password}`);
  return {
    ok: true,
    server: {
      ...baseCommon(id, cleanName(fragment, host), host, port, "trojan", meta.source),
      auth: password,
      sni,
      tlsEnabled: true,
      tls: { verify: !insecure, insecure },
      transport: parseTransport(p)
    }
  };
}

// ---------- VMess ----------

export function parseVmessLink(link, meta = {}) {
  const raw = String(link || "").trim();
  const m = /^vmess:\/\/([A-Za-z0-9+/=]+)\s*(?:#(.*))?$/.exec(raw);
  if (!m) return { ok: false, error: "не vmess-ссылка" };
  let j;
  try {
    j = JSON.parse(Buffer.from ? Buffer.from(m[1], "base64").toString("utf8") : atob(m[1]));
  } catch {
    try {
      const bin = atob(m[1]);
      j = JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0))));
    } catch {
      return { ok: false, error: "vmess: битый base64/JSON" };
    }
  }
  const host = j.add || j.address;
  const port = Number(j.port);
  const uuid = j.id;
  if (!host || !uuid || !Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, error: "vmess: неполные данные" };
  }
  const net = (j.net || "tcp").toLowerCase();
  const tlsOn = String(j.tls || "").toLowerCase() === "tls";
  const p = {
    type: net,
    host: j.host || "",
    path: j.path || "",
    servicename: j.path && net === "grpc" ? j.path : "",
    sni: j.sni || (tlsOn ? host : "")
  };
  const id = "sub-" + fnv1aHex(`vmess|${String(host).toLowerCase()}:${port}:${uuid}`);
  const server = {
    ...baseCommon(id, cleanName(m[2] || j.ps || "", host), host, port, "vmess", meta.source),
    uuid,
    cipher: j.scy || "auto",
    alterId: Number(j.aid) || 0,
    sni: tlsOn ? p.sni : "",
    tlsEnabled: tlsOn,
    tls: tlsOn ? { verify: true, insecure: false } : {},
    transport: parseTransport(p)
  };
  return { ok: true, server };
}

// ---------- Shadowsocks (SIP002) ----------

export function parseSSLink(link, meta = {}) {
  const raw = String(link || "").trim();
  const m = /^ss:\/\/([^#]*)(?:#(.*))?$/.exec(raw);
  if (!m) return { ok: false, error: "не ss-ссылка" };
  const body = m[1];
  const atIdx = body.lastIndexOf("@");
  if (atIdx < 0) return { ok: false, error: "ss: нет userinfo@host" };
  let userinfo = body.slice(0, atIdx);
  const { host, port } = splitHostPort(body.slice(atIdx + 1), 8388);
  if (!host) return { ok: false, error: "ss: не указан сервер" };

  let method = "";
  let password = "";
  if (/^[A-Za-z0-9+/=%_-]+$/.test(userinfo) && userinfo.includes("%3A") === false && !userinfo.includes(":")) {
    // base64(method:password)
    try {
      const dec = tryDecode(userinfo);
      const decoded = atob(dec.replace(/-/g, "+").replace(/_/g, "/"));
      const cIdx = decoded.indexOf(":");
      if (cIdx > 0) { method = decoded.slice(0, cIdx); password = decoded.slice(cIdx + 1); }
    } catch { /* не base64 — ниже fallback */ }
  }
  if (!method && userinfo.includes(":")) {
    const cIdx = userinfo.indexOf(":");
    method = userinfo.slice(0, cIdx);
    password = tryDecode(userinfo.slice(cIdx + 1));
  }
  if (!method || !password) return { ok: false, error: "ss: не разобран method:password" };

  const id = "sub-" + fnv1aHex(`ss|${host.toLowerCase()}:${port}:${method}:${password}`);
  return {
    ok: true,
    server: {
      ...baseCommon(id, cleanName(m[2] || "", host), host, port, "shadowsocks", meta.source),
      auth: password,
      cipher: method,
      tlsEnabled: false
    }
  };
}

// ---------- WireGuard / AmneziaWG ----------

/**
 * parseAmneziaParams — AWG-параметры из query (ключи уже lowercased), из пар
 * .conf-конфига или из полей формы. Понимает Jc/j_c/jc, Jmin/j_min, ..., H1..H4.
 * @returns {object|null} null — если AWG-параметров нет (обычный WireGuard)
 */
export function parseAmneziaParams(params) {
  if (!params) return null;
  const get = (...names) => {
    for (const n of names) {
      const key = String(n).toLowerCase().replace(/[_\-\s]/g, "");
      if (params[key] != null && params[key] !== "") return params[key];
    }
    return undefined;
  };
  const raw = {
    jc: get("jc", "j_c"), jmin: get("jmin", "j_min"), jmax: get("jmax", "j_max"),
    s1: get("s1"), s2: get("s2"),
    h1: get("h1"), h2: get("h2"), h3: get("h3"), h4: get("h4")
  };
  if (!Object.values(raw).some((v) => v != null && v !== "")) return null;
  const out = {};
  for (const [k, v] of Object.entries(raw)) {
    if (v == null || v === "") continue;
    const n = Number(String(v).trim());
    if (Number.isFinite(n)) out[k] = n;   // диапазон проверяет validateServerConfig
  }
  return Object.keys(out).length ? out : null;
}

export function parseWireGuardLink(link, meta = {}) {
  const raw = String(link || "").trim();
  const m = /^wireguard:\/\/([^#]*)(?:#(.*))?$/.exec(raw);
  if (!m) return { ok: false, error: "не wireguard-ссылка" };
  let body = m[1];
  const fragment = m[2] || "";

  let query = "";
  const qIdx = body.indexOf("?");
  if (qIdx >= 0) { query = body.slice(qIdx + 1); body = body.slice(0, qIdx); }

  const atIdx = body.lastIndexOf("@");
  if (atIdx < 0) return { ok: false, error: "wireguard: нет key@endpoint" };
  const privateKey = tryDecode(body.slice(0, atIdx));
  const { host, port } = splitHostPort(tryDecode(body.slice(atIdx + 1)), 51820);
  if (!privateKey) return { ok: false, error: "wireguard: пустой приватный ключ" };
  if (!host) return { ok: false, error: "wireguard: не указан endpoint" };

  const p = parseQuery(query);
  const peerPublicKey = p.publickey || p.pubkey || p.peer_public_key || "";
  if (!peerPublicKey) return { ok: false, error: "wireguard: нет publickey пира" };

  const address = (p.address || p.local_address || "").split(",").map((s) => s.trim()).filter(Boolean);
  const allowedIPs = (p.allowedips || p.allowed_ips || "").split(",").map((s) => s.trim()).filter(Boolean);
  const reserved = (p.reserved || "").split(",").map((n) => parseInt(n.trim(), 10)).filter((n) => Number.isFinite(n));
  const mtu = parseInt(p.mtu, 10);

  const amnezia = parseAmneziaParams(p);   // FIX(5.5.8): AWG-параметры из ссылки
  const id = "sub-" + fnv1aHex(`wg|${host.toLowerCase()}:${port}:${privateKey}:${peerPublicKey}:${amnezia ? JSON.stringify(amnezia) : ""}`);
  return {
    ok: true,
    server: {
      ...baseCommon(id, cleanName(fragment, host), host, port, "wireguard", meta.source),
      tlsEnabled: false,
      wireguard: {
        privateKey,
        peerPublicKey,
        preSharedKey: p.psk || p.presharedkey || "",
        address: address.length ? address : [],
        allowedIPs: allowedIPs.length ? allowedIPs : ["0.0.0.0/0", "::/0"],
        mtu: Number.isFinite(mtu) && mtu > 0 ? mtu : 1280,
        reserved: reserved.length === 3 ? reserved : undefined,
        keepalive: parseInt(p.keepalive, 10) || 25,
        ...(amnezia ? { amnezia } : {})
      },
      detour: null // «матрёшка» настраивается пользователем в UI
    }
  };
}

/**
 * splitWireGuardConfs — нарезать текст на блоки конфигов WireGuard/AmneziaWG.
 * Один блок = [Interface] + следующий за ним [Peer].
 */
export function splitWireGuardConfs(text) {
  const t = String(text || "");
  if (!/\[\s*interface\s*\]/i.test(t)) return [];
  return t.split(/(?=\[\s*interface\s*\])/i)
    .map((s) => s.trim())
    .filter((p) => p && /\[\s*interface\s*\]/i.test(p));
}

/**
 * parseWireGuardConf — разобрать конфиг .conf (wg-quick / AmneziaWG).
 * Понимает: PrivateKey, Address, DNS, MTU, Jc, Jmin, Jmax, S1, S2, H1..H4,
 * [Peer] PublicKey, PresharedKey, AllowedIPs, Endpoint, PersistentKeepalive.
 * @returns {{ok:boolean, server?:object, error?:string, amnezia?:boolean}}
 */
export function parseWireGuardConf(text, meta = {}) {
  const raw = String(text || "").trim();
  if (!raw) return { ok: false, error: "пустой конфиг" };
  if (!/\[\s*interface\s*\]/i.test(raw)) return { ok: false, error: "нет секции [Interface]" };

  const ifc = {};
  const peer = {};
  let section = null;
  for (const line of raw.split(/\r?\n/)) {
    const l = line.replace(/[#;].*$/, "").trim();
    if (!l) continue;
    if (/^\[\s*interface\s*\]$/i.test(l)) { section = ifc; continue; }
    if (/^\[\s*peer\s*\]$/i.test(l)) { section = peer; continue; }
    if (!section) continue;
    const eq = l.indexOf("=");
    if (eq < 0) continue;
    const k = l.slice(0, eq).trim().toLowerCase().replace(/[\s_\-]/g, "");
    const v = l.slice(eq + 1).trim();
    if (k && !(k in section)) section[k] = v;   // первый [Peer] выигрывает
  }

  const privateKey = ifc.privatekey || "";
  if (!privateKey) return { ok: false, error: "conf: нет PrivateKey в [Interface]" };
  const peerPublicKey = peer.publickey || "";
  if (!peerPublicKey) return { ok: false, error: "conf: нет PublicKey в [Peer]" };
  const { host, port } = splitHostPort(peer.endpoint || "", 51820);
  if (!host) return { ok: false, error: "conf: нет Endpoint в [Peer]" };

  const csv = (v) => String(v || "").split(",").map((s) => s.trim()).filter(Boolean);
  const address = csv(ifc.address);
  const allowedIPs = csv(peer.allowedips);
  const mtu = parseInt(ifc.mtu, 10);
  const keepalive = parseInt(peer.persistentkeepalive, 10);
  const amnezia = parseAmneziaParams(ifc);
  const dns = csv(ifc.dns);

  const id = "sub-" + fnv1aHex(`wgconf|${host.toLowerCase()}:${port}:${privateKey}:${peerPublicKey}:${amnezia ? JSON.stringify(amnezia) : ""}`);
  const name = meta.name || `${host}${amnezia ? " (AWG)" : ""}`;
  return {
    ok: true,
    amnezia: !!amnezia,
    server: {
      ...baseCommon(id, cleanName(name, host), host, port, "wireguard", meta.source),
      tlsEnabled: false,
      dns: dns.length ? dns : undefined,
      wireguard: {
        privateKey,
        peerPublicKey,
        preSharedKey: peer.presharedkey || "",
        address,
        allowedIPs: allowedIPs.length ? allowedIPs : ["0.0.0.0/0", "::/0"],
        mtu: Number.isFinite(mtu) && mtu > 0 ? mtu : 1280,
        keepalive: Number.isFinite(keepalive) && keepalive > 0 ? keepalive : 25,
        ...(amnezia ? { amnezia } : {})
      },
      detour: null
    }
  };
}

// ---------- пакетный разбор ----------

const PARSERS = [
  [/^vless:\/\//i, parseVLESSLink],
  [/^trojan:\/\//i, parseTrojanLink],
  [/^vmess:\/\//i, parseVmessLink],
  [/^ss:\/\//i, parseSSLink],
  [/^wireguard:\/\//i, parseWireGuardLink]
];

/**
 * parseShareLinks — разобрать массив ссылок любых поддерживаемых схем.
 * @returns {{servers:object[], failed:{link:string,error:string}[]}}
 */
export function parseShareLinks(links, meta = {}) {
  const servers = [];
  const failed = [];
  const seen = new Set();
  for (const link of links || []) {
    const parser = PARSERS.find(([re]) => re.test(link));
    if (!parser) { failed.push({ link: String(link).slice(0, 120), error: "неподдерживаемая схема" }); continue; }
    const r = parser[1](link, meta);
    if (!r.ok) { failed.push({ link: String(link).slice(0, 120), error: r.error }); continue; }
    if (seen.has(r.server.id)) continue;
    seen.add(r.server.id);
    servers.push(r.server);
  }
  return { servers, failed };
}
