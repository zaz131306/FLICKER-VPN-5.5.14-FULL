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

// ---------- WireGuard ----------

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

  const id = "sub-" + fnv1aHex(`wg|${host.toLowerCase()}:${port}:${privateKey}:${peerPublicKey}`);
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
        keepalive: parseInt(p.keepalive, 10) || 25
      },
      detour: null // «матрёшка» настраивается пользователем в UI
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
