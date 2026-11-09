// lib/protocol.js — конфигурации протоколов FLICKER VPN.
//
// Основной стек — TCP/443 с маскировкой: VLESS+Reality, Trojan, VMess, SS,
// WireGuard (включая «матрёшку» WireGuard-в-VLESS). Hysteria 2 (UDP/QUIC) —
// запасной экспериментальный транспорт: код сохранён, но в дефолтном UI и
// дефолтных подписках он скрыт. TUIC и симуляции Fake-SNI/Mux/REALITY удалены.

export const PROTOCOLS = {
  VLESS: {
    id: "vless",
    name: "VLESS + Reality",
    transport: "TCP/443",
    defaultPort: 443,
    features: ["reality", "vision", "utls", "ws", "grpc"],
    defaults: { tls: { verify: true, insecure: false, certificates: [] } }
  },
  TROJAN: {
    id: "trojan",
    name: "Trojan (TLS)",
    transport: "TCP/443",
    defaultPort: 443,
    features: ["tls", "ws", "grpc"],
    defaults: { tls: { verify: true, insecure: false, certificates: [] } }
  },
  VMESS: {
    id: "vmess",
    name: "VMess",
    transport: "TCP",
    defaultPort: 443,
    features: ["tls", "ws", "grpc"],
    defaults: { tls: { verify: true, insecure: false, certificates: [] } }
  },
  SHADOWSOCKS: {
    id: "shadowsocks",
    name: "Shadowsocks",
    transport: "TCP",
    defaultPort: 8388,
    features: ["aead"],
    defaults: { tls: { verify: false, insecure: true, certificates: [] } }
  },
  WIREGUARD: {
    id: "wireguard",
    name: "WireGuard",
    transport: "UDP (или TCP через детур)",
    defaultPort: 51820,
    features: ["detour-vless", "detour-trojan", "userspace"],
    defaults: { tls: { verify: false, insecure: true, certificates: [] } }
  },
  // Запасной UDP/QUIC-транспорт. Скрыт из дефолтного списка в UI:
  // включается тумблером «Экспериментальные UDP-протоколы» в настройках.
  HYSTERIA2: {
    id: "hysteria2",
    name: "Hysteria 2 (экспериментальный, UDP/QUIC)",
    transport: "QUIC",
    defaultPort: 443,
    experimental: true,
    features: ["obfs"],
    defaults: {
      auth: "",
      obfs: { type: "salamander", password: "" },
      tls: { verify: false, insecure: true, certificates: [] }
    }
  },
  // Локальный обход DPI (движок ByeDPI, MIT). Сервер не нужен: ciadpi поднимает
  // SOCKS5 на этом же компьютере и видоизменяет TCP-сегменты/TLS-записи так,
  // что DPI не может классифицировать соединение. Подробнее — lib/dpi.js.
  DPI: {
    id: "dpi",
    name: "DPI-обход (локально, без сервера)",
    transport: "локальный SOCKS5 (ByeDPI)",
    defaultPort: 1081,
    local: true,          // не требует ни внешнего сервера, ни native host
    features: ["no-server", "no-credentials", "socks5"],
    defaults: { tls: { verify: false, insecure: true, certificates: [] } }
  },
  // Диагностический транспорт: SOCKS5 -> прямой TCP без внешнего VPN-сервера.
  DIRECT: {
    id: "direct",
    name: "Direct (диагностика)",
    transport: "TCP",
    defaultPort: 443,
    features: [],
    defaults: { tls: { verify: false, insecure: true, certificates: [] } }
  }
};

export function getProtocol(protocol) {
  if (!protocol) return null;
  const key = String(protocol).toUpperCase();
  if (PROTOCOLS[key]) return PROTOCOLS[key];
  return Object.values(PROTOCOLS).find((p) => p.id === String(protocol).toLowerCase()) || null;
}

export function buildServerConfig(server) {
  const proto = getProtocol(server.protocol);
  if (!proto) throw new Error("Unknown protocol: " + server.protocol);

  return {
    protocol: proto.id,
    server: server.host || server.server || "",
    port: Number(server.port) || proto.defaultPort,
    // секреты
    auth: server.auth || "",
    uuid: server.uuid || "",
    cipher: server.cipher || "",
    // TLS / Reality / Vision (TCP/443-стек)
    tlsEnabled: server.tlsEnabled ?? false,
    sni: server.sni || "",
    flow: server.flow || "",
    fingerprint: server.fingerprint || "",
    spiderX: server.spiderX || "",
    reality: server.reality && server.reality.publicKey ? {
      publicKey: server.reality.publicKey,
      shortId: server.reality.shortId || ""
    } : undefined,
    transport: server.transport || undefined,
    packetEncoding: server.packetEncoding || "",
    // HY2 (запасной)
    obfs: server.obfs || proto.defaults.obfs || { type: "none", password: "" },
    congestion: server.congestion || { type: "bbr" },
    // WireGuard + «матрёшка»
    wireguard: server.wireguard ? (() => {
      // FIX(5.5.8): AmneziaWG-параметры приводим к канону; значения вне uint32
      // возвращаем в объект, чтобы validateServerConfig выдал ЯВНУЮ ошибку,
      // а не подсунул хосту обфускацию с нулями.
      const wg = { ...server.wireguard };
      const rawAwg = wg.amnezia || wg.amnezia_wg;
      const awg = normalizeAmnezia(rawAwg || wg);
      if (awg) wg.amnezia = awg; else delete wg.amnezia;
      const bad = awgInvalidEntries(rawAwg);
      if (Object.keys(bad).length) wg.amnezia = { ...(awg || {}), ...bad };
      return wg;
    })() : undefined,
    detour: server.detour || undefined,
    tls: server.tls || proto.defaults.tls,
    listen: server.listen || "127.0.0.1:1080"
  };
}

// ============ FIX(5.5.8): AmneziaWG (анти-DPI WireGuard) ============
// Параметры «Advanced Security» из AmneziaWG-конфигов. Имена в .conf: Jc, Jmin,
// Jmax, S1, S2, H1..H4; в sing-box-подобном JSON: j_c, j_min, j_max, s1, s2, h1..h4.
export const AMNEZIA_FIELDS = ["jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"];

function u32(v) {
  const n = typeof v === "number" ? v : parseInt(String(v == null ? "" : v).trim(), 10);
  return Number.isFinite(n) && n >= 0 && n <= 4294967295 ? n : null;
}

/**
 * normalizeAmnezia — привести AWG-параметры из любого источника (.conf, ссылка,
 * JSON хоста Amnezia) к канону {jc,jmin,jmax,s1,s2,h1..h4}.
 * @returns {object|null} null, если ни одного AWG-параметра не найдено
 */
export function normalizeAmnezia(raw) {
  if (!raw || typeof raw !== "object") return null;
  const src = {};
  for (const [k, v] of Object.entries(raw)) {
    const key = String(k).toLowerCase().replace(/[_\-\s]/g, "");
    src[key] = v;
  }
  const out = {};
  let found = 0;
  for (const f of AMNEZIA_FIELDS) {
    const v = src[f] !== undefined ? src[f] : undefined;
    const n = u32(v);
    if (n != null) { out[f] = n; found++; }
  }
  if (!found) return null;
  // дефолты Amnezia для незаполненных полей (типовые значения сервера 3.x)
  out.jc = out.jc ?? 3;
  out.jmin = out.jmin ?? 10;
  out.jmax = out.jmax ?? 50;
  out.s1 = out.s1 ?? 0;
  out.s2 = out.s2 ?? 0;
  for (const h of ["h1", "h2", "h3", "h4"]) if (out[h] == null) out[h] = 0;
  return out;
}

/**
 * awgInvalidEntries — значения AWG-параметров вне uint32 (или нечисловые).
 * @returns {object} например {h4: 5544332211}; пусто = всё в диапазоне
 */
export function awgInvalidEntries(raw) {
  const bad = {};
  if (!raw || typeof raw !== "object") return bad;
  for (const [k, v] of Object.entries(raw)) {
    const key = String(k).toLowerCase().replace(/[_\-\s]/g, "");
    if (!AMNEZIA_FIELDS.includes(key)) continue;
    if (v == null || v === "") continue;
    const n = Number(v);
    if (!Number.isFinite(n) || n < 0 || n > 4294967295) bad[key] = v;
  }
  return bad;
}

/** toSingBoxAmnezia — имена полей для хоста (j_c/j_min/j_max + s1/s2/h1..h4). */
export function toSingBoxAmnezia(a) {
  const n = normalizeAmnezia(a);
  if (!n) return undefined;
  return { j_c: n.jc, j_min: n.jmin, j_max: n.jmax, s1: n.s1, s2: n.s2, h1: n.h1, h2: n.h2, h3: n.h3, h4: n.h4 };
}

export function validateServerConfig(cfg) {
  const errors = [];
  const warnings = [];
  const host = cfg.server || cfg.host;
  if (!host) errors.push("Host is required");
  const port = Number(cfg.port);
  if (!port || port < 1 || port > 65535) errors.push("Invalid port");
  switch (cfg.protocol) {
    case "vless":
    case "vmess":
      if (!cfg.uuid) errors.push("VLESS/VMess UUID required");
      if (cfg.reality && !cfg.reality.publicKey) errors.push("Reality public key required");
      break;
    case "trojan":
      if (!cfg.auth) errors.push("Trojan password required");
      break;
    case "shadowsocks":
      if (!cfg.auth) errors.push("Shadowsocks password required");
      break;
    case "hysteria2":
      if (!cfg.auth) errors.push("HY2 password required");
      break;
    case "wireguard": {
      const wg = cfg.wireguard;
      if (!wg || !wg.privateKey) errors.push("WireGuard private key required");
      else if (!wg.peerPublicKey) errors.push("WireGuard peer public key required");
      // FIX(5.5.8): AmneziaWG — диапазоны и осмысленность, иначе хост молча
      // отклонит конфиг или пойдёт без обфускации
      if (wg && wg.amnezia) {
        for (const [k, v] of Object.entries(awgInvalidEntries(wg.amnezia))) {
          errors.push(`AmneziaWG: ${k}=${v} вне диапазона 0..4294967295 (uint32)`);
        }
        const a = normalizeAmnezia(wg.amnezia);
        if (!a) {
          warnings.push("AmneziaWG: параметры не распознаны (нужны Jc/Jmin/Jmax/S1/S2/H1..H4)");
        } else {
          if (a.jmin > a.jmax) errors.push("AmneziaWG: Jmin не может быть больше Jmax");
          if (a.jc < 1 || a.jc > 65535) errors.push("AmneziaWG: Jc вне диапазона 1..65535");
          if (!a.h1 && !a.h2 && !a.h3 && !a.h4) {
            warnings.push("AmneziaWG: H1..H4 равны 0 — обфускация заголовков фактически выключена");
          }
        }
      }
      if (cfg.detour) {
        if (cfg.detour.protocol === "vless" && (!cfg.detour.uuid || !cfg.detour.server)) {
          errors.push("Detour (VLESS): server и uuid обязательны");
        }
        if (cfg.detour.protocol === "trojan" && (!cfg.detour.password || !cfg.detour.server)) {
          errors.push("Detour (Trojan): server и password обязательны");
        }
      }
      break;
    }
  }
  return { valid: errors.length === 0, errors, warnings };
}
