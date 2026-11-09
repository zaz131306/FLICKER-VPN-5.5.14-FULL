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
    wireguard: server.wireguard || undefined,
    detour: server.detour || undefined,
    tls: server.tls || proto.defaults.tls,
    listen: server.listen || "127.0.0.1:1080"
  };
}

export function validateServerConfig(cfg) {
  const errors = [];
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
  return { valid: errors.length === 0, errors };
}
