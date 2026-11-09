// lib/errors.js — перевод технических ошибок туннеля/проверок в человеческие
// сообщения (задача 7). Используется и в background, и в popup.
//
// Таблица из ТЗ:
//   Сервер не отвечает      → «Сервер не отвечает (проверьте obfs-пароль или сервер мёртв)»
//   Неверный auth           → «Неверный пароль сервера»
//   Неверный obfs-password  → «Неверный obfs-пароль (таймаут соединения)»
//   Нет живых серверов      → «Нет доступных серверов. Обновите подписку или добавьте свой.»

export const ERRORS = {
  NO_SERVERS: "Нет доступных серверов. Обновите подписку или добавьте свой.",
  AUTH_FAILED: "Неверный пароль сервера",
  OBFS_TIMEOUT: "Неверный obfs-пароль (таймаут соединения)",
  NO_RESPONSE_OBFS: "Сервер не отвечает (проверьте obfs-пароль или сервер мёртв)",
  NO_RESPONSE: "Сервер не отвечает (сервер мёртв или сеть блокирует UDP)",
  DNS_FAILED: "Не удалось разрешить имя сервера (битый DNS или хост удалён)",
  HTTP_FAILED: "Сервер отвечает, но HTTP через туннель не работает",
  NATIVE_MISSING: "Native host недоступен. Установите native host (см. native/install.sh).",
  NO_CREDENTIALS: "У сервера нет учётных данных — укажите пароль/UUID"
};

const isPortBusy = (s) =>
  /address already in use|only one usage of each socket|socks5: listen/i.test(s);
const isTimeout = (s) =>
  /timeout|timed out|deadline|no recent network activity|handshake did not complete|таймаут/i.test(s);
const isAuth = (s) =>
  /authentication error|authfailed|auth failed|invalid.*password|неверн.*парол|401/i.test(s);
const isDns = (s) => /no such host|dns|server misbehaving|resolve/i.test(s);
const isRefused = (s) => /connection refused|unreachable/i.test(s);

/**
 * humanizeTunnelError — сообщение native host / драйвера → человекочитаемое.
 * @param {string} raw — сырая ошибка
 * @param {object} [server] — сервер (для учёта obfs-настроек)
 */
export function humanizeTunnelError(raw, server) {
  const s = String(raw || "");
  if (!s) return ERRORS.NO_RESPONSE;
  const hasObfs =
    (server?.obfs?.type === "salamander" && server?.obfs?.password) ||
    /obfs|salamander/i.test(s);

  if (isPortBusy(s)) {
    return "Не удалось занять SOCKS-порт: он используется другой программой или прошлым процессом FLICKER VPN. " +
      "Закройте вторую копию программы или перезагрузите компьютер. (native host 5.5.4+ выбирает свободный порт сам — обновите установщик.)";
  }
  if (isAuth(s)) return ERRORS.AUTH_FAILED;
  if (isDns(s)) return ERRORS.DNS_FAILED;
  if (isTimeout(s)) {
    // Таймаут при включённом obfs почти всегда = неверный obfs-пароль:
    // сервер не может расшифровать пакеты и молчит.
    return hasObfs ? ERRORS.OBFS_TIMEOUT : ERRORS.NO_RESPONSE;
  }
  if (isRefused(s)) return ERRORS.NO_RESPONSE_OBFS.replace("(проверьте obfs-пароль или сервер мёртв)", "(порт закрыт)");
  return s.length > 200 ? s.slice(0, 200) + "…" : s;
}

/**
 * humanizeProbeError — класс ошибки из native-пробы (probe errClass) → сообщение.
 * Классы приходят из Go-пакета probe: dns|refused|timeout|auth|http|config|other.
 */
/**
 * hostOutdatedError — native host 4.x не знает diagnose/announce/probeServers.
 * Раньше это выглядело как «Туннель не подтверждён» или шквал «неизвестная
 * команда»; теперь говорим прямо, что переустановить.
 */
export function hostOutdatedError(v) {
  return `Native host устарел (${v || "версия неизвестна"}): он не умеет подтверждать туннель, ` +
    `поэтому подключение будет сбрасываться. Установите FLICKER VPN 5.5.4: запустите ` +
    `FlickerVPN-Setup-5.5.4.exe, затем переустановите дополнение из flicker-vpn-5.5.4-signed.xpi ` +
    `и перезапустите Firefox.`;
}

export function humanizeProbeError(errClass, rawError, server) {
  switch (errClass) {
    case "dns": return ERRORS.DNS_FAILED;
    case "refused": return "Сервер сбросил соединение (порт закрыт)";
    case "timeout":
      return server?.obfs?.type === "salamander" && server?.obfs?.password
        ? ERRORS.NO_RESPONSE_OBFS
        : ERRORS.NO_RESPONSE;
    case "auth": return ERRORS.AUTH_FAILED;
    case "http": return ERRORS.HTTP_FAILED;
    case "config": return "Некорректные данные сервера";
    default:
      return rawError ? humanizeTunnelError(rawError, server) : ERRORS.NO_RESPONSE;
  }
}

// Технические сообщения валидации конфига → человеческие (для формы сервера)
const VALIDATION_MAP = [
  [/VLESS\/VMess UUID required/i, "нужен UUID"],
  [/Reality public key required/i, "нужен публичный ключ Reality (pbk)"],
  [/Trojan password required/i, "нужен пароль Trojan"],
  [/Shadowsocks password required/i, "нужен пароль Shadowsocks"],
  [/HY2 password required/i, "нужен пароль Hysteria 2"],
  [/WireGuard private key required/i, "нужен приватный ключ WireGuard"],
  [/WireGuard peer public key required/i, "нужен публичный ключ пира WireGuard"],
  [/Detour \(VLESS\)/i, "для «матрёшки» заполните VLESS-детур (server, uuid)"],
  [/Detour \(Trojan\)/i, "для «матрёшки» заполните Trojan-детур (server, password)"],
  [/Host is required/i, "не указан хост"],
  [/Invalid port/i, "некорректный порт"]
];

export function humanizeValidation(e) {
  return String(e || "").split("; ").map((part) => {
    for (const [re, ru] of VALIDATION_MAP) if (re.test(part)) return ru;
    return part;
  }).join("; ");
}
