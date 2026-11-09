// lib/dpi.js — локальный обход DPI через ByeDPI (без сервера и без VPN).
//
// Движок: https://github.com/hufrea/byedpi — чистый C, **MIT**, 3427★.
// Это локальный SOCKS5-прокси, который режет и переупорядочивает TCP-сегменты
// и TLS-записи так, чтобы DPI не смог собрать соединение и классифицировать
// его, а настоящий сервер — собрал. Сервер не нужен, обратного канала нет,
// DNS не перекодируется.
//
// Почему берём именно byedpi, а не ByeByeDPI-x-tg:
//   • ByeByeDPI-x-tg (EwenLoy) — GPL-3.0 Android-обёртка, Kotlin 98%, в релизах
//     только .apk, десктоп-сборок нет. Встроить в desktop-клиент нечего.
//   • Движок внутри неё — как раз hufrea/byedpi (см. её .gitmodules).
//   • byedpi — MIT, поэтому его можно класть в дистрибутив без заражения GPL.
//   • Есть готовые Windows-бинарники: byedpi-17.3-x86_64-w64.zip → ciadpi.exe
//     (x64, 129 КБ) + byedpi.bat + service_install.bat (режим службы Windows).
//
// Модуль чистый (без browser.*) — одинаково работает в расширении и в
// desktop-демоне, где ciadpi можно запускать sidecar-процессом.

/** Порт по умолчанию у ciadpi. Совпадает с портом native host — см. DPI_PORT_CONFLICT. */
export const DPI_DEFAULT_PORT = 1080;

/** Порт, на который ставим ByeDPI в FLICKER, чтобы не спорить с sing-box. */
export const FLICKER_DPI_PORT = 1081;

/**
 * Чем проверяем живость локального прокси.
 * detectportal.firefox.com — собственный эндпоинт Mozilla для определения
 * captive portal; отдаёт "success\n". Не Google и не сторонний сервис.
 */
export const DPI_PROBE_URL = "https://detectportal.firefox.com/success.txt";
export const DPI_PROBE_TIMEOUT_MS = 6000;

/**
 * Пресеты стратегий. Первые два — дословно из дистрибутива и README byedpi,
 * то есть проверены автором движка; остальные — из примеров README.
 * Аргументы можно править вручную: validateDpiArgs() подскажет про опечатки.
 */
export const DPI_PRESETS = [
  {
    id: "upstream-default",
    name: "По умолчанию из дистрибутива byedpi",
    args: "--split 1 --disorder 3+s --mod-http=h,d --auto=torst --tlsrec 1+s",
    origin: "byedpi.bat / service_install.bat, v0.17.3",
    note: "Стратегия, с которой byedpi поставляется. Начинать стоит с неё."
  },
  {
    id: "disorder-auto",
    name: "Disorder + авто-реакция на блокировку",
    args: "--disorder 1 --auto=torst --tlsrec 1+s",
    origin: "README byedpi, пример 1",
    note: "Куски уходят в обратном порядке; при похожем на блокировку событии " +
          "(таймаут или сброс после первого запроса) включается разбиение TLS-записи."
  },
  {
    id: "fake-ttl",
    name: "Fake-пакет с коротким TTL",
    args: "--fake -1 --ttl 8",
    origin: "README byedpi, пример 2",
    note: "Перед первым куском шлётся поддельный пакет с TTL 8: он доходит до DPI, " +
          "но не доходит до сервера. README предупреждает: на Windows --fake может " +
          "работать нестабильно."
  },
  {
    id: "tlsrec-only",
    name: "Только разбиение TLS-записи",
    args: "--tlsrec 1+s",
    origin: "из аргументов upstream-пресета",
    note: "Минимальное вмешательство: SNI уезжает в двух TLS-записях."
  },
  {
    id: "plain",
    name: "Без параметров",
    args: "",
    origin: "—",
    note: "Чистый SOCKS5-прокси без обхода. Нужен, чтобы проверить, что сам " +
          "прокси работает, прежде чем подбирать стратегию."
  }
];

/**
 * Известные опции ciadpi (v0.17.x) — для проверки опечаток.
 * Флаги без значения помечены false, с значением — true.
 */
export const KNOWN_OPTS = {
  i: true, ip: true, p: true, port: true, D: false, daemon: false,
  w: true, pidfile: true, E: false, transparent: false,
  c: true, "max-conn": true, I: true, "conn-ip": true,
  b: true, "buf-size": true, g: true, "def-ttl": true,
  N: false, "no-domain": false, U: false, "no-udp": false, F: false, tfo: false,
  A: true, auto: true, L: true, "auto-mode": true,
  u: true, "cache-ttl": true, y: true, "cache-dump": true, T: true, timeout: true,
  K: true, proto: true, H: true, hosts: true, j: true, ipset: true, V: true, pf: true,
  R: true, round: true, s: true, split: true, d: true, disorder: true,
  o: true, oob: true, q: true, disoob: true, f: true, fake: true,
  t: true, ttl: true, S: false, md5sig: false, O: true, "fake-offset": true,
  l: true, "fake-data": true, e: true, "oob-data": true,
  "tlsrec": true, "mod-http": true, "udp-fake": true, "hostmix": true,
  "synhost": true, "syndata": true, "hostfade": true, "drop-nl": true
};

/** Опции, конфликтующие с работой FLICKER как SOCKS-клиента. */
export const FORBIDDEN_OPTS = {
  transparent: "прозрачный режим отключает SOCKS — FLICKER не сможет направить трафик",
  E: "то же, что --transparent: SOCKS работать не будет",
  daemon: "в desktop-режиме процессом управляет FLICKER, демон не нужен",
  D: "то же, что --daemon",
  "no-domain": "без доменных имён SOCKS5-запросы Firefox (proxyDNS) будут отброшены",
  N: "то же, что --no-domain"
};

/**
 * parseArgs — разобрать командную строку ciadpi на токены.
 * Понимает кавычки, чтобы --fake-data="..." не разваливалось.
 */
export function parseArgs(args) {
  const out = [];
  const src = String(args || "");
  let cur = "";
  let quote = null;
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; continue; }
    if (/\s/.test(ch)) { if (cur) { out.push(cur); cur = ""; } continue; }
    cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

/**
 * validateDpiArgs — проверить аргументы ciadpi.
 * @returns {{ok:boolean, errors:string[], warnings:string[]}}
 */
export function validateDpiArgs(args) {
  const tokens = parseArgs(args);
  const errors = [];
  const warnings = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (!t.startsWith("-")) {
      errors.push(`«${t}» — не опция: аргументы ciadpi начинаются с - или --`);
      continue;
    }
    const name = t.replace(/^--?/, "").split("=")[0];
    if (!(name in KNOWN_OPTS)) {
      errors.push(`неизвестная опция --${name}`);
      continue;
    }
    if (name in FORBIDDEN_OPTS) {
      errors.push(`--${name} нельзя: ${FORBIDDEN_OPTS[name]}`);
      continue;
    }
    const needsValue = KNOWN_OPTS[name];
    const hasInline = t.includes("=");
    if (needsValue && !hasInline) {
      const next = tokens[i + 1];
      // Отрицательное число — это ЗНАЧЕНИЕ, а не новая опция: у ciadpi
      // смещения бывают со знаком минус (--fake -1, --split -2). Без этого
      // исключения пресет из README («--fake -1 --ttl 8») не проходил валидацию.
      const isNegativeNumber = typeof next === "string" && /^-\d/.test(next);
      if (!next || (next.startsWith("-") && !isNegativeNumber)) {
        errors.push(`--${name} требует значение`);
      } else {
        i++;
      }
    }
  }
  if (/--fake\b/.test(String(args || "")) && !/--fake-data/.test(String(args || ""))) {
    warnings.push("--fake на Windows работает нестабильно (предупреждение из README byedpi)");
  }
  if (!/-p\b|--port\b/.test(String(args || ""))) {
    warnings.push("порт не задан — ciadpi займёт 1080, это порт native host FLICKER");
  }
  return { ok: errors.length === 0, errors, warnings };
}

/**
 * buildDpiCommand — готовая строка запуска для пользователя.
 * @param {{presetId?:string, args?:string, port?:number, exe?:string, win?:boolean}} [o]
 */
export function buildDpiCommand(o = {}) {
  const preset = DPI_PRESETS.find((p) => p.id === (o.presetId || "upstream-default")) || DPI_PRESETS[0];
  const args = (o.args != null ? String(o.args) : preset.args).trim();
  const port = Number(o.port) || FLICKER_DPI_PORT;
  const exe = o.exe || (o.win === false ? "./ciadpi" : "ciadpi.exe");
  const parts = [exe];
  if (args) parts.push(args);
  // порт ставим последним и всегда явно: иначе ciadpi займёт 1080
  if (!/(^|\s)(-p|--port)(\s|=)/.test(args)) parts.push(`--port ${port}`);
  return parts.join(" ");
}

/**
 * buildServiceInstall — содержимое .bat для установки ciadpi службой Windows.
 * Служба переживает перезагрузку и не требует держать консоль открытой.
 * Запускать ОТ ИМЕНИ АДМИНИСТРАТОРА.
 * @param {{args?:string, port?:number, dir?:string}} [o]
 */
export function buildServiceInstall(o = {}) {
  const port = Number(o.port) || FLICKER_DPI_PORT;
  const args = (o.args != null ? String(o.args) : DPI_PRESETS[0].args).trim();
  const dir = o.dir || "%~dp0";
  const bin = `\\\"${dir}ciadpi.exe\\\" ${args} --port ${port}`.trim();
  return [
    "@echo off",
    "title FLICKER DPI - Install Service",
    `pushd "${dir}"`,
    "",
    "echo Запускать ОТ ИМЕНИ АДМИНИСТРАТОРА.",
    "echo Правая кнопка на файле - \"Запуск от имени администратора\".",
    "pause",
    "",
    'set svc_name="FlickerDPI"',
    'set svc_desc="ByeDPI local SOCKS proxy for FLICKER VPN (DPI bypass, no server)."',
    `set svc_bin="${bin}"`,
    "",
    "sc stop %svc_name%",
    "sc delete %svc_name%",
    'sc create %svc_name% binPath= %svc_bin% start= "auto"',
    "sc description %svc_name% %svc_desc%",
    "sc start %svc_name%",
    "",
    "popd",
    "pause",
    ""
  ].join("\r\n");
}

/** Краткое описание для UI: что это и зачем. */
export function describeDpi() {
  return "Локальный обход DPI на движке ByeDPI (MIT). Сервер и подписка не нужны: " +
    "ciadpi поднимает SOCKS5-прокси на этом же компьютере и так видоизменяет " +
    "TCP-сегменты и TLS-записи, что DPI не может распознать и заблокировать " +
    "соединение. Трафик идёт напрямую к сайтам — шифрования поверх вашего " +
    "соединения не добавляется, IP остаётся вашим.";
}


// ================= GoodbyeDPI — второй движок (v5.5) =================
//
// Движок: https://github.com/ValdikSS/GoodbyeDPI — Apache-2.0 (+ драйвер
// WinDivert, LGPL-3.0). Принципиальное отличие от ByeDPI: это НЕ SOCKS-прокси,
// а ПРОЗРАЧНЫЙ фильтр пакетов системного уровня. Он применяется ко всем
// программам сразу, браузеру не нужно настраивать прокси, и FLICKER не управляет
// его процессом — поэтому интеграция ограничена генератором команд и .bat
// (консольный запуск + служба Windows), как в официальных скриптах дистрибутива.
//
// Пресеты — дословно официальные .cmd из релиза v0.2.2:
//   1_russia_blacklist_dnsredir.cmd / 1_russia_blacklist.cmd /
//   2_any_country_dnsredir.cmd / 2_any_country.cmd
// Чёрный список РФ скачивается с antizapret.prostovpn.org (bitsadmin),
// как в 0_russia_update_blacklist_file.cmd.

export const GOODBYEDPI_PRESETS = [
  {
    id: "gdp-ru-dnsredir",
    name: "Россия: blacklist + DNS-редирект (официальный рекомендованный)",
    args: "-5 --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253 --blacklist russia-blacklist.txt",
    origin: "1_russia_blacklist_dnsredir.cmd, GoodbyeDPI v0.2.2",
    note: "Трюки применяются только к доменам из чёрного списка РФ; DNS уходит " +
          "на Yandex (77.88.8.8) порт 1253 — защита от DNS-отравления. Файл " +
          "russia-blacklist.txt скачивается служебным .bat (antizapret)."
  },
  {
    id: "gdp-ru-blacklist",
    name: "Россия: только blacklist",
    args: "-5 --blacklist russia-blacklist.txt",
    origin: "1_russia_blacklist.cmd, GoodbyeDPI v0.2.2",
    note: "То же без DNS-редиректа — подходит, если DNS уже защищён (DoH/DoT)."
  },
  {
    id: "gdp-any-dnsredir",
    name: "Любая страна + DNS-редирект",
    args: "-5 --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253",
    origin: "2_any_country_dnsredir.cmd, GoodbyeDPI v0.2.2",
    note: "Применяется ко всему трафику, без чёрного списка."
  },
  {
    id: "gdp-any",
    name: "Любая страна (минимальный режим)",
    args: "-5",
    origin: "2_any_country.cmd, GoodbyeDPI v0.2.2",
    note: "Максимальная совместимость: без DNS-редиректа и чёрного списка."
  }
];

/**
 * Опции goodbyedpi.exe по README v0.2.2 (флаги без значения — false,
 * со значением — true). Числовые режимы -1..-9 обрабатываются отдельно.
 */
export const GOODBYEDPI_KNOWN_OPTS = {
  p: false, q: false, r: false, s: false, m: false, a: false, n: false, w: false,
  f: true, k: true, e: true,
  port: true, "ip-id": true,
  "dns-addr": true, "dns-port": true, "dnsv6-addr": true, "dnsv6-port": true,
  "dns-verb": false, blacklist: true, "allow-no-sni": false, "frag-by-sni": false,
  "set-ttl": true
};

/**
 * validateGoodbyeDpiArgs — проверка командной строки goodbyedpi.exe.
 * @returns {{ok:boolean, errors:string[], warnings:string[]}}
 */
export function validateGoodbyeDpiArgs(args) {
  const tokens = parseArgs(args);
  const errors = [];
  const warnings = [];
  let modeFlags = 0;
  let hasBlacklist = false;
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (/^-\d$/.test(t)) { modeFlags++; continue; }        // числовой режим -1..-9
    if (!t.startsWith("-")) {
      errors.push(`«${t}» — не опция goodbyedpi`);
      continue;
    }
    const name = t.replace(/^--?/, "").split("=")[0];
    if (!(name in GOODBYEDPI_KNOWN_OPTS)) {
      errors.push(`неизвестная опция --${name} (проверьте README GoodbyeDPI v0.2.2)`);
      continue;
    }
    if (name === "blacklist") hasBlacklist = true;
    if (GOODBYEDPI_KNOWN_OPTS[name] && !t.includes("=")) {
      const next = tokens[i + 1];
      if (!next || (next.startsWith("-") && !/^-\d$/.test(next))) {
        errors.push(`--${name} требует значение`);
      } else {
        i++;
      }
    }
  }
  if (modeFlags > 1) warnings.push("несколько числовых режимов (-1..-9): официальный дистрибутив использует один");
  if (!hasBlacklist) {
    warnings.push("без --blacklist трюки применяются ко ВСЕМУ трафику; для РФ официальные скрипты используют --blacklist russia-blacklist.txt");
  }
  return { ok: errors.length === 0, errors, warnings };
}

/**
 * buildGoodbyeDpiCommand — строка запуска goodbyedpi для консоли.
 * @param {{presetId?:string, args?:string|null, exe?:string, win?:boolean}} [o]
 */
export function buildGoodbyeDpiCommand(o = {}) {
  const preset = GOODBYEDPI_PRESETS.find((p) => p.id === (o.presetId || "gdp-ru-dnsredir")) || GOODBYEDPI_PRESETS[0];
  const args = (o.args != null ? String(o.args) : preset.args).trim();
  const exe = o.exe || (o.win === false ? "./goodbyedpi" : "goodbyedpi.exe");
  return args ? `${exe} ${args}` : exe;
}

/**
 * buildGoodbyeDpiServiceInstall — .bat установки GoodbyeDPI службой Windows
 * (по образцу официального service_install_russia_blacklist_dnsredir.cmd).
 * Если в аргументах есть --blacklist — перед установкой скачивается свежий
 * список antizapret. Запускать ОТ АДМИНИСТРАТОРА.
 * @param {{args?:string, dir?:string}} [o]
 */
export function buildGoodbyeDpiServiceInstall(o = {}) {
  const preset = GOODBYEDPI_PRESETS[0];
  const args = (o.args != null ? String(o.args) : preset.args).trim();
  const dir = o.dir || "%~dp0";
  const usesBlacklist = /--blacklist(\s|=)/.test(args);
  // в binPath пути должны быть абсолютными и экранированными для sc
  const argsAbs = args.replace(/--blacklist\s+(\S+)/, '--blacklist \\"%CD%\\$1\\"');
  const bin = `\\"${dir}goodbyedpi.exe\\" ${argsAbs}`.trim();
  const lines = [
    "@ECHO OFF",
    "title FLICKER GoodbyeDPI - Install Service",
    "echo Запускать ОТ ИМЕНИ АДМИНИСТРАТОРА.",
    "echo Правая кнопка на файле - \"Запуск от имени администратора\".",
    "pause",
    `PUSHD "${dir}"`,
    ""
  ];
  if (usesBlacklist) {
    lines.push(
      "echo Скачиваем чёрный список РФ (antizapret)...",
      "bitsadmin /transfer flicker-gdp-blacklist https://antizapret.prostovpn.org/domains-export.txt \"%CD%\\russia-blacklist.txt\"",
      ""
    );
  }
  lines.push(
    "sc stop \"FlickerGoodbyeDPI\"",
    "sc delete \"FlickerGoodbyeDPI\"",
    `sc create "FlickerGoodbyeDPI" binPath= "${bin}" start= "auto"`,
    "sc description \"FlickerGoodbyeDPI\" \"GoodbyeDPI (Apache-2.0) - passive/active DPI circumvention, managed by FLICKER VPN\"",
    "sc start \"FlickerGoodbyeDPI\"",
    "",
    "POPD",
    "echo Готово. Служба FlickerGoodbyeDPI запускается автоматически при старте Windows.",
    "pause",
    ""
  );
  return lines.join("\r\n");
}

/** buildGoodbyeDpiBlacklistBat — отдельный .bat обновления чёрного списка. */
export function buildGoodbyeDpiBlacklistBat() {
  return [
    "@ECHO OFF",
    "title FLICKER GoodbyeDPI - Update blacklist",
    "PUSHD \"%~dp0\"",
    "bitsadmin /transfer flicker-gdp-blacklist https://antizapret.prostovpn.org/domains-export.txt \"%CD%\\russia-blacklist.txt\"",
    "POPD",
    "echo Готово: russia-blacklist.txt обновлён. Перезапустите службу FlickerGoodbyeDPI (sc stop/sc start).",
    "pause",
    ""
  ].join("\r\n");
}

/** Краткое описание для UI. */
export function describeGoodbyeDpi() {
  return "Альтернативный движок GoodbyeDPI (ValdikSS, Apache-2.0) — прозрачный " +
    "фильтр пакетов уровня системы на драйвере WinDivert: работает сразу для " +
    "всех программ, прокси в браузере НЕ нужен. FLICKER не управляет его " +
    "процессом — только генерирует команду запуска и .bat для установки " +
    "службой Windows. В popup при этом можно не подключаться к серверу вовсе " +
    "(или выбрать «Диагностика (direct)»). Совместим с VPN-туннелем FLICKER: " +
    "фильтр применяется к трафику до шифрования туннелем не будет — используйте " +
    "что-то одно для одного и того же трафика.";
}
