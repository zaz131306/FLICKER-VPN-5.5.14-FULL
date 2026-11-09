// Тесты lib/dpi.js — оба движка локального DPI-обхода (v5.5).
// ByeDPI (ciadpi, SOCKS5) и GoodbyeDPI (прозрачный фильтр, пресеты из
// официальных .cmd v0.2.2).
import test from "node:test";
import assert from "node:assert/strict";
import {
  DPI_PRESETS, FLICKER_DPI_PORT, validateDpiArgs, buildDpiCommand, buildServiceInstall,
  GOODBYEDPI_PRESETS, GOODBYEDPI_KNOWN_OPTS, validateGoodbyeDpiArgs,
  buildGoodbyeDpiCommand, buildGoodbyeDpiServiceInstall, buildGoodbyeDpiBlacklistBat,
  describeGoodbyeDpi, describeDpi
} from "../../lib/dpi.js";

test("ByeDPI: все пресеты проходят валидацию (с портом FLICKER)", () => {
  for (const p of DPI_PRESETS) {
    const v = validateDpiArgs(p.args + " --port " + FLICKER_DPI_PORT);
    assert.equal(v.ok, true, `пресет ${p.id}: ${v.errors.join("; ")}`);
  }
});

test("ByeDPI: запрещённые опции отклоняются", () => {
  assert.equal(validateDpiArgs("--transparent --port 1081").ok, false);
  assert.equal(validateDpiArgs("--daemon --port 1081").ok, false);
});

test("ByeDPI: buildDpiCommand всегда ставит явный порт", () => {
  const cmd = buildDpiCommand({});
  assert.match(cmd, /^ciadpi\.exe /);
  assert.ok(cmd.includes("--port " + FLICKER_DPI_PORT), cmd);
});

test("ByeDPI: service .bat — sc create FlickerDPI", () => {
  const bat = buildServiceInstall({});
  assert.ok(bat.includes("sc create %svc_name%"), bat.slice(0, 200));
  assert.ok(bat.includes("ciadpi.exe"));
});

test("GoodbyeDPI: официальные пресеты валидны", () => {
  assert.equal(GOODBYEDPI_PRESETS.length, 4);
  for (const p of GOODBYEDPI_PRESETS) {
    const v = validateGoodbyeDpiArgs(p.args);
    assert.equal(v.ok, true, `пресет ${p.id}: ${v.errors.join("; ")}`);
  }
  const ru = GOODBYEDPI_PRESETS.find((p) => p.id === "gdp-ru-dnsredir");
  // дословно официальный 1_russia_blacklist_dnsredir.cmd (v0.2.2)
  assert.ok(ru.args.includes("-5"));
  assert.ok(ru.args.includes("--dns-addr 77.88.8.8"));
  assert.ok(ru.args.includes("--dns-port 1253"));
  assert.ok(ru.args.includes("--blacklist russia-blacklist.txt"));
});

test("GoodbyeDPI: валидатор ловит опечатки и пропущенные значения", () => {
  assert.equal(validateGoodbyeDpiArgs("--nope 1").ok, false);
  assert.equal(validateGoodbyeDpiArgs("-5 --dns-addr").ok, false, "пропущено значение");
  assert.equal(validateGoodbyeDpiArgs("goodbyedpi.exe -5").ok, false, "голое имя exe — не опция");
  const v = validateGoodbyeDpiArgs("-5");
  assert.equal(v.ok, true);
  assert.ok(v.warnings.some((w) => w.includes("--blacklist")), "предупреждение про blacklist");
});

test("GoodbyeDPI: buildGoodbyeDpiCommand", () => {
  assert.equal(buildGoodbyeDpiCommand({ presetId: "gdp-any" }), "goodbyedpi.exe -5");
  const c = buildGoodbyeDpiCommand({ args: "-p -q" });
  assert.equal(c, "goodbyedpi.exe -p -q");
  assert.equal(buildGoodbyeDpiCommand({ presetId: "gdp-any", win: false }), "./goodbyedpi -5");
});

test("GoodbyeDPI: service .bat — sc create + bitsadmin + экранирование путей", () => {
  const ru = GOODBYEDPI_PRESETS[0].args;
  const bat = buildGoodbyeDpiServiceInstall({ args: ru });
  assert.ok(bat.includes('sc create "FlickerGoodbyeDPI"'), bat);
  assert.ok(bat.includes("bitsadmin"), "blacklist скачивается при установке");
  assert.ok(bat.includes("antizapret.prostovpn.org/domains-export.txt"));
  assert.ok(bat.includes('\\"%CD%\\russia-blacklist.txt\\"'), "путь blacklist экранирован для sc");
  assert.ok(bat.includes('start= "auto"'));
  const bat2 = buildGoodbyeDpiServiceInstall({ args: "-5" });
  assert.ok(!bat2.includes("bitsadmin"), "без --blacklist — без bitsadmin");
});

test("GoodbyeDPI: blacklist .bat", () => {
  const bat = buildGoodbyeDpiBlacklistBat();
  assert.ok(bat.includes("bitsadmin"));
  assert.ok(bat.includes("russia-blacklist.txt"));
});

test("описания движков — про лицензии", () => {
  assert.ok(describeDpi().includes("ByeDPI"));
  const g = describeGoodbyeDpi();
  assert.ok(g.includes("Apache-2.0"));
  assert.ok(g.includes("WinDivert"));
  assert.equal(GOODBYEDPI_KNOWN_OPTS.blacklist, true);
  assert.equal(GOODBYEDPI_KNOWN_OPTS.p, false);
});
