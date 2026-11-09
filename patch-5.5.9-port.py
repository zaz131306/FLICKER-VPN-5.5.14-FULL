#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Патч 5.5.9 (часть 2): порт локального DPI-обхода не спорит с native host.

Из лога пользователя:
    порт 127.0.0.1:1080 занят — SOCKS слушает 127.0.0.1:1081

Хост умеет autoPort и штатно сдвинулся на 1081. Но 1081 — это ровно дефолт
локального ciadpi (FLICKER_DPI_PORT): в DPI-режиме два прокси дрались за один
порт, ciadpi не поднимался, а браузеру вооружался порт, который никто не
слушает. Само состояние STATE.socksPort расширение отслеживает верно
(«SOCKS-порт сдвинут хостом»), поэтому правим только вторую сторону: уводим
дефолт DPI-порта из диапазона autoPort (1080, 1081, 1082…) и не даём режимам
встать на один порт.
"""
import io, os, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
EXT = os.path.join(ROOT, "ext")
DPI = os.path.join(EXT, "lib", "dpi.js")
BG = os.path.join(EXT, "background.js")

def rd(p):
    with io.open(p, "r", encoding="utf-8") as f: return f.read()
def wr(p, s):
    with io.open(p, "w", encoding="utf-8") as f: f.write(s)
applied, failed = [], []
def sub(path, old, new, tag):
    s = rd(path); n = s.count(old)
    if n != 1:
        failed.append((tag, os.path.basename(path), n)); return False
    wr(path, s.replace(old, new, 1)); applied.append(tag); return True

# ---------------------------------------------------------------- lib/dpi.js
sub(DPI, '''/** Порт, на который ставим ByeDPI в FLICKER, чтобы не спорить с sing-box. */
export const FLICKER_DPI_PORT = 1081;''',
'''/**
 * Порт, на который ставим ByeDPI в FLICKER, чтобы не спорить с sing-box.
 *
 * FIX(5.5.9): раньше тут был 1081 — и это ровно тот порт, на который native
 * host сдвигается при autoPort («порт 127.0.0.1:1080 занят — SOCKS слушает
 * 127.0.0.1:1081»). Два прокси на одном порту: ciadpi не поднимался, а браузеру
 * вооружался порт, который никто не слушает. Уводим дефолт из диапазона
 * autoPort (1080, 1081, 1082…) подальше.
 */
export const FLICKER_DPI_PORT = 10880;

/** Кандидаты для локального прокси, если желаемый порт уже занят. */
export const DPI_PORT_CANDIDATES = [10880, 10881, 10882, 10883, 10884, 10885];

/**
 * resolveDpiPort — порт для локального DPI-прокси, который НЕ спорит с SOCKS5
 * native host. Чистая функция: без browser.*, проверяется юнит-тестами.
 *
 * @param {object} [o]
 * @param {number} [o.wanted] желаемый порт (из настроек или описания узла)
 * @param {Array<number>|Set<number>} [o.taken] занятые порты (минимум — порт хоста)
 * @returns {{port: number, moved: boolean, wanted: number|null, taken: number[]}}
 */
export function resolveDpiPort(o = {}) {
  const taken = [...(o.taken || [])]
    .map((p) => Number(p))
    .filter((p) => Number.isInteger(p) && p > 0 && p < 65536);
  const isTaken = (p) => taken.includes(p);
  const wanted = Number.isInteger(Number(o.wanted)) ? Number(o.wanted) : null;
  const valid = wanted && wanted > 0 && wanted < 65536;
  if (valid && !isTaken(wanted)) {
    return { port: wanted, moved: false, wanted, taken };
  }
  for (const c of DPI_PORT_CANDIDATES) {
    if (!isTaken(c)) return { port: c, moved: true, wanted: valid ? wanted : null, taken };
  }
  // все кандидаты заняты (практически невозможно) — берём последний и говорим честно
  const last = DPI_PORT_CANDIDATES[DPI_PORT_CANDIDATES.length - 1];
  return { port: last, moved: true, wanted: valid ? wanted : null, taken };
}''', "dpi.port")

# ---------------------------------------------------------------- background.js
sub(BG, '  DPI_PRESETS, DPI_DEFAULT_PORT, FLICKER_DPI_PORT, DPI_PROBE_URL,',
'''  DPI_PRESETS, DPI_DEFAULT_PORT, FLICKER_DPI_PORT, DPI_PROBE_URL,
  resolveDpiPort,   // FIX(5.5.9): локальный DPI не встаёт на порт native host''',
      "bg.import")

sub(BG, '''async function startDpiTunnel(server) {
  const port = Number(server?.port) || STATE.dpiPort || FLICKER_DPI_PORT;
  STATE.tunnelKind = "dpi";
  STATE.dpiPort = port;''',
'''async function startDpiTunnel(server) {
  const wanted = Number(server?.port) || STATE.dpiPort || FLICKER_DPI_PORT;
  // FIX(5.5.9): native host умеет autoPort — при занятом 1080 он слушает 1081,
  // 1082… Если локальный ciadpi встанет на тот же порт, он не поднимется, а
  // браузеру мы вооружим порт, который никто не слушает (и трафик уйдёт
  // напрямую). Не спорим с хостом за порт.
  const picked = resolveDpiPort({ wanted, taken: [STATE.socksPort] });
  const port = picked.port;
  if (picked.moved) {
    const m = `Порт ${picked.wanted} занят SOCKS5 native host — DPI-обход поднят на ${port}.`;
    console.warn("[flicker] " + m);
    try { journal("dpi-port", m); } catch { /* journal определён ниже по файлу */ }
    broadcastUI({ type: "error", message: m });
  }
  STATE.tunnelKind = "dpi";
  STATE.dpiPort = port;''', "bg.dpiStart")

sub(BG, '''            if (port === STATE.socksPort) {
              sendResponse({
                ok: false,
                error: `Порт ${port} занят SOCKS5 native host. Возьми другой (по умолчанию ${FLICKER_DPI_PORT}).`
              });
              break;
            }''',
'''            if (port === STATE.socksPort) {
              // FIX(5.5.9): предлагаем конкретный свободный порт, а не абстрактный
              const alt = resolveDpiPort({ wanted: port, taken: [STATE.socksPort] }).port;
              sendResponse({
                ok: false,
                error: `Порт ${port} занят SOCKS5 native host (хост сдвинулся с 1080 через autoPort). Возьми свободный, например ${alt}.`
              });
              break;
            }''', "bg.dpiCfgMsg")

print("APPLIED:", len(applied))
for a in applied: print("  +", a)
if failed:
    print("FAILED:")
    for t, p, n in failed: print("  !", t, p, "matches=", n)
    sys.exit(1)
