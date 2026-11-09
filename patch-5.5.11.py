#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Патч 5.5.11 — по отчёту пользователя с уже стоящей 5.5.10.

Отчёт показал, что основное починено: VPN активен (vless 87.242.119.253:443),
трафик 2 362 591 байт, verified=true, verifyFails=0, обрывов нет,
в журнале НЕТ ни одного «release» — удержание отработало и прокси браузеру не
отдало. Остались два хвоста, оба видны в журнале:

  1) 09:08:51 [direct] выбран узел diag (direct) — это не VPN
     09:08:51 [start]   diag direct 127.0.0.1:443
     09:09:19 [start]   sub-6da6d52c vless 87.242.119.253:443
     → 28 секунд на старте расширение сидело на служебном direct-узле.
     Причина: прошлая сессия закончилась на «Диагностике», её id уехал в
     storage.session, а при восстановлении:
       • restoreSessionAfterReload() ставит resumeServerId = rec.serverId без
         проверки протокола;
       • resume-ветка в обработчике hello делает list.find(id) без проверки;
       • pickRecoveryTarget() фильтрует direct из списка кандидатов, НО потом
         ищет resume-ноду по ПОЛНОМУ списку:
             list.find(...) || (servers || []).find((s) => s.id === resumeId)
         — эта «дырка» (её оставили ради dpi-режима) снова пускает direct.

  2) 09:09:24 [hold-start] туннель больше не подтверждён — через 5 секунд после
     [start] и за 25 секунд до первого [verify-ok]. Это штатный выход на режим,
     а не обрыв: applyProxyModeNow() видит tunnelVerified=false, вызывает
     releaseProxy() и уходит в HOLD. Лишний цикл удержания на каждом старте.

Плюс: запоминаем последнюю НАСТОЯЩУЮ VPN-ноду, чтобы после direct-сессии
возврат шёл на неё, а не в автоподбор.
"""
import io, os, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
EXT = os.path.join(ROOT, "ext")
BG = os.path.join(EXT, "background.js")
MAN = os.path.join(EXT, "manifest.json")

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

# ------------------------------------------------------------------ STATE
sub(BG, '''  softDeadActAt: null,        // когда последний раз выносили вердикт (кулдаун)''',
'''  softDeadActAt: null,        // когда последний раз выносили вердикт (кулдаун)
  // FIX(5.5.11): последняя НАСТОЯЩАЯ VPN-нода (не direct/dpi). Нужна, чтобы
  // после сессии на служебной «Диагностике» старт шёл на рабочий сервер, а не
  // в автоподбор по списку, где 27 живых из 600.
  lastVpnServerId: null,
  lastStartAt: null,          // когда последний раз послали хосту start''', "state.lastVpn")

# ------------------------------------------------------------------ consts
sub(BG, '''const SOFT_DEAD_COOLDOWN_MS = 60_000;''',
'''const SOFT_DEAD_COOLDOWN_MS = 60_000;
// FIX(5.5.11): грация после старта. Хост поднимает туннель не мгновенно
// (в отчёте: [start] → через 5 c «туннель больше не подтверждён» → HOLD →
// через 25 c [verify-ok]). В этом окне tunnelVerified=false — норма, а не обрыв,
// поэтому прокси не трогаем и просто ждём diagnose.
const START_GRACE_MS = 10_000;''', "consts.grace")

# ------------------------------------------------------------------ beginSession
sub(BG, '''function beginSession(server) {
  STATE.session = { ...emptySession(), serverId: server?.id || null, startedAt: Date.now() };
}''',
'''function beginSession(server) {
  STATE.session = { ...emptySession(), serverId: server?.id || null, startedAt: Date.now() };
  // FIX(5.5.11): запоминаем последнюю VPN-ноду. Служебный direct-узел и
  // DPI-обход не запоминаются: это не туннель, возвращаться на них нельзя.
  if (server && server.id && !isLocalTransport(server)) {
    STATE.lastVpnServerId = server.id;
    try { browser.storage.local.set({ lastVpnServerId: server.id }).catch(() => {}); }
    catch { /* storage-сбой не имеет права ронять туннель */ }
  }
}''', "beginSession.lastVpn")

# ------------------------------------------------------------------ startTunnel: грация
sub(BG, '''  softLivenessReset();   // FIX(5.5.10): новая нода — счётчик отказов dial с нуля
  journal("start", `${server?.id || "?"} ${composed.config.protocol} ${server?.host || ""}:${server?.port || ""}`);''',
'''  softLivenessReset();   // FIX(5.5.10): новая нода — счётчик отказов dial с нуля
  STATE.lastStartAt = Date.now();   // FIX(5.5.11): отсчёт грации после старта
  journal("start", `${server?.id || "?"} ${composed.config.protocol} ${server?.host || ""}:${server?.port || ""}`);''',
      "start.grace")

# ------------------------------------------------------------------ applyProxyModeNow: не HOLD в грации
sub(BG, '''      if (!STATE.tunnelVerified) {
        if (STATE.proxyArmed) await releaseProxy("туннель больше не подтверждён");''',
'''      if (!STATE.tunnelVerified) {
        // FIX(5.5.11): первые секунды после start подтверждение ещё не могло
        // прийти — это штатный выход на режим, а не обрыв. Раньше здесь сразу
        // вызывался releaseProxy() и расширение уходило в HOLD на каждом старте
        // (в отчёте пользователя: [start] → через 5 c [hold-start] → через 25 c
        // [verify-ok]). Просто ждём diagnose, прокси не трогаем.
        if (isStamp(STATE.lastStartAt) && Date.now() - STATE.lastStartAt < START_GRACE_MS &&
            !STATE.recovering && STATE.holdSince == null) {
          if (!STATE.verifyTimer && !STATE.verifyRunning) scheduleVerify();
          dbgNative({
            command: "dbg",
            text: `proxy: грация после старта, жду подтверждения (${Math.max(0, Math.round((START_GRACE_MS - (Date.now() - STATE.lastStartAt)) / 1000))} c)`
          });
          journal("verify-grace", "жду подтверждения после старта — прокси не трогаю");
          return;
        }
        if (STATE.proxyArmed) await releaseProxy("туннель больше не подтверждён");''',
      "apply.grace")

# ------------------------------------------------------------------ resume после hello
sub(BG, '''        getServers().then((list) => {
          const srv = list.find((s) => s.id === rid);
          if (srv && STATE.status === "disconnected") {''',
'''        getServers().then((list) => {
          const srv = list.find((s) => s.id === rid);
          // FIX(5.5.11): служебный direct-узел («Диагностика») VPN не является,
          // поднимать его «вместо туннеля» после перезапуска хоста нельзя —
          // пользователь получит CONNECTED без VPN. Идём общим путём
          // восстановления: оно выберет настоящую ноду.
          if (srv && srv.protocol === "direct") {
            journal("direct", `resume после hello: пропущен ${srv.id} (direct) — это не VPN`);
            broadcastUI({
              type: "error",
              message: "Восстановление: служебный узел «Диагностика (direct)» пропущен — это не VPN. Подбираю настоящую ноду."
            });
            scheduleRecovery("resume после hello: direct-узел не является VPN");
            return;
          }
          if (srv && STATE.status === "disconnected") {''', "hello.noDirect")

# ------------------------------------------------------------------ restoreSessionAfterReload
sub(BG, '''  if (rec.serverId) {
    STATE.resumeServerId = rec.serverId;
    try {
      const list = await getServers();
      const srv = (list || []).find((x) => x.id === rec.serverId);
      if (srv) STATE.currentServer = srv;
    } catch { /* resumeServerId достаточно для восстановления */ }
  }''',
'''  if (rec.serverId) {
    STATE.resumeServerId = rec.serverId;
    try {
      const list = await getServers();
      const srv = (list || []).find((x) => x.id === rec.serverId);
      if (srv) STATE.currentServer = srv;
      // FIX(5.5.11): в отчёте пользователя старт выглядел так:
      //   [direct] выбран узел diag (direct) — это не VPN
      //   [start]  diag direct 127.0.0.1:443     ← 28 секунд без VPN
      //   [start]  sub-6da6d52c vless ...
      // Прошлая сессия закончилась на «Диагностике», её id лежал в
      // storage.session и восстанавливался как туннель. Так нельзя: direct —
      // это не VPN. Возвращаемся на последнюю настоящую ноду, а если её нет —
      // оставляем выбор восстановлению (оно direct не берёт).
      if (srv && srv.protocol === "direct") {
        const vpnId = STATE.lastVpnServerId && STATE.lastVpnServerId !== srv.id ? STATE.lastVpnServerId : null;
        const vpn = vpnId ? (list || []).find((x) => x.id === vpnId && !isLocalTransport(x)) : null;
        STATE.currentServer = vpn || null;
        STATE.resumeServerId = vpn ? vpn.id : null;
        journal("direct", `при старте пропущен служебный узел ${srv.id} (direct)` +
                          (vpn ? ` — продолжаю на последней VPN-ноде ${vpn.id}` : " — подберу VPN-ноду заново"));
        broadcastUI({
          type: "error",
          message: "Прошлый туннель был на служебном узле «Диагностика (direct)» — это не VPN. " +
                   (vpn ? `Поднимаю «${vpn.name || vpn.host || vpn.id}».` : "Подбираю настоящую ноду.")
        });
      }
    } catch { /* resumeServerId достаточно для восстановления */ }
  }''', "restore.noDirect")

# ------------------------------------------------------------------ pickRecoveryTarget: закрыть дырку
sub(BG, '''  const resume = list.find((s) => s.id === resumeId) ||
    (servers || []).find((s) => s && s.id === resumeId) || null;''',
'''  // FIX(5.5.11): «дырка» в фильтре выше. Исключение для resume-ноды искали по
  // ПОЛНОМУ списку, поэтому direct снова становился целью восстановления
  // (именно так в отчёте пользователя на старте поднялся узел diag). Исключение
  // оставляем только для dpi — это отдельный пользовательский режим обхода,
  // а direct не является VPN ни в каком виде.
  const resumeRaw = (servers || []).find((s) => s && s.id === resumeId) || null;
  const resume = list.find((s) => s.id === resumeId) ||
    (resumeRaw && resumeRaw.protocol === "dpi" ? resumeRaw : null);''', "ladder.noDirectHole")

# ------------------------------------------------------------------ init: загрузка lastVpnServerId
sub(BG, '''    "tunnelMode", "bypassSystemProxy", "dpiPort", "dpiPresetId", "dpiArgs",''',
'''    "tunnelMode", "bypassSystemProxy", "dpiPort", "dpiPresetId", "dpiArgs",
    "lastVpnServerId",   // FIX(5.5.11): последняя настоящая VPN-нода''', "init.get")

sub(BG, '''  STATE.holdProxy = saved.holdProxy !== false;''',
'''  STATE.holdProxy = saved.holdProxy !== false;
  // FIX(5.5.11): последняя VPN-нода — куда возвращаться после direct-сессии
  STATE.lastVpnServerId = typeof saved.lastVpnServerId === "string" ? saved.lastVpnServerId : null;''',
      "init.apply")

# ------------------------------------------------------------------ статус и отчёт
sub(BG, '''    softLiveness: softLivenessState(),   // FIX(5.5.10): серия отказов dial''',
'''    softLiveness: softLivenessState(),   // FIX(5.5.10): серия отказов dial
    // FIX(5.5.11): последняя VPN-нода и сколько осталось грации после старта
    lastVpnServerId: STATE.lastVpnServerId,
    startGraceLeftMs: isStamp(STATE.lastStartAt)
      ? Math.max(0, START_GRACE_MS - (Date.now() - STATE.lastStartAt)) : 0,''', "status.lastVpn")

sub(BG, '''            `soft liveness: отказов dial подряд=''',
'''            `последняя VPN-нода: ${st.lastVpnServerId || "-"} | грация после старта: ${Math.round((st.startGraceLeftMs || 0) / 1000)} c (окно ${Math.round(START_GRACE_MS / 1000)} c)`,
            `soft liveness: отказов dial подряд=''', "report.lastVpn")

# ------------------------------------------------------------------ __test
sub(BG, '''  noteTunnelDeath,
  deathsInWindow,''',
'''  noteTunnelDeath,
  deathsInWindow,
  // FIX(5.5.11)
  restoreSessionAfterReload,
  isStamp,''', "test.exports")

# ------------------------------------------------------------------ версия
s = rd(MAN); assert s.count('"version": "5.5.10"') == 1
wr(MAN, s.replace('"version": "5.5.10"', '"version": "5.5.11"', 1)); applied.append("manifest.version")

print("APPLIED:", len(applied))
for a in applied: print("  +", a)
if failed:
    print("FAILED:")
    for t, p, n in failed: print("  !", t, p, "matches=", n)
    sys.exit(1)
