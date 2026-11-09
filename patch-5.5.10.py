#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Патч 5.5.10 — по второму отчёту пользователя (расширение 5.5.8, хост 5.5.4).

Новое в логе, чего не было в первом дампе:

  A) «Рейтинг нод»: топ-1 — `direct` «Диагностика (direct)», score 0.736, 124 мс,
     ok 1/err 0. И «доверенных (подключаются без прогрева): 1» — это ОН ЖЕ.
     Узел, который не является VPN, выглядит как единственная надёжная нода:
     пинг до 127.0.0.1 всегда минимальный, ошибок нет (нечему рваться).

  B) liveness-петля:
        liveness: контрольный dial через туннель не удался: socks5: connect
        отклонён (код 0x1)
        dbg: soft liveness: tunnelAlive=false проигнорирован (SOCKS слушает)
     — и так 10:38:30, 10:39:45, 10:40:10, 10:41:01, 10:42:15, 10:45:10,
     10:46:43, 10:47:15. При этом «Передано: ↑0.00 MB ↓0.00 MB» — трафика не
     было НИ БАЙТА. То есть туннель мёртв по факту, но мягкий режим живости
     (FIX 5.5.4.3, чтобы не рвать рабочие туннели на медленных нодах) объявляет
     «всё хорошо», потому что SOCKS слушает. Пользователь видит CONNECTED и
     нулевой трафик.

  C) probe: готово — 27 живых из 600 за 6m20s; мёртвых 398, без истории 1335.
     Расширение гоняет переключения между мёртвыми нодами
     (hw14.roghanmo.com → 202.50.253.36 → обратно hw14).

Правки:
  G1 — сводка рейтинга считается только по VPN-нодам; локальные транспорты
       помечены в топе как «не VPN» и в сводку не входят.
  G2 — мягкий режим живости перестал быть слепым: N подряд отклонённых
       контрольных dial + НОЛЬ переданного трафика за всё время = нода мертва.
       Её помечают, с неё уходят (ротация), прокси при этом удерживается.
       Как только трафик пошёл или dial прошёл — счётчик обнуляется, прежнее
       мягкое поведение сохранено полностью.
  G3 — состояние soft-liveness видно в статусе и в отчёте об обрывах.
"""
import io, os, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
EXT = os.path.join(ROOT, "ext")
BG = os.path.join(EXT, "background.js")
OPT = os.path.join(EXT, "options.js")
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
sub(BG, '''  probeWarnAt: null,          // не спамим «хост занят пробой» (null = никогда)''',
'''  probeWarnAt: null,          // не спамим «хост занят пробой» (null = никогда)
  // FIX(5.5.10): учёт «SOCKS слушает, но контрольный dial отклонён».
  // В мягком режиме одиночное tunnelAlive=false — не приговор (у хоста 5.5.4
  // liveness-обход занимает до 30 c и на медленной бесплатной ноде не
  // укладывается в свой же таймаут). НО серия отказов при НУЛЕВОМ трафике —
  // это мёртвая нода, а не «медленная».
  softDeadStreak: 0,          // сколько diagnose подряд вернули tunnelAlive=false
  softDeadSince: null,        // с какого момента эта серия идёт
  softDeadActAt: null,        // когда последний раз выносили вердикт (кулдаун)''', "state.soft")

# ------------------------------------------------------------------ consts
sub(BG, '''const JOURNAL_MAX = 120;''',
'''const JOURNAL_MAX = 120;
// FIX(5.5.10): вердикт «нода мертва» в мягком режиме живости.
// Условие строгое, чтобы не повторить ошибку, из-за которой мягкий режим
// вообще ввели: рвать РАБОЧИЙ туннель из-за одного медленного dial нельзя.
//   3 отказа подряд + 45 секунд серии + НОЛЬ байт трафика за всё время +
//   статус connected  =>  трафик не ходит вовсе, значит туннеля нет.
const SOFT_DEAD_STREAK = 3;
const SOFT_DEAD_MIN_MS = 45_000;
const SOFT_DEAD_COOLDOWN_MS = 60_000;''', "consts.soft")

# ------------------------------------------------------------------ helpers
sub(BG, '''/** Хост сейчас занят пробой серверов: diagnose отвечает поздно, это не смерть. */
function probeRunning() {
  return !!(STATE.probe && STATE.probe.active);
}''',
'''/** Хост сейчас занят пробой серверов: diagnose отвечает поздно, это не смерть. */
function probeRunning() {
  return !!(STATE.probe && STATE.probe.active);
}

// ============ FIX(5.5.10): мягкий режим живости больше не слепой ============

/** Сброс серии отказов dial (dial прошёл или пошёл трафик). */
function softLivenessReset() {
  STATE.softDeadStreak = 0;
  STATE.softDeadSince = null;
}

/** Суммарный трафик текущей сессии, байт. */
function sessionBytes() {
  return (Number(STATE.bytesSent) || 0) + (Number(STATE.bytesReceived) || 0);
}

/**
 * softLivenessNote — зачесть очередной verdict `tunnelAlive=false` и решить,
 * не стала ли серия доказательством смерти ноды.
 *
 * @returns {{dead:boolean, streak:number, durMs:number, noTraffic:boolean}}
 */
function softLivenessNote() {
  const now = Date.now();
  if (!isStamp(STATE.softDeadSince)) STATE.softDeadSince = now;
  STATE.softDeadStreak = (STATE.softDeadStreak || 0) + 1;
  const durMs = now - STATE.softDeadSince;
  const noTraffic = sessionBytes() <= 0;
  const dead = STATE.softDeadStreak >= SOFT_DEAD_STREAK && durMs >= SOFT_DEAD_MIN_MS &&
    noTraffic && STATE.status === "connected";
  return { dead, streak: STATE.softDeadStreak, durMs, noTraffic };
}

/** Состояние soft-liveness для статуса/отчёта. */
function softLivenessState(now = Date.now()) {
  return {
    streak: STATE.softDeadStreak || 0,
    sinceMs: isStamp(STATE.softDeadSince) ? Math.max(0, now - STATE.softDeadSince) : 0,
    noTraffic: sessionBytes() <= 0,
    needStreak: SOFT_DEAD_STREAK,
    needMs: SOFT_DEAD_MIN_MS
  };
}''', "helpers.soft")

# ------------------------------------------------------------------ diagnose handler
sub(BG, '''      if (baseOk && d && d.tunnelAlive === false && !STATE.strictLiveness) {
        const now = Date.now();
        if (now - (STATE.lastSoftWarnAt || 0) > 60_000) {
          STATE.lastSoftWarnAt = now;
          console.warn("[flicker] хост: tunnelAlive=false, но SOCKS слушает — в мягком режиме продолжаю работать");
          dbgNative({ command: "dbg", text: "soft liveness: tunnelAlive=false проигнорирован (SOCKS слушает)" });
          broadcastUI({
            type: "livenessWarn",
            message: "Хост не прошёл свою контрольную проверку через туннель (tunnelAlive=false), " +
                     "но SOCKS слушает и трафик идёт — продолжаю работать. Строгий режим: настройки расширения."
          });
        }
      }
      handleVerifyResult(ok, d);''',
'''      // FIX(5.5.10): в логе пользователя эта ветка 8 минут подряд писала
      // «tunnelAlive=false проигнорирован (SOCKS слушает)» при «Передано ↑0.00
      // ↓0.00» и «socks5: connect отклонён (код 0x1)». То есть туннеля не было
      // вовсе, а расширение показывало CONNECTED. Одиночный отказ по-прежнему
      // игнорируем (медленная нода), но серию отказов при НУЛЕВОМ трафике
      // считаем смертью ноды и уходим с неё.
      let softDeadHandled = false;
      if (baseOk && d && d.tunnelAlive === false && !STATE.strictLiveness) {
        const v = softLivenessNote();
        const now = Date.now();
        const cooled = STATE.softDeadActAt == null || now - STATE.softDeadActAt > SOFT_DEAD_COOLDOWN_MS;
        if (v.dead && cooled) {
          STATE.softDeadActAt = now;
          const reason = `узел не пропускает трафик: контрольный dial через туннель отклонён ` +
                         `${v.streak} раз подряд за ${Math.round(v.durMs / 1000)} c, передано 0 байт`;
          console.warn("[flicker] soft liveness: " + reason);
          dbgNative({ command: "dbg", text: `soft liveness: DEAD ${reason}` });
          journal("soft-dead", reason);
          broadcastUI({
            type: "error",
            message: "⚠ " + reason + ". Считаю ноду мёртвой и ухожу с неё — прокси при этом удерживается на туннеле."
          });
          softLivenessReset();
          // две отметки обрыва (эта + внутри recoverFromDeadTunnel) дают
          // DEATHS_BEFORE_ROTATE, поэтому лестница сразу ротирует ноду,
          // а не пробует ту же самую снова
          const deadId = STATE.currentServer?.id || null;
          if (deadId) noteTunnelDeath(deadId, reason, transportFingerprint(STATE.currentServer));
          softDeadHandled = true;
          recoverFromDeadTunnel(reason).catch((e) => console.error("[flicker] soft-dead recover:", e));
        } else if (now - (STATE.lastSoftWarnAt || 0) > 60_000) {
          STATE.lastSoftWarnAt = now;
          console.warn("[flicker] хост: tunnelAlive=false, но SOCKS слушает — в мягком режиме продолжаю работать" +
                       (v.streak > 1 ? ` (подряд ${v.streak}, трафик ${v.noTraffic ? "нулевой" : "идёт"})` : ""));
          dbgNative({ command: "dbg", text: `soft liveness: tunnelAlive=false проигнорирован (SOCKS слушает, подряд ${v.streak}, трафик ${v.noTraffic ? "0" : "есть"})` });
          broadcastUI({
            type: "livenessWarn",
            message: v.noTraffic
              ? `Хост не проходит контрольную проверку через туннель (подряд ${v.streak}) и трафика пока НОЛЬ. ` +
                "Жду подтверждения; если так продолжится — сочту ноду мёртвой и сменю её. Строгий режим: настройки расширения."
              : "Хост не прошёл свою контрольную проверку через туннель (tunnelAlive=false), " +
                "но SOCKS слушает и трафик идёт — продолжаю работать. Строгий режим: настройки расширения."
          });
        }
      } else if (baseOk) {
        // dial прошёл — серия обнуляется, прежнее мягкое поведение сохранено
        softLivenessReset();
      }
      if (!softDeadHandled) handleVerifyResult(ok, d);''', "diag.softDead")

# ------------------------------------------------------------------ сброс серии при старте/смене ноды
sub(BG, '''  if (isLocalTransport(server)) warnDirectNode(server);
  journal("start", `${server?.id || "?"} ${composed.config.protocol} ${server?.host || ""}:${server?.port || ""}`);''',
'''  if (isLocalTransport(server)) warnDirectNode(server);
  softLivenessReset();   // FIX(5.5.10): новая нода — счётчик отказов dial с нуля
  journal("start", `${server?.id || "?"} ${composed.config.protocol} ${server?.host || ""}:${server?.port || ""}`);''',
      "start.softReset")

sub(BG, '''  STATE.currentProtocol = "dpi";
  STATE.status = "connecting";
  STATE.bytesSent = 0;
  STATE.bytesReceived = 0;''',
'''  STATE.currentProtocol = "dpi";
  STATE.status = "connecting";
  softLivenessReset();   // FIX(5.5.10): новый режим — учёт отказов dial с нуля
  STATE.bytesSent = 0;
  STATE.bytesReceived = 0;''', "dpi.softReset")

# ------------------------------------------------------------------ рейтинг: локальные транспорты не VPN
sub(BG, '''        case "getRatingSummary": {
          const servers = await getServers();
          const ranked = rankCandidates(STATE.rating, servers, { limit: Number(msg.limit) || 10, explore: 0 })''',
'''        case "getRatingSummary": {
          const servers = await getServers();
          // FIX(5.5.10): «Диагностика (direct)» всегда топ-1 по рейтингу — пинг до
          // 127.0.0.1 минимальный, ошибок нет (рваться нечему). В отчёте
          // пользователя именно она была единственной «доверенной» нодой, то есть
          // панель врала: доверенных VPN-нод не было вовсе. Сводку считаем только
          // по VPN-нодам, локальные транспорты помечаем отдельно.
          const vpnServers = servers.filter((s) => !isLocalTransport(s));
          const ranked = rankCandidates(STATE.rating, servers, { limit: Number(msg.limit) || 10, explore: 0 })''',
      "rating.filter")

sub(BG, '''                okCount: e.okCount, failCount: e.failCount, failStreak: e.failStreak,
                lastOkAt: e.lastOkAt
              };
            });
          sendResponse({ ok: true, summary: ratingSummary(STATE.rating, servers), top: ranked });''',
'''                okCount: e.okCount, failCount: e.failCount, failStreak: e.failStreak,
                lastOkAt: e.lastOkAt,
                nonVpn: isLocalTransport(r.server)   // FIX(5.5.10): direct/dpi — не VPN
              };
            });
          sendResponse({
            ok: true,
            summary: {
              ...ratingSummary(STATE.rating, vpnServers),
              nonVpn: servers.length - vpnServers.length,
              totalAll: servers.length
            },
            top: ranked
          });''', "rating.summary")

# ------------------------------------------------------------------ статус и отчёт
sub(BG, '''    probeActive: probeRunning(),''',
'''    probeActive: probeRunning(),
    softLiveness: softLivenessState(),   // FIX(5.5.10): серия отказов dial''',
      "status.soft")

sub(BG, '''            `проба серверов: active=${st.probeActive} total=${st.probeTotal} alive=${st.probe?.alive ?? "-"} pass=${st.probe?.pass ?? "-"}`,''',
'''            `проба серверов: active=${st.probeActive} total=${st.probeTotal} alive=${st.probe?.alive ?? "-"} pass=${st.probe?.pass ?? "-"}`,
            `soft liveness: отказов dial подряд=${st.softLiveness?.streak ?? 0} (нужно ${st.softLiveness?.needStreak ?? 3}), серия ${Math.round((st.softLiveness?.sinceMs ?? 0) / 1000)} c (нужно ${Math.round((st.softLiveness?.needMs ?? 45000) / 1000)} c), трафик ${(st.bytesSent || 0) + (st.bytesReceived || 0)} байт, strict=${STATE.strictLiveness ? "вкл" : "выкл"}`,''',
      "report.soft")

# ------------------------------------------------------------------ __test
sub(BG, '''  probeRunning,
  handleVerifyResult,''',
'''  probeRunning,
  handleVerifyResult,
  // FIX(5.5.10)
  softLivenessNote,
  softLivenessReset,
  softLivenessState,
  sessionBytes,
  noteTunnelDeath,''', "test.exports")

# ------------------------------------------------------------------ options.js: панель рейтинга
sub(OPT, '''  const sm = r.summary || {};
  const lines = [
    `Всего нод: ${sm.total ?? 0}`,
    `  доверенных (подключаются без прогрева): ${sm.trusted ?? 0}`,
    `  мёртвых:                                ${sm.dead ?? 0}`,
    `  без истории:                            ${sm.cold ?? 0}`,
    `  средняя скорость доверенных:            ${sm.avgMbps ?? 0} Мбит/с`
  ];''',
'''  const sm = r.summary || {};
  const lines = [
    // FIX(5.5.10): сводка — только по VPN-нодам. Локальные транспорты
    // (direct/dpi) раньше давали «доверенных: 1» ровно за счёт «Диагностики»,
    // которая VPN не является.
    `Всего VPN-нод: ${sm.total ?? 0}` + (sm.nonVpn ? ` (+${sm.nonVpn} локальных транспортов — не VPN, в сводке не учитываются)` : ""),
    `  доверенных (подключаются без прогрева): ${sm.trusted ?? 0}`,
    `  мёртвых:                                ${sm.dead ?? 0}`,
    `  без истории:                            ${sm.cold ?? 0}`,
    `  средняя скорость доверенных:            ${sm.avgMbps ?? 0} Мбит/с`
  ];
  if ((sm.trusted ?? 0) === 0 && (sm.total ?? 0) > 0) {
    lines.push("  ⚠ доверенных VPN-нод нет: подключение идёт через прогрев/пробу, а не мгновенно");
  }''', "opt.summary")

sub(OPT, '''        `${pad(n.rtt, 5)} мс  ${pad(n.mbps, 6)} Мбит/с  ok ${n.okCount ?? 0}/err ${n.failCount ?? 0}` +
        (n.failStreak ? `  (подряд ${n.failStreak})` : "")''',
'''        `${pad(n.rtt, 5)} мс  ${pad(n.mbps, 6)} Мбит/с  ok ${n.okCount ?? 0}/err ${n.failCount ?? 0}` +
        (n.failStreak ? `  (подряд ${n.failStreak})` : "") +
        // FIX(5.5.10): direct/dpi в топе помечены — это не VPN-нода
        (n.nonVpn ? "  ← НЕ VPN (локальный транспорт)" : "")''', "opt.topMark")

# ------------------------------------------------------------------ версия
s = rd(MAN); assert s.count('"version": "5.5.9"') == 1
wr(MAN, s.replace('"version": "5.5.9"', '"version": "5.5.10"', 1)); applied.append("manifest.version")

print("APPLIED:", len(applied))
for a in applied: print("  +", a)
if failed:
    print("FAILED:")
    for t, p, n in failed: print("  !", t, p, "matches=", n)
    sys.exit(1)
