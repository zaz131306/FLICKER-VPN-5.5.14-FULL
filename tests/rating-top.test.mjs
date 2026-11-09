// rating-top.test.mjs — FIX(5.5.13): топ рейтинга читаем и честен.
//
// Что показал пятый дамп пользователя (вкладка «Дополнительно» → «📈 Рейтинг
// нод», 1766 VPN-нод из подписки):
//
//   Всего VPN-нод: 1766 (+2 локальных транспортов — не VPN, в сводке не
//   учитываются)
//     доверенных (подключаются без прогрева): 1
//   Топ по рейтингу:
//      1. 0.675   vless   .𖥔 ݁ ˖ִ🛸༄˖°.    567 мс   — Мбит/с  ok 1/err 0
//      2. 0.65    direct  Диагностика (direct)  — мс  0 Мбит/с  ok 1/err 0  ← НЕ VPN
//      3. 0.084   vless   .𖥔 ݁ ˖ִ🛸༄˖°.    — мс     0 Мбит/с  ok 0/err 1
//      ... 4–9 — те же «.𖥔 ݁ ˖ִ🛸༄˖°.»
//
// Две беды:
//   • локальный транспорт «Диагностика (direct)» занимал 2-е место топа и
//     вытеснял реальную ноду из видимой десятки (подпись «← НЕ VPN» есть, а
//     место в рейтинге — тоже);
//   • ноды подписки называются одинаково, адреса в строке нет: отличить ноду от
//     ноды и сообщить, какая именно гадит, невозможно.
//
// Теперь: в топе только VPN-ноды, у каждой строки печатается host:port.
//
// Запуск: node --test tests/
//   BG_DIR=../flicker-5.5.12/ext node --test tests/rating-top.test.mjs → RED

import test from "node:test";
import assert from "node:assert/strict";
import { loadBackground, VLESS_SERVER, VLESS_SERVER_B } from "./bg-harness.mjs";

const DIAG = { id: "diag", name: "Диагностика (direct)", protocol: "direct", host: "127.0.0.1", port: 443 };
const DPI = { id: "dpi", name: "DPI-обход", protocol: "dpi", host: "127.0.0.1", port: 0 };
// как в подписке пользователя: имена неразличимы, отличаются только адреса
const EMOJI = ".𖥔 ݁ ˖ִ🛸༄˖°.";
const N1 = { ...VLESS_SERVER, id: "n1", name: EMOJI, host: "hw5.example.test", port: 443, ping: 120 };
const N2 = { ...VLESS_SERVER_B, id: "n2", name: EMOJI, host: "hw14.example.test", port: 2083, ping: 130 };
const N3 = { ...VLESS_SERVER, id: "n3", name: EMOJI, protocol: "vmess", host: "38.54.59.102", port: 443, ping: 140 };

test("топ рейтинга: локальных транспортов нет, адреса видны", async () => {
  const ctx = await loadBackground({ storage: { servers: [DIAG, DPI, N1, N2, N3] } });
  const { api, STATE } = ctx;
  try {
    // direct «идеален»: минимальный rtt, ноль ошибок — так он и выигрывал топ
    STATE.rating.pushSample(DIAG.id, { ok: true, rtt: 3, mbps: 0, tier: "free" });
    STATE.rating.markLatency(DIAG.id, 3);
    STATE.rating.pushSample(DPI.id, { ok: true, rtt: 5, mbps: 0, tier: "free" });
    STATE.rating.pushSample(N1.id, { ok: true, rtt: 120, mbps: 12, tier: "free" });
    STATE.rating.pushSample(N2.id, { ok: false, rtt: 130, mbps: 0, tier: "free" });
    STATE.rating.pushSample(N3.id, { ok: true, rtt: 140, mbps: 4, tier: "free" });

    const r = await api.fireRuntimeMessage({ action: "getRatingSummary", limit: 10 });
    assert.equal(r.ok, true, JSON.stringify(r).slice(0, 200));

    // getServers() добавляет ещё и встроенный «dpi-local», поэтому >= 2
    assert.ok(r.summary.nonVpn >= 2, "локальные транспорты посчитаны отдельно: " + r.summary.nonVpn);
    assert.equal(r.summary.total, 3, "в сводке только VPN-ноды");
    assert.ok(!(r.top || []).some((n) => n.nonVpn), "в топе нет не-VPN строк");
    assert.ok(!(r.top || []).some((n) => n.id === DIAG.id || n.id === DPI.id),
      "direct/dpi не занимают место в топе: " + JSON.stringify(r.top.map((n) => n.id)));

    const ids = (r.top || []).map((n) => n.id);
    assert.deepEqual(ids.slice().sort(), ["n1", "n2", "n3"], "все VPN-ноды в топе");

    for (const row of r.top) {
      assert.ok(row.host, `у строки ${row.id} есть адрес`);
      assert.ok(row.port != null, `у строки ${row.id} есть порт`);
      assert.equal(row.name, EMOJI, "имена нод одинаковые — как в подписке пользователя");
    }
    const addrs = new Set(r.top.map((n) => `${n.host}:${n.port}`));
    assert.equal(addrs.size, 3, "по адресу ноды различимы, хотя имена совпадают");
  } finally { await ctx.teardown(); }
});

test("топ рейтинга без VPN-истории: direct больше не «единственная доверенная нода»", async () => {
  const ctx = await loadBackground({ storage: { servers: [DIAG, N1, N2] } });
  const { api, STATE } = ctx;
  try {
    STATE.rating.pushSample(DIAG.id, { ok: true, rtt: 2, mbps: 0, tier: "free" });
    STATE.rating.markLatency(DIAG.id, 2);

    const r = await api.fireRuntimeMessage({ action: "getRatingSummary", limit: 10 });
    assert.equal(r.ok, true);
    assert.equal(r.summary.trusted, 0, "доверенных VPN-нод нет — сводка не врёт");
    assert.ok(!(r.top || []).some((n) => n.id === DIAG.id), "direct не в топе");
  } finally { await ctx.teardown(); }
});
