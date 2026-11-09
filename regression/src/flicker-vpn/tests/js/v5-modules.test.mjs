// Тесты v5-модулей, которые пришли в 5.x без покрытия:
// split-tunnel (маршрутизация), rating (рейтинг нод), sources (реестр источников).
import test from "node:test";
import assert from "node:assert/strict";
import {
  createRuleset, MODES, DEFAULT_MODE, toPassthrough, toSingBoxRules,
  normalizeDomain, RU_DIRECT_DOMAINS
} from "../../lib/split-tunnel.js";
import {
  makeRatingStore, needsProbe, ratingSummary, rankCandidates,
  SCORE_TRUSTED, SCORE_COLD, fingerprintOf
} from "../../lib/rating.js";
import { DEFAULT_SOURCES, META_SOURCES, TIER_WEIGHT } from "../../lib/sources.js";

// ---------- split-tunnel ----------
test("split-tunnel: SMART — RU напрямую, заблокированное через VPN", () => {
  const rs = createRuleset({ mode: MODES.SMART });
  assert.equal(rs.mode, MODES.SMART);
  assert.equal(DEFAULT_MODE, MODES.SMART);
  assert.equal(rs.decide({ host: "gosuslugi.ru" }), "direct");
  assert.equal(rs.decide({ host: "www.mos.ru" }), "direct");
  assert.equal(rs.decide({ host: "youtube.com" }), "vpn");
  assert.equal(rs.decide({ host: "www.youtube.com" }), "vpn");
  assert.equal(rs.decide({ host: "example.de" }), "vpn", "SMART: всё нероссийское — VPN");
});

test("split-tunnel: домены из списка Amnesia (v5.5) идут напрямую", () => {
  const rs = createRuleset({ mode: MODES.SMART });
  for (const h of ["emias.info", "www.emias.ru", "invitro.ru", "www.invitro.ru",
                   "edumsko.ru", "egais.ru", "lemanapro.ru", "sibmama.ru", "nix.ru", "myfin.by"]) {
    assert.equal(rs.decide({ host: h }), "direct", h);
  }
  // bitwarden.com НАМЕРЕННО не добавлен: глобальный сервис, direct = утечка мимо VPN
  assert.ok(!RU_DIRECT_DOMAINS.includes("bitwarden.com"));
  assert.equal(rs.decide({ host: "bitwarden.com" }), "vpn");
});

test("split-tunnel: приватные IP и имена без точки — всегда direct", () => {
  const rs = createRuleset({ mode: MODES.ALL });
  assert.equal(rs.decide({ ip: "192.168.1.1" }), "direct");
  assert.equal(rs.decide({ ip: "10.0.0.5" }), "direct");
  assert.equal(rs.decide({ host: "router" }), "direct");
  assert.equal(rs.decide({ host: "youtube.com" }), "vpn", "ALL: остальное через VPN");
});

test("split-tunnel: пользовательские исключения + passthrough", () => {
  const rs = createRuleset({ mode: MODES.SMART, extraDirect: ["Example.COM"] });
  assert.equal(rs.decide({ host: "example.com" }), "direct");
  const pass = toPassthrough(rs, ["test.org"]);
  assert.ok(pass.value.includes("<local>"));
  assert.ok(pass.value.includes("localhost"));
  assert.ok(pass.value.includes("example.com"), "нормализация регистра");
  assert.ok(pass.value.includes("test.org"));
  assert.ok(pass.value.length <= 8200, "passthrough в пределах лимита Firefox");
});

test("split-tunnel: normalizeDomain и toSingBoxRules", () => {
  assert.equal(normalizeDomain("  WWW.Example.COM. "), "www.example.com");
  const rs = createRuleset({ mode: MODES.SMART });
  const rules = toSingBoxRules(rs);
  assert.ok(rules, "правила для хоста генерятся");
  assert.ok(JSON.stringify(rules).length > 10);
});

// ---------- rating ----------
test("rating: холодная нода требует пробы", () => {
  assert.equal(needsProbe(undefined), true);
  const store = makeRatingStore();
  const cold = store.get("n1");
  assert.equal(cold.score, SCORE_COLD);
  assert.equal(needsProbe(cold), true);
});

test("rating: успешные замеры поднимают score, доверенная нода не требует пробы", () => {
  const store = makeRatingStore();
  store.touch("n2", { fingerprint: "fp1", tier: "ru" });
  for (let i = 0; i < 6; i++) store.pushSample("n2", { ok: true, rtt: 80, mbps: 20, loss: 0 });
  const e = store.get("n2");
  assert.ok(e.score > SCORE_COLD, "score вырос: " + e.score);
  if (e.score >= SCORE_TRUSTED) assert.equal(needsProbe(e), false);
});

test("rating: смена fingerprint сбрасывает историю (ротация паролей)", () => {
  const store = makeRatingStore();
  store.touch("n3", { fingerprint: "a" });
  store.pushSample("n3", { ok: true, rtt: 50 });
  const before = store.get("n3");
  assert.ok(before.samples.length > 0 || before.okCount > 0);
  store.touch("n3", { fingerprint: "b" });
  const e = store.get("n3");
  assert.equal(e.samples.length, 0);
  assert.equal(e.okCount, 0);
  assert.equal(e.fingerprint, "b");
});

test("rating: fingerprintOf стабилен и чувствителен к учётке", () => {
  const s = { host: "h", port: 443, protocol: "trojan", auth: "pw" };
  assert.equal(fingerprintOf(s), fingerprintOf({ ...s }));
  assert.notEqual(fingerprintOf(s), fingerprintOf({ ...s, auth: "pw2" }));
});

test("rating: summary и rankCandidates не падают на пустоте", () => {
  const store = makeRatingStore();
  const sum = ratingSummary(store, []);
  assert.equal(sum.total, 0);
  assert.deepEqual(rankCandidates(store, []), []);
});

// ---------- sources ----------
test("sources: реестр v5.5 — мёртвые удалены, метаданные свежие", () => {
  const ids = DEFAULT_SOURCES.map((s) => s.id);
  assert.equal(new Set(ids).size, ids.length, "id уникальны");
  assert.ok(!ids.includes("ebrasha"), "мёртвый ebrasha (404) удалён");
  assert.ok(!ids.includes("jichang"), "мёртвый jichang удалён ещё в v5");
  assert.ok(ids.includes("sscollector"), "замена — SS-Collector");
  for (const s of DEFAULT_SOURCES) {
    assert.ok(/^https:\/\//.test(s.url), s.id + ": https URL");
    assert.equal(s.verifiedAt, "2026-10-30", s.id + ": проверен сегодня");
    assert.ok(Object.keys(TIER_WEIGHT).includes(s.tier), s.id + ": tier известен");
    assert.ok(Number.isFinite(s.links) && s.links >= 0, s.id + ": links");
  }
  assert.equal(META_SOURCES.length, 1);
  assert.equal(META_SOURCES[0].id, "meta-peasoft");
});
