// amneziawg.test.mjs — FIX(5.5.5): AmneziaWG (анти-DPI WireGuard).
//
// Зачем: «голый» WireGuard DPI определяет по handshake и рвёт — отсюда и
// бесконечные «обрыв туннеля». AmneziaWG (github.com/bivlked/amneziawg-installer
// ставит такой сервер одной командой) добавляет обфускацию: Jc/Jmin/Jmax
// (мусорные пакеты перед handshake), S1/S2 (подмена размера), H1..H4
// (подмена констант заголовка). Расширение теперь:
//   • понимает .conf-конфиги (wg-quick и AmneziaWG) — из подписки/вставкой;
//   • понимает AWG-параметры в wireguard://-ссылках;
//   • валидирует диапазоны (Jmin > Jmax = нерабочий конфиг);
//   • шлёт параметры хосту ТОЛЬКО если хост объявил caps «amnezia»,
//     иначе честно говорит, что обфускации не будет (тихий игнор = тот же обрыв).
//
// Запуск: node --test tests/
//         BG_DIR=../ext554 node --test tests/amneziawg.test.mjs → RED (AWG не поддержан)

import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { loadBackground } from "./bg-harness.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
// тот же способ разрешения, что в bg-harness: BG_DIR относительно cwd
const LIB = process.env.BG_DIR
  ? path.resolve(process.env.BG_DIR, "lib")
  : path.resolve(HERE, "..", "ext", "lib");

const SP = await import(pathToFileURL(path.join(LIB, "share-parser.js")).href);
const PR = await import(pathToFileURL(path.join(LIB, "protocol.js")).href);
const SUB = await import(pathToFileURL(path.join(LIB, "subscriptions.js")).href);

const AWG_CONF = `[Interface]
PrivateKey = aPxGQw8Vb6Kd2n0hF5mZx1cLq7rT9yUwE3vBnMoSdGk=
Address = 10.221.0.2/32
DNS = 1.1.1.1, 8.8.8.8
MTU = 1280
Jc = 5
Jmin = 10
Jmax = 100
S1 = 32
S2 = 17
H1 = 123456789
H2 = 987654321
H3 = 1122334455
H4 = 3456789012

[Peer]
PublicKey = PUBPUBPUBPUBPUBPUBPUBPUBPUBPUBPUBPUBPUB123=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.7:54321
PersistentKeepalive = 25
`;

const PLAIN_CONF = `[Interface]
PrivateKey = aPxGQw8Vb6Kd2n0hF5mZx1cLq7rT9yUwE3vBnMoSdGk=
Address = 10.221.0.2/32

[Peer]
PublicKey = PUBPUBPUBPUBPUBPUBPUBPUBPUBPUBPUBPUBPUB123=
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.9:51820
`;

const AWG_SERVER = {
  id: "awg-1", name: "AmneziaWG свой", host: "203.0.113.7", port: 54321, protocol: "wireguard",
  tlsEnabled: false, sub: true, ping: 70,
  wireguard: {
    privateKey: "aPxGQw8Vb6Kd2n0hF5mZx1cLq7rT9yUwE3vBnMoSdGk=",
    peerPublicKey: "PUBPUBPUBPUBPUBPUBPUBPUBPUBPUBPUBPUBPUB123=",
    address: ["10.221.0.2/32"], allowedIPs: ["0.0.0.0/0", "::/0"], mtu: 1280, keepalive: 25,
    amnezia: { jc: 5, jmin: 10, jmax: 100, s1: 32, s2: 17, h1: 123456789, h2: 987654321, h3: 1122334455, h4: 3456789012 }
  }
};

test("разбор AmneziaWG .conf: ключи, endpoint и все 9 параметров обфускации", () => {
  const r = SP.parseWireGuardConf(AWG_CONF, { source: "custom" });
  assert.equal(r.ok, true, r.error);
  assert.equal(r.amnezia, true, "конфиг распознан как AmneziaWG");
  const s = r.server;
  assert.equal(s.protocol, "wireguard");
  assert.equal(s.host, "203.0.113.7");
  assert.equal(s.port, 54321);
  assert.equal(s.wireguard.privateKey, "aPxGQw8Vb6Kd2n0hF5mZx1cLq7rT9yUwE3vBnMoSdGk=");
  assert.equal(s.wireguard.peerPublicKey, "PUBPUBPUBPUBPUBPUBPUBPUBPUBPUBPUBPUBPUB123=");
  assert.equal(s.wireguard.mtu, 1280);
  assert.equal(s.wireguard.keepalive, 25);
  assert.deepEqual(s.wireguard.allowedIPs, ["0.0.0.0/0", "::/0"]);
  assert.deepEqual(s.wireguard.address, ["10.221.0.2/32"]);
  assert.deepEqual(s.wireguard.amnezia, {
    jc: 5, jmin: 10, jmax: 100, s1: 32, s2: 17,
    h1: 123456789, h2: 987654321, h3: 1122334455, h4: 3456789012
  });
});

test("обычный WireGuard .conf разбирается, AWG-параметров не появляется", () => {
  const r = SP.parseWireGuardConf(PLAIN_CONF, { source: "custom" });
  assert.equal(r.ok, true, r.error);
  assert.equal(r.amnezia, false);
  assert.equal(r.server.wireguard.amnezia, undefined);
  assert.equal(r.server.host, "198.51.100.9");
  assert.equal(r.server.port, 51820);
  assert.deepEqual(r.server.wireguard.allowedIPs, ["0.0.0.0/0"]);
});

test("мусор вместо конфига не роняет разбор, а даёт понятную ошибку", () => {
  assert.equal(SP.parseWireGuardConf("").ok, false);
  assert.equal(SP.parseWireGuardConf("vless://x@y").ok, false);
  assert.equal(SP.parseWireGuardConf("[Interface]\nAddress = 10.0.0.1/32").error.includes("PrivateKey"), true);
  assert.equal(SP.parseWireGuardConf("[Interface]\nPrivateKey = AAA").error.includes("PublicKey"), true);
  assert.deepEqual(SP.splitWireGuardConfs("привет, это не конфиг"), []);
  assert.equal(SP.splitWireGuardConfs(AWG_CONF + "\n" + PLAIN_CONF).length, 2, "два блока = два сервера");
});

test("AWG-параметры в wireguard://-ссылке", () => {
  const link = "wireguard://aPxGQw8Vb6Kd2n0hF5mZx1cLq7rT9yUwE3vBnMoSdGk=@203.0.113.7:54321" +
    "?publickey=PUBPUBPUBPUBPUBPUBPUBPUBPUBPUBPUBPUBPUB123=&allowedips=0.0.0.0/0" +
    "&address=10.221.0.2/32&mtu=1280&jc=3&jmin=10&jmax=50&s1=17&s2=19&h1=1&h2=2&h3=3&h4=4#AWG-Moscow";
  const r = SP.parseWireGuardLink(link, { source: "custom" });
  assert.equal(r.ok, true, r.error);
  assert.equal(r.server.name, "AWG-Moscow");
  assert.deepEqual(r.server.wireguard.amnezia, { jc: 3, jmin: 10, jmax: 50, s1: 17, s2: 19, h1: 1, h2: 2, h3: 3, h4: 4 });
});

test("конфиги .conf доходят до списка серверов через разбор подписки", () => {
  const r = SUB.parseSubscription(AWG_CONF, "custom");
  assert.equal(r.servers.length, 1, JSON.stringify(r.failed));
  assert.equal(r.servers[0].protocol, "wireguard");
  assert.ok(r.servers[0].wireguard.amnezia, "AWG-параметры не потерялись");
  const two = SUB.parseSubscription(AWG_CONF + "\n" + PLAIN_CONF, "custom");
  assert.equal(two.servers.length, 2, "два конфига = два сервера");
});

test("normalizeAmnezia: любые имена полей (Jc/j_c/jc), дефолты, отсев не-AWG", () => {
  assert.deepEqual(PR.normalizeAmnezia({ J_c: "7", J_min: 5, J_max: 60, S1: 0, S2: 0, H1: 1, H2: 2, H3: 3, H4: 4 }),
    { jc: 7, jmin: 5, jmax: 60, s1: 0, s2: 0, h1: 1, h2: 2, h3: 3, h4: 4 });
  assert.equal(PR.normalizeAmnezia({}), null, "пустой объект — не AWG");
  assert.equal(PR.normalizeAmnezia({ mtu: 1280, keepalive: 25 }), null, "обычные WG-поля не делают ноду AWG");
  assert.equal(PR.normalizeAmnezia(null), null);
  // частично заданные параметры дополняются типовыми значениями сервера 3.x
  const part = PR.normalizeAmnezia({ jc: 4 });
  assert.equal(part.jc, 4);
  assert.equal(part.jmin, 10);
  assert.equal(part.jmax, 50);
  assert.deepEqual(PR.toSingBoxAmnezia({ jc: 5, jmin: 10, jmax: 100, s1: 32, s2: 17, h1: 1, h2: 2, h3: 3, h4: 4 }),
    { j_c: 5, j_min: 10, j_max: 100, s1: 32, s2: 17, h1: 1, h2: 2, h3: 3, h4: 4 });
});

test("валидация: Jmin > Jmax — ошибка, нулевые H1..H4 — предупреждение", () => {
  const bad = PR.buildServerConfig({
    ...AWG_SERVER,
    wireguard: { ...AWG_SERVER.wireguard, amnezia: { jc: 5, jmin: 500, jmax: 100, s1: 0, s2: 0, h1: 1, h2: 2, h3: 3, h4: 4 } }
  });
  const vBad = PR.validateServerConfig(bad);
  assert.equal(vBad.valid, false, "конфиг с Jmin>Jmax нерабочий и не должен уходить хосту");
  assert.ok(vBad.errors.some((e) => /Jmin/i.test(e)), JSON.stringify(vBad.errors));

  const zeroH = PR.buildServerConfig({
    ...AWG_SERVER,
    wireguard: { ...AWG_SERVER.wireguard, amnezia: { jc: 5, jmin: 10, jmax: 100, s1: 0, s2: 0, h1: 0, h2: 0, h3: 0, h4: 0 } }
  });
  const vZero = PR.validateServerConfig(zeroH);
  assert.equal(vZero.valid, true, "нули допустимы, но обфускация заголовков выключена");
  assert.ok(Array.isArray(vZero.warnings) && vZero.warnings.some((w) => /H1/i.test(w)), JSON.stringify(vZero.warnings));

  const ok = PR.validateServerConfig(PR.buildServerConfig(AWG_SERVER));
  assert.equal(ok.valid, true, JSON.stringify(ok.errors));
  assert.deepEqual(ok.warnings || [], [], "правильный AWG-конфиг без предупреждений");
});

test("значение AWG вне uint32 — ошибка валидации, а не тихий ноль", () => {
  const cfg = PR.buildServerConfig({
    ...AWG_SERVER,
    wireguard: { ...AWG_SERVER.wireguard, amnezia: { jc: 5, jmin: 10, jmax: 100, s1: 0, s2: 0, h1: 1, h2: 2, h3: 3, h4: 5544332211 } }
  });
  const v = PR.validateServerConfig(cfg);
  assert.equal(v.valid, false, "H4 > 2^32-1 недопустим");
  assert.ok(v.errors.some((e) => /h4/i.test(e) && /uint32/.test(e)), JSON.stringify(v.errors));
});

test("buildServerConfig приводит AWG-параметры к канону", () => {
  const cfg = PR.buildServerConfig({
    ...AWG_SERVER,
    wireguard: { ...AWG_SERVER.wireguard, amnezia: { J_c: "5", J_min: "10", J_max: "100" } }
  });
  assert.equal(cfg.protocol, "wireguard");
  assert.deepEqual(cfg.wireguard.amnezia, { jc: 5, jmin: 10, jmax: 100, s1: 0, s2: 0, h1: 0, h2: 0, h3: 0, h4: 0 });
});

// ---------------------------------------------------------------------------
// Честность capability-gate: sing-box не знает amnezia_wg, поэтому параметры
// уходят хосту только если он сам объявил поддержку. Иначе — явное
// предупреждение пользователю, а не видимость работающей обфускации.
// ---------------------------------------------------------------------------
test("хост без caps «amnezia»: параметры не шлём и честно предупреждаем", async () => {
  const ctx = await loadBackground({ storage: { servers: [AWG_SERVER] } });
  const { STATE, T, api } = ctx;
  try {
    STATE.nativeCaps = new Set(["ack", "autoPort", "liveness"]);
    const errs = [];
    const origWarn = console.warn; console.warn = (m) => { errs.push(String(m)); origWarn(m); };
    const r = T.composeConfig(AWG_SERVER);
    console.warn = origWarn;
    assert.equal(r.ok, true, r.error);
    assert.equal(r.config.wireguard.amnezia_wg, undefined, "хост не поймёт amnezia_wg — не шлём");
    assert.equal(r.config.wireguard.amnezia, undefined, "и «сырые» параметры не должны создавать иллюзию обфускации");
    assert.equal(STATE.awgUnsupported, true, "факт неподдерживаемости виден в диагностике");
    assert.equal(T.statusPayload().awgUnsupported, true);
    assert.ok(errs.some((e) => /AmneziaWG/i.test(e)), "пользователю объяснили, что обфускации не будет");
  } finally { await ctx.teardown(); }
});

test("хост с caps «amnezia»: параметры уходят в конфиге start", async () => {
  const ctx = await loadBackground({ storage: { servers: [AWG_SERVER] } });
  const { STATE, T } = ctx;
  try {
    STATE.nativeCaps = new Set(["ack", "autoPort", "liveness", "amnezia"]);
    const r = T.composeConfig(AWG_SERVER);
    assert.equal(r.ok, true, r.error);
    assert.deepEqual(r.config.wireguard.amnezia_wg, {
      j_c: 5, j_min: 10, j_max: 100, s1: 32, s2: 17,
      h1: 123456789, h2: 987654321, h3: 1122334455, h4: 3456789012
    });
    assert.equal(STATE.awgUnsupported, false);
  } finally { await ctx.teardown(); }
});

test("AWG-нода участвует в автовыборе, голый WireGuard — нет", async () => {
  const ctx = await loadBackground({ storage: { servers: [AWG_SERVER] } });
  const { T } = ctx;
  try {
    assert.equal(T.isAutoSelectable(AWG_SERVER), true);
    assert.equal(T.isAutoSelectable({ ...AWG_SERVER, wireguard: { privateKey: "x", peerPublicKey: "y" } }), false);
    const pick = T.pickBestAlive([AWG_SERVER]);
    assert.equal(pick?.id, "awg-1", "AWG-нода — валидный кандидат автовыбора");
  } finally { await ctx.teardown(); }
});
