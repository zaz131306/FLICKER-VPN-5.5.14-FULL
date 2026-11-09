// build-xpi.mjs — собрать xpi под конкретный ID/версию (для подписи в AMO).
//
//   node sign/build-xpi.mjs --id my-flicker@example.com --version 5.5.4.1 --out dist/my.xpi
//
// Зачем менять ID: подписать в AMO можно только тот ID, который принадлежит
// твоему аккаунту. ID flicker-vpn@local.dev — чужой. НО: native-хост пускает
// только ID из allowed_extensions своего манифеста, поэтому после смены ID
// надо править com.flicker.vpn.json (см. sign/native-host-manifest.json).

import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync, rmSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { execFileSync } from "node:child_process";

const args = Object.fromEntries(process.argv.slice(2).reduce((a, v, i, arr) => {
  if (v.startsWith("--")) a.push([v.slice(2), arr[i + 1]]);
  return a;
}, []));

const SRC = args.src || "ext";
const ID = args.id || null;
const VERSION = args.version || null;
const OUT = args.out || `dist/flicker-vpn-${VERSION || "custom"}${ID ? "-ownid" : ""}.xpi`;

// работаем во временной копии, чтобы не портить ext/
const TMP = ".build-tmp";
rmSync(TMP, { recursive: true, force: true });
execFileSync("cp", ["-r", SRC, TMP]);

const mfPath = join(TMP, "manifest.json");
const mf = JSON.parse(readFileSync(mfPath, "utf8"));
if (ID) mf.browser_specific_settings.gecko.id = ID;
if (VERSION) mf.version = VERSION;
writeFileSync(mfPath, JSON.stringify(mf, null, 2));   // без завершающего \n, как в оригинале

mkdirSync(dirname(OUT), { recursive: true });
rmSync(OUT, { force: true });

const files = [];
(function walk(d) {
  for (const e of readdirSync(d).sort()) {
    const p = join(d, e);
    if (statSync(p).isDirectory()) walk(p);
    else files.push(p);
  }
})(TMP);

execFileSync("python3", ["-c", `
import zipfile, sys
files = sys.argv[1:]
tmp = ${JSON.stringify(TMP)}
with zipfile.ZipFile(${JSON.stringify(OUT)}, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for p in files:
        import os; z.write(p, os.path.relpath(p, tmp).replace(os.sep, "/"))
`, ...files]);
rmSync(TMP, { recursive: true, force: true });

console.log(`собрал ${OUT}`);
console.log(`  id      : ${mf.browser_specific_settings.gecko.id}`);
console.log(`  version : ${mf.version}`);
console.log(`  файлов  : ${files.length}`);
if (ID && ID !== "flicker-vpn@local.dev") {
  console.log(`\n  ВНИМАНИЕ: добавь этот id в allowed_extensions манифеста native-хоста:`);
  console.log(`    %LOCALAPPDATA%\\flicker-vpn\\com.flicker.vpn.json`);
  console.log(`    готовый файл: sign/native-host-manifest.json (поправь id и путь к exe)`);
}
