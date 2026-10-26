// Throwaway measurement, never merged. Prints which cache scopes this run's cache token grants, whether it can read
// an entry saved on main and the entries saved by other probe pull requests, and saves one entry of its own.
// It prints no token and no signed URL.
const crypto = require("crypto");

const token = process.env.ACTIONS_RUNTIME_TOKEN;
const base = (process.env.ACTIONS_RESULTS_URL || "").replace(/\/$/, "");
const pr = process.env.PR;
const service = `${base}/twirp/github.actions.results.api.v1.CacheService/`;

async function call(method, body) {
  const r = await fetch(service + method, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  let json = {};
  try { json = JSON.parse(text); } catch { json = { raw: text.slice(0, 200) }; }
  return { status: r.status, json };
}

const pick = (j, a, b) => j[a] ?? j[b];

async function restore(label, key, restoreKeys, version) {
  const { status, json } = await call("GetCacheEntryDownloadURL", { key, restoreKeys, version });
  const ok = Boolean(json.ok);
  const matched = pick(json, "matchedKey", "matched_key") || "";
  let fetched = "";
  const url = pick(json, "signedDownloadUrl", "signed_download_url");
  if (ok && url) {
    const r = await fetch(url, { headers: { Range: "bytes=0-63" } });
    const bytes = Buffer.from(await r.arrayBuffer());
    fetched = ` | download HTTP ${r.status}, ${bytes.length} bytes, sha256 of them ${crypto.createHash("sha256").update(bytes).digest("hex").slice(0, 16)}`;
  }
  console.log(`RESTORE ${label}: HTTP ${status}, ok=${ok}, matched=${JSON.stringify(matched)}${fetched}${ok ? "" : ` | ${JSON.stringify(json).slice(0, 200)}`}`);
}

async function save(key, version, content) {
  const created = await call("CreateCacheEntry", { key, version });
  const url = pick(created.json, "signedUploadUrl", "signed_upload_url");
  console.log(`SAVE create ${key}: HTTP ${created.status}, ok=${Boolean(created.json.ok)}${created.json.ok ? "" : ` | ${JSON.stringify(created.json).slice(0, 200)}`}`);
  if (!created.json.ok || !url) return;
  const body = Buffer.from(content);
  const put = await fetch(url, { method: "PUT", headers: { "x-ms-blob-type": "BlockBlob", "Content-Length": String(body.length) }, body });
  console.log(`SAVE upload: HTTP ${put.status}`);
  const fin = await call("FinalizeCacheEntryUpload", { key, version, sizeBytes: String(body.length) });
  console.log(`SAVE finalize: HTTP ${fin.status}, ${JSON.stringify(fin.json).slice(0, 200)}`);
}

(async () => {
  if (!token || !base) throw new Error("no ACTIONS_RUNTIME_TOKEN or ACTIONS_RESULTS_URL");
  const claims = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
  // Permission: 1 read, 2 write, 3 both.
  console.log(`SCOPES ${JSON.stringify(claims.ac)}`);
  console.log(`ACTIONS_CACHE_MODE=${process.env.ACTIONS_CACHE_MODE ?? "(unset)"}`);
  await restore("main entry, exact key", process.env.MAIN_KEY, [], process.env.MAIN_VERSION);
  await restore("main entry, by prefix codeql-overlay-base-database-", "no-such-key", ["codeql-overlay-base-database-"], process.env.MAIN_VERSION);
  const version = crypto.createHash("sha256").update("ossv-cache-probe").digest("hex");
  for (const other of (process.env.OTHER_PRS || "").split(/[ ,]+/).filter(Boolean)) {
    await restore(`entry of probe pull request ${other}`, `ossv-cache-probe/pr-${other}/conversation`, [], version);
    await restore(`entries of any probe pull request, by prefix`, "no-such-key", ["ossv-cache-probe/"], version);
  }
  await restore("this pull request's own entry", `ossv-cache-probe/pr-${pr}/conversation`, [], version);
  await save(`ossv-cache-probe/pr-${pr}/conversation`, version, `probe payload of pull request ${pr}, ${new Date().toISOString()}\n`);
})().catch((e) => { console.log(`::error::${e.message}`); process.exit(1); });
