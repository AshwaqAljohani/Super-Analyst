// ================= CONFIG =================
const SOC_ANALYZE = "http://127.0.0.1:6969/generate";
const SOC_CASE = "http://127.0.0.1:6969/case";

const VT_BASE = "https://www.virustotal.com/api/v3";
const ABUSE = "https://api.abuseipdb.com/api/v2/check";
const GREY = "https://api.greynoise.io/v3/community/";

// ================= MENU =================
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "a", title: "Analyze Command (AI)", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "b", title: "IOC Threat Lookup (VT/Abuse/Grey)", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "c", title: "Decode Base64", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "d", title: "Generate SOC Case (Intel + AI)", contexts: ["selection"] });
});

chrome.action.onClicked.addListener(() => chrome.runtime.openOptionsPage());

// ================= CONTEXT MENU HANDLER =================
chrome.contextMenus.onClicked.addListener(async (info) => {
  const text = (info.selectionText || "").trim();
  if (!text) return;

  if (info.menuItemId === "a") return analyze(text);
  if (info.menuItemId === "b") return lookup(text);
  if (info.menuItemId === "c") return decodeBase64(text);
  if (info.menuItemId === "d") return socCase(text);
});

// ================= MESSAGE HANDLER (for file bytes from options page) =================
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (!msg || !msg.action) return;

      if (msg.action === "vt_lookup_auto") {
        const vtKey = await getSync("vtApiKey");
        if (!vtKey) throw new Error("VT API key missing (set it in Options).");
        const out = await vtReqSmart(msg.value, vtKey);
        sendResponse({ ok: true, output: out });
        return;
      }

      if (msg.action === "vt_lookup_file_bytes") {
        const vtKey = await getSync("vtApiKey");
        if (!vtKey) throw new Error("VT API key missing (set it in Options).");

        const arrayBuffer = msg.arrayBuffer;
        if (!(arrayBuffer instanceof ArrayBuffer)) throw new Error("Invalid file bytes.");

        const sha256 = await sha256Hex(arrayBuffer);
        const out = await vtReqByHash(sha256, vtKey, { fileSha256: sha256 });
        sendResponse({ ok: true, output: out, sha256 });
        return;
      }
    } catch (e) {
      sendResponse({ ok: false, error: String(e && e.message ? e.message : e) });
    }
  })();

  return true;
});

// ================= AI ANALYZE (FIXED: matches SuperAnalyst.py) =================
async function analyze(cmd) {
  try {
    // Server expects: { "command": "<string>" }  :contentReference[oaicite:1]{index=1}
    const body = { command: cmd };

    const r = await fetch(SOC_ANALYZE, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });

    // server returns JSON even on error: {"error":"Missing command"} :contentReference[oaicite:2]{index=2}
    const j = await r.json().catch(() => ({}));

    if (!r.ok) {
      const msg = j?.error || `HTTP ${r.status}`;
      show("ai", "Command Analysis (AI)", cmd, `ERROR – ${msg}`);
      return;
    }

    // Server returns: {"analysis": "..."} :contentReference[oaicite:3]{index=3}
    const out = j?.analysis || "No output.";
    show("ai", "Command Analysis (AI)", cmd, out);
  } catch (e) {
    show("ai", "Command Analysis (AI)", cmd, `ERROR – ${e?.message || e}`);
  }
}

// ================= SOC CASE (Intel + AI) =================
async function socCase(iocRaw) {
  const ioc = classifyIOC(iocRaw);

  const vtKey = await getSync("vtApiKey");
  const abKey = await getSync("abuseApiKey");
  const grKey = await getSync("greyApiKey");

  // 1) SAME INTEL LOOKUP LOGIC AS lookup()
  let vt = "N/A";
  let ab = "N/A";
  let gr = "N/A";

  try {
    if (!vtKey) vt = "ERROR: VT API key missing (set it in Options).";
    else vt = await vtReqSmart(ioc.value, vtKey);
  } catch (e) {
    vt = `ERROR: ${e.message}`;
  }

  if (ioc.type === "ip") {
    try { if (abKey) ab = await abReq(ioc.value, abKey); } catch (e) { ab = `ERROR: ${e.message}`; }
    try { if (grKey) gr = await grReq(ioc.value, grKey); } catch (e) { gr = `ERROR: ${e.message}`; }
  }

  const intelBlock =
`IOC: ${iocRaw}
Detected Type: ${ioc.type}

--- VirusTotal ---
${vt}

--- AbuseIPDB ---
${ab}

--- GreyNoise ---
${gr}`;

  // 2) AI CASE REPORT (backend)
  let caseText = "N/A";
  try {
    const r = await fetch(SOC_CASE, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ioc: ioc.value,
        ioc_type: ioc.type,
        vt: vt,
        abuse: ab,
        grey: gr
      })
    });
    const j = await r.json().catch(() => ({}));
    caseText = j?.case_report || "No output.";
  } catch {
    caseText = "ERROR – case backend offline (127.0.0.1:6969)";
  }

  const out =
`${intelBlock}

========================
SOC CASE REPORT (AI)
========================
${caseText}`;

  show("case", "SOC Case (Intel + AI)", iocRaw, out);
}

// ================= BASE64 DECODE =================
function decodeBase64(text) {
  const v = (text || "").trim().replace(/\s+/g, "");
  try {
    const norm = v.replace(/-/g, "+").replace(/_/g, "/");
    const padded = norm + "===".slice((norm.length + 3) % 4);
    const out = atob(padded);
    show("b64", "Base64 Decode", text, out);
  } catch {
    show("b64", "Base64 Decode", text, "ERROR – invalid Base64.");
  }
}

// ================= IOC LOOKUP (VT + optional ABUSE/GREY for IP only) =================
async function lookup(iocRaw) {
  const ioc = classifyIOC(iocRaw);

  const vtKey = await getSync("vtApiKey");
  const abKey = await getSync("abuseApiKey");
  const grKey = await getSync("greyApiKey");

  let vt = "N/A";
  let ab = "N/A";
  let gr = "N/A";

  try {
    if (!vtKey) vt = "ERROR: VT API key missing (set it in Options).";
    else vt = await vtReqSmart(ioc.value, vtKey);
  } catch (e) {
    vt = `ERROR: ${e.message}`;
  }

  if (ioc.type === "ip") {
    try { if (abKey) ab = await abReq(ioc.value, abKey); } catch (e) { ab = `ERROR: ${e.message}`; }
    try { if (grKey) gr = await grReq(ioc.value, grKey); } catch (e) { gr = `ERROR: ${e.message}`; }
  }

  const out =
`IOC: ${iocRaw}
Detected Type: ${ioc.type}

--- VirusTotal ---
${vt}

--- AbuseIPDB ---
${ab}

--- GreyNoise ---
${gr}`;

  show("intel", "Threat Intel Lookup", iocRaw, out);
}

// ================= IOC CLASSIFICATION (SHARED) =================
function classifyIOC(raw) {
  const v = String(raw || "").trim();

  if (isHexHash(v)) return { type: "hash", value: v };

  if (isIPv4(v) || isIPv6(v)) return { type: "ip", value: v };

  const url = normalizeUrl(v);
  if (url) return { type: "url", value: url, vt_url_id: vtUrlId(url) };

  if (isLikelyDomain(v)) return { type: "domain", value: v };

  return { type: "unknown", value: v };
}

// ================= VIRUSTOTAL SMART ROUTING =================
function isHexHash(s) {
  const v = (s || "").trim();
  return (
    (/^[a-fA-F0-9]{32}$/.test(v)) ||   // MD5
    (/^[a-fA-F0-9]{40}$/.test(v)) ||   // SHA1
    (/^[a-fA-F0-9]{64}$/.test(v))      // SHA256
  );
}

function isIPv4(s) {
  const v = (s || "").trim();
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return false;
  return v.split(".").every(o => {
    const n = Number(o);
    return Number.isInteger(n) && n >= 0 && n <= 255;
  });
}

// Routing-grade IPv6 check
function isIPv6(s) {
  const v = (s || "").trim();
  if (!v.includes(":")) return false;
  if (!/^[0-9a-fA-F:.]+$/.test(v)) return false;
  return v.length >= 2 && v.length <= 45;
}

function isLikelyDomain(s) {
  const v = (s || "").trim();
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(v)) return false;
  if (!/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}$/.test(v)) return false;
  if (v.startsWith(".") || v.endsWith(".") || v.includes("..")) return false;
  return true;
}

function normalizeUrl(input) {
  let v = (input || "").trim();
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(v) && v.includes("/")) v = "http://" + v;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(v)) return null;

  try { return new URL(v).toString(); } catch { return null; }
}

// VT URL ID: base64url(UTF8(url)) without "=" padding
function vtUrlId(url) {
  const bytes = new TextEncoder().encode(url);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function vtFetch(path, apiKey) {
  const r = await fetch(`${VT_BASE}${path}`, { headers: { "x-apikey": apiKey } });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) {
    const msg = d?.error?.message || d?.error?.code || `HTTP ${r.status}`;
    throw new Error(`VT error: ${msg}`);
  }
  return d;
}

function fmtStats(stats) {
  const s = stats || {};
  return [
    `harmless: ${s.harmless ?? 0}`,
    `undetected: ${s.undetected ?? 0}`,
    `suspicious: ${s.suspicious ?? 0}`,
    `malicious: ${s.malicious ?? 0}`,
    `timeout: ${s.timeout ?? 0}`
  ].join("\n");
}

async function vtReqSmart(input, apiKey) {
  const v = String(input || "").trim();

  if (isHexHash(v)) return await vtReqByHash(v, apiKey);

  if (isIPv4(v) || isIPv6(v)) {
    const d = await vtFetch(`/ip_addresses/${encodeURIComponent(v)}`, apiKey);
    const attrs = d?.data?.attributes || {};
    return [
      `type: ip`,
      `ip: ${v}`,
      `country: ${attrs.country || "N/A"}`,
      `asn: ${attrs.asn ?? "N/A"}`,
      `as_owner: ${attrs.as_owner || "N/A"}`,
      `last_analysis_stats:\n${fmtStats(attrs.last_analysis_stats)}`
    ].join("\n");
  }

  const url = normalizeUrl(v);
  if (url) {
    const id = vtUrlId(url);
    const d = await vtFetch(`/urls/${id}`, apiKey);
    const attrs = d?.data?.attributes || {};
    return [
      `type: url`,
      `url: ${url}`,
      `final_url: ${attrs.last_final_url || "N/A"}`,
      `title: ${attrs.title || "N/A"}`,
      `last_analysis_stats:\n${fmtStats(attrs.last_analysis_stats)}`
    ].join("\n");
  }

  if (isLikelyDomain(v)) {
    const d = await vtFetch(`/domains/${encodeURIComponent(v)}`, apiKey);
    const attrs = d?.data?.attributes || {};
    return [
      `type: domain`,
      `domain: ${v}`,
      `registrar: ${attrs.registrar || "N/A"}`,
      `creation_date: ${attrs.creation_date ? new Date(attrs.creation_date * 1000).toISOString() : "N/A"}`,
      `last_analysis_stats:\n${fmtStats(attrs.last_analysis_stats)}`
    ].join("\n");
  }

  throw new Error("Unsupported input: not a hash, IP, URL, or domain.");
}

async function vtReqByHash(hash, apiKey, extra = {}) {
  const v = String(hash || "").trim();
  const d = await vtFetch(`/files/${encodeURIComponent(v)}`, apiKey);
  const attrs = d?.data?.attributes || {};
  const maybeSha = extra.fileSha256 ? `sha256: ${extra.fileSha256}` : `hash: ${v}`;
  return [
    `type: file-hash`,
    maybeSha,
    `meaningful_name: ${attrs.meaningful_name || "N/A"}`,
    `last_analysis_stats:\n${fmtStats(attrs.last_analysis_stats)}`
  ].join("\n");
}

async function sha256Hex(arrayBuffer) {
  const hashBuf = await crypto.subtle.digest("SHA-256", arrayBuffer);
  const hashArr = Array.from(new Uint8Array(hashBuf));
  return hashArr.map(b => b.toString(16).padStart(2, "0")).join("");
}

// ================= ABUSEIPDB =================
async function abReq(ip, key) {
  const url = `${ABUSE}?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
  const r = await fetch(url, { headers: { Key: key, Accept: "application/json" } });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    const msg = j?.errors?.[0]?.detail || `HTTP ${r.status}`;
    throw new Error(`AbuseIPDB error: ${msg}`);
  }
  return [
    `abuseConfidenceScore: ${j?.data?.abuseConfidenceScore ?? "N/A"}`,
    `totalReports: ${j?.data?.totalReports ?? "N/A"}`,
    `countryCode: ${j?.data?.countryCode ?? "N/A"}`,
    `isp: ${j?.data?.isp ?? "N/A"}`
  ].join("\n");
}

// ================= GREYNOISE (community) =================
async function grReq(ip, key) {
  const r = await fetch(`${GREY}${encodeURIComponent(ip)}`, { headers: { key, Accept: "application/json" } });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    const msg = j?.message || `HTTP ${r.status}`;
    throw new Error(`GreyNoise error: ${msg}`);
  }
  return [
    `noise: ${j?.noise ?? "N/A"}`,
    `riot: ${j?.riot ?? "N/A"}`,
    `classification: ${j?.classification ?? "N/A"}`,
    `name: ${j?.name ?? "N/A"}`,
    `link: ${j?.link ?? "N/A"}`
  ].join("\n");
}

// ================= STORAGE / UI =================
async function getSync(k) {
  return (await chrome.storage.sync.get(k))[k];
}

async function show(kind, title, input, output) {
  await chrome.storage.local.set({
    lastResult: { kind, title, input, output, ts: new Date().toISOString() }
  });
  chrome.windows.create({ url: "result.html", type: "popup", width: 1050, height: 760 });
}
