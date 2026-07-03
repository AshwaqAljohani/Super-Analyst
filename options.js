const el = (id) => document.getElementById(id);

init();

async function init() {
  const s = await chrome.storage.sync.get(["vtApiKey", "abuseApiKey", "greyApiKey"]);
  if (s.vtApiKey) el("vtStatus").textContent = "Key is set.";
  if (s.abuseApiKey) el("abuseStatus").textContent = "Key is set.";
  if (s.greyApiKey) el("greyStatus").textContent = "Key is set.";

  el("saveVt").onclick = () => save("vtApiKey", "vtKey", "vtStatus");
  el("clearVt").onclick = () => clr("vtApiKey", "vtStatus", "vtKey");
  el("toggleVt").onclick = () => tog("vtKey");

  el("saveAbuse").onclick = () => save("abuseApiKey", "abuseKey", "abuseStatus");
  el("clearAbuse").onclick = () => clr("abuseApiKey", "abuseStatus", "abuseKey");
  el("toggleAbuse").onclick = () => tog("abuseKey");

  el("saveGrey").onclick = () => save("greyApiKey", "greyKey", "greyStatus");
  el("clearGrey").onclick = () => clr("greyApiKey", "greyStatus", "greyKey");
  el("toggleGrey").onclick = () => tog("greyKey");

  el("checkFile").onclick = checkFileOnVT;
  el("openResult").onclick = () => chrome.windows.create({ url: "result.html", type: "popup", width: 1050, height: 760 });
}

async function save(key, input, status) {
  const v = el(input).value.trim();
  if (!v) return (el(status).textContent = "ERROR: empty value.");
  await chrome.storage.sync.set({ [key]: v });
  el(status).textContent = "Saved.";
}

async function clr(key, status, input) {
  await chrome.storage.sync.remove(key);
  el(input).value = "";
  el(status).textContent = "Cleared.";
}

function tog(id) {
  el(id).type = el(id).type === "password" ? "text" : "password";
}

async function checkFileOnVT() {
  el("fileStatus").textContent = "";
  el("fileOut").textContent = "";

  const f = el("filePick").files && el("filePick").files[0];
  if (!f) {
    el("fileStatus").textContent = "ERROR: no file selected.";
    return;
  }

  try {
    el("fileStatus").textContent = "Reading file…";
    const buf = await f.arrayBuffer();

    el("fileStatus").textContent = "Hashing (SHA-256) + VT lookup…";
    const resp = await chrome.runtime.sendMessage({ action: "vt_lookup_file_bytes", arrayBuffer: buf });

    if (!resp || !resp.ok) throw new Error(resp?.error || "Unknown error");

    el("fileStatus").textContent = `OK. SHA-256: ${resp.sha256}`;
    el("fileOut").textContent = resp.output;

    await chrome.storage.local.set({
      lastResult: { kind: "vt-file", title: "VT File Lookup", input: f.name, output: resp.output, ts: new Date().toISOString() }
    });
  } catch (e) {
    el("fileStatus").textContent = `ERROR: ${e.message}`;
  }
}
