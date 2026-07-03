(() => {
  const metaText = document.getElementById("metaText");
  const statusDot = document.getElementById("statusDot");
  const kindTag = document.getElementById("kindTag");
  const sevTag = document.getElementById("sevTag");

  const input = document.getElementById("inputBox");
  const outputBox = document.getElementById("outputBox");

  const copyInput = document.getElementById("copyInput");
  const copyOutput = document.getElementById("copyOutput");
  const closeBtn = document.getElementById("closeBtn");

  let rawOut = "";

  function esc(s){
    return String(s)
      .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
      .replace(/"/g,"&quot;").replace(/'/g,"&#39;");
  }

  function highlightTokens(text){
    let t = esc(text);

    // ERROR / OK keywords
    t = t.replace(/\bERROR\b/gi, `<span class="tok-err">ERROR</span>`);
    t = t.replace(/\bOK\b/gi, `<span class="tok-ok">OK</span>`);
    t = t.replace(/\bWARN(ING)?\b/gi, `<span class="tok-warn">$&</span>`);

    // SHA256/SHA1/MD5 (hex)
    t = t.replace(/\b[a-fA-F0-9]{64}\b/g, `<span class="tok-hash">$&</span>`);
    t = t.replace(/\b[a-fA-F0-9]{40}\b/g, `<span class="tok-hash">$&</span>`);
    t = t.replace(/\b[a-fA-F0-9]{32}\b/g, `<span class="tok-hash">$&</span>`);

    // IPv4
    t = t.replace(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g, `<span class="tok-ip">$&</span>`);

    // URLs (simple but effective)
    t = t.replace(/\bhttps?:\/\/[^\s<>"']+/g, `<span class="tok-url">$&</span>`);

    // Domains (after URLs so we don't double-style)
    t = t.replace(/\b(?!https?:\/\/)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b/g, `<span class="tok-dom">$&</span>`);

    // Key: value style
    t = t.replace(/^([A-Za-z_][A-Za-z0-9_ -]{0,40}):/gm, `<span class="tok-key">$1</span>:`);

    return t;
  }

  function parseVTSeverity(raw){
    // looks for:
    // last_analysis_stats:
    // harmless: X
    // undetected: X
    // suspicious: X
    // malicious: X
    const mal = raw.match(/^\s*malicious:\s*(\d+)/mi);
    const sus = raw.match(/^\s*suspicious:\s*(\d+)/mi);

    const m = mal ? Number(mal[1]) : 0;
    const s = sus ? Number(sus[1]) : 0;

    if (m >= 1) return { sev: "bad", label: `VT: malicious=${m}` };
    if (s >= 1) return { sev: "warn", label: `VT: suspicious=${s}` };
    // if VT stats exist and both zero -> good
    if (mal || sus) return { sev: "good", label: `VT: clean (0/0)` };
    return { sev: "good", label: "" };
  }

  function splitSections(raw){
    // Expected format coming from your service_worker:
    // IOC: ...
    // Detected Type: ...
    // --- VirusTotal ---
    // ...
    // --- AbuseIPDB ---
    // ...
    // --- GreyNoise ---
    // ...
    // ========================
    // SOC CASE REPORT (AI)
    // ========================
    // ...
    const sections = [];

    // optional SOC CASE split
    const caseMarker = "\n========================\nSOC CASE REPORT (AI)\n========================\n";
    let main = raw;
    let casePart = null;

    const idx = raw.indexOf(caseMarker);
    if (idx >= 0) {
      main = raw.slice(0, idx);
      casePart = raw.slice(idx + caseMarker.length);
    }

    // split intel blocks by tool headers
    const getBlock = (name) => {
      const re = new RegExp(`\\n---\\s*${name}\\s*---\\n`, "i");
      const parts = main.split(re);
      if (parts.length < 2) return null;
      // parts[0] = header info or previous blocks, parts[1] starts with this tool block (but may include following tools)
      return parts;
    };

    // Build header card from top part up to first tool header
    const firstTool = main.search(/\n---\s*(VirusTotal|AbuseIPDB|GreyNoise)\s*---\n/i);
    const header = (firstTool >= 0) ? main.slice(0, firstTool).trim() : main.trim();
    if (header) sections.push({ title: "Summary", badge: "Info", badgeClass: "cyan", body: header });

    // Extract each tool block by locating markers
    const tools = ["VirusTotal", "AbuseIPDB", "GreyNoise"];
    for (let i = 0; i < tools.length; i++) {
      const name = tools[i];
      const startRe = new RegExp(`\\n---\\s*${name}\\s*---\\n`, "i");
      const start = main.search(startRe);
      if (start < 0) continue;

      // find next tool marker after start
      let end = main.length;
      for (let j = i + 1; j < tools.length; j++) {
        const nextRe = new RegExp(`\\n---\\s*${tools[j]}\\s*---\\n`, "i");
        const next = main.slice(start + 1).search(nextRe);
        if (next >= 0) { end = start + 1 + next; break; }
      }

      // compute the slice body only
      const bodyStart = start + (main.match(startRe)[0]).length;
      const body = main.slice(bodyStart, end).trim();

      sections.push({
        title: name,
        badge: name === "VirusTotal" ? "VT" : (name === "AbuseIPDB" ? "ABUSE" : "GREY"),
        badgeClass: name === "VirusTotal" ? "violet" : (name === "AbuseIPDB" ? "cyan" : "cyan"),
        body
      });
    }

    if (casePart && casePart.trim()) {
      sections.push({ title: "SOC Case Report (AI)", badge: "AI", badgeClass: "violet", body: casePart.trim() });
    }

    return sections;
  }

  function renderSections(raw){
    const sections = splitSections(raw);

    // severity from VT block if present
    const vtBlock = sections.find(s => s.title.toLowerCase() === "virustotal");
    const sev = vtBlock ? parseVTSeverity(vtBlock.body) : { sev:"good", label:"" };

    // status dot
    statusDot.classList.remove("warn", "bad");
    if (sev.sev === "warn") statusDot.classList.add("warn");
    if (sev.sev === "bad") statusDot.classList.add("bad");

    sevTag.textContent = sev.label || "";
    const isError = /\bERROR\b/i.test(raw);
    if (isError) statusDot.classList.add("bad");

    const cards = document.createElement("div");
    cards.className = "cards";

    for (const s of sections) {
      const card = document.createElement("div");
      card.className = "card";

      const head = document.createElement("div");
      head.className = "cardHead";

      const title = document.createElement("div");
      title.className = "cardTitle";
      title.textContent = s.title;

      const badge = document.createElement("span");
      badge.className = `badge ${s.badgeClass || ""}`;
      badge.textContent = s.badge || "INFO";

      // Add severity badge specifically for VT
      if (s.title.toLowerCase() === "virustotal") {
        const sevB = document.createElement("span");
        sevB.className = `badge ${sev.sev}`;
        sevB.textContent = sev.sev === "bad" ? "HIGH" : (sev.sev === "warn" ? "MED" : "LOW");
        head.appendChild(sevB);
      }

      head.appendChild(title);
      head.appendChild(badge);

      const body = document.createElement("div");
      body.className = "cardBody";
      body.innerHTML = highlightTokens(s.body || "");

      card.appendChild(head);
      card.appendChild(body);
      cards.appendChild(card);
    }

    outputBox.innerHTML = "";
    outputBox.appendChild(cards);
  }

  async function main(){
    const { lastResult } = await chrome.storage.local.get("lastResult");
    const ts = lastResult?.ts || "";
    const title = lastResult?.title || "Output";

    metaText.textContent = `${title} • ${ts}`;
    kindTag.textContent = lastResult?.kind ? `kind: ${lastResult.kind}` : "";

    input.value = lastResult?.input || "";
    rawOut = lastResult?.output || "";

    renderSections(rawOut);

    copyInput.onclick = () => navigator.clipboard.writeText(input.value);
    copyOutput.onclick = () => navigator.clipboard.writeText(rawOut);
    closeBtn.onclick = () => window.close();
  }

  main();
})();
