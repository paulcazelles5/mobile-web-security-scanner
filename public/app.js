const targetInput = document.querySelector("#target");
const scanButton = document.querySelector("#scan");
const statusEl = document.querySelector("#status");
const resultsEl = document.querySelector("#results");
let lastReport = null;

const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
}[ch]));

function renderReport(report) {
  lastReport = report;
  resultsEl.hidden = false;
  document.querySelector("#response-title").textContent = `${report.status} ${report.statusText}`;
  document.querySelector("#scan-meta").textContent = `${report.url} · ${new Date(report.scannedAt).toLocaleString()}`;
  document.querySelector("#total").textContent = report.summary.total;
  const order = ["critical", "high", "medium", "low", "info"];
  document.querySelector("#counts").innerHTML = order.map(s =>
    `<div class="count ${s}"><strong>${report.summary[s]}</strong><span>${s}</span></div>`
  ).join("");

  const container = document.querySelector("#findings");
  if (!report.findings.length) {
    container.innerHTML = '<div class="panel">No configured checks failed. This does not prove the site is secure.</div>';
  } else {
    container.innerHTML = report.findings.map(f => `
      <article class="finding">
        <div class="finding-top"><h3>${esc(f.title)}</h3><span class="severity ${esc(f.severity)}">${esc(f.severity)}</span></div>
        <p><b>Evidence:</b> ${esc(f.evidence)}</p>
        <p><b>Suggested fix:</b> ${esc(f.fix)}</p>
      </article>`).join("");
  }
  document.querySelector("#notes").innerHTML = report.notes.map(n => `<li>${esc(n)}</li>`).join("");
}

scanButton.addEventListener("click", async () => {
  const url = targetInput.value.trim();
  if (!url) {
    statusEl.textContent = "Enter a website URL first.";
    targetInput.focus();
    return;
  }
  scanButton.disabled = true;
  scanButton.textContent = "Scanning…";
  statusEl.textContent = "Connecting and checking response headers…";
  resultsEl.hidden = true;
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Scan failed.");
    renderReport(data);
    statusEl.textContent = "Scan complete.";
  } catch (error) {
    statusEl.textContent = error.message || "Scan failed. Check the URL and try again.";
  } finally {
    scanButton.disabled = false;
    scanButton.textContent = "Scan";
  }
});

targetInput.addEventListener("keydown", e => {
  if (e.key === "Enter") scanButton.click();
});

document.querySelector("#export").addEventListener("click", () => {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "security-scan-report.json";
  link.click();
  URL.revokeObjectURL(url);
});


const labButton = document.querySelector("#search-labs");
const labResults = document.querySelector("#lab-results");
const practiceLabs = [
  {
    name: "PortSwigger Web Security Academy",
    type: "Free guided labs",
    description: "Interactive lessons for common web vulnerabilities in a purpose-built training environment.",
    url: "https://portswigger.net/web-security"
  },
  {
    name: "OWASP Juice Shop",
    type: "Intentionally vulnerable app",
    description: "A deliberately insecure application designed for security training. Use its official hosted demo or your own local instance.",
    url: "https://owasp.org/www-project-juice-shop/"
  },
  {
    name: "HackerOne — Programs",
    type: "Authorized bug bounty scopes",
    description: "Choose a program and read its scope and rules before testing any asset.",
    url: "https://hackerone.com/opportunities"
  },
  {
    name: "Bugcrowd — Programs",
    type: "Authorized bug bounty scopes",
    description: "Browse programs and test only assets explicitly included in the program scope.",
    url: "https://bugcrowd.com/programs"
  }
];

labButton.addEventListener("click", () => {
  labResults.hidden = false;
  labResults.innerHTML = practiceLabs.map(lab => `
    <article class="lab-card">
      <div><h3>${esc(lab.name)}</h3><span class="lab-type">${esc(lab.type)}</span></div>
      <p>${esc(lab.description)}</p>
      <a href="${esc(lab.url)}" target="_blank" rel="noopener noreferrer">Open resource ↗</a>
    </article>
  `).join("");
  labButton.textContent = "Labs shown";
  labButton.disabled = true;
});
