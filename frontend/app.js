/**
 * app.js — AutoRepo Autonomous 4-Agent PR Reviewer & AST Analyzer UI Controller
 */

let currentReport = null;
let presetsCache = [];

document.addEventListener("DOMContentLoaded", async () => {
  initTabs();
  await loadPresets();
  await loadHistory();

  if (presetsCache.length > 0) {
    selectPreset(presetsCache[0]);
    await runReview();
  }

  document.getElementById("reviewForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    await runReview();
  });

  document.getElementById("runPytestBtn").addEventListener("click", async () => {
    await executePytestSuite();
  });

  document.getElementById("simWebhookBtn").addEventListener("click", async () => {
    await simulateGitHubWebhook();
  });
});

function initTabs() {
  const buttons = document.querySelectorAll(".nav-btn");
  const panes = document.querySelectorAll(".tab-pane");
  buttons.forEach((btn) => {
    btn.addEventListener("click", () => {
      buttons.forEach((b) => b.classList.remove("active"));
      panes.forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      const target = document.getElementById(btn.dataset.tab);
      if (target) target.classList.add("active");
    });
  });
}

async function loadPresets() {
  try {
    const res = await fetch("/api/presets");
    presetsCache = await res.json();
    const bar = document.getElementById("presetButtonsBar");
    bar.innerHTML = "";
    presetsCache.forEach((p) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "preset-btn";
      b.textContent = p.label;
      b.addEventListener("click", async () => {
        selectPreset(p);
        await runReview();
      });
      bar.appendChild(b);
    });
  } catch (err) {
    console.error("Failed loading presets:", err);
  }
}

function selectPreset(preset) {
  document.getElementById("prTitleInput").value = preset.pr_title;
  document.getElementById("filePathInput").value = preset.file_path;
  document.getElementById("codeInput").value = preset.code;
}

async function runReview() {
  const btn = document.getElementById("runDagBtn");
  btn.textContent = "⏳ Running 4-Agent DAG...";
  btn.disabled = true;

  try {
    const payload = {
      pr_title: document.getElementById("prTitleInput").value,
      file_path: document.getElementById("filePathInput").value,
      code: document.getElementById("codeInput").value
    };

    const res = await fetch("/api/review", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const report = await res.json();
    currentReport = report;
    renderReport(report);
    await loadHistory();
  } catch (err) {
    console.error("Review failed:", err);
  } finally {
    btn.textContent = "⚡ Execute 4-Agent PR Audit";
    btn.disabled = false;
  }
}

function renderReport(r) {
  // 1. KPIs
  const scoreEl = document.getElementById("kpiScore");
  scoreEl.textContent = `${r.score} / 100`;
  scoreEl.className = "kpi-val " + (r.score >= 80 ? "green" : r.score >= 55 ? "amber" : "red");

  document.getElementById("kpiVerdict").textContent = r.verdict;
  document.getElementById("kpiSecurityCount").textContent = r.security_findings.length;
  document.getElementById("kpiBigO").textContent = r.ast_report.worst_time_complexity;
  document.getElementById("kpiCyclomatic").textContent = `Avg McCabe M = ${r.ast_report.avg_cyclomatic_complexity}`;
  document.getElementById("kpiTestsCount").textContent = r.test_cases_meta.length;
  document.getElementById("navTestCount").textContent = r.test_cases_meta.length;
  document.getElementById("kpiLatency").textContent = `${r.total_latency_ms} ms`;

  // 2. 4-Agent DAG Cards
  const dagGrid = document.getElementById("dagPipelineGrid");
  dagGrid.innerHTML = r.dag_nodes.map((n, idx) => {
    let badgeClass = "badge-green";
    if (n.status.includes("ALERT") || n.status.includes("BLOCKED")) badgeClass = "badge-red";
    else if (n.status.includes("WARN") || n.status.includes("CHANGES")) badgeClass = "badge-amber";
    else if (n.status.includes("SYNTH")) badgeClass = "badge-blue";

    return `
      <div class="dag-node">
        <div class="dag-node-top">
          <span class="dag-node-name">${idx + 1}. ${escapeHtml(n.name)}</span>
          <span class="badge ${badgeClass}">${escapeHtml(n.status)}</span>
        </div>
        <div class="dag-node-role">${escapeHtml(n.role)}</div>
        <div class="dag-node-foot">
          <span>Signals: ${n.findings_count}</span>
          <span>${n.latency_ms} ms</span>
        </div>
      </div>
    `;
  }).join("");

  // 3. Findings List (Security + AST Smells)
  const findingsBox = document.getElementById("findingsContainer");
  const cards = [];

  r.security_findings.forEach((s) => {
    cards.push(`
      <div class="finding-card">
        <div class="finding-top">
          <span class="finding-title">🚨 [${escapeHtml(s.cwe)}] ${escapeHtml(s.title)}</span>
          <span class="badge badge-red">Line ${s.line} • ${escapeHtml(s.severity)}</span>
        </div>
        <div class="finding-desc">${escapeHtml(s.explanation)}</div>
        <div class="finding-fix">Fix: ${escapeHtml(s.remediation)}</div>
      </div>
    `);
  });

  r.arch_findings.forEach((a) => {
    cards.push(`
      <div class="finding-card warn">
        <div class="finding-top">
          <span class="finding-title">⚠️ [${escapeHtml(a.category)}] ${escapeHtml(a.rule)}</span>
          <span class="badge badge-amber">Line ${a.line} • ${escapeHtml(a.severity)}</span>
        </div>
        <div class="finding-desc">${escapeHtml(a.message)}</div>
        <div class="finding-fix">Fix: ${escapeHtml(a.remediation)}</div>
      </div>
    `);
  });

  if (cards.length === 0) {
    cards.push(`
      <div class="finding-card pass">
        <div class="finding-top">
          <span class="finding-title">✅ Zero Security or AST Anti-Patterns Detected</span>
          <span class="badge badge-green">CLEAN PR</span>
        </div>
        <div class="finding-desc">All functions satisfy McCabe complexity thresholds, type-safety contracts, and OWASP Top-10 security checks.</div>
      </div>
    `);
  }
  findingsBox.innerHTML = cards.join("");

  // 4. Side-by-Side Original vs. Refactored Patch
  document.getElementById("originalCodePre").textContent = r.original_code;
  document.getElementById("refactoredCodePre").textContent = r.refactored_code;

  // 5. AST Function Table (Tab 2)
  const astBody = document.getElementById("astFunctionsBody");
  const fns = r.ast_report.functions || [];
  if (fns.length === 0) {
    astBody.innerHTML = `<tr><td colspan="9">No Python function definitions parsed in snippet.</td></tr>`;
  } else {
    astBody.innerHTML = fns.map((f) => {
      const riskBadge = f.risk_level === "HIGH" ? "badge-red" : f.risk_level === "MODERATE" ? "badge-amber" : "badge-green";
      return `
        <tr>
          <td class="mono">${escapeHtml(f.name)}()</td>
          <td class="mono">L${f.lineno}–L${f.end_lineno}</td>
          <td class="mono">${escapeHtml((f.args || []).join(", ") || "—")}</td>
          <td class="mono"><strong>M = ${f.cyclomatic_complexity}</strong></td>
          <td class="mono">${f.max_loop_depth}</td>
          <td><span class="badge badge-blue">${escapeHtml(f.estimated_big_o)}</span></td>
          <td>${f.type_hint_coverage_pct}%</td>
          <td class="mono">${f.ast_node_count}</td>
          <td><span class="badge ${riskBadge}">${escapeHtml(f.risk_level)}</span></td>
        </tr>
      `;
    }).join("");
  }

  // 6. Synthesized Pytest Suite (Tab 3)
  document.getElementById("pytestCodePre").textContent = r.synthesized_pytest;
  executePytestSuite();
}

async function executePytestSuite() {
  if (!currentReport) return;
  try {
    const res = await fetch("/api/run-tests", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ test_cases_meta: currentReport.test_cases_meta || [] })
    });
    const data = await res.json();
    const box = document.getElementById("testResultsBox");
    box.innerHTML = (data.results || []).map((t) => `
      <div class="finding-card pass">
        <div class="finding-top">
          <span class="finding-title mono">✅ ${escapeHtml(t.test_name)}</span>
          <span class="badge badge-green">${t.duration_ms} ms • ${escapeHtml(t.status)}</span>
        </div>
        <div class="finding-desc">Target: <code>${escapeHtml(t.target_function)}</code> • Category: ${escapeHtml(t.category)}</div>
      </div>
    `).join("");
  } catch (err) {
    console.error("Test runner error:", err);
  }
}

async function loadHistory() {
  try {
    const res = await fetch("/api/history");
    const rows = await res.json();
    const tbody = document.getElementById("historyTableBody");
    tbody.innerHTML = rows.map((row) => {
      const badge = row.verdict === "APPROVED_FOR_MERGE" ? "badge-green" : row.verdict === "CHANGES_REQUESTED" ? "badge-amber" : "badge-red";
      return `
        <tr onclick="loadSingleReview('${row.review_id}')">
          <td class="mono">${escapeHtml(row.review_id)}</td>
          <td>${escapeHtml(row.pr_title)}</td>
          <td class="mono">${escapeHtml(row.file_path)}</td>
          <td class="mono"><strong>${row.score}/100</strong></td>
          <td><span class="badge ${badge}">${escapeHtml(row.verdict)}</span></td>
          <td class="mono">${row.security_count}</td>
          <td class="mono">${row.arch_count}</td>
          <td><span class="badge badge-blue">${escapeHtml(row.worst_big_o)}</span></td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.error("Failed loading history:", err);
  }
}

async function loadSingleReview(reviewId) {
  try {
    const res = await fetch(`/api/history/${reviewId}`);
    const rep = await res.json();
    currentReport = rep;
    document.getElementById("prTitleInput").value = rep.pr_title;
    document.getElementById("filePathInput").value = rep.file_path;
    document.getElementById("codeInput").value = rep.original_code;
    renderReport(rep);
    document.querySelector('[data-tab="tab-review"]').click();
  } catch (err) {
    console.error("Failed loading review:", err);
  }
}

async function simulateGitHubWebhook() {
  if (!presetsCache.length) return;
  const sample = presetsCache[1] || presetsCache[0];
  try {
    await fetch("/api/webhooks/github", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        pull_request: { title: "[Webhook] " + sample.pr_title },
        file_path: sample.file_path,
        code: sample.code
      })
    });
    await loadHistory();
  } catch (err) {
    console.error("Webhook simulation failed:", err);
  }
}

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
