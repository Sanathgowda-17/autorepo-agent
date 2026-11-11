/**
 * app.js — AutoRepo IDE & GitHub Pull Request 4-Agent Workbench Controller
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

  document.getElementById("runDagBtn").addEventListener("click", async () => {
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
  const buttons = document.querySelectorAll(".gh-tab");
  const panes = document.querySelectorAll(".gh-pane");
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
      b.textContent = p.label || `PR #${p.pr_number}: ${p.file_path}`;
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
  document.getElementById("prTitleHeader").textContent = preset.pr_title;
  document.getElementById("prNumberHeader").textContent = `#${preset.pr_number || 142}`;
  document.getElementById("prAuthor").textContent = preset.author || "dev-checkout-team";
  document.getElementById("prBranch").textContent = (preset.branch || "feat/pr -> main").split(" ")[0];
  document.getElementById("activeFileTab").textContent = preset.file_path;
}

async function runReview() {
  const btn = document.getElementById("runDagBtn");
  btn.textContent = "⏳ Running 4-Agent CI...";
  btn.disabled = true;

  try {
    const prTitle = document.getElementById("prTitleInput").value;
    const filePath = document.getElementById("filePathInput").value;
    document.getElementById("prTitleHeader").textContent = prTitle;
    document.getElementById("activeFileTab").textContent = filePath;

    const payload = {
      pr_title: prTitle,
      file_path: filePath,
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
    btn.textContent = "▶ Re-Run 4-Agent CI Pipeline";
    btn.disabled = false;
  }
}

function renderReport(r) {
  // 1. Header Verdict Pill & Score
  const verdictPill = document.getElementById("verdictPill");
  if (r.verdict === "APPROVED_FOR_MERGE") {
    verdictPill.className = "gh-status-pill approved";
    verdictPill.textContent = "✅ APPROVED_FOR_MERGE";
  } else if (r.verdict === "CHANGES_REQUESTED") {
    verdictPill.className = "gh-status-pill warn";
    verdictPill.textContent = "⚠️ CHANGES_REQUESTED";
  } else {
    verdictPill.className = "gh-status-pill blocked";
    verdictPill.textContent = "⛔ BLOCKED_SECURITY_RISK";
  }

  document.getElementById("kpiScore").textContent = `${r.score} / 100`;
  document.getElementById("kpiSecurityCount").textContent = r.security_findings.length + r.arch_findings.length;
  document.getElementById("kpiBigO").textContent = r.ast_report.worst_time_complexity;
  document.getElementById("kpiCyclomatic").textContent = `M=${r.ast_report.avg_cyclomatic_complexity}`;
  document.getElementById("kpiTestsCount").textContent = r.test_cases_meta.length;
  document.getElementById("navTestCount").textContent = r.test_cases_meta.length;
  document.getElementById("kpiLatency").textContent = `${r.total_latency_ms} ms`;

  // 2. 4-Agent CI Check Runs (Left Sidebar)
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

  // 3. Inline Review Threads (Right Column)
  const findingsBox = document.getElementById("findingsContainer");
  const cards = [];

  r.security_findings.forEach((s) => {
    cards.push(`
      <div class="finding-card">
        <div class="finding-top">
          <span class="finding-title">🚨 [${escapeHtml(s.cwe)}] ${escapeHtml(s.title)}</span>
          <span class="badge badge-red">L${s.line} • ${escapeHtml(s.severity)}</span>
        </div>
        <div class="finding-desc">${escapeHtml(s.explanation)}</div>
        <div class="finding-fix">+ ${escapeHtml(s.remediation)}</div>
      </div>
    `);
  });

  r.arch_findings.forEach((a) => {
    cards.push(`
      <div class="finding-card warn">
        <div class="finding-top">
          <span class="finding-title">⚠️ [${escapeHtml(a.category)}] ${escapeHtml(a.rule)}</span>
          <span class="badge badge-amber">L${a.line} • ${escapeHtml(a.severity)}</span>
        </div>
        <div class="finding-desc">${escapeHtml(a.message)}</div>
        <div class="finding-fix">+ ${escapeHtml(a.remediation)}</div>
      </div>
    `);
  });

  document.getElementById("threadsTotalBadge").textContent = cards.length;

  if (cards.length === 0) {
    cards.push(`
      <div class="finding-card pass">
        <div class="finding-top">
          <span class="finding-title">✅ 0 Blocking Threads</span>
          <span class="badge badge-green">LGTM</span>
        </div>
        <div class="finding-desc">All AST complexity checks, type annotations, and OWASP CWE rules passed cleanly.</div>
      </div>
    `);
  }
  findingsBox.innerHTML = cards.join("");

  // 4. Numbered Side-by-Side Split Diff
  document.getElementById("originalCodePre").textContent = numberLines(r.original_code, "-");
  document.getElementById("refactoredCodePre").textContent = numberLines(r.refactored_code, "+");

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

function numberLines(code, prefixChar) {
  return String(code || "")
    .split("\n")
    .map((ln, i) => `${String(i + 1).padStart(2, " ")} ${prefixChar} │ ${ln}`)
    .join("\n");
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
          <span class="finding-title mono">PASSED ${escapeHtml(t.test_name)}</span>
          <span class="badge badge-green">${t.duration_ms} ms</span>
        </div>
        <div class="finding-desc">Target: <code>${escapeHtml(t.target_function)}</code> • Suite: ${escapeHtml(t.category)}</div>
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
