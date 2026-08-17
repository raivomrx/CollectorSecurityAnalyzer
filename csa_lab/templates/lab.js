(() => {
  "use strict";
  const csrf = document.querySelector('meta[name="csa-csrf"]').content;
  const state = { assessments: [], currentId: "", current: null, interfaces: [], timer: null, cveTimer: null, cveRunning: false };
  const $ = (id) => document.getElementById(id);

  async function request(path, options = {}) {
    const settings = { cache: "no-store", ...options };
    settings.headers = { ...(settings.headers || {}) };
    if (settings.method && settings.method !== "GET") {
      settings.headers["X-CSA-Lab-CSRF"] = csrf;
    }
    if (settings.body && typeof settings.body === "object" && !(settings.body instanceof ArrayBuffer)) {
      settings.headers["Content-Type"] = "application/json";
      settings.body = JSON.stringify(settings.body);
    }
    const response = await fetch(path, settings);
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || data.error || "CSA Lab request failed");
    return data;
  }

  function showMessage(message, error = false) {
    const target = error ? $("error-banner") : $("success-banner");
    const other = error ? $("success-banner") : $("error-banner");
    other.classList.add("hidden");
    target.textContent = message;
    target.classList.remove("hidden");
    window.setTimeout(() => target.classList.add("hidden"), 8000);
  }

  async function loadAssessments() {
    const data = await request("/api/v1/assessments");
    state.assessments = data.assessments;
    renderAssessmentList();
  }

  function renderAssessmentList() {
    const root = $("recent-assessments");
    root.replaceChildren();
    if (!state.assessments.length) {
      const p = document.createElement("p");
      p.className = "muted";
      p.textContent = "No assessments yet.";
      root.append(p);
      return;
    }
    state.assessments.forEach((item) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `assessment-item${item.assessmentId === state.currentId ? " active" : ""}`;
      const name = document.createElement("strong");
      name.textContent = item.name;
      const status = document.createElement("span");
      status.textContent = `${item.status}  |  ${item.uniqueEndpoints} / ${item.expectedEndpoints} endpoints`;
      const date = document.createElement("span");
      date.textContent = item.createdAt;
      button.append(name, status, date);
      button.addEventListener("click", () => openAssessment(item.assessmentId));
      root.append(button);
    });
  }

  async function openAssessment(assessmentId) {
    if (state.currentId !== assessmentId && state.cveTimer) {
      window.clearTimeout(state.cveTimer);
      state.cveTimer = null;
    }
    state.currentId = assessmentId;
    state.current = await request(`/api/v1/assessments/${encodeURIComponent(assessmentId)}`);
    $("home-view").classList.add("hidden");
    $("assessment-view").classList.remove("hidden");
    renderAssessment();
    renderAssessmentList();
    syncCveProgress().catch(() => {});
  }

  function renderAssessment() {
    const payload = state.current;
    const assessment = payload.assessment;
    const status = assessment.status;
    const completeEndpoints = payload.endpoints.filter((item) => item.status === "COMPLETE");
    const processingEndpoints = payload.endpoints.filter((item) => item.status !== "COMPLETE");
    $("assessment-name").textContent = assessment.name;
    $("assessment-reference").textContent = assessment.organization || assessment.referenceNumber || "CSA assessment";
    $("assessment-status").textContent = status.replaceAll("_", " ");
    $("assessment-status").className = `status status-${status.toLowerCase()}`;
    $("endpoint-count").textContent = `${payload.endpoints.length} / ${assessment.expectedEndpoints}`;
    $("submission-count").textContent = String(payload.acceptedSubmissionCount);
    $("audit-status").textContent = payload.audit.auditVerificationStatus || "FAILED";
    $("report-status").textContent = assessment.reportPath ? "Generated" : "Not generated";
    $("listener-status").textContent = status === "COLLECTING"
      ? `Collection Server: Running | Listener: ${assessment.listenerAddress}:${assessment.listenerPort} | Firewall: scoped to ${assessment.sourceSubnet}`
      : "Collection server is stopped.";
    const portalVisible = status === "COLLECTING" && payload.portalUrl;
    $("portal-panel").classList.toggle("hidden", !portalVisible);
    $("portal-url").textContent = payload.portalUrl || "";
    $("start-collection").disabled = status !== "DRAFT";
    $("pause-collection").disabled = status !== "COLLECTING";
    $("resume-collection").disabled = !["PAUSED", "RECOVERY_REQUIRED"].includes(status);
    $("stop-collection").disabled = !["COLLECTING", "PAUSED", "RECOVERY_REQUIRED"].includes(status);
    const deletable = ["DRAFT", "CLOSED", "COMPLETED"].includes(status);
    $("delete-assessment").classList.toggle("hidden", !deletable);
    $("delete-assessment").textContent = status === "DRAFT"
      ? "Delete Draft"
      : "Delete Assessment";
    $("generate-report").disabled = !["READY_FOR_REPORT", "COMPLETED"].includes(status)
      || completeEndpoints.length === 0;
    $("run-cve-analysis").disabled = completeEndpoints.length === 0 || state.cveRunning;
    $("open-report").disabled = !assessment.reportPath;
    $("show-report").disabled = !assessment.reportPath;
    if (status === "COLLECTING") {
      $("report-preview").textContent = "Stop collection after endpoint analysis completes to enable the final report.";
    } else if (!completeEndpoints.length && processingEndpoints.length) {
      $("report-preview").textContent = "No completed endpoint analysis is available. Review endpoint processing status before generating a report.";
    } else if (completeEndpoints.length) {
      const cveStates = [...new Set(completeEndpoints.map((item) => item.cveAnalysisStatus))].join(", ");
      $("report-preview").textContent = `Endpoints included: ${completeEndpoints.length}. CVE analysis: ${cveStates}. Processing or failed submissions excluded: ${processingEndpoints.length}. Rejected submissions excluded: ${payload.rejectedSubmissionCount}. Coverage gaps present: ${completeEndpoints.some((item) => item.capabilityGaps.length) ? "Yes" : "No"}.`;
    } else {
      $("report-preview").textContent = "A report can be generated after at least one endpoint is analyzed.";
    }
    const recovery = status === "RECOVERY_REQUIRED";
    $("recovery-panel").classList.toggle("hidden", !recovery);
    $("recovery-details").textContent = (assessment.recoveryDetails || []).join(" ");
    renderEndpoints(payload.endpoints);
    renderAdvanced(payload);
  }

  function renderEndpoints(endpoints) {
    const body = $("endpoint-table");
    body.replaceChildren();
    const completed = endpoints.filter((item) => item.status === "COMPLETE").length;
    $("endpoint-summary").textContent = endpoints.length
      ? `${completed} completed analysis${completed === 1 ? "" : "es"}; ${endpoints.length - completed} processing or failed.`
      : "No analyzed endpoints received.";
    if (!endpoints.length) {
      const row = document.createElement("tr");
      const cell = document.createElement("td");
      cell.colSpan = 8;
      cell.textContent = "No endpoints received.";
      row.append(cell);
      body.append(row);
      return;
    }
    endpoints.forEach((item, index) => {
      const row = document.createElement("tr");
      row.dataset.index = String(index);
      const values = [
        item.deviceId,
        item.status,
        item.transport,
        item.coveragePercent === null ? "-" : `${item.coveragePercent}%`,
        item.findingCount === null ? "-" : String(item.findingCount),
        item.cveAnalysisStatus,
        `${item.executionMode} / ${item.integrityLevel}`,
        item.receivedAt,
      ];
      values.forEach((value) => {
        const cell = document.createElement("td");
        cell.textContent = value;
        row.append(cell);
      });
      row.addEventListener("click", () => showEndpoint(item));
      body.append(row);
    });
  }

  function showEndpoint(item) {
    const root = $("endpoint-detail");
    root.replaceChildren();
    const heading = document.createElement("h3");
    heading.textContent = `Endpoint ${item.deviceId}`;
    const list = document.createElement("dl");
    const values = {
      "Submission ID": item.submissionId,
      "Transport": item.transport,
      "Collector": item.collectorVersion,
      "Execution mode": item.executionMode,
      "Integrity level": item.integrityLevel,
      "Elevated": item.isElevated ? "YES" : "NO",
      "Local admin member": item.localAdministratorMember === null ? "UNKNOWN" : item.localAdministratorMember ? "YES" : "NO",
      "Coverage": `${item.coveragePercent}%`,
      "Receipt": item.receiptStatus,
      "Evidence digest": item.evidenceDigest,
      "Capability gaps": String(item.capabilityGaps.length),
      "CVE analysis": item.cveAnalysisStatus,
      "Unique CVEs": String(item.cveSummary?.uniqueCves ?? 0),
      "Confirmed CVEs": String(item.cveSummary?.confirmedUniqueCves ?? 0),
      "Possible CVEs": String(item.cveSummary?.possibleUniqueCves ?? 0),
      "Severity counts": Object.entries(item.severityCounts).map(([key, value]) => `${key}: ${value}`).join(", ") || "None",
    };
    Object.entries(values).forEach(([label, value]) => {
      const wrapper = document.createElement("div");
      const term = document.createElement("dt");
      const description = document.createElement("dd");
      term.textContent = label;
      description.textContent = value;
      wrapper.append(term, description);
      list.append(wrapper);
    });
    root.append(heading, list);
    const evaluations = item.cveSummary?.productEvaluations || [];
    appendCvePipeline(root, evaluations);
    root.classList.remove("hidden");
  }

  function appendCvePipeline(root, evaluations, endpoint = "") {
    if (!evaluations.length) return;
    const pipelineHeading = document.createElement("h4");
    pipelineHeading.textContent = endpoint
      ? `${endpoint} CVE product evaluation pipeline`
      : "CVE product evaluation pipeline";
    const wrapper = document.createElement("div");
    wrapper.className = "table-scroll";
    const table = document.createElement("table");
    const head = document.createElement("thead");
    const headerRow = document.createElement("tr");
    ["Product", "Installed version", "Normalization", "Mapping / CPE", "Provider", "Failure stage", "Failure reason", "Retryable", "Terminal state"].forEach((label) => {
      const cell = document.createElement("th");
      cell.textContent = label;
      headerRow.append(cell);
    });
    head.append(headerRow);
    const body = document.createElement("tbody");
    evaluations.forEach((evaluation) => {
      const row = document.createElement("tr");
      const values = [
        evaluation.displayName || "Unknown",
        evaluation.version || "Unknown",
        `${evaluation.normalizationStatus} (${evaluation.normalizationConfidence}%)`,
        `${evaluation.productMappingStatus}; ${evaluation.cpe || `${evaluation.cpeCandidateCount || 0} candidate(s)`}`,
        `${evaluation.provider || "NVD"}: ${evaluation.providerQueryStatus}`,
        evaluation.failureStage || "-",
        evaluation.failureReason || evaluation.reason || evaluation.providerReason || "-",
        evaluation.retryable ? "YES" : "NO",
        `${evaluation.terminalStatus || evaluation.cveResultStatus} (${evaluation.confirmedCves || 0} confirmed)`,
      ];
      values.forEach((value) => {
        const cell = document.createElement("td");
        cell.textContent = value;
        row.append(cell);
      });
      body.append(row);
    });
    table.append(head, body);
    wrapper.append(table);
    root.append(pipelineHeading, wrapper);
  }

  function renderAdvanced(payload) {
    const assessment = payload.assessment;
    const root = $("advanced-values");
    root.replaceChildren();
    const values = {
      "Assessment ID": assessment.assessmentId,
      "Session ID": assessment.sessionId,
      "Listener": `${assessment.listenerAddress}:${assessment.listenerPort}`,
      "Source subnet": assessment.sourceSubnet,
      "Network profile": assessment.networkProfile,
      "Session expiry": assessment.expiresAt,
      "Firewall rule": assessment.firewallRuleName,
      "Collector downloads": String(assessment.downloadCount),
      "Offline collection": assessment.offlineCollection ? "Enabled" : "Disabled",
    };
    Object.entries(values).forEach(([label, value]) => {
      const div = document.createElement("div");
      const dt = document.createElement("dt");
      const dd = document.createElement("dd");
      dt.textContent = label;
      dd.textContent = value;
      div.append(dt, dd);
      root.append(div);
    });
    const pipelineRoot = $("advanced-cve-pipeline");
    pipelineRoot.replaceChildren();
    payload.endpoints.forEach((endpoint) => {
      appendCvePipeline(
        pipelineRoot,
        endpoint.cveSummary?.productEvaluations || [],
        endpoint.deviceId,
      );
    });
  }

  async function loadInterfaces() {
    const data = await request("/api/v1/interfaces");
    state.interfaces = data.interfaces;
    const select = $("network-interface");
    select.replaceChildren();
    data.interfaces.forEach((item, index) => {
      const option = document.createElement("option");
      option.value = String(index);
      option.textContent = `${item.name} | ${item.address} | ${item.subnet} | ${item.profile}${item.recommended ? " | Recommended" : ""}`;
      select.append(option);
    });
    if (!data.interfaces.length) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "No suitable connected network found";
      select.append(option);
    }
    updateNetworkWarning();
  }

  function updateNetworkWarning() {
    const item = state.interfaces[Number($("network-interface").value)];
    const warning = $("network-warning");
    warning.textContent = item && item.warning ? item.warning : "";
    warning.classList.toggle("hidden", !item || !item.warning);
  }

  async function createAssessment(event) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const network = state.interfaces[Number(form.get("networkInterface"))];
    if (!network) return showMessage("Select a connected collection network.", true);
    const button = $("create-assessment");
    button.disabled = true;
    button.textContent = "Creating...";
    try {
      const data = await request("/api/v1/assessments", {
        method: "POST",
        body: {
          name: form.get("name"),
          expectedEndpoints: Number(form.get("expectedEndpoints")),
          organization: form.get("organization"),
          referenceNumber: form.get("referenceNumber"),
          description: form.get("description"),
          assessorNotes: form.get("assessorNotes"),
          listenerAddress: network.address,
          sourceSubnet: network.subnet,
          networkProfile: network.profile,
          interfaceId: network.interfaceId,
          listenerPort: Number(form.get("listenerPort")),
          sessionExpiryHours: Number(form.get("sessionExpiryHours")),
          allowedSubmissions: form.get("allowedSubmissions") || null,
          collectionProfile: form.get("collectionProfile"),
          offlineCollection: form.get("offlineCollection") === "on",
        },
      });
      $("wizard-dialog").close();
      formElement.reset();
      await loadAssessments();
      await openAssessment(data.assessment.assessmentId);
      showMessage("Assessment created. Collection remains closed until you start it.");
    } catch (error) {
      showMessage(error.message, true);
    } finally {
      button.disabled = false;
      button.textContent = "Create Assessment";
    }
  }

  async function action(name, confirmation = "") {
    if (!state.currentId) return;
    if (confirmation && !window.confirm(confirmation)) return;
    try {
      await request(`/api/v1/assessments/${encodeURIComponent(state.currentId)}/${name}`, { method: "POST" });
      await loadAssessments();
      await openAssessment(state.currentId);
      showMessage(`Assessment ${name.replaceAll("-", " ")} completed.`);
    } catch (error) {
      showMessage(error.message, true);
    }
  }

  async function runCveAnalysis() {
    if (!state.currentId) return;
    try {
      const data = await request(`/api/v1/assessments/${encodeURIComponent(state.currentId)}/cve-analysis`, {
        method: "POST",
      });
      renderCveProgress(data.progress);
      scheduleCveProgressPoll();
    } catch (error) {
      await openAssessment(state.currentId);
      showMessage(error.message, true);
    }
  }

  function renderCveProgress(progress) {
    const running = progress.state === "RUNNING";
    state.cveRunning = running;
    $("cve-progress").classList.toggle("hidden", progress.state === "IDLE");
    $("cve-progress-bar").value = Number(progress.percent || 0);
    $("cve-progress-message").textContent = progress.message || progress.phase.replaceAll("_", " ");
    const endpoint = progress.endpointTotal
      ? `Endpoint ${progress.endpointIndex || 0}/${progress.endpointTotal}`
      : "";
    const products = progress.productsTotal
      ? `Products ${progress.productsProcessed || 0}/${progress.productsTotal}`
      : "";
    const current = progress.currentProduct
      ? `${progress.currentProduct} ${progress.currentVersion || ""}`.trim()
      : "";
    const cves = progress.cvesTotal
      ? `CVEs ${progress.cvesProcessed || 0}/${progress.cvesTotal}`
      : "";
    const currentCve = progress.currentCve || "";
    $("cve-progress-details").textContent = [endpoint, products, current, cves, currentCve].filter(Boolean).join(" | ");
    const completed = state.current?.endpoints?.filter((item) => item.status === "COMPLETE").length || 0;
    $("run-cve-analysis").disabled = running || completed === 0;
  }

  async function syncCveProgress() {
    if (!state.currentId) return;
    const assessmentId = state.currentId;
    const data = await request(`/api/v1/assessments/${encodeURIComponent(assessmentId)}/cve-analysis-status`);
    if (assessmentId !== state.currentId) return;
    renderCveProgress(data.progress);
    if (data.progress.state === "RUNNING") scheduleCveProgressPoll();
  }

  function scheduleCveProgressPoll() {
    if (state.cveTimer) window.clearTimeout(state.cveTimer);
    state.cveTimer = window.setTimeout(pollCveProgress, 700);
  }

  async function pollCveProgress() {
    const assessmentId = state.currentId;
    if (!assessmentId) return;
    try {
      const data = await request(`/api/v1/assessments/${encodeURIComponent(assessmentId)}/cve-analysis-status`);
      if (assessmentId !== state.currentId) return;
      renderCveProgress(data.progress);
      if (data.progress.state === "RUNNING") {
        scheduleCveProgressPoll();
        return;
      }
      await loadAssessments();
      await openAssessment(assessmentId);
      const result = data.progress.result || data.progress.state;
      showMessage(
        result === "COMPLETE"
          ? "CVE analysis completed with full coverage."
          : `CVE analysis finished with status ${result}. Review product pipeline details before generating the report.`,
        data.progress.state === "FAILED",
      );
    } catch (error) {
      state.cveRunning = false;
      showMessage(error.message, true);
    }
  }

  async function generateReport(allowWithoutCve = false) {
    const incomplete = state.current?.endpoints?.some(
      (item) => item.status === "COMPLETE" && item.cveAnalysisStatus !== "COMPLETE",
    );
    if (incomplete && !allowWithoutCve) {
      $("cve-report-dialog").showModal();
      return;
    }
    try {
      const data = await request(`/api/v1/assessments/${encodeURIComponent(state.currentId)}/report`, {
        method: "POST",
        body: {
          includeTechnicalEvidence: $("include-evidence").checked,
          includeAudit: $("include-audit").checked,
          includeEndpointDetails: $("include-endpoints").checked,
          allowWithoutCve,
        },
      });
      await loadAssessments();
      await openAssessment(state.currentId);
      showMessage(`Report generated: ${data.reportName}`);
    } catch (error) {
      showMessage(error.message, true);
    }
  }

  async function deleteAssessment() {
    const status = state.current?.assessment?.status;
    if (!state.currentId || !["DRAFT", "CLOSED", "COMPLETED"].includes(status)) return;
    const confirmation = status === "DRAFT"
      ? "Permanently delete this empty draft assessment? This action cannot be undone."
      : "Permanently delete this assessment, its evidence, reports, and local audit history? A deletion receipt remains in the application audit. This action cannot be undone.";
    if (!window.confirm(confirmation)) return;
    try {
      await request(`/api/v1/assessments/${encodeURIComponent(state.currentId)}/delete`, { method: "POST" });
      state.currentId = "";
      state.current = null;
      await loadAssessments();
      $("assessment-view").classList.add("hidden");
      $("home-view").classList.remove("hidden");
      showMessage("Assessment deleted.");
    } catch (error) {
      showMessage(error.message, true);
    }
  }

  async function exportArchive() {
    const passphrase = window.prompt("Archive passphrase (minimum 12 characters):");
    if (passphrase === null) return;
    if (passphrase.length < 12) {
      showMessage("Archive passphrase must be at least 12 characters.", true);
      return;
    }
    const confirmation = window.prompt("Enter the archive passphrase again:");
    if (confirmation !== passphrase) {
      showMessage("Archive passphrases do not match.", true);
      return;
    }
    try {
      const data = await request(`/api/v1/assessments/${encodeURIComponent(state.currentId)}/export`, {
        method: "POST",
        body: { passphrase },
      });
      showMessage(`Encrypted assessment archive created: ${data.archiveName}`);
    } catch (error) {
      showMessage(error.message, true);
    }
  }

  async function importOffline(event) {
    const file = event.target.files[0];
    if (!file) return;
    try {
      const body = await file.arrayBuffer();
      await request(`/api/v1/assessments/${encodeURIComponent(state.currentId)}/offline`, {
        method: "POST",
        headers: { "Content-Type": "application/vnd.csa.offline+json" },
        body,
      });
      await openAssessment(state.currentId);
      showMessage("Encrypted offline package imported and analyzed.");
    } catch (error) {
      showMessage(error.message, true);
    } finally {
      event.target.value = "";
    }
  }

  function openWizard() {
    $("wizard-dialog").showModal();
    loadInterfaces().catch((error) => showMessage(error.message, true));
  }

  $("new-assessment").addEventListener("click", openWizard);
  $("home-new-assessment").addEventListener("click", openWizard);
  document.querySelectorAll(".close-dialog").forEach((button) => button.addEventListener("click", () => $("wizard-dialog").close()));
  $("network-interface").addEventListener("change", updateNetworkWarning);
  $("wizard-form").addEventListener("submit", createAssessment);
  $("start-collection").addEventListener("click", () => action("start"));
  $("pause-collection").addEventListener("click", () => action("pause"));
  $("resume-collection").addEventListener("click", () => action("resume"));
  $("stop-collection").addEventListener("click", () => action("stop", "Stop collection and invalidate unused session credentials? Received evidence will be retained."));
  $("delete-assessment").addEventListener("click", deleteAssessment);
  $("resume-recovery").addEventListener("click", () => action("resume"));
  $("cleanup-recovery").addEventListener("click", () => action("recovery-cleanup", "Close orphaned collection access and retain all evidence?"));
  $("refresh-assessment").addEventListener("click", () => openAssessment(state.currentId).catch((error) => showMessage(error.message, true)));
  $("copy-portal").addEventListener("click", async () => {
    await navigator.clipboard.writeText(state.current.portalUrl);
    showMessage("Collector page address copied.");
  });
  $("open-portal").addEventListener("click", () => window.open(state.current.portalUrl, "_blank", "noopener"));
  $("run-cve-analysis").addEventListener("click", runCveAnalysis);
  $("generate-report").addEventListener("click", () => generateReport());
  $("cancel-cve-report").addEventListener("click", () => $("cve-report-dialog").close());
  $("generate-without-cve").addEventListener("click", () => {
    $("cve-report-dialog").close();
    generateReport(true);
  });
  $("dialog-run-cve").addEventListener("click", () => {
    $("cve-report-dialog").close();
    runCveAnalysis();
  });
  $("open-report").addEventListener("click", () => window.open(`/reports/${encodeURIComponent(state.currentId)}`, "_blank", "noopener"));
  $("show-report").addEventListener("click", () => action("show-report"));
  $("export-archive").addEventListener("click", exportArchive);
  $("offline-file").addEventListener("change", importOffline);
  $("settings-button").addEventListener("click", () => $("settings-dialog").showModal());
  $("export-diagnostics").addEventListener("click", async () => {
    try {
      const data = await request("/api/v1/diagnostics", { method: "POST" });
      showMessage(`Sanitized diagnostic bundle created: ${data.bundleName}`);
    } catch (error) {
      showMessage(error.message, true);
    }
  });
  document.querySelectorAll(".settings-tab").forEach((button) => button.addEventListener("click", () => {
    document.querySelectorAll(".settings-tab").forEach((item) => item.classList.toggle("active", item === button));
    document.querySelectorAll("[data-panel]").forEach((panel) => panel.classList.toggle("hidden", panel.dataset.panel !== button.dataset.tab));
  }));
  $("exit-button").addEventListener("click", async () => {
    if (!window.confirm("Exit CSA Lab and close active collection access?")) return;
    await request("/api/v1/shutdown", { method: "POST" });
    document.body.textContent = "CSA Lab has closed. You may close this browser tab.";
  });

  window.setInterval(() => {
    request("/api/v1/heartbeat").catch(() => $("connection-state").textContent = "Console disconnected");
    if (state.currentId) openAssessment(state.currentId).catch(() => {});
  }, 5000);

  loadAssessments().catch((error) => showMessage(error.message, true));
})();
