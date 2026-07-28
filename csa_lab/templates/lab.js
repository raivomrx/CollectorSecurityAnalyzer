(() => {
  "use strict";
  const csrf = document.querySelector('meta[name="csa-csrf"]').content;
  const state = { assessments: [], currentId: "", current: null, interfaces: [], timer: null };
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
    state.currentId = assessmentId;
    state.current = await request(`/api/v1/assessments/${encodeURIComponent(assessmentId)}`);
    $("home-view").classList.add("hidden");
    $("assessment-view").classList.remove("hidden");
    renderAssessment();
    renderAssessmentList();
  }

  function renderAssessment() {
    const payload = state.current;
    const assessment = payload.assessment;
    const status = assessment.status;
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
    $("generate-report").disabled = payload.endpoints.length === 0;
    $("open-report").disabled = !assessment.reportPath;
    $("show-report").disabled = !assessment.reportPath;
    $("report-preview").textContent = payload.endpoints.length
      ? `Endpoints included: ${payload.endpoints.length}. Latest submissions selected: ${payload.endpoints.length}. Rejected submissions excluded: ${payload.rejectedSubmissionCount}. Coverage gaps present: ${payload.endpoints.some((item) => item.capabilityGaps.length) ? "Yes" : "No"}.`
      : "A report can be generated after at least one endpoint is analyzed.";
    const recovery = status === "RECOVERY_REQUIRED";
    $("recovery-panel").classList.toggle("hidden", !recovery);
    $("recovery-details").textContent = (assessment.recoveryDetails || []).join(" ");
    renderEndpoints(payload.endpoints);
    renderAdvanced(assessment);
  }

  function renderEndpoints(endpoints) {
    const body = $("endpoint-table");
    body.replaceChildren();
    $("endpoint-summary").textContent = endpoints.length
      ? `${endpoints.length} unique analyzed endpoint${endpoints.length === 1 ? "" : "s"}.`
      : "No analyzed endpoints received.";
    if (!endpoints.length) {
      const row = document.createElement("tr");
      const cell = document.createElement("td");
      cell.colSpan = 7;
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
    root.classList.remove("hidden");
  }

  function renderAdvanced(assessment) {
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
    const form = new FormData(event.currentTarget);
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
      event.currentTarget.reset();
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

  async function generateReport() {
    try {
      const data = await request(`/api/v1/assessments/${encodeURIComponent(state.currentId)}/report`, {
        method: "POST",
        body: {
          includeTechnicalEvidence: $("include-evidence").checked,
          includeAudit: $("include-audit").checked,
          includeEndpointDetails: $("include-endpoints").checked,
        },
      });
      await loadAssessments();
      await openAssessment(state.currentId);
      showMessage(`Report generated: ${data.reportName}`);
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
  $("resume-recovery").addEventListener("click", () => action("resume"));
  $("cleanup-recovery").addEventListener("click", () => action("recovery-cleanup", "Close orphaned collection access and retain all evidence?"));
  $("refresh-assessment").addEventListener("click", () => openAssessment(state.currentId).catch((error) => showMessage(error.message, true)));
  $("copy-portal").addEventListener("click", async () => {
    await navigator.clipboard.writeText(state.current.portalUrl);
    showMessage("Collector page address copied.");
  });
  $("open-portal").addEventListener("click", () => window.open(state.current.portalUrl, "_blank", "noopener"));
  $("generate-report").addEventListener("click", generateReport);
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
