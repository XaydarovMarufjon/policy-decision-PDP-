export const adminConsoleHtml = String.raw`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Policy Engine PDP</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #f6f7f9;
        --surface: #ffffff;
        --surface-2: #eef2f6;
        --text: #17202a;
        --muted: #64748b;
        --line: #d7dee8;
        --blue: #1d4ed8;
        --green: #0f766e;
        --red: #b42318;
        --amber: #9a5b00;
        --code: #101828;
      }

      * {
        box-sizing: border-box;
      }

      body {
        margin: 0;
        background: var(--bg);
        color: var(--text);
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        letter-spacing: 0;
      }

      button,
      textarea,
      input {
        font: inherit;
      }

      .shell {
        min-height: 100vh;
        display: grid;
        grid-template-rows: auto 1fr;
      }

      header {
        border-bottom: 1px solid var(--line);
        background: var(--surface);
      }

      .topbar {
        max-width: 1440px;
        margin: 0 auto;
        min-height: 64px;
        padding: 12px 20px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
      }

      .brand {
        display: flex;
        align-items: center;
        gap: 12px;
        min-width: 0;
      }

      .mark {
        width: 36px;
        height: 36px;
        border-radius: 8px;
        background: #17202a;
        color: #ffffff;
        display: grid;
        place-items: center;
        font-weight: 800;
      }

      h1 {
        margin: 0;
        font-size: 18px;
        line-height: 1.2;
      }

      .endpoint {
        color: var(--muted);
        font-size: 13px;
        white-space: nowrap;
      }

      .status-row {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
        justify-content: flex-end;
      }

      .chip {
        min-height: 28px;
        padding: 5px 9px;
        border-radius: 8px;
        border: 1px solid var(--line);
        background: var(--surface-2);
        color: var(--text);
        font-size: 12px;
        font-weight: 700;
      }

      .chip.ok {
        border-color: #99d6ca;
        background: #e7f7f3;
        color: var(--green);
      }

      .chip.fail {
        border-color: #f3b7b1;
        background: #fff0ee;
        color: var(--red);
      }

      main {
        max-width: 1440px;
        width: 100%;
        margin: 0 auto;
        padding: 18px 20px 24px;
      }

      .workspace {
        display: grid;
        grid-template-columns: minmax(360px, 0.9fr) minmax(420px, 1.1fr);
        gap: 16px;
        align-items: start;
      }

      .panel {
        background: var(--surface);
        border: 1px solid var(--line);
        border-radius: 8px;
        overflow: hidden;
      }

      .panel-head {
        min-height: 48px;
        padding: 12px 14px;
        border-bottom: 1px solid var(--line);
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
      }

      h2 {
        margin: 0;
        font-size: 14px;
        line-height: 1.2;
      }

      .actions {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
      }

      .button {
        min-height: 34px;
        border: 1px solid var(--line);
        border-radius: 6px;
        background: #ffffff;
        color: var(--text);
        padding: 7px 11px;
        cursor: pointer;
        font-weight: 700;
      }

      .button:hover {
        background: #f8fafc;
      }

      .button.primary {
        border-color: var(--blue);
        background: var(--blue);
        color: #ffffff;
      }

      .button.primary:hover {
        background: #1e40af;
      }

      .editor {
        width: 100%;
        min-height: 520px;
        resize: vertical;
        border: 0;
        outline: 0;
        padding: 14px;
        color: var(--code);
        background: #fbfcfe;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
        font-size: 13px;
        line-height: 1.55;
      }

      .result-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 10px;
        padding: 12px;
        border-bottom: 1px solid var(--line);
        background: #fbfcfe;
      }

      .reason-box {
        display: none;
        margin: 0;
        padding: 12px 14px;
        border-bottom: 1px solid var(--line);
        background: #fbfcfe;
      }

      .reason-box.visible {
        display: block;
      }

      .reason-title {
        color: var(--muted);
        font-size: 12px;
        font-weight: 800;
        margin-bottom: 7px;
      }

      .reason-text {
        border: 1px solid var(--line);
        border-radius: 8px;
        background: #ffffff;
        padding: 10px;
        color: var(--text);
        font-size: 13px;
        font-weight: 800;
        line-height: 1.45;
      }

      .reason-box.deny .reason-text,
      .reason-box.block .reason-text,
      .reason-box.error .reason-text {
        border-color: #f3b7b1;
        background: #fff0ee;
        color: var(--red);
      }

      .reason-box.allow .reason-text,
      .reason-box.permit .reason-text {
        border-color: #99d6ca;
        background: #e7f7f3;
        color: var(--green);
      }

      .metric {
        border: 1px solid var(--line);
        border-radius: 8px;
        background: var(--surface);
        padding: 10px;
        min-height: 72px;
      }

      .metric-label {
        color: var(--muted);
        font-size: 12px;
        margin-bottom: 8px;
      }

      .metric-value {
        font-size: 16px;
        font-weight: 800;
        overflow-wrap: anywhere;
      }

      .metric-value.allow,
      .metric-value.permit {
        color: var(--green);
      }

      .metric-value.deny,
      .metric-value.block {
        color: var(--red);
      }

      .tabs {
        display: flex;
        border-bottom: 1px solid var(--line);
        overflow-x: auto;
      }

      .tab {
        border: 0;
        border-right: 1px solid var(--line);
        border-radius: 0;
        background: #ffffff;
        min-height: 42px;
        padding: 10px 12px;
        font-weight: 800;
        cursor: pointer;
        color: var(--muted);
        white-space: nowrap;
      }

      .tab.active {
        color: var(--blue);
        background: #eef4ff;
      }

      pre {
        margin: 0;
        min-height: 430px;
        max-height: 650px;
        overflow: auto;
        padding: 14px;
        color: var(--code);
        background: #fbfcfe;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
        font-size: 13px;
        line-height: 1.55;
        white-space: pre-wrap;
        overflow-wrap: anywhere;
      }

      .route-flow {
        min-height: 430px;
        max-height: 650px;
        overflow: auto;
        padding: 16px;
        background: #fbfcfe;
      }

      .route-flow.empty {
        color: var(--muted);
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
        font-size: 13px;
      }

      .route-step {
        position: relative;
        display: grid;
        grid-template-columns: 42px minmax(0, 1fr);
        gap: 12px;
        opacity: 0;
        transform: translateY(8px);
        animation: routeIn 320ms ease forwards;
      }

      .route-step + .route-step {
        margin-top: 12px;
      }

      .route-rail {
        position: relative;
        display: flex;
        justify-content: center;
      }

      .route-step:not(:last-child) .route-rail::after {
        content: "";
        position: absolute;
        top: 42px;
        bottom: -18px;
        width: 2px;
        background: #c9d5e5;
      }

      .route-dot {
        position: relative;
        z-index: 1;
        width: 34px;
        height: 34px;
        border-radius: 999px;
        display: grid;
        place-items: center;
        background: #e7f7f3;
        border: 1px solid #99d6ca;
        color: var(--green);
        font-weight: 900;
        font-size: 13px;
      }

      .route-body {
        border: 1px solid var(--line);
        border-radius: 8px;
        background: var(--surface);
        overflow: hidden;
      }

      .route-main {
        padding: 12px;
      }

      .route-title-row {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 10px;
      }

      .route-title {
        margin: 0;
        font-size: 14px;
        line-height: 1.35;
      }

      .route-stage {
        flex: 0 0 auto;
        max-width: 48%;
        padding: 4px 7px;
        border-radius: 6px;
        background: #eef4ff;
        color: var(--blue);
        font-size: 11px;
        font-weight: 900;
        overflow-wrap: anywhere;
      }

      .route-description {
        margin: 8px 0 0;
        color: var(--muted);
        font-size: 13px;
        line-height: 1.45;
      }

      .route-payloads {
        border-top: 1px solid var(--line);
        background: #fbfcfe;
      }

      .route-payloads details {
        border-top: 1px solid var(--line);
      }

      .route-payloads details:first-child {
        border-top: 0;
      }

      .route-payloads summary {
        min-height: 36px;
        padding: 9px 12px;
        cursor: pointer;
        color: var(--text);
        font-weight: 800;
        font-size: 12px;
      }

      .route-payloads pre {
        min-height: 0;
        max-height: 280px;
        border-top: 1px solid var(--line);
        background: #ffffff;
      }

      .audit-panel {
        margin-top: 16px;
      }

      .audit-meta {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
      }

      .audit-list {
        min-height: 180px;
        max-height: 460px;
        overflow: auto;
        background: #fbfcfe;
      }

      .audit-empty {
        padding: 14px;
        color: var(--muted);
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
        font-size: 13px;
      }

      .audit-row {
        display: grid;
        grid-template-columns: 170px minmax(160px, 1fr) 120px 110px minmax(160px, 1fr);
        gap: 10px;
        align-items: center;
        padding: 11px 14px;
        border-top: 1px solid var(--line);
      }

      .audit-row:first-child {
        border-top: 0;
      }

      .audit-time,
      .audit-subtle {
        color: var(--muted);
        font-size: 12px;
      }

      .audit-strong {
        font-weight: 800;
        overflow-wrap: anywhere;
      }

      .audit-pill {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-height: 26px;
        width: fit-content;
        padding: 4px 8px;
        border-radius: 7px;
        font-size: 12px;
        font-weight: 900;
        background: var(--surface-2);
      }

      .audit-pill.allow,
      .audit-pill.permit {
        color: var(--green);
        background: #e7f7f3;
        border: 1px solid #99d6ca;
      }

      .audit-pill.deny,
      .audit-pill.block {
        color: var(--red);
        background: #fff0ee;
        border: 1px solid #f3b7b1;
      }

      .audit-reason {
        margin-top: 6px;
        width: fit-content;
        max-width: 100%;
        border-radius: 7px;
        padding: 5px 8px;
        background: #fff0ee;
        color: var(--red);
        font-size: 12px;
        font-weight: 800;
        overflow-wrap: anywhere;
      }

      .audit-details {
        grid-column: 1 / -1;
      }

      .audit-details summary {
        cursor: pointer;
        color: var(--blue);
        font-size: 12px;
        font-weight: 900;
      }

      .audit-details pre {
        min-height: 0;
        max-height: 260px;
        margin-top: 8px;
        border: 1px solid var(--line);
        border-radius: 8px;
        background: #ffffff;
      }

      @keyframes routeIn {
        to {
          opacity: 1;
          transform: translateY(0);
        }
      }

      @media (prefers-reduced-motion: reduce) {
        .route-step {
          animation: none;
          opacity: 1;
          transform: none;
        }
      }

      .empty {
        color: var(--muted);
      }

      .toast {
        margin-top: 10px;
        min-height: 32px;
        color: var(--red);
        font-size: 13px;
        font-weight: 700;
      }

      .toast.ok {
        color: var(--green);
      }

      .hidden {
        display: none;
      }

      @media (max-width: 980px) {
        .workspace {
          grid-template-columns: 1fr;
        }

        .editor {
          min-height: 360px;
        }

        .result-grid {
          grid-template-columns: 1fr;
        }

        .audit-row {
          grid-template-columns: 1fr;
        }
      }

      @media (max-width: 620px) {
        .topbar {
          align-items: flex-start;
          flex-direction: column;
        }

        .status-row {
          justify-content: flex-start;
        }

        main {
          padding: 12px;
        }

        .panel-head {
          align-items: flex-start;
          flex-direction: column;
        }

        .actions {
          width: 100%;
        }

        .button {
          flex: 1 1 auto;
        }
      }
    </style>
  </head>
  <body>
    <div class="shell">
      <header>
        <div class="topbar">
          <div class="brand">
            <div class="mark">PE</div>
            <div>
              <h1>Policy Engine PDP</h1>
              <div class="endpoint">POST /pdp/evaluate</div>
            </div>
          </div>
          <div class="status-row">
            <span id="pdpStatus" class="chip">PDP checking</span>
            <span id="opaStatus" class="chip">OPA checking</span>
          </div>
        </div>
      </header>

      <main>
        <div class="workspace">
          <section class="panel">
            <div class="panel-head">
              <h2>Request</h2>
              <div class="actions">
                <button class="button" data-sample="allowEvidence">Allow</button>
                <button class="button" data-sample="denyRisk">High Risk</button>
                <button class="button" data-sample="denyRole">Unknown Role</button>
                <button class="button" data-sample="canonical">Canonical</button>
                <button id="formatBtn" class="button">Format</button>
                <button id="sendBtn" class="button primary">Evaluate</button>
              </div>
            </div>
            <textarea id="requestEditor" class="editor" spellcheck="false"></textarea>
            <div id="message" class="toast"></div>
          </section>

          <section class="panel">
            <div class="panel-head">
              <h2>Decision</h2>
              <span id="latency" class="chip">Idle</span>
            </div>
            <div class="result-grid">
              <div class="metric">
                <div class="metric-label">Decision</div>
                <div id="decisionValue" class="metric-value">-</div>
              </div>
              <div class="metric">
                <div class="metric-label">Enforcement</div>
                <div id="enforcementValue" class="metric-value">-</div>
              </div>
              <div class="metric">
                <div class="metric-label">Risk Score</div>
                <div id="riskValue" class="metric-value">-</div>
              </div>
            </div>
            <div id="reasonBox" class="reason-box">
              <div class="reason-title">Reason</div>
              <div id="reasonText" class="reason-text">-</div>
            </div>
            <div class="tabs" role="tablist">
              <button class="tab active" data-view="route">Route</button>
              <button class="tab" data-view="full">Response</button>
              <button class="tab" data-view="context">Context Builder</button>
              <button class="tab" data-view="trace">Sources Trace</button>
              <button class="tab" data-view="pe">OPA / PE</button>
              <button class="tab" data-view="pa">PA</button>
            </div>
            <div id="routeViewer" class="route-flow empty">No decision yet.</div>
            <pre id="responseViewer" class="hidden"></pre>
          </section>
        </div>

        <section class="panel audit-panel">
          <div class="panel-head">
            <h2>PDP Audit Logs</h2>
            <div class="audit-meta">
              <span id="auditStatus" class="chip">Not loaded</span>
              <button id="auditRefreshBtn" class="button">Refresh</button>
            </div>
          </div>
          <div id="auditList" class="audit-list">
            <div class="audit-empty">No audit logs loaded.</div>
          </div>
        </section>
      </main>
    </div>

    <script>
      const samples = {
        allowEvidence: {
          request_id: "req-allow-001",
          request_metadata: {
            client: "admin-ui",
            correlation_id: "corr-allow-001",
            received_at: "2026-07-06T10:00:00.000Z"
          },
          subject_ref: {
            type: "mock_token",
            token: "mock-token-ali",
            session_id: "sess-ali-001",
            user_agent: "Mozilla/5.0 Chrome"
          },
          device_evidence: {
            device_id: "device-456",
            hostname: "soc-laptop-456",
            agent_id: "wazuh-agent-456",
            os: "Ubuntu",
            os_version: "24.04",
            browser: "Chrome 126",
            certificate_fingerprint: "sha256:allow-device-cert-fingerprint"
          },
          network: {
            source_ip: "10.10.80.55",
            source_port: 54822,
            protocol: "https",
            geo_country: "UZ",
            network_zone: "corp-vpn"
          },
          resource_ref: {
            resource_id: "incident_db",
            path: "/api/incidents/123",
            environment: "production",
            tenant_id: "soc",
            sensitivity_hint: "high"
          },
          risk_evidence: {
            source: "manual-test",
            siem_score: 20,
            threat_intel_match: false,
            impossible_travel: false,
            alert_ids: []
          },
          action: "read"
        },
        denyRisk: {
          request_id: "req-deny-risk-001",
          request_metadata: {
            client: "admin-ui",
            correlation_id: "corr-deny-risk-001",
            received_at: "2026-07-06T10:01:00.000Z"
          },
          subject_ref: {
            type: "mock_token",
            token: "mock-token-ali",
            session_id: "sess-ali-risk-001",
            user_agent: "Mozilla/5.0 Chrome"
          },
          device_evidence: {
            device_id: "device-456",
            hostname: "soc-laptop-456",
            agent_id: "wazuh-agent-456",
            os: "Ubuntu",
            os_version: "24.04",
            browser: "Chrome 126",
            certificate_fingerprint: "sha256:risk-device-cert-fingerprint"
          },
          network: {
            source_ip: "10.10.80.90",
            source_port: 61244,
            protocol: "https",
            geo_country: "UZ",
            network_zone: "unknown"
          },
          resource_ref: {
            resource_id: "incident_db",
            path: "/api/incidents/123",
            environment: "production",
            tenant_id: "soc",
            sensitivity_hint: "high"
          },
          risk_evidence: {
            source: "manual-test",
            siem_score: 90,
            threat_intel_match: false,
            impossible_travel: false,
            alert_ids: ["wazuh-alert-9001"],
            risk_reason: "Manual high-risk test"
          },
          action: "read"
        },
        denyRole: {
          request_id: "req-deny-role-001",
          request_metadata: {
            client: "admin-ui",
            correlation_id: "corr-deny-role-001",
            received_at: "2026-07-06T10:02:00.000Z"
          },
          subject_ref: {
            type: "mock_token",
            token: "mock-token-guest",
            session_id: "sess-guest-001",
            user_agent: "Mozilla/5.0 Chrome"
          },
          device_evidence: {
            device_id: "device-456",
            hostname: "shared-laptop-456",
            agent_id: "wazuh-agent-456",
            os: "Ubuntu",
            os_version: "24.04",
            browser: "Chrome 126",
            certificate_fingerprint: "sha256:guest-device-cert-fingerprint"
          },
          network: {
            source_ip: "10.10.80.55",
            source_port: 54823,
            protocol: "https",
            geo_country: "UZ",
            network_zone: "corp-vpn"
          },
          resource_ref: {
            resource_id: "incident_db",
            path: "/api/incidents/123",
            environment: "production",
            tenant_id: "soc",
            sensitivity_hint: "high"
          },
          risk_evidence: {
            source: "manual-test",
            siem_score: 20,
            threat_intel_match: false,
            impossible_travel: false,
            alert_ids: []
          },
          action: "read"
        },
        canonical: {
          request_id: "req-canonical-001",
          subject: {
            user: "ali.valiyev",
            role: "analyst",
            department: "SOC",
            mfa: true
          },
          device: {
            managed: true,
            edr_status: "healthy",
            patch_level: "ok",
            ip: "10.10.80.55"
          },
          risk: {
            siem_score: 20,
            threat_intel_match: false,
            impossible_travel: false
          },
          resource: {
            type: "database",
            name: "incident_db",
            criticality: "high"
          },
          action: "read"
        }
      };

      const editor = document.getElementById("requestEditor");
      const viewer = document.getElementById("responseViewer");
      const routeViewer = document.getElementById("routeViewer");
      const message = document.getElementById("message");
      const pdpStatus = document.getElementById("pdpStatus");
      const opaStatus = document.getElementById("opaStatus");
      const latency = document.getElementById("latency");
      const decisionValue = document.getElementById("decisionValue");
      const enforcementValue = document.getElementById("enforcementValue");
      const riskValue = document.getElementById("riskValue");
      const reasonBox = document.getElementById("reasonBox");
      const reasonText = document.getElementById("reasonText");
      const auditStatus = document.getElementById("auditStatus");
      const auditList = document.getElementById("auditList");
      let lastResponse = null;
      let activeView = "route";

      function pretty(value) {
        return JSON.stringify(value, null, 2);
      }

      function escapeHtml(value) {
        return String(value)
          .replaceAll("&", "&amp;")
          .replaceAll("<", "&lt;")
          .replaceAll(">", "&gt;")
          .replaceAll('"', "&quot;")
          .replaceAll("'", "&#039;");
      }

      function setSample(name) {
        editor.value = pretty(samples[name]);
        clearMessage();
      }

      function clearMessage() {
        message.textContent = "";
        message.className = "toast";
      }

      function setMessage(text, ok) {
        message.textContent = text;
        message.className = ok ? "toast ok" : "toast";
      }

      function setStatus(el, text, ok) {
        el.textContent = text;
        el.className = ok ? "chip ok" : "chip fail";
      }

      function setMetric(el, value, className) {
        el.textContent = value || "-";
        el.className = className ? "metric-value " + className : "metric-value";
      }

      function setReason(reason, state) {
        const reasons = Array.isArray(reason) ? reason : reason ? [reason] : [];
        if (reasons.length === 0) {
          reasonBox.className = "reason-box";
          reasonText.textContent = "-";
          return;
        }

        reasonBox.className = "reason-box visible " + (state || "");
        reasonText.textContent = reasons.join(" · ");
      }

      function renderView() {
        if (!lastResponse) {
          routeViewer.textContent = "No decision yet.";
          routeViewer.className = "route-flow empty";
          viewer.textContent = "";
          viewer.className = "hidden";
          return;
        }

        if (activeView === "route") {
          viewer.className = "hidden";
          routeViewer.className = "route-flow";
          renderRoute(lastResponse.route || []);
          return;
        }

        routeViewer.className = "route-flow hidden";
        viewer.className = "";
        if (activeView === "context") {
          viewer.textContent = pretty(lastResponse.context);
          return;
        }
        if (activeView === "trace") {
          viewer.textContent = pretty(lastResponse.context && lastResponse.context.trace ? lastResponse.context.trace : []);
          return;
        }
        if (activeView === "pe") {
          viewer.textContent = pretty(lastResponse.pe);
          return;
        }
        if (activeView === "pa") {
          viewer.textContent = pretty(lastResponse.pa);
          return;
        }
        viewer.textContent = pretty(lastResponse);
      }

      function renderRoute(route) {
        if (!Array.isArray(route) || route.length === 0) {
          routeViewer.textContent = "No route data.";
          routeViewer.className = "route-flow empty";
          return;
        }

        routeViewer.innerHTML = route
          .map(function (step, index) {
            const blocks = [
              routeBlock("Input", step.input),
              routeBlock("Process", step.process),
              routeBlock("Output", step.output)
            ].join("");

            return [
              '<article class="route-step" style="animation-delay: ' + index * 90 + 'ms">',
                '<div class="route-rail"><div class="route-dot">' + escapeHtml(step.order || index + 1) + '</div></div>',
                '<div class="route-body">',
                  '<div class="route-main">',
                    '<div class="route-title-row">',
                      '<h3 class="route-title">' + escapeHtml(step.title || step.stage || "Step") + '</h3>',
                      '<span class="route-stage">' + escapeHtml(step.stage || "stage") + '</span>',
                    '</div>',
                    '<p class="route-description">' + escapeHtml(step.description || "") + '</p>',
                  '</div>',
                  '<div class="route-payloads">' + blocks + '</div>',
                '</div>',
              '</article>'
            ].join("");
          })
          .join("");
      }

      function routeBlock(label, value) {
        if (typeof value === "undefined") {
          return "";
        }

        return [
          '<details>',
            '<summary>' + escapeHtml(label) + '</summary>',
            '<pre>' + escapeHtml(pretty(value)) + '</pre>',
          '</details>'
        ].join("");
      }

      function formatTime(value) {
        if (!value) {
          return "-";
        }

        const date = new Date(value);
        if (Number.isNaN(date.getTime())) {
          return value;
        }

        return date.toLocaleString();
      }

      async function loadAuditLogs() {
        auditStatus.textContent = "Loading";
        auditStatus.className = "chip";

        try {
          const response = await fetch("/pdp/audit?limit=20");
          const body = await response.json();

          if (!response.ok) {
            throw new Error(body.message || "Audit request failed");
          }

          renderAuditLogs(body.entries || []);
          auditStatus.textContent = String(body.count || 0) + " total";
          auditStatus.className = "chip ok";
        } catch (error) {
          auditList.innerHTML = '<div class="audit-empty">Audit logs unavailable.</div>';
          auditStatus.textContent = "Failed";
          auditStatus.className = "chip fail";
        }
      }

      function renderAuditLogs(entries) {
        if (!Array.isArray(entries) || entries.length === 0) {
          auditList.innerHTML = '<div class="audit-empty">No audit logs yet.</div>';
          return;
        }

        auditList.innerHTML = entries
          .map(function (entry) {
            const decision = entry.decision || "-";
            const command = entry.enforcement ? entry.enforcement.command : "-";
            const subject = entry.subject || {};
            const resource = entry.resource || {};
            const policy = entry.policy || {};
            const reasons = Array.isArray(entry.reason) ? entry.reason : [];
            const reasonHtml = decision === "deny" || command === "block"
              ? '<div class="audit-reason">' + escapeHtml(reasons.join(" · ") || "Blocked by policy") + '</div>'
              : "";

            return [
              '<article class="audit-row">',
                '<div>',
                  '<div class="audit-time">' + escapeHtml(formatTime(entry.evaluatedAt)) + '</div>',
                  '<div class="audit-subtle">' + escapeHtml(entry.requestId || entry.decisionId || "-") + '</div>',
                '</div>',
                '<div>',
                  '<div class="audit-strong">' + escapeHtml(subject.user || "-") + '</div>',
                  '<div class="audit-subtle">' + escapeHtml([subject.role, subject.department].filter(Boolean).join(" / ") || "-") + '</div>',
                '</div>',
                '<div><span class="audit-pill ' + escapeHtml(decision) + '">' + escapeHtml(decision) + '</span></div>',
                '<div><span class="audit-pill ' + escapeHtml(command) + '">' + escapeHtml(command) + '</span></div>',
                '<div>',
                  '<div class="audit-strong">' + escapeHtml(resource.name || "-") + '</div>',
                  '<div class="audit-subtle">' + escapeHtml((entry.action || "-") + " · " + (policy.matchedPolicyId || "-")) + '</div>',
                  reasonHtml,
                '</div>',
                '<details class="audit-details">',
                  '<summary>View event JSON</summary>',
                  '<pre>' + escapeHtml(pretty(entry)) + '</pre>',
                '</details>',
              '</article>'
            ].join("");
          })
          .join("");
      }

      async function loadHealth() {
        try {
          const response = await fetch("/pdp/health");
          const body = await response.json();
          setStatus(pdpStatus, "PDP ok", response.ok);
          setStatus(opaStatus, body.opaDecisionUrl ? "OPA configured" : "OPA missing", Boolean(body.opaDecisionUrl));
        } catch (error) {
          setStatus(pdpStatus, "PDP offline", false);
          setStatus(opaStatus, "OPA unknown", false);
        }
      }

      async function evaluateRequest() {
        clearMessage();
        let payload;
        try {
          payload = JSON.parse(editor.value);
        } catch (error) {
          setMessage("Invalid JSON", false);
          return;
        }

        const started = performance.now();
        latency.textContent = "Running";
        try {
          const response = await fetch("/pdp/evaluate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
          });
          const body = await response.json();
          const elapsed = Math.round(performance.now() - started);
          latency.textContent = String(elapsed) + " ms";

          if (!response.ok) {
            lastResponse = body;
            setMessage(body.message || "Request failed", false);
            setMetric(decisionValue, "error", "deny");
            setMetric(enforcementValue, "-", "");
            setMetric(riskValue, "-", "");
            setReason(body.message || "Request failed", "error");
            renderView();
            return;
          }

          lastResponse = body;
          setMetric(decisionValue, body.decision, body.decision);
          setMetric(enforcementValue, body.pa.enforcementCommand, body.pa.enforcementCommand);
          setMetric(riskValue, String(body.pe.riskScore), "");
          setReason(body.reason, body.decision === "deny" ? "deny" : "allow");
          setMessage("Decision received", true);
          renderView();
          loadAuditLogs();
        } catch (error) {
          latency.textContent = "Failed";
          setMessage("PDP request failed", false);
        }
      }

      document.querySelectorAll("[data-sample]").forEach(function (button) {
        button.addEventListener("click", function () {
          setSample(button.getAttribute("data-sample"));
        });
      });

      document.querySelectorAll("[data-view]").forEach(function (button) {
        button.addEventListener("click", function () {
          activeView = button.getAttribute("data-view");
          document.querySelectorAll("[data-view]").forEach(function (tab) {
            tab.classList.toggle("active", tab === button);
          });
          renderView();
        });
      });

      document.getElementById("formatBtn").addEventListener("click", function () {
        try {
          editor.value = pretty(JSON.parse(editor.value));
          setMessage("Formatted", true);
        } catch (error) {
          setMessage("Invalid JSON", false);
        }
      });

      document.getElementById("sendBtn").addEventListener("click", evaluateRequest);
      document.getElementById("auditRefreshBtn").addEventListener("click", loadAuditLogs);

      setSample("allowEvidence");
      loadHealth();
      loadAuditLogs();
    </script>
  </body>
</html>`;
