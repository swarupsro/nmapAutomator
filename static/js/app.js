(() => {
  const form = document.getElementById("scan-form");
  const formStatus = document.getElementById("form-status");
  const jobsList = document.getElementById("jobs-list");
  const heroJobCount = document.getElementById("hero-job-count");
  const refreshButton = document.getElementById("refresh-jobs");
  const scrollButton = document.querySelector("[data-scroll]");
  const jobsState = new Map();
  const POLL_INTERVAL = 5000;

  async function fetchJSON(url, options) {
    const response = await fetch(url, options);
    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || "Request failed");
    }
    return response.json();
  }

  function getSelectedScanners() {
    return Array.from(form.querySelectorAll('input[name="selectedScanners"]:checked')).map(
      (input) => input.value
    );
  }

  function serializeForm() {
    return {
      hosts: form.hosts.value.trim(),
      scanType: form.scanType.value,
      dns: form.dns.value.trim(),
      staticNmap: form.staticNmap.value.trim(),
      customOutput: form.customOutput.value.trim(),
      extraArgs: form.extraArgs.value.trim(),
      remoteMode: form.remoteMode.checked,
      notes: form.notes.value.trim(),
      selectedScanners: getSelectedScanners(),
    };
  }

  function formatTimestamp(value) {
    if (!value) return "Pending";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  function formatDuration(start, end) {
    if (!start) return "—";
    const startDate = new Date(start);
    const endDate = end ? new Date(end) : new Date();
    const diff = Math.round((endDate - startDate) / 1000);
    if (diff < 1) return "<1s";
    const minutes = Math.floor(diff / 60);
    const seconds = diff % 60;
    if (!minutes) return `${seconds}s`;
    return `${minutes}m ${seconds}s`;
  }

  function escapeHtml(value = "") {
    return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function formatResultsRows(results) {
    return results
      .map(
        (row) => `
        <tr>
          <td>${escapeHtml(row.target)}</td>
          <td>${escapeHtml(row.port)}</td>
          <td>${escapeHtml(row.protocol)}</td>
          <td>${escapeHtml(row.service)}</td>
          <td>${escapeHtml(row.detail || "")}</td>
        </tr>`
      )
      .join("");
  }

  function resultsToClipboard(results) {
    return results
      .map(
        (row) =>
          `${row.target || ""},${row.port || ""},${row.protocol || ""},${row.service || ""},${
            row.detail || ""
          }`
      )
      .join("\n");
  }

  function renderResultsBlock(job) {
    const results = job.results || [];
    if (!results.length) {
      return '<div class="results-panel"><p class="muted">Structured findings will appear here once the scans finish.</p></div>';
    }
    const csvButton = job.resultsCsvUrl
      ? `<a class="ghost" href="${job.resultsCsvUrl}" download>CSV</a>`
      : "";
    return `
      <div class="results-panel">
        <div class="results-actions">
          <p class="muted">${results.length} unique findings</p>
          <div class="results-actions-buttons">
            <button class="ghost" data-copy-results data-job-id="${job.id}">Copy</button>
            ${csvButton}
          </div>
        </div>
        <div class="results-table-wrapper">
          <table class="results-table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Port</th>
                <th>Proto</th>
                <th>Service</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              ${formatResultsRows(results)}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  function renderJobs(jobs) {
    jobsList.innerHTML = "";
    if (!jobs.length) {
      jobsList.classList.add("empty");
      jobsList.innerHTML = '<p class="empty-copy">No scans yet. Launch one to watch the console light up.</p>';
      heroJobCount.textContent = "0";
      return;
    }

    jobsList.classList.remove("empty");
    heroJobCount.textContent = String(jobs.length);

    jobs.forEach((job) => {
      const card = document.createElement("article");
      card.className = "job-card";
      card.dataset.jobId = job.id;

      const statusClass = `status-pill ${job.status}`;
      const targets = job.targets && job.targets.length
        ? `<div class="target-chips">${job.targets
            .map((target) => `<span class="target-chip">${escapeHtml(target)}</span>`)
            .join("")}</div>`
        : "";
      const notesBlock = job.notes
        ? `<p><strong>Notes:</strong> ${job.notes}</p>`
        : "";
      const resultsBlock = renderResultsBlock(job);

      card.innerHTML = `
        <header>
          <div>
            <p class="eyebrow">#${job.id.slice(0, 8)}</p>
            <h3>${job.host} &middot; ${job.scanType}</h3>
          </div>
          <span class="${statusClass}">${job.status}</span>
        </header>
        ${targets}
        <div class="job-meta">
          <span><strong>Created</strong>${formatTimestamp(job.createdAt)}</span>
          <span><strong>Started</strong>${formatTimestamp(job.startedAt)}</span>
          <span><strong>Duration</strong>${formatDuration(job.startedAt, job.finishedAt)}</span>
        </div>
        <p class="muted"><strong>Command</strong><br /><code>${job.command || "Queueing..."}</code></p>
        ${notesBlock}
        ${resultsBlock}
        <div class="log-window">${(job.log || "Waiting for output&hellip;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/\n/g, "<br />")}</div>
        ${job.error ? `<p class="job-error">${job.error}</p>` : ""}
        <div class="job-actions"></div>
      `;

      const actions = card.querySelector(".job-actions");
      if (job.downloadUrl) {
        const downloadButton = document.createElement("a");
        downloadButton.href = job.downloadUrl;
        downloadButton.textContent = "Download output";
        downloadButton.className = "secondary";
        downloadButton.setAttribute("download", "");
        actions.appendChild(downloadButton);
      }

      jobsList.appendChild(card);

      const logWindow = card.querySelector(".log-window");
      logWindow.scrollTop = logWindow.scrollHeight;
    });
  }

  async function refreshJobs() {
    try {
      const jobs = await fetchJSON("/jobs");
      jobs.forEach((job) => jobsState.set(job.id, job));
      renderJobs(jobs);
    } catch (error) {
      console.error(error);
      formStatus.textContent = "Could not refresh job list.";
    }
  }

  async function handleSubmit(event) {
    event.preventDefault();
    formStatus.textContent = "Launching scan...";
    const payload = serializeForm();

    if (!payload.hosts || !payload.scanType) {
      formStatus.textContent = "Targets and scan type are required.";
      return;
    }

    try {
      const job = await fetchJSON("/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      form.reset();
      formStatus.textContent = "Scan queued successfully.";
      jobsState.set(job.id, job);
      await refreshJobs();
    } catch (error) {
      console.error(error);
      formStatus.textContent = error.message || "Failed to launch scan.";
    }
  }

  function handleJobsClick(event) {
    const copyButton = event.target.closest("[data-copy-results]");
    if (copyButton) {
      const jobId = copyButton.getAttribute("data-job-id");
      const job = jobsState.get(jobId);
      if (!job || !(job.results || []).length) return;
      const text = resultsToClipboard(job.results);
      navigator.clipboard
        .writeText(text)
        .then(() => {
          copyButton.textContent = "Copied!";
          setTimeout(() => {
            copyButton.textContent = "Copy";
          }, 1500);
        })
        .catch(() => {
          formStatus.textContent = "Clipboard unavailable.";
        });
    }
  }

  function setupPolling() {
    setInterval(() => {
      refreshJobs();
    }, POLL_INTERVAL);
  }

  function setupScrollButton() {
    if (!scrollButton) return;
    scrollButton.addEventListener("click", () => {
      const selector = scrollButton.getAttribute("data-scroll");
      const target = document.querySelector(selector);
      if (target) {
        target.scrollIntoView({ behavior: "smooth" });
      }
    });
  }

  function init() {
    if (!form) return;
    form.addEventListener("submit", handleSubmit);
    refreshButton?.addEventListener("click", refreshJobs);
    jobsList?.addEventListener("click", handleJobsClick);
    setupPolling();
    setupScrollButton();
    refreshJobs();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
