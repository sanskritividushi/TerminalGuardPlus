const API_BASE = 'https://terminalguardrtsd.onrender.com';

let blockChart = null;
let falsePositiveChart = null;
let falseNegativeChart = null;
let accuracyChart = null;
let severityChart = null;
let hourlyChart = null;
let logs = [];
let allLogs = [];
let currentPage = 1;
const logsPerPage = 15;

async function fetchStats() {
    try {
        const res = await fetch(`${API_BASE}/statistics`);
        if (!res.ok) throw new Error("Failed to fetch stats");
        const data = await res.json();
        document.getElementById("totalCommands").textContent = data.total_commands;
        document.getElementById("blockedCommands").textContent = data.blocked_commands;
        document.getElementById("allowedCommands").textContent = data.allowed_commands;
        document.getElementById("totalSecrets").textContent = data.total_secrets_detected;
        document.getElementById("blockRate").textContent = data.block_rate_percent;
        document.getElementById("falsePositiveRate").textContent = data.false_positive_rate;
        document.getElementById("falseNegativeRate").textContent = data.false_negative_rate;
        document.getElementById("accuracyPercent").textContent = data.accuracy_percent;
        renderBlockChart(data.blocked_commands, data.allowed_commands);
    } catch (error) {
        console.error(error);
    }
}

async function fetchLogs() {
    try {
        const res = await fetch(`${API_BASE}/logs?count=100`);
        if (!res.ok) throw new Error("Failed to fetch logs");
        const data = await res.json();
        allLogs = data.logs;
        currentPage = 1;
        renderCurrentPage();
        calculateAndRenderMetrics();
    } catch (error) {
        console.error(error);
    }
}

function renderCurrentPage() {
    const totalLogs = allLogs.length;
    const startIndex = (currentPage - 1) * logsPerPage;
    const endIndex = Math.min(startIndex + logsPerPage, totalLogs);

    logs = allLogs.slice(startIndex, endIndex);
    renderLogsTable(logs);
    updatePaginationInfo(startIndex + 1, endIndex, totalLogs);
    updatePaginationButtons();
}

function updatePaginationInfo(start, end, total) {
    const info = total > 0 ? `Logs ${start}-${end} of ${total}` : 'No logs';
    document.getElementById('paginationInfoTop').textContent = info;
}

function updatePaginationButtons() {
    const totalPages = Math.ceil(allLogs.length / logsPerPage);
    const isFirstPage = currentPage === 1;
    const isLastPage = currentPage >= totalPages;

    document.getElementById('prevPageTop').disabled = isFirstPage;
    document.getElementById('nextPageTop').disabled = isLastPage;
}

function nextPage() {
    const totalPages = Math.ceil(allLogs.length / logsPerPage);
    if (currentPage < totalPages) {
        currentPage++;
        renderCurrentPage();
    }
}

function prevPage() {
    if (currentPage > 1) {
        currentPage--;
        renderCurrentPage();
    }
}

function renderBlockChart(blocked, allowed) {
    const ctx = document.getElementById("blockChart").getContext("2d");
    if (blockChart) blockChart.destroy();
    blockChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Blocked', 'Allowed'],
            datasets: [{
                data: [blocked, allowed],
                backgroundColor: ['#f44336', '#4caf50']
            }]
        },
        options: { responsive: false, plugins: { legend: { position: 'bottom' } } }
    });
}

function renderLogsTable(logs) {
    const tbody = document.getElementById("logTableBody");
    tbody.innerHTML = "";
    logs.forEach(log => {
        const tr = document.createElement("tr");

        const tdCmd = document.createElement("td");
        tdCmd.textContent = (log.command || "").slice(0, 60);
        tr.appendChild(tdCmd);

        const tdAction = document.createElement("td");
        tdAction.textContent = log.action;
        tdAction.className = log.action === "BLOCKED" ? "status-blocked" : "status-allowed";
        tr.appendChild(tdAction);

        const tdSecret = document.createElement("td");
        tdSecret.textContent = log.secrets_found > 0 ? "Yes" : "No";
        tdSecret.className = log.secrets_found > 0 ? "secret-yes" : "secret-no";
        tr.appendChild(tdSecret);

        const tdMark = document.createElement("td");
        if (log.mark_detection === "true") {
            const correctSpan = document.createElement("span");
            correctSpan.textContent = "Correct";
            correctSpan.className = "correct-label";
            tdMark.appendChild(correctSpan);
        } else if (log.mark_detection === "false") {
            const incorrectSpan = document.createElement("span");
            incorrectSpan.textContent = "Incorrect";
            incorrectSpan.className = "incorrect-label";
            tdMark.appendChild(incorrectSpan);
        } else {
            const tickBtn = document.createElement("button");
            tickBtn.textContent = "✔️";
            tickBtn.title = "Mark Correct";
            tickBtn.onclick = () => handleMarkDetection(log._id || log.id, "true");

            const crossBtn = document.createElement("button");
            crossBtn.textContent = "❌";
            crossBtn.title = "Mark Incorrect";
            crossBtn.onclick = () => handleMarkDetection(log._id || log.id, "false");

            tdMark.appendChild(tickBtn);
            tdMark.appendChild(crossBtn);
        }
        tr.appendChild(tdMark);

        tbody.appendChild(tr);
    });
}

async function handleMarkDetection(logId, mark) {
    try {
        await fetch(`${API_BASE}/logs/mark_detection`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ log_id: logId, mark }),
        });
        const savedPage = currentPage;
        await fetchLogs();
        currentPage = savedPage;
        renderCurrentPage();
    } catch (error) {
        console.error("Failed to update mark detection:", error);
    }
}

function calculateAndRenderMetrics() {
    let TP = 0, TN = 0, FP = 0, FN = 0;
    allLogs.forEach(log => {
        if (log.mark_detection === "true" || log.mark_detection === "false") {
            const markedTrue = log.mark_detection === "true";
            const secretFound = log.secrets_found > 0;
            if (secretFound) {
                markedTrue ? TP++ : FP++;
            } else {
                markedTrue ? FN++ : TN++;
            }
        }
    });

    renderFalsePositiveChart(FP, TP);
    renderFalseNegativeChart(FN, TN);
    renderAccuracyChart(TP + TN, FP + FN);
}

function renderFalsePositiveChart(FP, TP) {
    const ctx = document.getElementById("falsePositiveChart").getContext("2d");
    if (falsePositiveChart) falsePositiveChart.destroy();
    falsePositiveChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['False Positives', 'True Positives'],
            datasets: [{ data: [FP, TP], backgroundColor: ['#f44336', '#4caf50'] }]
        },
        options: { responsive: false, plugins: { legend: { position: 'bottom' } } }
    });
}

function renderFalseNegativeChart(FN, TN) {
    const ctx = document.getElementById("falseNegativeChart").getContext("2d");
    if (falseNegativeChart) falseNegativeChart.destroy();
    falseNegativeChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['False Negatives', 'True Negatives'],
            datasets: [{ data: [FN, TN], backgroundColor: ['#f44336', '#4caf50'] }]
        },
        options: { responsive: false, plugins: { legend: { position: 'bottom' } } }
    });
}

function renderAccuracyChart(correct, incorrect) {
    const ctx = document.getElementById("accuracyChart").getContext("2d");
    if (accuracyChart) accuracyChart.destroy();
    accuracyChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Correct', 'Incorrect'],
            datasets: [{ data: [correct, incorrect], backgroundColor: ['#4caf50', '#f44336'] }]
        },
        options: { responsive: false, plugins: { legend: { position: 'bottom' } } }
    });
}

// NEW: Fetch performance/latency metrics
async function fetchPerformance() {
    try {
        const res = await fetch(`${API_BASE}/performance`);
        if (!res.ok) throw new Error("Failed to fetch performance");
        const data = await res.json();
        document.getElementById("avgLatency").textContent = data.avg_latency_ms || "-";
        document.getElementById("minLatency").textContent = data.min_latency_ms || "-";
        document.getElementById("maxLatency").textContent = data.max_latency_ms || "-";
        document.getElementById("p95Latency").textContent = data.p95_latency_ms || "-";
    } catch (error) {
        console.error("Performance fetch error:", error);
    }
}

// NEW: Fetch severity breakdown
async function fetchSeverity() {
    try {
        const res = await fetch(`${API_BASE}/severity`);
        if (!res.ok) throw new Error("Failed to fetch severity");
        const data = await res.json();
        renderSeverityChart(data.by_severity || {});
    } catch (error) {
        console.error("Severity fetch error:", error);
    }
}

function renderSeverityChart(severityData) {
    const ctx = document.getElementById("severityChart").getContext("2d");
    if (severityChart) severityChart.destroy();

    const labels = Object.keys(severityData);
    const values = Object.values(severityData);

    if (labels.length === 0) {
        labels.push("No data");
        values.push(1);
    }

    const colors = {
        'critical': '#d32f2f',
        'high': '#f57c00',
        'medium': '#fbc02d',
        'low': '#4caf50',
        'unknown': '#9e9e9e'
    };

    const backgroundColors = labels.map(l => colors[l.toLowerCase()] || '#9e9e9e');

    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels.map(l => l.toUpperCase()),
            datasets: [{ data: values, backgroundColor: backgroundColors }]
        },
        options: { responsive: false, plugins: { legend: { position: 'bottom' } } }
    });
}

// NEW: Fetch trends
async function fetchTrends() {
    try {
        const res = await fetch(`${API_BASE}/trends`);
        if (!res.ok) throw new Error("Failed to fetch trends");
        const data = await res.json();
        renderHourlyChart(data.by_hour || {});
    } catch (error) {
        console.error("Trends fetch error:", error);
    }
}

function renderHourlyChart(hourlyData) {
    const ctx = document.getElementById("hourlyChart").getContext("2d");
    if (hourlyChart) hourlyChart.destroy();

    // Fill all 24 hours
    const labels = [];
    const values = [];
    for (let i = 0; i < 24; i++) {
        labels.push(`${i}:00`);
        values.push(hourlyData[i] || 0);
    }

    hourlyChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Detections',
                data: values,
                backgroundColor: '#2196f3'
            }]
        },
        options: {
            responsive: false,
            plugins: { legend: { display: false } },
            scales: {
                y: { beginAtZero: true, ticks: { stepSize: 1 } }
            }
        }
    });
}

document.getElementById("refreshButton").onclick = async () => {
    await fetchStats();
    await fetchLogs();
    await fetchPerformance();
    await fetchSeverity();
    await fetchTrends();
};

window.onload = async () => {
    await fetchStats();
    await fetchLogs();
    await fetchPerformance();
    await fetchSeverity();
    await fetchTrends();
};
