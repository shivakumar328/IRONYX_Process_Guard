/**
 * IRONYX Process Guard — Crystal Glass Dashboard
 * Frontend application logic — real-time data from Flask API
 */

// ── State ───────────────────────────────────────────────────────────────────
const state = {
  processes: [],
  alerts: [],
  network: [],
  keyboard: [],
  system: {},
  risk: {},
  cpuHistory: [],
  memHistory: [],
  maxHistoryPoints: 60,
  currentPage: 'dashboard',
  refreshInterval: 3000,
  refreshTimer: null,
};

// ── API Helpers ─────────────────────────────────────────────────────────────
async function fetchAPI(endpoint) {
  try {
    const res = await fetch(`/api/${endpoint}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.error(`API error (${endpoint}):`, err);
    return null;
  }
}

async function postAPI(endpoint) {
  try {
    const res = await fetch(`/api/${endpoint}`, { method: 'POST' });
    return await res.json();
  } catch (err) {
    console.error(`API error (${endpoint}):`, err);
    return null;
  }
}

// ── Navigation ──────────────────────────────────────────────────────────────
function switchPage(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const pageEl = document.getElementById(`page-${page}`);
  const navEl = document.querySelector(`[data-page="${page}"]`);
  if (pageEl) pageEl.classList.add('active');
  if (navEl) navEl.classList.add('active');

  state.currentPage = page;

  // Load page-specific data
  if (page === 'processes') loadProcesses();
  if (page === 'alerts') loadAlerts();
  if (page === 'network') loadNetwork();
  if (page === 'keyboard') loadKeyboard();
}

document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => switchPage(item.dataset.page));
});

// ── Formatting Helpers ──────────────────────────────────────────────────────
function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${(bytes / 1073741824).toFixed(1)} GB`;
}

function formatUptime(seconds) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function timeAgo(isoString) {
  if (!isoString) return '—';
  const diff = Date.now() - new Date(isoString).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function riskBadge(level, score) {
  const cls = `risk-badge risk-badge-${level}`;
  const label = level.toUpperCase();
  const color = level === 'high' ? '#ef4444' : level === 'medium' ? '#f59e0b' : '#22c55e';
  return `<span class="${cls}"><span class="risk-score-bar"><span class="risk-score-fill" style="width:${score}%;background:${color}"></span></span>${label} ${score}</span>`;
}

function truncate(str, len) {
  if (!str) return '—';
  return str.length > len ? str.substring(0, len) + '…' : str;
}

// ── Toast ───────────────────────────────────────────────────────────────────
function toast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transform = 'translateX(100%)';
    setTimeout(() => el.remove(), 200);
  }, 4000);
}

// ── Dashboard: System Info ──────────────────────────────────────────────────
async function loadSystem() {
  const data = await fetchAPI('system');
  if (!data) return;
  state.system = data;

  // Stat cards
  document.getElementById('stat-cpu').textContent = `${data.cpu_percent.toFixed(1)}%`;
  document.getElementById('stat-cpu-bar').style.width = `${data.cpu_percent}%`;
  document.getElementById('stat-cpu-cores').textContent = `${data.cpu_count} cores · load ${data.load_average[0]}`;

  document.getElementById('stat-mem').textContent = `${data.memory.percent.toFixed(1)}%`;
  document.getElementById('stat-mem-bar').style.width = `${data.memory.percent}%`;
  document.getElementById('stat-mem-detail').textContent =
    `${formatBytes(data.memory.used)} / ${formatBytes(data.memory.total)}`;

  document.getElementById('stat-procs').textContent = data.process_count;

  // Sidebar
  document.getElementById('sidebar-os').textContent = truncate(data.distribution || data.os, 28);
  document.getElementById('sidebar-uptime').textContent = `↑ ${formatUptime(data.uptime_seconds)}`;

  // CPU history for chart
  state.cpuHistory.push(data.cpu_percent);
  state.memHistory.push(data.memory.percent);
  if (state.cpuHistory.length > state.maxHistoryPoints) state.cpuHistory.shift();
  if (state.memHistory.length > state.maxHistoryPoints) state.memHistory.shift();

  drawCpuMemChart();
}

// ── Dashboard: Risk Summary ─────────────────────────────────────────────────
async function loadRisk() {
  const data = await fetchAPI('risk');
  if (!data) return;
  state.risk = data;

  document.getElementById('stat-high-risk').textContent = data.high_risk;
  document.getElementById('stat-risk-detail').textContent =
    `${data.medium_risk} medium · ${data.low_risk} low`;
  document.getElementById('stat-proc-detail').textContent =
    `${data.total_processes} monitored`;

  // Donut chart
  updateDonut(data.low_risk, data.medium_risk, data.high_risk, data.total_processes);

  // Top risk list
  const topList = document.getElementById('top-risk-list');
  if (data.top_risk.length === 0 || data.top_risk.every(p => p.score === 0)) {
    topList.innerHTML = '<div class="empty-state">No risky processes detected ✓</div>';
  } else {
    topList.innerHTML = data.top_risk.slice(0, 8).map(p => {
      const color = p.level === 'high' ? '#ef4444' : p.level === 'medium' ? '#f59e0b' : '#22c55e';
      return `
        <div class="risk-list-item">
          <span class="risk-list-score" style="color:${color}">${p.score}</span>
          <div class="risk-list-info">
            <div class="risk-list-name">${escapeHtml(p.name)}</div>
            <div class="risk-list-meta">PID ${p.pid} · ${p.level.toUpperCase()}</div>
          </div>
        </div>`;
    }).join('');
  }
}

// ── Dashboard: Recent Alerts ────────────────────────────────────────────────
async function loadRecentAlerts() {
  const data = await fetchAPI('alerts?limit=5');
  if (!data) return;
  state.alerts = data;

  const list = document.getElementById('recent-alerts-list');
  if (data.length === 0) {
    list.innerHTML = '<div class="empty-state">No alerts ✓</div>';
  } else {
    list.innerHTML = data.map(a => {
      const iconColor = a.risk_level === 'high' ? 'high' : 'medium';
      const iconSvg = a.risk_level === 'high'
        ? '<svg viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" width="16" height="16"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
        : '<svg viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" width="16" height="16"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
      return `
        <div class="alert-list-item">
          <div class="alert-list-icon ${iconColor}">${iconSvg}</div>
          <div class="alert-list-content">
            <div class="alert-list-title">${escapeHtml(a.process_name || 'Unknown')} <span class="mono" style="color:var(--text-dim)">#${a.pid || '?'}</span></div>
            <div class="alert-list-reason">${escapeHtml(truncate(a.reason, 80))}</div>
          </div>
          <div class="alert-list-time">${timeAgo(a.timestamp)}</div>
        </div>`;
    }).join('');
  }

  // Nav badge
  const unack = data.filter(a => !a.acknowledged).length;
  const badge = document.getElementById('nav-alert-count');
  if (unack > 0) {
    badge.textContent = unack;
    badge.style.display = 'inline-block';
  } else {
    badge.style.display = 'none';
  }
}

// ── Processes Page ──────────────────────────────────────────────────────────
async function loadProcesses() {
  const data = await fetchAPI('processes');
  if (!data) return;
  state.processes = data;
  renderProcessTable(data);
}

function renderProcessTable(procs) {
  const tbody = document.getElementById('process-tbody');
  if (!procs || procs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty-state">No processes found</td></tr>';
    return;
  }

  tbody.innerHTML = procs.map(p => `
    <tr>
      <td class="mono">${p.pid}</td>
      <td><strong style="color:var(--text-primary)">${escapeHtml(p.name)}</strong></td>
      <td>${escapeHtml(p.username)}</td>
      <td class="num">${p.cpu_percent.toFixed(1)}</td>
      <td class="num">${p.mem_mb.toFixed(0)}</td>
      <td>${p.accesses_keyboard ? '<span class="kb-warning">⚠ YES</span>' : '<span class="kb-ok">No</span>'}</td>
      <td>${p.is_root ? '<span style="color:var(--warning)">Yes</span>' : 'No'}</td>
      <td class="num">${p.connection_count}</td>
      <td>${riskBadge(p.risk_level, p.risk_score)}</td>
    </tr>
  `).join('');
}

function filterProcesses() {
  const query = document.getElementById('process-search').value.toLowerCase().trim();
  const riskFilter = document.getElementById('process-risk-filter').value;

  let filtered = state.processes;
  if (query) {
    filtered = filtered.filter(p =>
      p.name.toLowerCase().includes(query) ||
      String(p.pid).includes(query) ||
      p.username.toLowerCase().includes(query)
    );
  }
  if (riskFilter !== 'all') {
    filtered = filtered.filter(p => p.risk_level === riskFilter);
  }
  renderProcessTable(filtered);
}

// ── Alerts Page ─────────────────────────────────────────────────────────────
async function loadAlerts() {
  const data = await fetchAPI('alerts?limit=100');
  if (!data) return;
  state.alerts = data;

  const tbody = document.getElementById('alert-tbody');
  if (data.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No alerts recorded ✓</td></tr>';
    return;
  }

  tbody.innerHTML = data.map(a => `
    <tr>
      <td class="mono" style="font-size:11px">${(a.timestamp || '').slice(0,19)}</td>
      <td class="mono">${a.pid || '—'}</td>
      <td><strong style="color:var(--text-primary)">${escapeHtml(a.process_name || '—')}</strong></td>
      <td class="num"><strong>${a.risk_score || 0}</strong></td>
      <td>${riskBadge(a.risk_level || 'low', a.risk_score || 0)}</td>
      <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis">${escapeHtml(truncate(a.reason, 100))}</td>
      <td>${a.acknowledged ? '<span style="color:var(--success)">Acknowledged</span>' : '<span style="color:var(--text-muted)">Pending</span>'}</td>
    </tr>
  `).join('');
}

// ── Network Page ────────────────────────────────────────────────────────────
async function loadNetwork() {
  const data = await fetchAPI('network');
  if (!data) return;
  state.network = data;

  const tbody = document.getElementById('network-tbody');
  if (data.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No active network connections</td></tr>';
    return;
  }

  tbody.innerHTML = data.map(c => {
    const flags = (c.flags || []).map(f => `<span class="risk-badge risk-badge-${f.includes('blacklist') ? 'high' : f.includes('suspicious') ? 'medium' : 'low'}">${escapeHtml(f)}</span>`).join(' ');
    return `
      <tr>
        <td class="mono">${c.pid}</td>
        <td>${escapeHtml(c.process_name)}</td>
        <td class="mono">${c.local_ip}:${c.local_port}</td>
        <td class="mono">${c.remote_ip || '—'}:${c.remote_port || '—'}</td>
        <td>${(c.type || '').toUpperCase()}</td>
        <td>${c.status || '—'}</td>
        <td>${flags || '<span class="kb-ok">None</span>'}</td>
      </tr>`;
  }).join('');
}

// ── Keyboard Page ───────────────────────────────────────────────────────────
async function loadKeyboard() {
  const data = await fetchAPI('keyboard');
  if (!data) return;
  state.keyboard = data;

  const tbody = document.getElementById('keyboard-tbody');
  if (data.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No processes accessing keyboard devices</td></tr>';
    return;
  }

  tbody.innerHTML = data.map(k => `
    <tr>
      <td class="mono">${k.pid}</td>
      <td><strong style="color:var(--text-primary)">${escapeHtml(k.name)}</strong></td>
      <td>${escapeHtml(k.username)}</td>
      <td class="mono" style="font-size:11px">${escapeHtml(truncate(k.exe, 50))}</td>
      <td>${k.is_known
        ? '<span style="color:var(--success)">✓ Known</span>'
        : '<span class="kb-warning">⚠ UNKNOWN</span>'}</td>
      <td class="mono" style="font-size:11px">${(k.devices || []).join(', ')}</td>
      <td>${k.source}</td>
    </tr>
  `).join('');
}

// ── Reports Page ────────────────────────────────────────────────────────────
async function generateReport(format) {
  toast(`Generating ${format.toUpperCase()} report…`, 'info');
  const data = await fetchAPI(`report?format=${format}`);
  const resultDiv = document.getElementById('report-result');
  const bodyDiv = document.getElementById('report-result-body');

  if (data && data.files && data.files.length > 0) {
    resultDiv.style.display = 'block';
    bodyDiv.innerHTML = data.files.map(f =>
      `<p style="margin:8px 0"><span style="color:var(--success)">✓</span> Report saved to: <code>${escapeHtml(f)}</code></p>`
    ).join('');
    toast(`${format.toUpperCase()} report generated successfully`, 'success');
  } else {
    toast(`Failed to generate ${format} report`, 'error');
  }
}

// ── CPU/Memory Chart (Canvas) ───────────────────────────────────────────────
function drawCpuMemChart() {
  const canvas = document.getElementById('chart-cpu-mem');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = 200 * dpr;
  ctx.scale(dpr, dpr);

  const w = rect.width;
  const h = 200;
  const pad = { top: 20, right: 20, bottom: 30, left: 40 };
  const chartW = w - pad.left - pad.right;
  const chartH = h - pad.top - pad.bottom;

  ctx.clearRect(0, 0, w, h);

  // Grid lines
  ctx.strokeStyle = 'rgba(63, 63, 70, 0.3)';
  ctx.lineWidth = 1;
  ctx.font = '10px JetBrains Mono';
  ctx.fillStyle = '#52525b';
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + (chartH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(pad.left + chartW, y);
    ctx.stroke();
    const val = 100 - (i * 25);
    ctx.fillText(`${val}%`, 4, y + 3);
  }

  // Draw line chart
  function drawLine(data, color, fillColor) {
    if (data.length < 2) return;
    const step = chartW / (state.maxHistoryPoints - 1);

    // Fill area
    ctx.beginPath();
    ctx.moveTo(pad.left, pad.top + chartH);
    data.forEach((val, i) => {
      const x = pad.left + i * step;
      const y = pad.top + chartH - (val / 100) * chartH;
      ctx.lineTo(x, y);
    });
    ctx.lineTo(pad.left + (data.length - 1) * step, pad.top + chartH);
    ctx.closePath();
    ctx.fillStyle = fillColor;
    ctx.fill();

    // Line
    ctx.beginPath();
    data.forEach((val, i) => {
      const x = pad.left + i * step;
      const y = pad.top + chartH - (val / 100) * chartH;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.stroke();
  }

  drawLine(state.memHistory, '#f59e0b', 'rgba(245, 158, 11, 0.08)');
  drawLine(state.cpuHistory, '#6366f1', 'rgba(99, 102, 241, 0.08)');

  // Legend
  ctx.font = '11px Inter';
  ctx.fillStyle = '#6366f1';
  ctx.fillRect(pad.left, 4, 10, 3);
  ctx.fillStyle = '#a1a1aa';
  ctx.fillText('CPU', pad.left + 14, 8);
  ctx.fillStyle = '#f59e0b';
  ctx.fillRect(pad.left + 50, 4, 10, 3);
  ctx.fillStyle = '#a1a1aa';
  ctx.fillText('Memory', pad.left + 64, 8);
}

// ── Donut Chart ─────────────────────────────────────────────────────────────
function updateDonut(low, medium, high, total) {
  const circumference = 2 * Math.PI * 80; // ~502.4
  const lowArc = (low / total) * circumference;
  const medArc = (medium / total) * circumference;
  const highArc = (high / total) * circumference;

  document.getElementById('donut-low').setAttribute('stroke-dasharray', `${lowArc} ${circumference}`);
  document.getElementById('donut-low').setAttribute('stroke-dashoffset', '0');

  document.getElementById('donut-medium').setAttribute('stroke-dasharray', `${medArc} ${circumference}`);
  document.getElementById('donut-medium').setAttribute('stroke-dashoffset', `${-lowArc}`);

  document.getElementById('donut-high').setAttribute('stroke-dasharray', `${highArc} ${circumference}`);
  document.getElementById('donut-high').setAttribute('stroke-dashoffset', `${-(lowArc + medArc)}`);

  document.getElementById('donut-total').textContent = total;
}

// ── Utility ─────────────────────────────────────────────────────────────────
function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function updateRefreshTime() {
  const now = new Date();
  const t = now.toLocaleTimeString();
  document.getElementById('last-refresh').textContent = `Updated ${t}`;
}

// ── Main Refresh Loop ───────────────────────────────────────────────────────
async function refreshAll() {
  await Promise.all([
    loadSystem(),
    loadRisk(),
    loadRecentAlerts(),
  ]);

  if (state.currentPage === 'processes') await loadProcesses();
  if (state.currentPage === 'network') await loadNetwork();
  if (state.currentPage === 'keyboard') await loadKeyboard();

  updateRefreshTime();
}

// ── Init ────────────────────────────────────────────────────────────────────
async function init() {
  console.log('🛡 IRONYX Process Guard — Dashboard initializing…');
  await refreshAll();
  state.refreshTimer = setInterval(refreshAll, state.refreshInterval);
  console.log('✓ Dashboard live — refreshing every 3 seconds');
}

// Handle window resize for canvas chart
window.addEventListener('resize', () => {
  drawCpuMemChart();
});

// Start
init();
