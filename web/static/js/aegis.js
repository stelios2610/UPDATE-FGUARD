// AegisGuard Web UI - common JS

// ── Toast notifications ────────────────────────────────────────────────────

function toast(msg, type = 'info') {
  const c = document.getElementById('toast-container') || (() => {
    const el = document.createElement('div');
    el.id = 'toast-container';
    document.body.appendChild(el);
    return el;
  })();
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.innerHTML = `<span>${msg}</span>`;
  c.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transform = 'translateX(100%)'; t.style.transition = '0.3s'; setTimeout(() => t.remove(), 350); }, 3500);
}

// ── API helpers ────────────────────────────────────────────────────────────

async function api(method, url, body = null) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || res.statusText);
  return data;
}

const GET = url => api('GET', url);
const POST = (url, body) => api('POST', url, body);
const PUT = (url, body) => api('PUT', url, body);
const DELETE = url => api('DELETE', url);

// ── Modal helpers ──────────────────────────────────────────────────────────

function openModal(id) { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') document.querySelectorAll('.modal-overlay.open')
    .forEach(m => m.classList.remove('open'));
});

// ── Confirm dialog ─────────────────────────────────────────────────────────

function confirm2(msg) { return confirm(msg); }

// ── Dashboard live refresh ─────────────────────────────────────────────────

async function refreshDashboardStats() {
  try {
    const d = await GET('/api/dashboard');
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('stat-conns', d.connections);
    set('stat-blocked', d.blocked_today);
    set('stat-threats', d.threats);
    set('stat-cpu', d.cpu_percent.toFixed(1) + '%');
    set('stat-mem', d.mem_percent.toFixed(1) + '%');
    set('stat-sent', d.bytes_sent_fmt);
    set('stat-recv', d.bytes_recv_fmt);
  } catch (e) { console.warn('Stats refresh error:', e); }
}

// ── Table filter ───────────────────────────────────────────────────────────

function filterTable(inputId, tableId) {
  const input = document.getElementById(inputId);
  const table = document.getElementById(tableId);
  if (!input || !table) return;
  input.addEventListener('input', () => {
    const q = input.value.toLowerCase();
    table.querySelectorAll('tbody tr').forEach(row => {
      row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });
}

// ── Copy to clipboard ──────────────────────────────────────────────────────

function copyText(text) {
  navigator.clipboard.writeText(text).then(() => toast('Copied!', 'success'));
}

// ── Format bytes ───────────────────────────────────────────────────────────

function fmtBytes(n) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return n.toFixed(1) + ' ' + units[i];
}

// ── Auto-refresh connections table on monitor page ─────────────────────────

async function refreshConnections() {
  const tbody = document.getElementById('conn-tbody');
  if (!tbody) return;
  try {
    const conns = await GET('/api/monitor/connections');
    tbody.innerHTML = conns.map(c => `
      <tr>
        <td><span class="badge badge-${c.proto === 'TCP' ? 'info' : 'warn'}">${c.proto}</span></td>
        <td class="font-mono">${c.local_ip}</td>
        <td class="font-mono">${c.local_port}</td>
        <td class="font-mono">${c.remote_ip || '-'}</td>
        <td class="font-mono">${c.remote_port || '-'}</td>
        <td><span class="badge badge-${c.status === 'Established' ? 'allow' : 'disabled'}">${c.status}</span></td>
        <td>${c.process}</td>
      </tr>`).join('');
  } catch (e) {}
}

// ── Refresh IPS alerts ─────────────────────────────────────────────────────

async function refreshAlerts() {
  const tbody = document.getElementById('alert-tbody');
  if (!tbody) return;
  try {
    const alerts = await GET('/api/ips/alerts');
    const sevClass = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'med', LOW: 'info' };
    tbody.innerHTML = alerts.map(a => `
      <tr>
        <td class="font-mono text-muted">${a.timestamp.substr(0,19).replace('T',' ')}</td>
        <td><span class="badge badge-${sevClass[a.severity] || 'info'}">${a.severity}</span></td>
        <td>${a.name}</td>
        <td class="font-mono">${a.remote_ip}</td>
        <td class="text-muted">${a.detail}</td>
      </tr>`).join('');
    document.getElementById('alert-count') && (document.getElementById('alert-count').textContent = alerts.length);
  } catch (e) {}
}

// ── Page init ──────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  filterTable('search-input', 'main-table');

  if (document.getElementById('stat-conns')) {
    refreshDashboardStats();
    setInterval(refreshDashboardStats, 5000);
  }
  if (document.getElementById('conn-tbody')) {
    refreshConnections();
    setInterval(refreshConnections, 3000);
  }
  if (document.getElementById('alert-tbody')) {
    refreshAlerts();
    setInterval(refreshAlerts, 4000);
  }
});
