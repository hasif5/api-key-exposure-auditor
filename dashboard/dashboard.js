import { getDb, importDb, clearAll, deleteFinding,
  getCollection, saveToCollection, removeFromCollection,
  getIgnoreDomains, setIgnoreDomains, purgeIgnored } from '../lib/store.js';
import { assessRisk } from '../lib/audit.js';

let savedKeys = new Set();
const collapsedGroups = new Set();
const COLLAPSED_KEY = 'gaks_collapsed_groups';

function saveCollapsed() {
  chrome.storage.local.set({ [COLLAPSED_KEY]: Array.from(collapsedGroups) }).catch(() => {});
}
async function loadCollapsed() {
  try {
    const res = await chrome.storage.local.get(COLLAPSED_KEY);
    if (Array.isArray(res[COLLAPSED_KEY])) {
      collapsedGroups.clear();
      res[COLLAPSED_KEY].forEach((d) => collapsedGroups.add(d));
    }
  } catch (e) { /* ignore */ }
}

function hostOf(o) {
  try { return new URL(o).hostname; } catch (e) { return o || 'unknown'; }
}
function groupDomainOf(f) {
  return (f.origins && f.origins.length) ? hostOf(f.origins[0]) : 'unknown';
}

const els = {
  rows: document.getElementById('rows'),
  empty: document.getElementById('emptyMsg'),
  stats: document.getElementById('stats'),
  filter: document.getElementById('filter'),
  gen: document.getElementById('genChk'),
  toast: document.getElementById('toast'),
  progress: document.getElementById('progress'),
  progressBar: document.getElementById('progressBar'),
  progressLabel: document.getElementById('progressLabel')
};

// ---- Progress bar ----------------------------------------------------------

function showProgressDeterminate(current, total, label) {
  els.progress.hidden = false;
  els.progressBar.classList.remove('indeterminate');
  const pct = total ? Math.round((current / total) * 100) : 0;
  els.progressBar.style.width = pct + '%';
  els.progressLabel.textContent = label || (current + ' / ' + total);
}

function showProgressIndeterminate(label) {
  els.progress.hidden = false;
  els.progressBar.classList.add('indeterminate');
  els.progressBar.style.width = '';
  els.progressLabel.textContent = label || 'Auditing…';
}

function hideProgress() {
  els.progress.hidden = true;
  els.progressBar.classList.remove('indeterminate');
  els.progressBar.style.width = '0%';
  els.progressLabel.textContent = '';
}

let consented = false;
const expanded = new Set();

function toast(msg) {
  els.toast.textContent = msg;
  els.toast.classList.add('show');
  setTimeout(() => els.toast.classList.remove('show'), 2200);
}

function ensureConsent() {
  if (consented) return true;
  const ok = window.confirm(
    'Active audit makes REAL API calls to Google (Maps, Gemini, Vertex AI) using the ' +
    'selected key(s). These calls may incur cost to the key owner.\n\n' +
    'Only proceed for keys you are authorized to test. Continue?'
  );
  if (ok) consented = true;
  return ok;
}

function fmtTime(iso) {
  if (!iso) return '';
  try { return new Date(iso).toLocaleString(); } catch (e) { return iso; }
}

function classLabel(c) { return c.replace(/-/g, ' '); }

function auditSummary(audits) {
  const wrap = document.createElement('div');
  wrap.className = 'summary';
  if (!audits || !audits.length) {
    const s = document.createElement('span');
    s.className = 'tag';
    s.textContent = 'not audited';
    wrap.appendChild(s);
    return wrap;
  }
  audits.forEach((a) => {
    const p = document.createElement('span');
    p.className = 'pill ' + a.classification;
    p.title = a.service + ' · ' + a.endpoint + ' — HTTP ' + a.httpStatus + ' ' + (a.detail || '');
    p.textContent = a.service.split(' ')[0] + ': ' + classLabel(a.classification);
    wrap.appendChild(p);
  });
  return wrap;
}

function detailTable(f) {
  const td = document.createElement('td');
  td.colSpan = 7;
  const tbl = document.createElement('table');
  tbl.className = 'detail-table';
  tbl.innerHTML =
    '<thead><tr><th>Service</th><th>Endpoint</th><th>HTTP</th><th>API status</th>' +
    '<th>Classification</th><th>Billing</th><th>Detail</th><th>When</th></tr></thead>';
  const body = document.createElement('tbody');
  (f.audits || []).forEach((a) => {
    const billCell = a.billable
      ? '<span class="pill billable">billable</span>'
      : '<span class="pill enabled">free</span>';
    const tr = document.createElement('tr');
    tr.innerHTML =
      '<td>' + esc(a.service) + '</td>' +
      '<td>' + esc(a.endpoint) + '</td>' +
      '<td class="mono">' + esc(String(a.httpStatus)) + '</td>' +
      '<td class="mono">' + esc(a.apiStatus || '') + '</td>' +
      '<td><span class="pill ' + a.classification + '">' + classLabel(a.classification) + '</span></td>' +
      '<td>' + billCell + '<div class="seen">' + esc(a.costNote || '') + '</div></td>' +
      '<td>' + esc(a.detail || '') + '</td>' +
      '<td class="seen">' + esc(fmtTime(a.ts)) + '</td>';
    body.appendChild(tr);
  });
  if (!(f.audits || []).length) {
    body.innerHTML = '<tr><td colspan="8" class="seen">No audit has been run for this key.</td></tr>';
  }
  tbl.appendChild(body);
  td.appendChild(tbl);
  return td;
}

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

async function runAudit(findingId, statusEl) {
  if (!ensureConsent()) return null;
  if (statusEl) statusEl.textContent = 'auditing…';
  try {
    const resp = await chrome.runtime.sendMessage({
      type: 'GAKS_AUDIT',
      findingId,
      includeGenerate: els.gen.checked
    });
    if (resp && resp.ok) return resp.finding;
    if (statusEl) statusEl.textContent = 'failed';
    return null;
  } catch (e) {
    if (statusEl) statusEl.textContent = 'error';
    return null;
  }
}

function buildRow(f) {
  const tr = document.createElement('tr');
  const risk = assessRisk(f.audits);
  if (risk.level === 'critical') tr.className = 'row-critical';
  else if (risk.level === 'high') tr.className = 'row-high';

  // Risk cell (prominent flag for unrestricted keys)
  const riskTd = document.createElement('td');
  const riskBadge = document.createElement('span');
  riskBadge.className = 'risk ' + risk.level;
  riskBadge.textContent = risk.level === 'critical' ? 'CRITICAL'
    : risk.level === 'high' ? 'UNRESTRICTED'
    : risk.level === 'restricted' ? 'RESTRICTED'
    : 'UNKNOWN';
  riskTd.appendChild(riskBadge);
  const riskSub = document.createElement('span');
  riskSub.className = 'risk-sub';
  riskSub.textContent = risk.enabledServices.length
    ? (risk.bypass ? 'referrer bypass · ' : '') + 'reachable: ' + risk.enabledServices.join(', ')
    : risk.label;
  if (risk.bypass) riskSub.title = risk.label;
  riskTd.appendChild(riskSub);

  // Key cell
  const keyTd = document.createElement('td');
  const keyWrap = document.createElement('div');
  keyWrap.className = 'key';
  const code = document.createElement('span');
  code.textContent = f.key;
  const copy = document.createElement('button');
  copy.className = 'copy-btn';
  copy.textContent = 'copy';
  copy.addEventListener('click', () => {
    navigator.clipboard.writeText(f.key);
    toast('Key copied');
  });
  keyWrap.appendChild(code);
  keyWrap.appendChild(copy);
  keyTd.appendChild(keyWrap);

  // Origins (a key can appear on several)
  const origTd = document.createElement('td');
  origTd.className = 'origin';
  const origins = f.origins || [];
  const originHtml = origins.length
    ? origins.map((o) => esc(o)).join('<br>')
    : '<span class="no">unknown</span>';
  origTd.innerHTML = originHtml +
    (origins.length > 1 ? '<div class="seen">' + origins.length + ' origins</div>' : '') +
    '<div class="seen">first ' + esc(fmtTime(f.firstSeen)) + '</div>' +
    '<div class="seen">last ' + esc(fmtTime(f.lastSeen)) + '</div>';

  // Sources
  const srcTd = document.createElement('td');
  (f.sources || []).forEach((s) => {
    const t = document.createElement('span');
    t.className = 'tag src-' + s;
    t.textContent = s;
    srcTd.appendChild(t);
  });

  // Maps context
  const mapsTd = document.createElement('td');
  mapsTd.innerHTML = f.mapsContext ? '<span class="yes">yes</span>' : '<span class="no">no</span>';

  // Audit summary
  const sumTd = document.createElement('td');
  sumTd.appendChild(auditSummary(f.audits));

  // Actions
  const actTd = document.createElement('td');
  actTd.className = 'actions';
  const auditBtn = document.createElement('button');
  auditBtn.className = 'btn';
  auditBtn.textContent = (f.audits && f.audits.length) ? 'Re-audit' : 'Audit';
  const status = document.createElement('span');
  status.className = 'spinner';
  const detailBtn = document.createElement('button');
  detailBtn.className = 'btn ghost';
  detailBtn.textContent = expanded.has(f.id) ? 'Hide details' : 'Details';
  const saveBtn = document.createElement('button');
  saveBtn.className = 'btn ghost save-btn';
  const paintSave = () => {
    const on = savedKeys.has(f.key);
    saveBtn.textContent = on ? '★ Saved' : '☆ Save';
    saveBtn.classList.toggle('on', on);
    saveBtn.title = on ? 'Remove from collection' : 'Save to my collection';
  };
  paintSave();
  saveBtn.addEventListener('click', async () => {
    saveBtn.disabled = true;
    try {
      if (savedKeys.has(f.key)) { await removeFromCollection(f.key); savedKeys.delete(f.key); }
      else { await saveToCollection(f); savedKeys.add(f.key); }
      paintSave();
    } finally { saveBtn.disabled = false; }
  });
  const delBtn = document.createElement('button');
  delBtn.className = 'btn danger';
  delBtn.textContent = 'Delete';

  auditBtn.addEventListener('click', async () => {
    auditBtn.disabled = true;
    showProgressIndeterminate('Auditing ' + f.key.slice(0, 14) + '…');
    const updated = await runAudit(f.id, status);
    hideProgress();
    auditBtn.disabled = false;
    if (updated) {
      if (savedKeys.has(updated.key)) await saveToCollection(updated); // refresh saved snapshot
      status.textContent = '';
      // Update this row in place — no full re-render, so the table doesn't
      // re-sort and the page doesn't jump/scroll to the top.
      replaceRowInPlace(tr, updated);
    }
  });
  detailBtn.addEventListener('click', () => {
    // Toggle the detail row in place (no full re-render / scroll jump).
    if (expanded.has(f.id)) {
      expanded.delete(f.id);
      const next = tr.nextElementSibling;
      if (next && next.classList.contains('detail-row')) next.remove();
      detailBtn.textContent = 'Details';
    } else {
      expanded.add(f.id);
      const dr = document.createElement('tr');
      dr.className = 'detail-row';
      dr.appendChild(detailTable(f));
      tr.after(dr);
      detailBtn.textContent = 'Hide details';
    }
  });
  delBtn.addEventListener('click', async () => {
    if (!window.confirm('Delete this finding and its audit history?')) return;
    await deleteFinding(f.id);
    render();
  });

  actTd.appendChild(auditBtn);
  actTd.appendChild(saveBtn);
  actTd.appendChild(detailBtn);
  actTd.appendChild(delBtn);
  actTd.appendChild(status);

  tr.appendChild(riskTd);
  tr.appendChild(keyTd);
  tr.appendChild(origTd);
  tr.appendChild(srcTd);
  tr.appendChild(mapsTd);
  tr.appendChild(sumTd);
  tr.appendChild(actTd);
  return tr;
}

// Swap a single row's DOM for a freshly built one, preserving table order,
// scroll position, and any expanded detail row beneath it.
function replaceRowInPlace(oldTr, finding) {
  const idx = currentFindings.findIndex((x) => x.id === finding.id);
  if (idx !== -1) currentFindings[idx] = finding;

  const detailNode = (oldTr.nextElementSibling &&
    oldTr.nextElementSibling.classList.contains('detail-row')) ? oldTr.nextElementSibling : null;

  const newTr = buildRow(finding);
  oldTr.replaceWith(newTr);

  if (detailNode) {
    const newDetail = document.createElement('tr');
    newDetail.className = 'detail-row';
    newDetail.appendChild(detailTable(finding));
    detailNode.replaceWith(newDetail);
  }
  renderStats(currentFindings);
}

function renderStats(findings) {
  const total = findings.length;
  const maps = findings.filter((f) => f.mapsContext).length;
  const audited = findings.filter((f) => f.audits && f.audits.length).length;
  let unrestricted = 0, billable = 0;
  findings.forEach((f) => {
    const r = assessRisk(f.audits);
    if (r.level === 'critical' || r.level === 'high') unrestricted++;
    if (r.billableEnabled) billable++;
  });
  const data = [
    { n: total, l: 'keys found' },
    { n: maps, l: 'maps-context' },
    { n: audited, l: 'audited' },
    { n: unrestricted, l: 'UNRESTRICTED', alert: unrestricted > 0 },
    { n: billable, l: 'billable reachable', alert: billable > 0 }
  ];
  els.stats.innerHTML = '';
  data.forEach((d) => {
    const div = document.createElement('div');
    div.className = 'stat' + (d.alert ? ' alert' : '');
    div.innerHTML = '<div class="n">' + d.n + '</div><div class="l">' + d.l + '</div>';
    els.stats.appendChild(div);
  });
}

// Risk ordering: most dangerous keys float to the top.
const RISK_RANK = { critical: 0, high: 1, restricted: 2, unknown: 3 };

let currentFindings = [];

async function render() {
  const scrollY = window.scrollY; // preserve position across rebuilds
  const db = await getDb();
  const coll = await getCollection();
  savedKeys = new Set(coll.items.map((i) => i.key));
  currentFindings = db.findings.slice();
  const q = (els.filter.value || '').toLowerCase().trim();
  let items = currentFindings;
  if (q) {
    items = items.filter((f) =>
      f.key.toLowerCase().includes(q) ||
      (f.origins || []).some((o) => o.toLowerCase().includes(q)));
  }
  // Stable "logged" order — by first-seen time. NEVER sorted by risk, so a row
  // or its domain group never jumps when an audit starts/completes.
  const loggedTs = (f) => new Date(f.firstSeen).getTime() || 0;
  const byLogged = (a, b) => loggedTs(a) - loggedTs(b) || a.key.localeCompare(b.key);

  // Group findings by their primary domain.
  const groups = new Map();
  items.forEach((f) => {
    const d = groupDomainOf(f);
    if (!groups.has(d)) groups.set(d, []);
    groups.get(d).push(f);
  });
  const groupArr = Array.from(groups.entries());
  groupArr.forEach(([, arr]) => arr.sort(byLogged));
  // Group order = when the domain was first logged (earliest first). Stable.
  const firstLogged = (arr) => Math.min(...arr.map(loggedTs));
  groupArr.sort((a, b) => firstLogged(a[1]) - firstLogged(b[1]) || a[0].localeCompare(b[0]));

  renderStats(currentFindings);
  els.rows.innerHTML = '';
  els.empty.style.display = items.length ? 'none' : 'block';

  groupArr.forEach(([domain, arr], gi) => {
    const collapsed = collapsedGroups.has(domain);

    // Per-domain status breakdown.
    const c = { critical: 0, high: 0, restricted: 0, closed: 0, unaudited: 0 };
    arr.forEach((f) => {
      if (!f.audits || !f.audits.length) { c.unaudited++; return; }
      const lv = assessRisk(f.audits).level;
      if (lv === 'critical') c.critical++;
      else if (lv === 'high') c.high++;
      else if (lv === 'restricted') c.restricted++;
      else c.closed++;
    });
    const stat = (n, cls, label) => n ? '<span class="gh-stat ' + cls + '">' + n + ' ' + label + '</span>' : '';
    const statusHtml =
      stat(c.critical, 'critical', 'critical') +
      stat(c.high, 'high', 'unrestricted') +
      stat(c.restricted, 'restricted', 'restricted') +
      stat(c.closed, 'closed', 'no access') +
      stat(c.unaudited, 'unaudited', 'unaudited');

    const hdr = document.createElement('tr');
    hdr.className = 'group-header';
    const td = document.createElement('td');
    td.colSpan = 7;

    const left = document.createElement('div');
    left.className = 'gh-left';
    left.innerHTML =
      '<span class="gh-toggle">' + (collapsed ? '▶' : '▼') + '</span>' +
      '<span class="gh-seq">#' + (gi + 1) + '</span>' +
      '<span class="gh-domain">' + esc(domain) + '</span>' +
      '<span class="gh-count">' + arr.length + ' key' + (arr.length > 1 ? 's' : '') + '</span>' +
      '<span class="gh-status">' + statusHtml + '</span>';

    const right = document.createElement('div');
    right.className = 'gh-right';

    if (domain && domain !== 'unknown') {
      const ignoreBtn = document.createElement('button');
      ignoreBtn.className = 'btn ghost small gh-ignore';
      ignoreBtn.textContent = '🚫 Ignore domain';
      ignoreBtn.title = 'Stop logging keys from ' + domain + ' and remove its existing keys';
      ignoreBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        ignoreDomain(domain);
      });
      right.appendChild(ignoreBtn);
    }

    const auditAllBtn = document.createElement('button');
    auditAllBtn.className = 'btn small gh-audit';
    auditAllBtn.textContent = 'Audit all in domain';
    auditAllBtn.addEventListener('click', (e) => {
      e.stopPropagation();           // don't toggle the accordion
      auditGroup(arr.slice(), auditAllBtn);
    });
    right.appendChild(auditAllBtn);

    td.appendChild(left);
    td.appendChild(right);
    hdr.appendChild(td);
    hdr.addEventListener('click', () => {
      if (collapsed) collapsedGroups.delete(domain); else collapsedGroups.add(domain);
      saveCollapsed();
      render();
    });
    els.rows.appendChild(hdr);
    if (collapsed) return;

    arr.forEach((f) => {
      els.rows.appendChild(buildRow(f));
      if (expanded.has(f.id)) {
        const dr = document.createElement('tr');
        dr.className = 'detail-row';
        dr.appendChild(detailTable(f));
        els.rows.appendChild(dr);
      }
    });
  });

  window.scrollTo(0, scrollY); // keep the user where they were
}

// How many keys to audit at once. Each key itself fans out to ~14 probes
// (internally capped at 5 concurrent), so this multiplies that — keep it modest
// to stay under Google's rate limits.
const KEY_AUDIT_CONCURRENCY = 4;

// Run audits over a list of findings with bounded concurrency, updating progress
// as each completes. Returns the number audited.
async function auditMany(findings, onProgress) {
  const total = findings.length;
  let done = 0;
  let idx = 0;
  async function worker() {
    while (idx < findings.length) {
      const f = findings[idx++];
      const updated = await runAudit(f.id, null);
      if (updated && savedKeys.has(updated.key)) await saveToCollection(updated);
      done++;
      if (onProgress) onProgress(done, total);
    }
  }
  await Promise.all(Array.from({ length: Math.min(KEY_AUDIT_CONCURRENCY, total) }, worker));
  return done;
}

// Audit every key under one domain group concurrently (positions stay put).
async function auditGroup(findings, btn) {
  if (!findings.length) return;
  if (!ensureConsent()) return;
  const total = findings.length;
  const label = btn.textContent;
  btn.disabled = true;
  showProgressDeterminate(0, total, 'Auditing domain 0 / ' + total);
  const done = await auditMany(findings, (d, t) => {
    btn.textContent = 'Auditing ' + d + '/' + t + '…';
    showProgressDeterminate(d, t, 'Audited ' + d + ' / ' + t);
  });
  hideProgress();
  btn.disabled = false;
  btn.textContent = label;
  render();
  toast('Audited ' + done + ' keys in this domain');
}

// Add a domain to the ignore list AND remove its already-logged keys
// (delete + ignore in one action).
async function ignoreDomain(domain) {
  if (!domain || domain === 'unknown') return;
  if (!window.confirm('Ignore "' + domain + '"?\n\nThis removes its currently logged keys and stops ' +
    'detecting keys on this domain going forward. (Built-in defaults and your existing custom list are kept.)')) return;
  const current = await getIgnoreDomains();
  const saved = await setIgnoreDomains(current.concat(domain));
  const res = await purgeIgnored(saved);
  loadIgnore(); // refresh the settings textarea
  render();
  toast('Ignoring ' + domain + ' — removed ' + (res ? res.removed : 0) +
    ' key' + ((res && res.removed === 1) ? '' : 's'));
}

// ---- Toolbar actions -------------------------------------------------------

document.getElementById('collBtn').addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('collection/collection.html') });
});

document.getElementById('exportBtn').addEventListener('click', async () => {
  const db = await getDb();
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const blob = new Blob([JSON.stringify(db, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'gaks-findings-' + stamp + '.json';
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast('Exported ' + db.findings.length + ' findings');
});

document.getElementById('csvBtn').addEventListener('click', async () => {
  const db = await getDb();
  const cols = ['key', 'origins', 'sources', 'mapsContext', 'risk', 'firstSeen', 'lastSeen',
    'service', 'endpoint', 'httpStatus', 'apiStatus', 'classification', 'billable', 'costNote', 'detail', 'auditTs'];
  const rows = [cols];
  db.findings.forEach((f) => {
    const risk = assessRisk(f.audits).level;
    const base = [f.key, (f.origins || []).join(' '), (f.sources || []).join(' '), f.mapsContext,
      risk, f.firstSeen || '', f.lastSeen || ''];
    if (f.audits && f.audits.length) {
      f.audits.forEach((a) => {
        rows.push(base.concat([a.service, a.endpoint, a.httpStatus, a.apiStatus,
          a.classification, a.billable, a.costNote, a.detail, a.ts]));
      });
    } else {
      rows.push(base.concat(['', '', '', '', 'not-audited', '', '', '', '']));
    }
  });
  const csv = rows.map((r) => r.map(csvCell).join(',')).join('\r\n');
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'gaks-findings-' + stamp + '.csv';
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast('Exported CSV (' + (rows.length - 1) + ' rows)');
});

function csvCell(v) {
  const s = String(v == null ? '' : v);
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

document.getElementById('importFile').addEventListener('change', async (ev) => {
  const file = ev.target.files && ev.target.files[0];
  if (!file) return;
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    const res = await importDb(data);
    toast('Imported / merged ' + (res ? res.merged : 0) + ' findings');
    render();
  } catch (e) {
    toast('Import failed: invalid JSON');
  }
  ev.target.value = '';
});

document.getElementById('clearBtn').addEventListener('click', async () => {
  if (!window.confirm('Permanently delete ALL logged findings and audit history?')) return;
  await clearAll();
  expanded.clear();
  render();
  toast('Cleared all findings');
});

document.getElementById('auditAllBtn').addEventListener('click', async () => {
  if (!currentFindings.length) { toast('Nothing to audit'); return; }
  if (!ensureConsent()) return;
  const btn = document.getElementById('auditAllBtn');
  const queue = currentFindings.slice();
  const total = queue.length;
  btn.disabled = true;
  showProgressDeterminate(0, total, 'Auditing 0 / ' + total);
  const done = await auditMany(queue, (d, t) => {
    btn.textContent = 'Auditing ' + d + '/' + t + '…';
    showProgressDeterminate(d, t, 'Audited ' + d + ' / ' + t);
  });
  hideProgress();
  btn.disabled = false;
  btn.textContent = 'Audit all';
  render();
  toast('Audited ' + done + ' keys');
});

els.filter.addEventListener('input', render);

// ---- Ignored-domains settings ----
const ignoreInput = document.getElementById('ignoreInput');
const ignoreStatus = document.getElementById('ignoreStatus');

async function loadIgnore() {
  const list = await getIgnoreDomains();
  ignoreInput.value = list.join('\n');
}

document.getElementById('ignoreSave').addEventListener('click', async () => {
  const raw = ignoreInput.value.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
  const saved = await setIgnoreDomains(raw);
  const res = await purgeIgnored(saved);
  ignoreInput.value = saved.join('\n');
  ignoreStatus.textContent = 'Saved ' + saved.length + ' custom domain' + (saved.length === 1 ? '' : 's') +
    '; removed ' + (res ? res.removed : 0) + ' stored key' + ((res && res.removed === 1) ? '' : 's') + '.';
  render();
});

// Re-render if storage changes while the dashboard is open.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && (changes.gaks_db || changes.gaks_collection)) render();
});

loadIgnore();
loadCollapsed().then(render);
