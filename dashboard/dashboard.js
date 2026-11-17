import { getDb, importDb, clearAll, deleteFinding,
  getCollection, saveToCollection, removeFromCollection,
  getIgnoreDomains, setIgnoreDomains, purgeIgnored } from '../lib/store.js';
import { assessRisk } from '../lib/providers.js';

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

// Plain-language meaning of each classification (for tooltips + legend).
const CLASS_HELP = {
  'enabled': 'Reachable with NO Referer — the key works for this API from anywhere (exploitable)',
  'restricted-referer': 'Blocked by an HTTP-referrer restriction (key is locked to specific sites)',
  'restricted-ip': 'Blocked by an IP-address restriction',
  'api-not-enabled': 'This API is not enabled / not allowed for this key',
  'invalid-key': 'Key is invalid, expired, or revoked',
  'over-quota': 'Valid, but a quota/billing limit was hit',
  'inconclusive': 'Could not be determined from a server-side request',
  'denied': 'Rejected for another reason',
  'error': 'Network/transport error reaching the endpoint'
};

const PROVIDER_LABELS = { google: 'Google', openai: 'OpenAI', anthropic: 'Anthropic', openrouter: 'OpenRouter', xai: 'xAI', twilio: 'Twilio', aws: 'AWS', github: 'GitHub', gitlab: 'GitLab', slack: 'Slack', stripe: 'Stripe', unknown: 'Unknown' };
function providerBadge(id) {
  id = id || 'google';
  const span = document.createElement('span');
  span.className = 'prov-badge prov-' + id;
  span.textContent = PROVIDER_LABELS[id] || id;
  return span;
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
  progressLabel: document.getElementById('progressLabel'),
  paginationBar: document.getElementById('pagination'),
  providerFilter: document.getElementById('providerFilter'),
  riskFilter: document.getElementById('riskFilter'),
  statusFilter: document.getElementById('statusFilter'),
  sortBy: document.getElementById('sortBy'),
  pageSizeSelect: document.getElementById('pageSizeSelect'),
  cancelAuditBtn: document.getElementById('cancelAuditBtn')
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
  if (els.cancelAuditBtn) els.cancelAuditBtn.hidden = true;
}

function showCancelBtn() {
  if (els.cancelAuditBtn) els.cancelAuditBtn.hidden = false;
}

if (els.cancelAuditBtn) {
  els.cancelAuditBtn.addEventListener('click', () => {
    auditAborted = true;
    els.cancelAuditBtn.hidden = true;
    els.progressLabel.textContent = 'Cancelling…';
  });
}

let consented = false;
let auditAborted = false;
const expanded = new Set();
// >0 while any audit (single, per-domain, or all) is running. The storage-change
// listener checks this to avoid re-rendering the whole table on every per-key
// write during a batch; the audit flows update the UI themselves.
let auditing = 0;

// Active summary-tile filter (null = show everything). Toggled by clicking a
// stat tile, so "show me only the unrestricted keys" is one click.
let activeStatFilter = null; // null | 'maps' | 'audited' | 'unrestricted' | 'billable'

// Pagination state — keys panel
let currentPage = 0;
let pageSize = 25;
// Pagination state — unknown panel
let ukCurrentPage = 0;
let ukPageSize = 25;

function matchesFreeText(f, q) {
  if (!q) return true;
  if (f.key.toLowerCase().includes(q)) return true;
  if ((f.provider || '').toLowerCase().includes(q)) return true;
  if ((f.origins || []).some((o) => o.toLowerCase().includes(q))) return true;
  if ((f.snippet || '').toLowerCase().includes(q)) return true;
  if ((f.sources || []).some((s) => s.toLowerCase().includes(q))) return true;
  if ((f.pageUrls || []).some((u) => u.toLowerCase().includes(q))) return true;
  return false;
}

function matchesStatFilter(f) {
  if (!activeStatFilter) return true;
  if (activeStatFilter === 'maps') return !!f.mapsContext;
  if (activeStatFilter === 'audited') return !!(f.audits && f.audits.length);
  const r = assessRisk(f.audits, f.provider);
  if (activeStatFilter === 'unrestricted') return r.level === 'critical' || r.level === 'high';
  if (activeStatFilter === 'billable') return !!r.billableEnabled;
  return true;
}

function toast(msg) {
  els.toast.textContent = msg;
  els.toast.classList.add('show');
  setTimeout(() => els.toast.classList.remove('show'), 2200);
}

function ensureConsent() {
  if (consented) return true;
  const ok = window.confirm(
    'Active audit makes REAL API calls to provider endpoints using the ' +
    'selected key(s). These calls may incur cost.\n\n' +
    'Only proceed if these are your own keys. Continue?'
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
  wrap.className = 'audit-summary';
  if (!audits || !audits.length) {
    const s = document.createElement('span');
    s.className = 'tag';
    s.textContent = 'not audited';
    wrap.appendChild(s);
    return wrap;
  }
  const enabled = [], denied = [];
  let billableCount = 0;
  audits.forEach((a) => {
    const cl = a.classification || 'unknown';
    if (cl === 'enabled' || cl === 'over-quota') enabled.push(a);
    else denied.push(a);
    if (a.billable) billableCount++;
  });
  if (enabled.length) {
    const line = document.createElement('div');
    line.className = 'audit-enabled';
    enabled.forEach((a) => {
      const p = document.createElement('span');
      p.className = 'pill enabled';
      p.textContent = '✓ ' + a.service;
      line.appendChild(p);
    });
    wrap.appendChild(line);
  }
  if (denied.length) {
    const groups = {};
    denied.forEach((a) => {
      const cl = a.classification || 'unknown';
      if (!groups[cl]) groups[cl] = [];
      groups[cl].push(a.service);
    });
    const line = document.createElement('div');
    line.className = 'audit-denied';
    Object.keys(groups).forEach((cl) => {
      const p = document.createElement('span');
      p.className = 'pill ' + cl;
      p.textContent = classLabel(cl) + ' ×' + groups[cl].length;
      p.title = groups[cl].join(', ');
      line.appendChild(p);
    });
    wrap.appendChild(line);
  }
  if (billableCount) {
    const bp = document.createElement('span');
    bp.className = 'pill billable';
    bp.textContent = '$ ×' + billableCount;
    bp.title = billableCount + ' billable probe' + (billableCount > 1 ? 's' : '');
    wrap.appendChild(bp);
  }
  return wrap;
}

function detailTable(f) {
  const td = document.createElement('td');
  td.colSpan = 5;
  const audits = f.audits || [];
  if (!audits.length) {
    td.innerHTML = '<div class="detail-empty">No audit has been run for this key.</div>';
    return td;
  }
  const groups = {};
  audits.forEach((a) => {
    const svc = a.service || 'Unknown';
    if (!groups[svc]) groups[svc] = [];
    groups[svc].push(a);
  });
  const order = ['enabled', 'over-quota', 'restricted-referer', 'restricted-ip',
    'api-not-enabled', 'denied', 'invalid-key', 'error', 'inconclusive'];
  const clsRank = (c) => { const i = order.indexOf(c); return i === -1 ? 99 : i; };
  Object.keys(groups).forEach((svc) => {
    const section = document.createElement('div');
    section.className = 'detail-group';
    const hd = document.createElement('div');
    hd.className = 'detail-group-hd';
    hd.textContent = svc;
    section.appendChild(hd);
    groups[svc].sort((a, b) => clsRank(a.classification) - clsRank(b.classification));
    groups[svc].forEach((a) => {
      const card = document.createElement('div');
      card.className = 'detail-card detail-card-' + (a.classification || 'unknown');
      const top = document.createElement('div');
      top.className = 'dc-top';
      top.innerHTML =
        '<span class="dc-endpoint">' + esc(a.endpoint) + '</span>' +
        '<span class="dc-http mono">HTTP ' + esc(String(a.httpStatus)) + '</span>' +
        (a.apiStatus ? '<span class="dc-api mono">' + esc(a.apiStatus) + '</span>' : '') +
        '<span class="pill ' + a.classification + '">' + classLabel(a.classification) + '</span>' +
        (a.billable
          ? '<span class="pill billable">$ ' + esc(a.costNote || 'billable') + '</span>'
          : '<span class="dc-free">free</span>');
      card.appendChild(top);
      if (a.detail) {
        const det = document.createElement('div');
        det.className = 'dc-detail';
        det.textContent = a.detail;
        card.appendChild(det);
      }
      section.appendChild(card);
    });
    td.appendChild(section);
  });
  return td;
}

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Compact "host/…/file.js" label for a URL.
function hostFile(u) {
  try {
    const p = new URL(u);
    const file = p.pathname.split('/').filter(Boolean).pop() || p.pathname;
    return p.host + '/…/' + file;
  } catch (e) { return u.length > 60 ? u.slice(0, 60) + '…' : u; }
}

// Clickable links to the exact resource(s) a key was found in. Built via DOM
// (not innerHTML) so URLs can't break out into markup.
function sourceLinksEl(f) {
  const urls = (f.pageUrls || []).filter((u) => /^https?:\/\//.test(u));
  if (!urls.length) return null;
  const box = document.createElement('div');
  box.className = 'seen-links';
  urls.slice(0, 6).forEach((u) => {
    const a = document.createElement('a');
    a.href = u;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.textContent = hostFile(u);
    a.title = u;
    box.appendChild(a);
  });
  return box;
}

// Per-key audit with a 60-second timeout to prevent indefinite hangs.
const AUDIT_TIMEOUT_MS = 60000;

async function runAudit(findingId, statusEl) {
  if (!ensureConsent()) return null;
  if (statusEl) statusEl.textContent = 'auditing…';
  try {
    const timeout = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('audit_timeout')), AUDIT_TIMEOUT_MS));
    const resp = await Promise.race([
      chrome.runtime.sendMessage({
        type: 'GAKS_AUDIT',
        findingId,
        includeGenerate: els.gen.checked
      }),
      timeout
    ]);
    if (resp && resp.ok) return resp.finding;
    if (statusEl) statusEl.textContent = 'failed';
    return null;
  } catch (e) {
    if (statusEl) statusEl.textContent = e.message === 'audit_timeout' ? 'timeout' : 'error';
    return null;
  }
}

function buildRow(f) {
  const tr = document.createElement('tr');
  const risk = assessRisk(f.audits, f.provider);
  if (risk.level === 'critical') tr.className = 'row-critical';
  else if (risk.level === 'high') tr.className = 'row-high';

  // Risk cell — just the badge, tight
  const riskTd = document.createElement('td');
  riskTd.className = 'risk-cell';
  const riskBadge = document.createElement('span');
  riskBadge.className = 'risk ' + risk.level;
  riskBadge.textContent = risk.level === 'critical' ? 'CRITICAL'
    : risk.level === 'high' ? 'UNRESTRICTED'
    : risk.level === 'restricted' ? 'RESTRICTED'
    : 'UNKNOWN';
  riskBadge.title = risk.label;
  riskTd.appendChild(riskBadge);

  // Key cell
  const keyTd = document.createElement('td');
  const keyWrap = document.createElement('div');
  keyWrap.className = 'key';
  keyWrap.appendChild(providerBadge(f.provider));
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

  // Paired secret (Twilio Auth Token / AWS Secret Access Key), if captured.
  if (f.secret) {
    const sec = document.createElement('div');
    sec.className = 'key-secret';
    const sv = document.createElement('span');
    sv.className = 'mono';
    sv.textContent = f.secret;
    const sc = document.createElement('button');
    sc.className = 'copy-btn';
    sc.textContent = 'copy';
    sc.addEventListener('click', () => { navigator.clipboard.writeText(f.secret); toast('Secret copied'); });
    sec.appendChild(document.createTextNode('secret '));
    sec.appendChild(sv);
    sec.appendChild(sc);
    keyTd.appendChild(sec);
  }

  // Where it was found — snippet/code reference (consistent with the popup).
  if (f.snippet) {
    const ref = document.createElement('div');
    ref.className = 'key-ref';
    ref.textContent = f.snippet;
    keyTd.appendChild(ref);
  }
  // The same key on other surfaces: one extra reference per source tag.
  if (f.snippets) {
    for (const src of Object.keys(f.snippets)) {
      const text = f.snippets[src];
      if (!text || text === f.snippet) continue;
      const more = document.createElement('div');
      more.className = 'key-ref';
      more.textContent = src + ': ' + text;
      keyTd.appendChild(more);
    }
  }

  // Seen on — merged: origins, clickable source URLs, sources, timestamps
  const seenTd = document.createElement('td');
  seenTd.className = 'seen-cell';
  const origins = f.origins || [];
  const originHtml = origins.length
    ? origins.map((o) => esc(o)).join('<br>')
    : '<span class="no">unknown</span>';
  const srcHtml = (f.sources || []).map((s) =>
    '<span class="tag src-' + s + '">' + esc(s) + '</span>').join(' ');
  const mapsTag = f.mapsContext ? ' <span class="tag src-maps">maps</span>' : '';
  seenTd.innerHTML = originHtml +
    '<div class="seen-meta">' + srcHtml + mapsTag + '</div>' +
    '<div class="seen">first ' + esc(fmtTime(f.firstSeen)) + '</div>' +
    '<div class="seen">last ' + esc(fmtTime(f.lastSeen)) + '</div>';
  const links = sourceLinksEl(f);
  if (links) seenTd.insertBefore(links, seenTd.querySelector('.seen-meta'));

  // Audit results
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
    auditing++; // suppress storage-driven full re-renders; we repaint the row below
    showProgressIndeterminate('Auditing ' + f.key.slice(0, 14) + '…');
    try {
      const updated = await runAudit(f.id, status);
      if (updated) {
        if (savedKeys.has(updated.key)) await saveToCollection(updated); // refresh saved snapshot
        status.textContent = '';
        // Update this row in place — no full re-render, so the table doesn't
        // re-sort and the page doesn't jump/scroll to the top.
        replaceRowInPlace(tr, updated);
      }
    } finally {
      auditing--;
      hideProgress();
      auditBtn.disabled = false;
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

  // 'unknown' findings are heuristic matches with no endpoint to validate.
  if (f.provider !== 'unknown') actTd.appendChild(auditBtn);
  actTd.appendChild(saveBtn);
  actTd.appendChild(detailBtn);
  actTd.appendChild(delBtn);
  actTd.appendChild(status);

  tr.appendChild(riskTd);
  tr.appendChild(keyTd);
  tr.appendChild(seenTd);
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
    const r = assessRisk(f.audits, f.provider);
    if (r.level === 'critical' || r.level === 'high') unrestricted++;
    if (r.billableEnabled) billable++;
  });
  const data = [
    { n: total, l: 'keys found', key: null },        // clears the filter
    { n: maps, l: 'maps-context', key: 'maps' },
    { n: audited, l: 'audited', key: 'audited' },
    { n: unrestricted, l: 'UNRESTRICTED', alert: unrestricted > 0, key: 'unrestricted' },
    { n: billable, l: 'billable reachable', alert: billable > 0, key: 'billable' }
  ];
  els.stats.innerHTML = '';
  data.forEach((d) => {
    const div = document.createElement('div');
    const active = d.key && activeStatFilter === d.key;
    div.className = 'stat clickable' + (d.alert ? ' alert' : '') + (active ? ' active' : '');
    div.title = d.key ? 'Filter to ' + d.l + ' keys (click again to clear)' : 'Show all keys';
    div.innerHTML = '<div class="n">' + d.n + '</div><div class="l">' + d.l + '</div>';
    div.addEventListener('click', () => {
      // Toggle: re-clicking the active tile (or the "keys found" total) clears it.
      activeStatFilter = active ? null : d.key;
      currentPage = 0;
      render();
    });
    els.stats.appendChild(div);
  });
}

// Risk ordering: most dangerous keys float to the top.
const RISK_RANK = { critical: 0, high: 1, restricted: 2, unknown: 3 };

// Shared pagination-bar renderer used by both the keys and unknown panels.
function renderPaginationBar(container, total, start, end, totalPages, page, size, onChange) {
  if (!container) return;
  container.innerHTML = '';
  if (total === 0) { container.hidden = true; return; }
  container.hidden = false;

  const info = document.createElement('span');
  info.className = 'pg-info';
  info.textContent = 'Showing ' + (start + 1) + '\u2013' + end + ' of ' + total;

  const nav = document.createElement('span');
  nav.className = 'pg-nav';
  const prevBtn = document.createElement('button');
  prevBtn.className = 'btn ghost small';
  prevBtn.textContent = '\u2190 Prev';
  prevBtn.disabled = page <= 0;
  prevBtn.addEventListener('click', () => onChange(page - 1, size));
  const pageLabel = document.createElement('span');
  pageLabel.className = 'pg-current';
  pageLabel.textContent = 'Page ' + (page + 1) + ' / ' + totalPages;
  const nextBtn = document.createElement('button');
  nextBtn.className = 'btn ghost small';
  nextBtn.textContent = 'Next \u2192';
  nextBtn.disabled = page >= totalPages - 1;
  nextBtn.addEventListener('click', () => onChange(page + 1, size));
  nav.appendChild(prevBtn);
  nav.appendChild(pageLabel);
  nav.appendChild(nextBtn);

  const sizeWrap = document.createElement('span');
  sizeWrap.className = 'pg-size';
  const sizeLabel = document.createElement('span');
  sizeLabel.className = 'pg-size-label';
  sizeLabel.textContent = 'Per page:';
  sizeWrap.appendChild(sizeLabel);
  [25, 50, 100, 0].forEach((s) => {
    const btn = document.createElement('button');
    btn.className = 'btn ghost small' + (size === s ? ' pg-active' : '');
    btn.textContent = s === 0 ? 'All' : String(s);
    btn.addEventListener('click', () => onChange(0, s));
    sizeWrap.appendChild(btn);
  });

  container.appendChild(info);
  container.appendChild(nav);
  container.appendChild(sizeWrap);
}

let currentFindings = [];

// Serialize renders: a full table rebuild is async (awaits storage), so two
// overlapping calls would race — each clearing the table and restoring a stale
// scroll position, which is what made the page jump up and down. Coalesce any
// call that arrives mid-render into a single follow-up pass.
let rendering = false;
let renderQueued = false;
async function render() {
  if (rendering) { renderQueued = true; return; }
  rendering = true;
  try {
    await doRender();
  } finally {
    rendering = false;
    if (renderQueued) { renderQueued = false; render(); }
  }
}

async function doRender() {
  const scrollY = window.scrollY; // preserve position across rebuilds
  const db = await getDb();
  const coll = await getCollection();
  savedKeys = new Set(coll.items.map((i) => i.key));
  currentFindings = db.findings.slice();
  const q = (els.filter.value || '').toLowerCase().trim();
  const matchesQuery = (f) => matchesFreeText(f, q);
  // Heuristic 'unknown' findings live in their own tab so they don't drown the
  // real, auditable keys.
  const known = currentFindings.filter((f) => f.provider !== 'unknown');
  const unknown = currentFindings.filter((f) => f.provider === 'unknown');
  renderUnknown(unknown, matchesQuery);
  // Read dropdown filter / sort state
  const providerVal = els.providerFilter ? els.providerFilter.value : '';
  const riskVal = els.riskFilter ? els.riskFilter.value : '';
  const statusVal = els.statusFilter ? els.statusFilter.value : '';
  const sortByVal = els.sortBy ? els.sortBy.value : 'first-seen';

  let items = known.filter((f) => {
    if (!matchesQuery(f) || !matchesStatFilter(f)) return false;
    if (providerVal && f.provider !== providerVal) return false;
    if (riskVal) {
      const rl = assessRisk(f.audits, f.provider).level;
      if (rl !== riskVal) return false;
    }
    if (statusVal === 'audited' && !(f.audits && f.audits.length)) return false;
    if (statusVal === 'not-audited' && (f.audits && f.audits.length)) return false;
    return true;
  });

  // Sorting helpers
  const loggedTs = (f) => new Date(f.firstSeen).getTime() || 0;
  const lastTs = (f) => new Date(f.lastSeen).getTime() || 0;
  const riskOf = (f) => RISK_RANK[assessRisk(f.audits, f.provider).level] ?? 3;

  let byItem, groupSort;
  if (sortByVal === 'last-seen') {
    byItem = (a, b) => lastTs(b) - lastTs(a) || a.key.localeCompare(b.key);
    const latestTs = (arr) => Math.max(...arr.map(lastTs));
    groupSort = (a, b) => latestTs(b[1]) - latestTs(a[1]) || a[0].localeCompare(b[0]);
  } else if (sortByVal === 'risk') {
    byItem = (a, b) => riskOf(a) - riskOf(b) || a.key.localeCompare(b.key);
    const bestRisk = (arr) => Math.min(...arr.map(riskOf));
    groupSort = (a, b) => bestRisk(a[1]) - bestRisk(b[1]) || a[0].localeCompare(b[0]);
  } else {
    // Default: first-seen (earliest first). Stable logged order.
    byItem = (a, b) => loggedTs(a) - loggedTs(b) || a.key.localeCompare(b.key);
    const firstLoggedTs = (arr) => Math.min(...arr.map(loggedTs));
    groupSort = (a, b) => firstLoggedTs(a[1]) - firstLoggedTs(b[1]) || a[0].localeCompare(b[0]);
  }

  // Group findings by their primary domain.
  const groups = new Map();
  items.forEach((f) => {
    const d = groupDomainOf(f);
    if (!groups.has(d)) groups.set(d, []);
    groups.get(d).push(f);
  });
  const groupArr = Array.from(groups.entries());
  groupArr.forEach(([, arr]) => arr.sort(byItem));
  groupArr.sort(groupSort);

  renderStats(known);
  els.rows.innerHTML = '';
  els.empty.style.display = items.length ? 'none' : 'block';

  // ---- Pagination: flatten groups into an ordered key list ----
  const flatKeys = [];
  const groupMeta = new Map();
  groupArr.forEach(([domain, arr], gi) => {
    groupMeta.set(domain, { arr, gi });
    arr.forEach((f) => flatKeys.push({ domain, f }));
  });

  const totalKeys = flatKeys.length;
  const effSize = pageSize === 0 ? (totalKeys || 1) : pageSize;
  const totalPages = Math.max(1, Math.ceil(totalKeys / effSize));
  if (currentPage >= totalPages) currentPage = totalPages - 1;
  if (currentPage < 0) currentPage = 0;
  const pgStart = currentPage * effSize;
  const pgEnd = Math.min(pgStart + effSize, totalKeys);
  const pageSlice = flatKeys.slice(pgStart, pgEnd);

  // Re-group the visible slice, preserving domain order
  const pageGroupOrder = [];
  const pageGroupMap = new Map();
  pageSlice.forEach(({ domain, f }) => {
    if (!pageGroupMap.has(domain)) {
      pageGroupMap.set(domain, []);
      pageGroupOrder.push(domain);
    }
    pageGroupMap.get(domain).push(f);
  });

  pageGroupOrder.forEach((domain) => {
    const { arr, gi } = groupMeta.get(domain);
    const pageFindings = pageGroupMap.get(domain);
    const collapsed = collapsedGroups.has(domain);

    // Per-domain status breakdown (full domain, not just this page's slice).
    const c = { critical: 0, high: 0, restricted: 0, closed: 0, unaudited: 0 };
    arr.forEach((f) => {
      if (!f.audits || !f.audits.length) { c.unaudited++; return; }
      const lv = assessRisk(f.audits, f.provider).level;
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
    td.colSpan = 5;

    const countText = pageFindings.length < arr.length
      ? pageFindings.length + ' of ' + arr.length + ' key' + (arr.length > 1 ? 's' : '')
      : arr.length + ' key' + (arr.length > 1 ? 's' : '');

    const left = document.createElement('div');
    left.className = 'gh-left';
    left.innerHTML =
      '<span class="gh-toggle">' + (collapsed ? '▶' : '▼') + '</span>' +
      '<span class="gh-seq">#' + (gi + 1) + '</span>' +
      '<span class="gh-domain">' + esc(domain) + '</span>' +
      '<span class="gh-count">' + countText + '</span>' +
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

    const bar = document.createElement('div');
    bar.className = 'gh-bar';
    bar.appendChild(left);
    bar.appendChild(right);
    td.appendChild(bar);
    hdr.appendChild(td);
    hdr.addEventListener('click', () => {
      if (collapsed) collapsedGroups.delete(domain); else collapsedGroups.add(domain);
      saveCollapsed();
      render();
    });
    els.rows.appendChild(hdr);
    if (collapsed) return;

    pageFindings.forEach((f) => {
      els.rows.appendChild(buildRow(f));
      if (expanded.has(f.id)) {
        const dr = document.createElement('tr');
        dr.className = 'detail-row';
        dr.appendChild(detailTable(f));
        els.rows.appendChild(dr);
      }
    });
  });

  renderPaginationBar(els.paginationBar, totalKeys, pgStart, pgEnd, totalPages,
    currentPage, pageSize, (page, size) => {
      currentPage = page; pageSize = size;
      if (els.pageSizeSelect) els.pageSizeSelect.value = String(size);
      render();
    });

  window.scrollTo(0, scrollY); // keep the user where they were
}

// ---- Unknown / heuristic tab ----------------------------------------------

const tabBtns = document.querySelectorAll('.tab-btn');
const keysPanel = document.getElementById('keysPanel');
const unknownPanel = document.getElementById('unknownPanel');
const unknownList = document.getElementById('unknownList');
const unknownEmpty = document.getElementById('unknownEmpty');
const unknownStats = document.getElementById('unknownStats');
const unknownCountEl = document.getElementById('unknownCount');
const ukPaginationBar = document.getElementById('unknownPagination');
const ukCollapsedGroups = new Set(); // domains collapsed in the unknown tab
const ukRefOpen = new Set();         // finding ids whose code reference is expanded

tabBtns.forEach((btn) => {
  btn.addEventListener('click', () => {
    tabBtns.forEach((b) => b.classList.toggle('active', b === btn));
    const tab = btn.dataset.tab;
    keysPanel.hidden = tab !== 'keys';
    unknownPanel.hidden = tab !== 'unknown';
  });
});

// Strip a leading "reason — " (or "in foo.js — reason — ") prefix so we can show
// the matched reason as a label and the code window as a reference separately.
function splitReason(snippet) {
  const s = String(snippet || '');
  const i = s.indexOf(' — ');
  if (i === -1) return { reason: '', ref: s };
  return { reason: s.slice(0, i), ref: s.slice(i + 3) };
}

// A short "type" label from the match reason (the long "assigned to" form is
// trimmed to just the field name).
function ukTypeLabel(reason) {
  if (!reason) return 'match';
  const m = /^secret-like value assigned to "(.+)"$/.exec(reason);
  return m ? 'assigned: ' + m[1] : reason;
}

// One compact row: type · key · sources · toggleable code reference.
function buildUnknownRow(f) {
  const { reason, ref } = splitReason(f.snippet);
  const row = document.createElement('div');
  row.className = 'uk-row';

  const head = document.createElement('div');
  head.className = 'uk-rowhead';

  const type = document.createElement('span');
  type.className = 'uk-type';
  type.textContent = ukTypeLabel(reason);
  type.title = reason || '';
  head.appendChild(type);

  const keyEl = document.createElement('span');
  keyEl.className = 'uk-key mono';
  keyEl.textContent = f.key.length > 44 ? f.key.slice(0, 44) + '…' : f.key;
  keyEl.title = f.key;
  head.appendChild(keyEl);

  const copyBtn = document.createElement('button');
  copyBtn.className = 'btn ghost small';
  copyBtn.textContent = 'copy';
  copyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(f.key);
    copyBtn.textContent = 'copied';
    setTimeout(() => (copyBtn.textContent = 'copy'), 1200);
  });
  head.appendChild(copyBtn);

  (f.sources || []).forEach((s) => {
    const t = document.createElement('span');
    t.className = 'tag src-' + s;
    t.textContent = s;
    head.appendChild(t);
  });

  const spacer = document.createElement('span');
  spacer.className = 'uk-spacer';
  head.appendChild(spacer);

  const open = ukRefOpen.has(f.id);
  let body = null;
  if (ref || (f.pageUrls || []).length) {
    const refBtn = document.createElement('button');
    refBtn.className = 'btn ghost small';
    refBtn.textContent = open ? 'hide ref ▾' : 'reference ▸';
    refBtn.addEventListener('click', () => {
      if (ukRefOpen.has(f.id)) ukRefOpen.delete(f.id); else ukRefOpen.add(f.id);
      renderUnknownCurrent();
    });
    head.appendChild(refBtn);
  }

  const delBtn = document.createElement('button');
  delBtn.className = 'btn danger small';
  delBtn.textContent = 'Delete';
  delBtn.addEventListener('click', async () => { await deleteFinding(f.id); render(); });
  head.appendChild(delBtn);

  row.appendChild(head);

  if (open) {
    body = document.createElement('div');
    body.className = 'uk-rowbody';
    const links = sourceLinksEl(f);
    if (links) body.appendChild(links);
    if (ref) {
      const pre = document.createElement('pre');
      pre.className = 'uk-ref';
      pre.textContent = ref;
      body.appendChild(pre);
    }
    row.appendChild(body);
  }
  return row;
}

// Re-render the unknown tab from the last-known data without a full dashboard
// rebuild (used by in-tab toggles so the page doesn't jump).
let lastUnknown = [];
function renderUnknownCurrent() {
  const q = (els.filter.value || '').toLowerCase().trim();
  const matchesQuery = (f) => matchesFreeText(f, q);
  renderUnknown(lastUnknown, matchesQuery);
}

function renderUnknown(unknown, matchesQuery) {
  lastUnknown = unknown;
  if (unknownCountEl) unknownCountEl.textContent = unknown.length ? String(unknown.length) : '';
  if (!unknownList) return;
  const items = unknown.filter(matchesQuery);

  // Group by domain (most matches first) — third-party scripts cluster here.
  const groups = new Map();
  items.forEach((f) => {
    const d = groupDomainOf(f);
    if (!groups.has(d)) groups.set(d, []);
    groups.get(d).push(f);
  });
  const groupArr = Array.from(groups.entries())
    .sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));

  // Sort within each group before flattening for stable pagination order.
  groupArr.forEach(([, list]) => {
    list.sort((a, b) => (new Date(b.lastSeen) - new Date(a.lastSeen)) || a.key.localeCompare(b.key));
  });

  unknownStats.innerHTML =
    '<div class="stat"><div class="n">' + items.length + '</div><div class="l">matches</div></div>' +
    '<div class="stat"><div class="n">' + groupArr.length + '</div><div class="l">sites</div></div>';

  unknownList.innerHTML = '';
  unknownEmpty.style.display = items.length ? 'none' : 'block';

  // ---- Pagination for the unknown tab ----
  const flatUk = [];
  const ukGroupMeta = new Map();
  groupArr.forEach(([domain, list]) => {
    ukGroupMeta.set(domain, list);
    list.forEach((f) => flatUk.push({ domain, f }));
  });

  const totalUk = flatUk.length;
  const effUkSize = ukPageSize === 0 ? (totalUk || 1) : ukPageSize;
  const totalUkPages = Math.max(1, Math.ceil(totalUk / effUkSize));
  if (ukCurrentPage >= totalUkPages) ukCurrentPage = totalUkPages - 1;
  if (ukCurrentPage < 0) ukCurrentPage = 0;
  const ukStart = ukCurrentPage * effUkSize;
  const ukEnd = Math.min(ukStart + effUkSize, totalUk);
  const ukSlice = flatUk.slice(ukStart, ukEnd);

  const ukPageOrder = [];
  const ukPageMap = new Map();
  ukSlice.forEach(({ domain, f }) => {
    if (!ukPageMap.has(domain)) {
      ukPageMap.set(domain, []);
      ukPageOrder.push(domain);
    }
    ukPageMap.get(domain).push(f);
  });

  ukPageOrder.forEach((domain) => {
    const fullList = ukGroupMeta.get(domain);
    const pageList = ukPageMap.get(domain);
    const collapsed = ukCollapsedGroups.has(domain);

    const group = document.createElement('div');
    group.className = 'uk-group';

    const hdr = document.createElement('div');
    hdr.className = 'uk-group-hdr';
    const left = document.createElement('div');
    left.className = 'uk-group-left';
    const ukCountText = pageList.length < fullList.length
      ? pageList.length + ' of ' + fullList.length
      : String(fullList.length);
    left.innerHTML = '<span class="gh-toggle">' + (collapsed ? '▶' : '▼') + '</span>' +
      '<span class="uk-group-domain">' + esc(domain) + '</span>' +
      '<span class="uk-group-count">' + ukCountText + '</span>';
    hdr.appendChild(left);

    const right = document.createElement('div');
    right.className = 'uk-group-right';
    if (domain && domain !== 'unknown') {
      const ignoreBtn = document.createElement('button');
      ignoreBtn.className = 'btn ghost small';
      ignoreBtn.textContent = '🚫 Ignore site';
      ignoreBtn.title = 'Stop scanning ' + domain + ' and remove its findings';
      ignoreBtn.addEventListener('click', (e) => { e.stopPropagation(); ignoreDomain(domain); });
      right.appendChild(ignoreBtn);
    }
    const delAll = document.createElement('button');
    delAll.className = 'btn danger small';
    delAll.textContent = 'Delete ' + fullList.length;
    delAll.addEventListener('click', async (e) => {
      e.stopPropagation();
      if (!window.confirm('Delete all ' + fullList.length + ' heuristic matches from ' + domain + '?')) return;
      for (const f of fullList) await deleteFinding(f.id);
      render();
    });
    right.appendChild(delAll);
    hdr.appendChild(right);

    hdr.addEventListener('click', () => {
      if (ukCollapsedGroups.has(domain)) ukCollapsedGroups.delete(domain);
      else ukCollapsedGroups.add(domain);
      renderUnknownCurrent();
    });
    group.appendChild(hdr);

    if (!collapsed) {
      const bodyWrap = document.createElement('div');
      bodyWrap.className = 'uk-group-body';
      pageList.forEach((f) => bodyWrap.appendChild(buildUnknownRow(f)));
      group.appendChild(bodyWrap);
    }
    unknownList.appendChild(group);
  });

  renderPaginationBar(ukPaginationBar, totalUk, ukStart, ukEnd, totalUkPages,
    ukCurrentPage, ukPageSize, (page, size) => {
      ukCurrentPage = page; ukPageSize = size; renderUnknownCurrent();
    });
}

// How many keys to audit at once. Each key itself fans out to ~14 probes
// (internally capped at 5 concurrent), so this multiplies that — keep it modest
// to stay under Google's rate limits.
const KEY_AUDIT_CONCURRENCY = 4;

// Run audits over a list of findings with bounded concurrency, updating progress
// as each completes. Returns the number audited.
async function auditMany(findings, onProgress) {
  // Skip heuristic 'unknown' findings — there's no provider endpoint for them.
  findings = findings.filter((f) => f.provider !== 'unknown');
  auditAborted = false;
  const total = findings.length;
  let done = 0;
  let idx = 0;
  async function worker() {
    while (idx < findings.length && !auditAborted) {
      const f = findings[idx++];
      // One key's failure (audit error, storage hiccup) must not abort the whole
      // batch — swallow per-key and keep going.
      try {
        const updated = await runAudit(f.id, null);
        if (updated && savedKeys.has(updated.key)) await saveToCollection(updated);
      } catch (e) { /* skip this key, continue the batch */ }
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
  auditing++;
  showProgressDeterminate(0, total, 'Auditing domain 0 / ' + total);
  showCancelBtn();
  let done = 0;
  try {
    done = await auditMany(findings, (d, t) => {
      btn.textContent = 'Auditing ' + d + '/' + t + '…';
      showProgressDeterminate(d, t, 'Audited ' + d + ' / ' + t);
    });
  } finally {
    auditing--;
    hideProgress();
    btn.disabled = false;
    btn.textContent = label;
  }
  render();
  const suffix = auditAborted ? ' (cancelled)' : '';
  toast('Audited ' + done + ' keys in this domain' + suffix);
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
    const risk = assessRisk(f.audits, f.provider).level;
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
  auditing++;
  showProgressDeterminate(0, total, 'Auditing 0 / ' + total);
  showCancelBtn();
  let done = 0;
  try {
    done = await auditMany(queue, (d, t) => {
      btn.textContent = 'Auditing ' + d + '/' + t + '…';
      showProgressDeterminate(d, t, 'Audited ' + d + ' / ' + t);
    });
  } finally {
    auditing--;
    hideProgress();
    btn.disabled = false;
    btn.textContent = 'Audit all';
  }
  render();
  const suffix = auditAborted ? ' (cancelled)' : '';
  toast('Audited ' + done + ' keys' + suffix);
});

els.filter.addEventListener('input', () => { currentPage = 0; ukCurrentPage = 0; render(); });

// Filter / sort dropdowns — all reset to page 0 on change.
['providerFilter', 'riskFilter', 'statusFilter', 'sortBy'].forEach((id) => {
  if (els[id]) els[id].addEventListener('change', () => { currentPage = 0; render(); });
});
if (els.pageSizeSelect) {
  els.pageSizeSelect.addEventListener('change', () => {
    pageSize = parseInt(els.pageSizeSelect.value, 10) || 0;
    currentPage = 0;
    render();
  });
}

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

// Re-render if storage changes while the dashboard is open. A batch audit fires
// one storage write per key (times every saved key), so re-rendering on each
// would thrash the whole table dozens of times a second. Debounce, and skip
// entirely while an audit is running — those flows repaint themselves when done.
let autoRenderTimer = null;
function scheduleAutoRender() {
  clearTimeout(autoRenderTimer);
  autoRenderTimer = setTimeout(() => {
    autoRenderTimer = null;
    if (auditing === 0) render();
  }, 200);
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && (changes.gaks_db || changes.gaks_collection)) scheduleAutoRender();
});

loadIgnore();
loadCollapsed().then(render);
