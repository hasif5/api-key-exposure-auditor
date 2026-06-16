import { getDb, findingId, getCollection, saveToCollection, removeFromCollection } from '../lib/store.js';
import { assessRisk } from '../lib/providers.js';

const CLASS_HELP = {
  'enabled': 'Reachable with NO Referer — works from anywhere (exploitable)',
  'restricted-referer': 'Blocked by an HTTP-referrer restriction',
  'restricted-ip': 'Blocked by an IP-address restriction',
  'api-not-enabled': 'This API is not enabled / not allowed for this key',
  'invalid-key': 'Key is invalid, expired, or revoked',
  'over-quota': 'Valid, but a quota/billing limit was hit',
  'inconclusive': 'Could not be determined server-side',
  'denied': 'Rejected for another reason',
  'error': 'Network/transport error'
};

const PROVIDER_LABELS = { google: 'Google', openai: 'OpenAI', anthropic: 'Anthropic', openrouter: 'OpenRouter', xai: 'xAI', twilio: 'Twilio' };
function providerBadge(id) {
  id = id || 'google';
  const span = document.createElement('span');
  span.className = 'prov-badge prov-' + id;
  span.textContent = PROVIDER_LABELS[id] || id;
  return span;
}

let savedKeys = new Set();

const els = {
  origin: document.getElementById('origin'),
  list: document.getElementById('list'),
  empty: document.getElementById('emptyMsg'),
  count: document.getElementById('count'),
  ack: document.getElementById('ackChk'),
  gen: document.getElementById('genChk'),
  rescan: document.getElementById('rescanBtn')
};

let activeTab = null;
let auditing = new Set();
const popupExpanded = new Set();

function openDashboard() {
  chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/dashboard.html') });
}
document.getElementById('dashBtn').addEventListener('click', openDashboard);
document.getElementById('dashBtn2').addEventListener('click', openDashboard);

function openCollection() {
  chrome.tabs.create({ url: chrome.runtime.getURL('collection/collection.html') });
}
document.getElementById('collBtn').addEventListener('click', openCollection);

els.rescan.addEventListener('click', async () => {
  if (!activeTab) return;
  try {
    await chrome.tabs.sendMessage(activeTab.id, { type: 'GAKS_RESCAN' });
  } catch (e) { /* content script may not be present */ }
  setTimeout(render, 700);
});

// Persisted toggles.
chrome.storage.local.get(['gaks_ack', 'gaks_gen']).then((s) => {
  els.ack.checked = !!s.gaks_ack;
  els.gen.checked = s.gaks_gen !== false; // billable probes ON by default
  refreshAuditButtons();
});
els.ack.addEventListener('change', () => {
  chrome.storage.local.set({ gaks_ack: els.ack.checked });
  refreshAuditButtons();
});
els.gen.addEventListener('change', () => {
  chrome.storage.local.set({ gaks_gen: els.gen.checked });
});

function refreshAuditButtons() {
  const enabled = els.ack.checked;
  document.querySelectorAll('.audit-btn').forEach((b) => {
    if (!auditing.has(b.dataset.id)) b.disabled = !enabled;
  });
}

function classLabel(c) {
  return c.replace(/-/g, ' ');
}

function renderFinding(f, collapsible) {
  const collapsed = collapsible && !popupExpanded.has(f.id);
  const card = document.createElement('div');
  card.className = 'card' + (collapsed ? ' collapsed' : '');

  // -- Header row (always visible) --
  const top = document.createElement('div');
  top.className = 'card-top';
  top.appendChild(providerBadge(f.provider));
  const keyEl = document.createElement('span');
  keyEl.className = 'keyline';
  keyEl.textContent = collapsed ? f.key.slice(0, 18) + '…' : f.key;
  if (collapsed) keyEl.title = f.key;
  top.appendChild(keyEl);

  if (collapsible) {
    const r = assessRisk(f.audits, f.provider);
    const riskTag = document.createElement('span');
    riskTag.className = 'risk-pill ' + r.level;
    riskTag.textContent = r.level === 'critical' ? 'CRITICAL'
      : r.level === 'high' ? 'UNRESTRICTED'
      : r.level === 'restricted' ? 'RESTRICTED'
      : f.audits && f.audits.length ? 'UNKNOWN' : 'not audited';
    top.appendChild(riskTag);

    const arrow = document.createElement('span');
    arrow.className = 'card-toggle';
    arrow.textContent = collapsed ? '▸' : '▾';
    top.appendChild(arrow);

    top.style.cursor = 'pointer';
    top.addEventListener('click', (e) => {
      if (e.target.closest('.copy-btn')) return;
      if (collapsed) popupExpanded.add(f.id); else popupExpanded.delete(f.id);
      render();
    });
  }

  if (!collapsed) {
    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-btn';
    copyBtn.textContent = 'copy';
    copyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(f.key);
      copyBtn.textContent = 'copied';
      setTimeout(() => (copyBtn.textContent = 'copy'), 1200);
    });
    top.appendChild(copyBtn);
  }
  card.appendChild(top);

  if (collapsed) return card;

  // -- Expanded body --
  const tags = document.createElement('div');
  tags.className = 'tags';
  if (f.mapsContext) {
    const t = document.createElement('span');
    t.className = 'tag maps';
    t.textContent = 'Maps context';
    tags.appendChild(t);
  }
  (f.sources || []).forEach((s) => {
    const t = document.createElement('span');
    t.className = 'tag src-' + s;
    t.textContent = s;
    tags.appendChild(t);
  });
  card.appendChild(tags);

  const riskBanner = document.createElement('div');
  riskBanner.className = 'risk-banner';
  updateRiskBanner(riskBanner, f.audits, f.provider);
  card.appendChild(riskBanner);

  if (f.snippet) {
    const sn = document.createElement('div');
    sn.className = 'snippet';
    sn.textContent = f.snippet;
    card.appendChild(sn);
  }

  const auditBtn = document.createElement('button');
  auditBtn.className = 'btn small audit-btn';
  auditBtn.dataset.id = f.id;
  auditBtn.textContent = f.audits && f.audits.length ? 'Re-audit key' : 'Audit key';
  auditBtn.disabled = !els.ack.checked;
  card.appendChild(auditBtn);

  const saveBtn = document.createElement('button');
  saveBtn.className = 'save-btn';
  function paintSave() {
    const on = savedKeys.has(f.key);
    saveBtn.textContent = on ? '★ Saved' : '☆ Save';
    saveBtn.classList.toggle('on', on);
    saveBtn.title = on ? 'Remove from collection' : 'Save to my collection';
  }
  paintSave();
  saveBtn.addEventListener('click', async () => {
    saveBtn.disabled = true;
    try {
      if (savedKeys.has(f.key)) {
        await removeFromCollection(f.key);
        savedKeys.delete(f.key);
      } else {
        await saveToCollection(f);
        savedKeys.add(f.key);
      }
      paintSave();
    } finally {
      saveBtn.disabled = false;
    }
  });
  card.appendChild(saveBtn);

  const status = document.createElement('span');
  status.className = 'spinner';
  status.style.marginLeft = '8px';
  card.appendChild(status);

  const auditsBox = document.createElement('div');
  auditsBox.className = 'audits' + (f.audits && f.audits.length ? ' show' : '');
  renderAudits(auditsBox, f.audits || []);
  card.appendChild(auditsBox);

  auditBtn.addEventListener('click', async () => {
    auditing.add(f.id);
    auditBtn.disabled = true;
    status.textContent = 'auditing…';
    try {
      const resp = await chrome.runtime.sendMessage({
        type: 'GAKS_AUDIT',
        findingId: f.id,
        includeGenerate: els.gen.checked
      });
      if (resp && resp.ok && resp.finding) {
        f.audits = resp.finding.audits;
        auditsBox.classList.add('show');
        renderAudits(auditsBox, f.audits);
        updateRiskBanner(riskBanner, f.audits, f.provider);
        if (savedKeys.has(f.key)) saveToCollection(f);
        auditBtn.textContent = 'Re-audit key';
        status.textContent = '';
      } else {
        status.textContent = 'audit failed';
      }
    } catch (e) {
      status.textContent = 'audit error';
    } finally {
      auditing.delete(f.id);
      auditBtn.disabled = !els.ack.checked;
    }
  });

  return card;
}

function updateRiskBanner(el, audits, provider) {
  const r = assessRisk(audits, provider);
  el.className = 'risk-banner';
  if (!audits || !audits.length) return;
  if (r.level === 'critical' || r.level === 'high' || r.level === 'restricted') {
    el.classList.add('show', r.level);
    const head = r.level === 'critical' ? (r.bypass ? '⚠ CRITICAL — REFERRER BYPASS (billable)' : '⚠ CRITICAL — UNRESTRICTED & BILLABLE')
      : r.level === 'high' ? (r.bypass ? '⚠ REFERRER RESTRICTION BYPASSED' : '⚠ UNRESTRICTED KEY')
      : '✓ Restricted (referrer/IP locked)';
    const sub = r.enabledServices.length ? 'reachable (no Referer): ' + r.enabledServices.join(', ') : r.label;
    el.innerHTML = head + '<span class="sub">' + sub + '</span>';
  }
}

function renderAudits(box, audits) {
  box.innerHTML = '';
  audits.forEach((a) => {
    const row = document.createElement('div');
    row.className = 'audit-row';

    const svc = document.createElement('span');
    svc.className = 'audit-svc';
    svc.textContent = a.service + ' · ' + a.endpoint;

    const detail = document.createElement('span');
    detail.className = 'audit-detail';
    detail.textContent = (a.httpStatus ? 'HTTP ' + a.httpStatus + ' — ' : '') + (a.detail || a.apiStatus || '');

    const pills = document.createElement('span');
    const pill = document.createElement('span');
    pill.className = 'pill ' + a.classification;
    pill.textContent = classLabel(a.classification);
    pill.title = CLASS_HELP[a.classification] || classLabel(a.classification);
    pills.appendChild(pill);
    if (a.billable) {
      const bp = document.createElement('span');
      bp.className = 'pill billable';
      bp.textContent = '$';
      bp.title = a.costNote || 'Billable';
      bp.style.marginLeft = '3px';
      pills.appendChild(bp);
    }

    row.appendChild(svc);
    row.appendChild(detail);
    row.appendChild(pills);
    box.appendChild(row);
  });
}

async function getTabKeys() {
  if (!activeTab) return new Set();
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'GAKS_GET_TAB_KEYS', tabId: activeTab.id });
    if (resp && resp.ok) return new Set(resp.keys);
  } catch (e) { /* worker waking up */ }
  return new Set();
}

async function render() {
  const db = await getDb();
  const coll = await getCollection();
  savedKeys = new Set(coll.items.map((i) => i.key));
  let origin = '';
  try { origin = activeTab && activeTab.url ? new URL(activeTab.url).origin : ''; } catch (e) { origin = ''; }
  els.origin.textContent = origin || 'this page';

  // Show the keys actually associated with this tab (what the badge counts),
  // which includes keys found in cross-origin frames / network / scripts.
  // Fall back to an exact-origin match so nothing is missed if the tab-key
  // map was lost (e.g. right after the worker restarted).
  const tabKeySet = await getTabKeys();
  const items = db.findings.filter((f) =>
    tabKeySet.has(f.key) || (origin && (f.origins || []).includes(origin)));
  els.list.innerHTML = '';
  if (!items.length) {
    const p = document.createElement('p');
    p.className = 'empty';
    p.textContent = 'No API keys detected on this page yet.';
    els.list.appendChild(p);
  } else {
    const rank = { critical: 0, high: 1, restricted: 2, unknown: 3 };
    const collapsible = items.length > 1;
    items
      .sort((a, b) =>
        (rank[assessRisk(a.audits, a.provider).level] - rank[assessRisk(b.audits, b.provider).level]) ||
        (b.mapsContext - a.mapsContext) || a.key.localeCompare(b.key))
      .forEach((f) => els.list.appendChild(renderFinding(f, collapsible)));
  }
  els.count.textContent = items.length + (items.length === 1 ? ' key' : ' keys');
}

async function init() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  activeTab = tabs[0] || null;
  await render();
  // Findings can arrive shortly after the popup opens (async scans).
  setTimeout(render, 1200);
}

init();
