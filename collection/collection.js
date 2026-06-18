import {
  getCollection, removeFromCollection, setCollectionNote,
  setCollectionAudits, clearCollection, importCollection
} from '../lib/store.js';
import { assessRisk } from '../lib/providers.js';

const CLASS_HELP = {
  'enabled': 'Reachable with NO Referer — works from anywhere (exploitable)',
  'restricted-referer': 'Blocked by an HTTP-referrer restriction',
  'restricted-ip': 'Blocked by an IP-address restriction',
  'api-not-enabled': 'This API is not enabled / not allowed for this key',
  'invalid-key': 'Key is invalid, expired, or revoked',
  'over-quota': 'Valid, but a quota/billing limit was hit',
  'inconclusive': 'Could not be determined from a server-side request',
  'denied': 'Rejected for another reason',
  'error': 'Network/transport error'
};

const PROVIDER_LABELS = { google: 'Google', openai: 'OpenAI', anthropic: 'Anthropic', openrouter: 'OpenRouter', xai: 'xAI', twilio: 'Twilio', aws: 'AWS', github: 'GitHub', unknown: 'Unknown' };
function providerBadge(id) {
  id = id || 'google';
  const span = document.createElement('span');
  span.className = 'prov-badge prov-' + id;
  span.textContent = PROVIDER_LABELS[id] || id;
  return span;
}

const els = {
  list: document.getElementById('list'),
  empty: document.getElementById('emptyMsg'),
  filter: document.getElementById('filter'),
  gen: document.getElementById('genChk'),
  toast: document.getElementById('toast')
};

const RISK_RANK = { critical: 0, high: 1, restricted: 2, unknown: 3 };
const noteTimers = new Map();

function toast(msg) {
  els.toast.textContent = msg;
  els.toast.classList.add('show');
  setTimeout(() => els.toast.classList.remove('show'), 2000);
}

function esc(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function classLabel(c) { return c.replace(/-/g, ' '); }
function fmtTime(iso) { try { return new Date(iso).toLocaleString(); } catch (e) { return iso || ''; } }

function riskBadge(level) {
  const span = document.createElement('span');
  span.className = 'risk ' + level;
  span.textContent = level === 'critical' ? 'CRITICAL'
    : level === 'high' ? 'UNRESTRICTED'
    : level === 'restricted' ? 'RESTRICTED' : 'UNKNOWN';
  return span;
}

function buildCard(item) {
  const risk = assessRisk(item.audits, item.provider);
  const card = document.createElement('div');
  card.className = 'card risk-' + risk.level;

  // Top row: risk + remove
  const top = document.createElement('div');
  top.className = 'row between';
  top.appendChild(riskBadge(risk.level));
  const removeBtn = document.createElement('button');
  removeBtn.className = 'icon-btn';
  removeBtn.title = 'Remove from collection';
  removeBtn.textContent = '✕ remove';
  removeBtn.addEventListener('click', async () => {
    await removeFromCollection(item.key);
    render();
    toast('Removed from collection');
  });
  top.appendChild(removeBtn);
  card.appendChild(top);

  // Key + copy
  const keyRow = document.createElement('div');
  keyRow.className = 'row';
  keyRow.appendChild(providerBadge(item.provider));
  const key = document.createElement('span');
  key.className = 'key';
  key.textContent = item.key;
  const copy = document.createElement('button');
  copy.className = 'copy-btn';
  copy.textContent = 'copy';
  copy.addEventListener('click', () => { navigator.clipboard.writeText(item.key); toast('Key copied'); });
  keyRow.appendChild(key);
  keyRow.appendChild(copy);
  card.appendChild(keyRow);

  // Tags
  const tags = document.createElement('div');
  tags.className = 'tags';
  if (item.mapsContext) { const t = document.createElement('span'); t.className = 'tag maps'; t.textContent = 'Maps context'; tags.appendChild(t); }
  (item.sources || []).forEach((s) => { const t = document.createElement('span'); t.className = 'tag'; t.textContent = s; tags.appendChild(t); });
  card.appendChild(tags);

  // Origins + saved time
  const meta = document.createElement('div');
  meta.className = 'meta';
  const origins = item.origins || [];
  meta.innerHTML = (origins.length ? esc(origins.join(', ')) : 'origin unknown') +
    '<br>saved ' + esc(fmtTime(item.savedAt)) +
    (item.updatedAt && item.updatedAt !== item.savedAt ? ' · updated ' + esc(fmtTime(item.updatedAt)) : '');
  card.appendChild(meta);

  // Audit summary
  const summary = document.createElement('div');
  summary.className = 'summary';
  if (item.audits && item.audits.length) {
    item.audits.forEach((a) => {
      const p = document.createElement('span');
      p.className = 'pill ' + a.classification;
      p.title = (CLASS_HELP[a.classification] || classLabel(a.classification)) +
        '\n\n' + a.service + ' · ' + a.endpoint + ' — HTTP ' + a.httpStatus +
        (a.billable ? ' · billable' : ' · free') + (a.detail ? '\n' + a.detail : '');
      p.textContent = a.service + ': ' + classLabel(a.classification);
      summary.appendChild(p);
    });
  } else {
    const p = document.createElement('span'); p.className = 'pill'; p.textContent = 'not audited'; summary.appendChild(p);
  }
  card.appendChild(summary);

  // Note
  const note = document.createElement('textarea');
  note.className = 'note';
  note.placeholder = 'Add a note (e.g. site, owner, disclosure status)…';
  note.value = item.note || '';
  note.addEventListener('input', () => {
    clearTimeout(noteTimers.get(item.key));
    noteTimers.set(item.key, setTimeout(() => setCollectionNote(item.key, note.value), 500));
  });
  card.appendChild(note);

  // Actions: re-audit
  const actions = document.createElement('div');
  actions.className = 'row';
  const auditBtn = document.createElement('button');
  auditBtn.className = 'btn small';
  auditBtn.textContent = (item.audits && item.audits.length) ? 'Re-audit' : 'Audit';
  const status = document.createElement('span');
  status.className = 'spinner';
  auditBtn.addEventListener('click', async () => {
    if (!window.confirm('Audit performs live API calls using this key and may incur cost. Only proceed if this is your own key. Continue?')) return;
    auditBtn.disabled = true;
    status.textContent = 'auditing…';
    try {
      const resp = await chrome.runtime.sendMessage({ type: 'GAKS_AUDIT_RAW', key: item.key, provider: item.provider, secret: item.secret, includeGenerate: els.gen.checked });
      if (resp && resp.ok) {
        await setCollectionAudits(item.key, resp.audits);
        render();
        toast('Audit complete');
      } else {
        status.textContent = 'audit failed';
      }
    } catch (e) {
      status.textContent = 'audit error';
    } finally {
      auditBtn.disabled = false;
    }
  });
  if (item.provider === 'unknown') {
    const note = document.createElement('span');
    note.className = 'hint';
    note.textContent = 'Heuristic match — cannot be auto-validated.';
    actions.appendChild(note);
  } else {
    actions.appendChild(auditBtn);
  }
  actions.appendChild(status);
  card.appendChild(actions);

  return card;
}

async function render() {
  const c = await getCollection();
  const q = (els.filter.value || '').toLowerCase().trim();
  let items = c.items.slice();
  if (q) {
    items = items.filter((i) =>
      i.key.toLowerCase().includes(q) ||
      (i.note || '').toLowerCase().includes(q) ||
      (i.origins || []).some((o) => o.toLowerCase().includes(q)));
  }
  items.sort((a, b) =>
    (RISK_RANK[assessRisk(a.audits, a.provider).level] - RISK_RANK[assessRisk(b.audits, b.provider).level]) ||
    (new Date(b.savedAt) - new Date(a.savedAt)));

  els.list.innerHTML = '';
  if (!items.length) {
    const p = document.createElement('p');
    p.className = 'empty';
    p.innerHTML = c.items.length
      ? 'No saved keys match your filter.'
      : 'Your collection is empty. Click <strong>Save</strong> on any key in the popup or dashboard to add it here.';
    els.list.appendChild(p);
    return;
  }
  items.forEach((i) => els.list.appendChild(buildCard(i)));
}

// ---- Toolbar ----
document.getElementById('dashBtn').addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/dashboard.html') });
});

document.getElementById('exportBtn').addEventListener('click', async () => {
  const c = await getCollection();
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const blob = new Blob([JSON.stringify(c, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'gaks-collection-' + stamp + '.json';
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast('Exported ' + c.items.length + ' saved keys');
});

document.getElementById('importFile').addEventListener('change', async (ev) => {
  const file = ev.target.files && ev.target.files[0];
  if (!file) return;
  try {
    const data = JSON.parse(await file.text());
    const res = await importCollection(data);
    toast('Imported / merged ' + (res ? res.merged : 0) + ' keys');
    render();
  } catch (e) {
    toast('Import failed: invalid JSON');
  }
  ev.target.value = '';
});

document.getElementById('clearBtn').addEventListener('click', async () => {
  if (!window.confirm('Remove ALL saved keys from your collection? (Auto-detected findings are not affected.)')) return;
  await clearCollection();
  render();
  toast('Collection cleared');
});

els.filter.addEventListener('input', render);

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.gaks_collection) render();
});

render();
