/*
 * site-audit.js — passive site security analysis.
 *
 * Analyzes HTTP response headers, cookies, mixed content, SRI, DOM patterns,
 * and server-side file exposure to surface common misconfigurations on visited
 * sites.  Stores per-origin reports in chrome.storage.local.
 */

const SITE_SEC_KEY = 'gaks_site_security';
let writeChain = Promise.resolve();

function nowIso() { return new Date().toISOString(); }

// ---- Header checks ---------------------------------------------------------

const HEADER_CHECKS = [
  {
    name: 'content-security-policy',
    id: 'csp',
    title: 'Missing Content-Security-Policy',
    severity: 'high',
    detail: 'No CSP header. The site has no browser-enforced defense against XSS injection.'
  },
  {
    name: 'strict-transport-security',
    id: 'hsts',
    title: 'Missing Strict-Transport-Security',
    severity: 'high',
    detail: 'No HSTS header. Browsers may allow downgrades to HTTP via man-in-the-middle attacks.'
  },
  {
    name: 'x-content-type-options',
    id: 'xcto',
    title: 'Missing X-Content-Type-Options',
    severity: 'medium',
    detail: 'Without "nosniff", browsers may MIME-sniff responses into executable content types.'
  },
  {
    name: 'x-frame-options',
    id: 'xfo',
    title: 'Missing X-Frame-Options',
    severity: 'medium',
    detail: 'No clickjacking protection. The page can be embedded in a hostile iframe.',
    skipIf(hdrs) {
      const csp = hdrs['content-security-policy'];
      return csp && /frame-ancestors/i.test(csp);
    }
  },
  {
    name: 'referrer-policy',
    id: 'referrer',
    title: 'Missing Referrer-Policy',
    severity: 'low',
    detail: 'Full URLs may leak to third-party sites via the Referer header.'
  },
  {
    name: 'permissions-policy',
    id: 'permissions',
    title: 'Missing Permissions-Policy',
    severity: 'low',
    detail: 'Camera, microphone, and geolocation are available to embedded iframes by default.'
  }
];

const HEADER_WARNINGS = [
  {
    name: 'access-control-allow-origin',
    id: 'cors-wildcard',
    test: (v) => v === '*',
    title: 'CORS allows all origins (Access-Control-Allow-Origin: *)',
    severity: 'medium',
    detail: 'Any website can read responses from this origin.'
  },
  {
    name: 'server',
    id: 'server-info',
    test: (v) => /\/[0-9]/.test(v),
    title: 'Server header discloses version info',
    severity: 'info',
    detailFn: (v) => 'Server: ' + v + ' — version details help attackers target known vulnerabilities.'
  },
  {
    name: 'x-powered-by',
    id: 'x-powered-by',
    test: () => true,
    title: 'X-Powered-By header reveals technology stack',
    severity: 'info',
    detailFn: (v) => 'X-Powered-By: ' + v
  }
];

export function analyzeHeaders(responseHeaders) {
  const hdrs = {};
  for (const h of responseHeaders) {
    hdrs[(h.name || '').toLowerCase()] = h.value || '';
  }
  const issues = [];
  for (const check of HEADER_CHECKS) {
    if (hdrs[check.name]) continue;
    if (check.skipIf && check.skipIf(hdrs)) continue;
    issues.push({
      id: 'header:' + check.id,
      category: 'headers',
      severity: check.severity,
      title: check.title,
      detail: check.detail
    });
  }
  for (const warn of HEADER_WARNINGS) {
    const val = hdrs[warn.name];
    if (!val || !warn.test(val)) continue;
    issues.push({
      id: 'header:' + warn.id,
      category: 'headers',
      severity: warn.severity,
      title: warn.title,
      detail: warn.detailFn ? warn.detailFn(val) : warn.detail
    });
  }
  return issues;
}

// ---- Cookie checks ---------------------------------------------------------

export function analyzeCookies(cookies, isHttps) {
  const issues = [];
  if (!cookies || !cookies.length) return issues;

  const noSecure = cookies.filter((c) => isHttps && !c.secure);
  const noHttpOnly = cookies.filter((c) => !c.httpOnly);
  const noSameSite = cookies.filter((c) => !c.sameSite || c.sameSite === 'unspecified');

  if (noSecure.length) {
    issues.push({
      id: 'cookie:no-secure',
      category: 'cookies',
      severity: 'high',
      title: noSecure.length + ' of ' + cookies.length + ' cookie' + (cookies.length > 1 ? 's' : '') + ' missing Secure flag',
      detail: 'These cookies can be intercepted over unencrypted HTTP: ' +
        noSecure.map((c) => c.name).join(', ')
    });
  }
  if (noHttpOnly.length) {
    issues.push({
      id: 'cookie:no-httponly',
      category: 'cookies',
      severity: 'medium',
      title: noHttpOnly.length + ' of ' + cookies.length + ' cookie' + (cookies.length > 1 ? 's' : '') + ' missing HttpOnly flag',
      detail: 'JavaScript (and XSS attacks) can read these cookies: ' +
        noHttpOnly.map((c) => c.name).join(', ')
    });
  }
  if (noSameSite.length) {
    issues.push({
      id: 'cookie:no-samesite',
      category: 'cookies',
      severity: 'medium',
      title: noSameSite.length + ' of ' + cookies.length + ' cookie' + (cookies.length > 1 ? 's' : '') + ' missing SameSite attribute',
      detail: 'Vulnerable to cross-site request forgery (CSRF): ' +
        noSameSite.map((c) => c.name).join(', ')
    });
  }
  return issues;
}

// ---- Mixed content / transport checks --------------------------------------

export function analyzeMixedContent(data) {
  const issues = [];
  if (!data) return issues;

  if (data.pageIsHttp) {
    issues.push({
      id: 'transport:no-https',
      category: 'mixed-content',
      severity: 'high',
      title: 'Page served over plain HTTP',
      detail: 'All traffic is unencrypted. Credentials, cookies, and page content can be intercepted or modified in transit.'
    });
  }
  if (data.httpResources && data.httpResources.length) {
    const n = data.httpResources.length;
    issues.push({
      id: 'mixed:resources',
      category: 'mixed-content',
      severity: 'medium',
      title: n + ' HTTP resource' + (n > 1 ? 's' : '') + ' loaded on HTTPS page',
      detail: data.httpResources.slice(0, 5).join('\n') +
        (n > 5 ? '\n…and ' + (n - 5) + ' more' : '')
    });
  }
  if (data.insecureForms && data.insecureForms.length) {
    const n = data.insecureForms.length;
    issues.push({
      id: 'mixed:forms',
      category: 'mixed-content',
      severity: 'high',
      title: n + ' form' + (n > 1 ? 's' : '') + ' posting to HTTP',
      detail: 'Form data may be intercepted in transit: ' +
        data.insecureForms.slice(0, 3).join(', ')
    });
  }
  return issues;
}

// ---- SRI checks ------------------------------------------------------------

export function analyzeSri(scripts, links) {
  const issues = [];

  const riskyScripts = (scripts || []).filter((s) => s.crossOrigin && !s.hasIntegrity);
  if (riskyScripts.length) {
    const n = riskyScripts.length;
    issues.push({
      id: 'sri:scripts',
      category: 'sri',
      severity: 'medium',
      title: n + ' third-party script' + (n > 1 ? 's' : '') + ' loaded without integrity check',
      detail: 'If the CDN is compromised, attackers can inject code:\n' +
        riskyScripts.slice(0, 5).map((s) => s.src).join('\n') +
        (n > 5 ? '\n…and ' + (n - 5) + ' more' : '')
    });
  }
  const riskyLinks = (links || []).filter((l) => l.crossOrigin && !l.hasIntegrity);
  if (riskyLinks.length) {
    const n = riskyLinks.length;
    issues.push({
      id: 'sri:links',
      category: 'sri',
      severity: 'low',
      title: n + ' third-party stylesheet' + (n > 1 ? 's' : '') + ' without integrity check',
      detail: 'CSS injection can exfiltrate data:\n' +
        riskyLinks.slice(0, 5).map((l) => l.href).join('\n') +
        (n > 5 ? '\n…and ' + (n - 5) + ' more' : '')
    });
  }
  return issues;
}

// ---- DOM pattern checks ----------------------------------------------------

export function analyzeDomPatterns(counts) {
  const issues = [];
  if (!counts) return issues;
  if (counts.eval > 0) {
    issues.push({
      id: 'dom:eval',
      category: 'dom',
      severity: 'medium',
      title: 'eval() called ' + counts.eval + ' time' + (counts.eval > 1 ? 's' : ''),
      detail: 'eval() executes arbitrary strings as code — a major XSS vector if the input includes user-controlled data.'
    });
  }
  if (counts.documentWrite > 0) {
    issues.push({
      id: 'dom:document-write',
      category: 'dom',
      severity: 'medium',
      title: 'document.write() called ' + counts.documentWrite + ' time' + (counts.documentWrite > 1 ? 's' : ''),
      detail: 'document.write() can inject attacker-controlled HTML. Modern DOM APIs are safer.'
    });
  }
  return issues;
}

// ---- Server exposure probes ------------------------------------------------

const EXPOSURE_PROBES = [
  { path: '/.git/HEAD', sig: /^ref:\s+refs\//, severity: 'critical', title: 'Git repository exposed (.git/HEAD)' },
  { path: '/.git/config', sig: /\[core\]|\[remote/, severity: 'critical', title: 'Git config exposed (.git/config)' },
  { path: '/.svn/entries', sig: /^(?:\d+\s*\n|dir\n)/m, severity: 'critical', title: 'SVN repository exposed (.svn/entries)' },
  { path: '/phpinfo.php', sig: /phpinfo\(\)|PHP Version|<title>phpinfo/i, severity: 'high', title: 'phpinfo() page exposed' },
  { path: '/server-status', sig: /Apache Server Status/i, severity: 'high', title: 'Apache server-status exposed' },
  { path: '/server-info', sig: /Apache Server Information/i, severity: 'high', title: 'Apache server-info exposed' },
  { path: '/actuator', sig: /"_links"\s*:/, severity: 'high', title: 'Spring Boot Actuator exposed' },
  { path: '/actuator/env', sig: /"activeProfiles"|"propertySources"/i, severity: 'critical', title: 'Spring Boot environment exposed' },
  { path: '/wp-config.php.bak', sig: /DB_NAME|DB_PASSWORD|DB_HOST/i, severity: 'critical', title: 'WordPress config backup exposed' },
  { path: '/.well-known/security.txt', sig: /Contact:|Policy:/i, severity: 'info', title: 'security.txt present', positive: true },
  { path: '/crossdomain.xml', sig: /<cross-domain-policy/i, severity: 'medium', title: 'Flash crossdomain.xml found (legacy risk)' }
];

const PROBE_TIMEOUT = 5000;

export async function probeExposurePaths(origin) {
  const issues = [];
  const probes = EXPOSURE_PROBES.map(async (def) => {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT);
      const res = await fetch(origin + def.path, {
        signal: controller.signal,
        credentials: 'omit',
        redirect: 'manual'
      });
      clearTimeout(timer);
      if (res.status !== 200) return;
      const text = await res.text();
      if (!text || text.length > 500000) return;
      if (!def.sig.test(text)) return;
      const snippet = text.slice(0, 200).replace(/\s+/g, ' ').trim();
      issues.push({
        id: 'exposure:' + def.path,
        category: 'exposure',
        severity: def.severity,
        title: def.title,
        detail: (def.positive ? '' : 'Accessible at ' + def.path + ' — ') +
          snippet.slice(0, 150) + (snippet.length >= 150 ? '…' : '')
      });
    } catch (e) { /* timeout / network error */ }
  });
  await Promise.all(probes);
  return issues;
}

// ---- Severity helpers (for UI sorting/stats) --------------------------------

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function sevRank(severity) {
  return SEV_RANK[severity] != null ? SEV_RANK[severity] : 5;
}

export function siteSeveritySummary(issues) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const i of issues || []) {
    if (counts[i.severity] != null) counts[i.severity]++;
  }
  return counts;
}

// ---- Category labels (for UI) -----------------------------------------------

export const CATEGORY_META = {
  headers:          { icon: '🔒', label: 'Security Headers' },
  cookies:          { icon: '🍪', label: 'Cookies' },
  'mixed-content':  { icon: '⚠️', label: 'Mixed Content' },
  sri:              { icon: '🔗', label: 'Subresource Integrity' },
  dom:              { icon: '⚡',        label: 'Dangerous DOM' },
  exposure:         { icon: '📁', label: 'Server Exposure' }
};

// ---- Storage ---------------------------------------------------------------

async function getRawDb() {
  const res = await chrome.storage.local.get(SITE_SEC_KEY);
  return res[SITE_SEC_KEY] || {};
}

export async function getSiteSecurityDb() {
  return getRawDb();
}

function withSiteDb(mutator) {
  writeChain = writeChain.then(async () => {
    const db = await getRawDb();
    const result = await mutator(db);
    await chrome.storage.local.set({ [SITE_SEC_KEY]: db });
    return result;
  }).catch((e) => {
    console.error('[GAKS] site-security write failed:', e);
  });
  return writeChain;
}

export function upsertSiteIssues(origin, url, newIssues) {
  if (!newIssues || !newIssues.length) return Promise.resolve();
  return withSiteDb((db) => {
    let site = db[origin];
    if (!site) {
      site = { origin, url, firstScan: nowIso(), lastScan: nowIso(), issues: [] };
      db[origin] = site;
    }
    site.lastScan = nowIso();
    if (url) site.url = url;
    const byId = new Map(site.issues.map((i) => [i.id, i]));
    for (const issue of newIssues) {
      const existing = byId.get(issue.id);
      byId.set(issue.id, {
        ...issue,
        firstSeen: (existing && existing.firstSeen) || nowIso(),
        lastSeen: nowIso()
      });
    }
    site.issues = Array.from(byId.values());
    return site;
  });
}

export function clearSiteSecurity() {
  return chrome.storage.local.remove(SITE_SEC_KEY);
}

export function deleteSiteOrigin(origin) {
  return withSiteDb((db) => {
    delete db[origin];
    return true;
  });
}
