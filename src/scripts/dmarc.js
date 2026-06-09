// lilDMARC: check a domain's SPF, DKIM, DMARC, MX, and BIMI records.
// All lookups run in the browser over DNS-over-HTTPS (Cloudflare first,
// Google as fallback). Nothing is proxied through a server.

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

/* ---------- theme (OS-aware, matches the family) ---------- */
const MOON_SVG = '<svg viewBox="0 0 24 24" width="17" height="17" aria-hidden="true"><path fill="currentColor" d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg>';
const SUN_SVG = '<svg viewBox="0 0 24 24" width="17" height="17" aria-hidden="true"><g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M4.6 4.6l1.4 1.4M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4l1.4-1.4M18 6l1.4-1.4"/></g></svg>';

function setThemeIcon(btn, theme) {
  if (theme === 'dark') { btn.innerHTML = SUN_SVG; btn.setAttribute('aria-label', 'Switch to light mode'); }
  else { btn.innerHTML = MOON_SVG; btn.setAttribute('aria-label', 'Switch to dark mode'); }
}
function initTheme() {
  const btn = $('#ui-theme-btn');
  const current = () => (document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light');
  setThemeIcon(btn, current());
  btn.addEventListener('click', () => {
    const next = current() === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('lildmarc-theme', next); } catch (e) {}
    setThemeIcon(btn, next);
  });
}

/* ---------- DNS over HTTPS ---------- */
async function doh(name, type) {
  // Cloudflare first, Google as fallback. Both speak JSON with CORS.
  try {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
      headers: { accept: 'application/dns-json' },
    });
    if (r.ok) return await r.json();
    throw new Error('cf ' + r.status);
  } catch {
    const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`);
    if (!r.ok) throw new Error('Both DNS resolvers failed for ' + name);
    return await r.json();
  }
}

// TXT record data arrives as one or more quoted chunks; join them.
function txtValue(data) {
  const parts = String(data).match(/"([^"]*)"/g);
  return parts ? parts.map((p) => p.slice(1, -1)).join('') : String(data);
}

async function txtRecords(name) {
  const d = await doh(name, 'TXT');
  return (d.Answer || []).filter((a) => a.type === 16).map((a) => txtValue(a.data).trim());
}

async function mxRecords(name) {
  const d = await doh(name, 'MX');
  return (d.Answer || [])
    .filter((a) => a.type === 15)
    .map((a) => {
      const [pref, ...host] = String(a.data).split(/\s+/);
      return { pref: Number(pref), host: host.join(' ').replace(/\.$/, '') };
    })
    .sort((a, b) => a.pref - b.pref);
}

/* ---------- helpers ---------- */
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function normalizeDomain(raw) {
  let s = (raw || '').trim().toLowerCase();
  s = s.replace(/^https?:\/\//, '').replace(/^www\./, '');
  s = s.split('/')[0].split('?')[0].replace(/\.$/, '');
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(s)) return null;
  return s;
}

const DKIM_SELECTORS = ['google', 'selector1', 'selector2', 'k1', 'k2', 'kl', 'kl2', 's1', 's2', 'em', 'smtp', 'mandrill', 'default', 'mail'];

const MX_PROVIDERS = [
  [/google\.com$|googlemail\.com$/, 'Google Workspace'],
  [/protection\.outlook\.com$|outlook\.com$/, 'Microsoft 365'],
  [/zoho(?:mail)?\.(com|eu)$/, 'Zoho Mail'],
  [/messagingengine\.com$/, 'Fastmail'],
  [/protonmail\.ch$|proton\.me$/, 'Proton Mail'],
  [/titan\.email$/, 'Titan'],
  [/mxrouting\.net$/, 'MXroute'],
  [/icloud\.com$/, 'iCloud Mail'],
  [/secureserver\.net$/, 'GoDaddy / Microsoft'],
  [/mimecast\.com$/, 'Mimecast'],
  [/pphosted\.com$/, 'Proofpoint'],
];

function mxProvider(hosts) {
  for (const { host } of hosts) {
    for (const [re, name] of MX_PROVIDERS) if (re.test(host)) return name;
  }
  return null;
}

/* ---------- checks ---------- */
function checkSpf(txts) {
  const spf = txts.filter((t) => /^v=spf1(\s|$)/i.test(t));
  if (!spf.length) {
    return [{ k: 'err', t: 'No SPF record', m: 'Without SPF, anyone can send mail claiming to be this domain, and inbox providers know it. Add a TXT record starting with v=spf1.', rec: null }];
  }
  if (spf.length > 1) {
    return [{ k: 'err', t: 'Multiple SPF records', m: `Found ${spf.length} records starting with v=spf1. The standard allows exactly one, and many receivers treat duplicates as a permanent error. Merge them into a single record.`, rec: spf.join('\n') }];
  }
  const rec = spf[0];
  const out = [];
  const allMatch = rec.match(/([-~?+])all\b/i);
  if (!allMatch) out.push({ k: 'warn', t: 'SPF has no "all" mechanism', m: 'The record never says what to do with senders it does not list. End it with ~all (softfail) or -all (fail).', rec });
  else if (allMatch[1] === '+') out.push({ k: 'err', t: 'SPF ends in +all', m: 'This authorizes the entire internet to send as this domain, which defeats the point of SPF. Change it to ~all or -all.', rec });
  else if (allMatch[1] === '?') out.push({ k: 'warn', t: 'SPF ends in ?all', m: 'Neutral means receivers ignore the result. Move to ~all (softfail) or -all (fail) so SPF actually protects the domain.', rec });
  else out.push({ k: 'ok', t: `SPF record found (${allMatch[1]}all)`, m: allMatch[1] === '-' ? 'Strict fail policy: unlisted senders are rejected outright.' : 'Softfail policy: unlisted senders are treated with suspicion. Solid, widely recommended setup.', rec });

  const lookups = (rec.match(/\b(include:|redirect=|exists:)|(^|\s)a(:|\s|$)|(^|\s)mx(:|\s|$)|(^|\s)ptr(:|\s|$)/gi) || []).length;
  if (lookups > 10) out.push({ k: 'err', t: 'SPF over the 10-lookup limit', m: `Roughly ${lookups} DNS-querying mechanisms at the top level. Past 10 total (including nested includes), receivers return a permanent error. Flatten or trim the record.`, rec: null });
  else if (lookups >= 8) out.push({ k: 'warn', t: 'SPF close to the 10-lookup limit', m: `Roughly ${lookups} DNS-querying mechanisms at the top level, and nested includes count too. Worth auditing before something silently breaks.`, rec: null });
  return out;
}

function checkDmarc(txts) {
  const recs = txts.filter((t) => /^v=DMARC1\b/i.test(t));
  if (!recs.length) {
    return [{ k: 'err', t: 'No DMARC record', m: 'Without DMARC, receivers have no instruction for mail that fails SPF and DKIM, and spoofing your domain stays easy. Add a TXT record at _dmarc with at least v=DMARC1; p=none; rua=mailto:you@yourdomain.', rec: null }];
  }
  if (recs.length > 1) {
    return [{ k: 'err', t: 'Multiple DMARC records', m: 'More than one TXT at _dmarc makes receivers ignore DMARC entirely. Keep exactly one.', rec: recs.join('\n') }];
  }
  const rec = recs[0];
  const out = [];
  const p = (rec.match(/\bp\s*=\s*(none|quarantine|reject)/i) || [])[1]?.toLowerCase();
  const pct = (rec.match(/\bpct\s*=\s*(\d+)/i) || [])[1];
  if (!p) out.push({ k: 'err', t: 'DMARC has no policy', m: 'The record is missing p=. Receivers need p=none, p=quarantine, or p=reject.', rec });
  else if (p === 'none') out.push({ k: 'warn', t: 'DMARC is monitor-only (p=none)', m: 'Failures are reported but still delivered, so spoofed mail gets through. Fine while gathering reports; the goal is p=quarantine, then p=reject.', rec });
  else out.push({ k: 'ok', t: `DMARC enforced (p=${p}${pct && pct !== '100' ? `, pct=${pct}` : ''})`, m: p === 'reject' ? 'Strongest setting: mail that fails authentication is refused.' : `Failing mail goes to spam.${pct && pct !== '100' ? ` Note: only ${pct}% of failing mail is affected; raise pct to 100 when ready.` : ''}`, rec });
  if (!/\brua\s*=/i.test(rec)) out.push({ k: 'warn', t: 'No aggregate reports (rua)', m: 'Without rua=mailto:... you get zero visibility into who is sending as this domain. Add a reporting address.', rec: null });
  return out;
}

function checkDkim(found, probed, customSelector) {
  if (found.length) {
    return found.map(({ selector, rec }) => ({
      k: 'ok',
      t: `DKIM key found: ${selector}`,
      m: `Selector "${selector}" publishes a public key, so mail signed with it can be verified.`,
      rec,
    }));
  }
  return [{
    k: 'warn',
    t: 'No DKIM key on the common selectors',
    m: `None of the ${probed} selectors checked (${customSelector ? `including "${customSelector}"` : 'google, selector1, k1, and other common ones'}) returned a key. DKIM may still exist on a custom selector, check your email provider's DNS settings, or enter the selector above and re-check.`,
    rec: null,
  }];
}

function checkMx(hosts) {
  if (!hosts.length) {
    return [{ k: 'warn', t: 'No MX records', m: 'This domain cannot receive mail. Fine for a send-only or parked domain; a problem if replies are expected.', rec: null }];
  }
  const provider = mxProvider(hosts);
  const list = hosts.slice(0, 4).map((h) => `${h.pref} ${h.host}`).join('\n') + (hosts.length > 4 ? `\n… ${hosts.length - 4} more` : '');
  return [{ k: 'ok', t: provider ? `Mail handled by ${provider}` : 'MX records found', m: `${hosts.length} MX record${hosts.length > 1 ? 's' : ''}. ${provider ? '' : 'Provider not recognized from the host names.'}`.trim(), rec: list }];
}

function checkBimi(txts) {
  const rec = txts.find((t) => /^v=BIMI1\b/i.test(t));
  if (rec) return [{ k: 'ok', t: 'BIMI record found', m: 'Inboxes that support BIMI can show your logo next to messages.', rec }];
  return [{ k: 'info', t: 'No BIMI record (optional)', m: 'BIMI shows your logo in supporting inboxes. It requires DMARC at enforcement (quarantine or reject) and, for most providers, a Verified Mark Certificate. Nice to have, not required.', rec: null }];
}

/* ---------- render ---------- */
const ICON = {
  err: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M15 9l-6 6M9 9l6 6"/></svg>',
  warn: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.8 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.8a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4M12 17h.01"/></svg>',
  ok: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>',
  info: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></svg>',
};

function checkCard(c) {
  const rec = c.rec ? `<pre class="rec"><code>${esc(c.rec)}</code></pre>` : '';
  return `<div class="check check--${c.k}">
    <span class="check-ic">${ICON[c.k]}</span>
    <div class="check-body">
      <div class="check-t">${esc(c.t)}</div>
      <div class="check-m">${esc(c.m)}</div>
      ${rec}
    </div>
  </div>`;
}

function sectionHtml(name, checks) {
  return `<div class="dsec"><div class="dsec-h">${name}</div>${checks.map(checkCard).join('')}</div>`;
}

function note(kind, msg) {
  return `<div class="t-note t-note--${kind}">${esc(msg)}</div>`;
}

function summaryHtml(domain, all) {
  const n = { err: 0, warn: 0, ok: 0, info: 0 };
  all.forEach((c) => { n[c.k]++; });
  let verdict;
  if (n.err) verdict = `${domain} has ${n.err} issue${n.err > 1 ? 's' : ''} that will hurt deliverability.`;
  else if (n.warn) verdict = `${domain} is mostly set up, with ${n.warn} thing${n.warn > 1 ? 's' : ''} worth tightening.`;
  else verdict = `${domain} looks well set up. Nice.`;
  return `<div class="t-head">
    <div class="t-summary">${esc(verdict)}</div>
    <div class="insp-pills">
      <span class="pill pill--err">${n.err}</span>
      <span class="pill pill--warn">${n.warn}</span>
      <span class="pill pill--ok">${n.ok}</span>
    </div>
  </div>`;
}

function setLoading(domain) {
  $('#results').innerHTML = `<div class="t-loading"><span class="spin" aria-hidden="true"></span> Reading DNS records for ${esc(domain)}&hellip;</div>`;
}

/* ---------- run ---------- */
async function run() {
  const domain = normalizeDomain($('#f-domain').value);
  if (!domain) {
    $('#results').innerHTML = note('err', 'Enter a bare domain like yourdomain.com.');
    return;
  }
  const custom = $('#f-selector').value.trim().replace(/\._domainkey.*$/i, '');
  const btn = $('#check-btn');
  btn.disabled = true;
  setLoading(domain);

  try {
    const selectors = custom && !DKIM_SELECTORS.includes(custom) ? [custom, ...DKIM_SELECTORS] : DKIM_SELECTORS;
    const [rootTxt, dmarcTxt, mx, bimiTxt, ...dkim] = await Promise.all([
      txtRecords(domain).catch(() => []),
      txtRecords('_dmarc.' + domain).catch(() => []),
      mxRecords(domain).catch(() => []),
      txtRecords('default._bimi.' + domain).catch(() => []),
      ...selectors.map((sel) =>
        txtRecords(`${sel}._domainkey.${domain}`)
          .then((txts) => ({ sel, rec: txts.find((t) => /(^|;)\s*v\s*=\s*DKIM1|(^|;)\s*k\s*=|(^|;)\s*p\s*=/i.test(t)) }))
          .catch(() => ({ sel, rec: null }))
      ),
    ]);

    const dkimFound = dkim.filter((d) => d.rec).map((d) => ({ selector: d.sel, rec: d.rec }));

    const sections = [
      ['SPF', checkSpf(rootTxt)],
      ['DMARC', checkDmarc(dmarcTxt)],
      ['DKIM', checkDkim(dkimFound, selectors.length, custom)],
      ['MX', checkMx(mx)],
      ['BIMI', checkBimi(bimiTxt)],
    ];
    const all = sections.flatMap(([, c]) => c);
    $('#results').innerHTML = summaryHtml(domain, all) + sections.map(([n, c]) => sectionHtml(n, c)).join('');
  } catch (e) {
    $('#results').innerHTML = note('err', 'Could not reach the DNS resolvers. Check your connection and try again.');
  } finally {
    btn.disabled = false;
  }
}

function initDmarc() {
  initTheme();
  $('#check-form').addEventListener('submit', (e) => { e.preventDefault(); run(); });
  $$('.ex').forEach((b) =>
    b.addEventListener('click', () => { $('#f-domain').value = b.dataset.ex; run(); }));
}

export { initDmarc };
