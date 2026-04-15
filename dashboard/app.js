// Portable Recon Toolkit - Dashboard client
// Uses only browser standard features, no external libraries.
(function () {
  'use strict';

  const state = {
    sessions: [],
    filtered: [],
    current: null,
    currentData: null,
    filterText: '',
    schedules: [],
  };

  const el = {
    sessionList: document.getElementById('sessionList'),
    filter: document.getElementById('filter'),
    empty: document.getElementById('empty'),
    content: document.getElementById('content'),
    panels: document.getElementById('panels'),
    headerCard: document.getElementById('header-card'),
    status: document.getElementById('status'),
    refresh: document.getElementById('refresh'),
    schedulesList: document.getElementById('schedulesList'),
    schedulesHeading: document.getElementById('schedulesHeading'),
  };

  // ---------- data ----------

  async function loadIndex() {
    el.status.textContent = 'Loading...';
    try {
      const res = await fetch('/results/index.json?t=' + Date.now());
      if (!res.ok) throw new Error('no index');
      const data = await res.json();
      state.sessions = Array.isArray(data.sessions) ? data.sessions : [];
      applyFilter();
      el.status.textContent = state.sessions.length + ' session' + (state.sessions.length === 1 ? '' : 's');
    } catch (e) {
      state.sessions = [];
      applyFilter();
      el.status.textContent = 'No sessions yet';
    }
    // Schedules are optional; a 404 is normal when none are configured.
    loadSchedules();
  }

  async function loadSchedules() {
    try {
      const res = await fetch('/config/schedules.json?t=' + Date.now());
      if (!res.ok) {
        state.schedules = [];
        renderSchedules();
        return;
      }
      const data = await res.json();
      state.schedules = Array.isArray(data.schedules) ? data.schedules : [];
    } catch (e) {
      state.schedules = [];
    }
    renderSchedules();
  }

  function renderSchedules() {
    if (!el.schedulesList) return;
    if (!state.schedules.length) {
      el.schedulesList.hidden = true;
      el.schedulesHeading.hidden = true;
      el.schedulesList.innerHTML = '';
      return;
    }
    el.schedulesList.hidden = false;
    el.schedulesHeading.hidden = false;
    el.schedulesList.innerHTML = '';
    for (const s of state.schedules) {
      const li = document.createElement('li');
      li.className = 'schedule';
      const statusClass = s.enabled === false ? 'off'
        : (s.last_status === 'changed' ? 'changed'
          : (s.last_status === 'error' ? 'err'
            : (s.last_status === 'unchanged' ? 'clean' : 'pending')));
      const lastRun = s.last_run_epoch
        ? new Date(s.last_run_epoch * 1000).toLocaleString()
        : 'never';
      li.innerHTML =
        '<div class="s-target">' + escapeHtml(s.target || '?') + '</div>' +
        '<div class="s-meta">' +
          '<span class="s-type ' + escapeHtml((s.workflow || 'scan').toLowerCase()) + '">' +
            escapeHtml((s.workflow || 'scan')) +
          '</span>' +
          '<span class="sched-dot ' + statusClass + '" title="' +
            escapeHtml(s.last_status || 'pending') + '"></span>' +
          '<span class="sched-every">&#x231B; ' + escapeHtml(s.interval || '') + '</span>' +
        '</div>' +
        '<div class="s-meta"><span class="muted">last: ' + escapeHtml(lastRun) + '</span></div>';
      li.addEventListener('click', () => {
        if (s.last_session_id) {
          const match = state.sessions.find(x => x.id === s.last_session_id);
          if (match) selectSession(match);
        }
      });
      el.schedulesList.appendChild(li);
    }
  }

  function applyFilter() {
    const q = state.filterText.trim().toLowerCase();
    state.filtered = !q
      ? state.sessions
      : state.sessions.filter(s =>
          (s.target || '').toLowerCase().includes(q) ||
          (s.scan_type || '').toLowerCase().includes(q));
    renderSessionList();
  }

  function renderSessionList() {
    el.sessionList.innerHTML = '';
    if (state.filtered.length === 0) {
      const li = document.createElement('li');
      li.style.color = 'var(--muted)';
      li.style.cursor = 'default';
      li.style.background = 'transparent';
      li.style.borderColor = 'transparent';
      li.textContent = state.sessions.length === 0 ? 'No sessions recorded' : 'No matches';
      el.sessionList.appendChild(li);
      return;
    }
    for (const s of state.filtered) {
      const li = document.createElement('li');
      const t = (s.scan_type || 'scan').toLowerCase();
      li.innerHTML =
        '<div class="s-target">' + escapeHtml(s.target || '?') + '</div>' +
        '<div class="s-meta">' +
          '<span class="s-type ' + escapeHtml(t) + '">' + escapeHtml(t) + '</span>' +
          '<span>' + escapeHtml(s.created || '') + '</span>' +
        '</div>';
      li.addEventListener('click', () => selectSession(s));
      if (state.current && state.current.id === s.id) li.classList.add('selected');
      el.sessionList.appendChild(li);
    }
  }

  async function selectSession(s) {
    state.current = s;
    renderSessionList();
    el.empty.hidden = true;
    el.content.hidden = false;
    try {
      const res = await fetch('/results/' + s.file + '?t=' + Date.now());
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      state.currentData = data;
      renderAll(data);
      activateTab('summary');
    } catch (e) {
      el.panels.innerHTML = '<div class="card"><h3>Error</h3>Failed to load: ' + escapeHtml(e.message) + '</div>';
    }
  }

  // ---------- rendering ----------

  function renderAll(data) {
    renderHeader(data);
    el.panels.innerHTML =
      '<div class="panel active" id="panel-summary">' + renderSummary(data) + '</div>' +
      '<div class="panel" id="panel-changes">' + renderChanges(data) + '</div>' +
      '<div class="panel" id="panel-nmap">' + renderNmap(data) + '</div>' +
      '<div class="panel" id="panel-ports">' + renderPorts(data) + '</div>' +
      '<div class="panel" id="panel-dns">' + renderDns(data) + '</div>' +
      '<div class="panel" id="panel-subs">' + renderSubs(data) + '</div>' +
      '<div class="panel" id="panel-whois">' + renderWhois(data) + '</div>' +
      '<div class="panel" id="panel-raw"><div class="card"><h3>Raw JSON</h3><pre>' +
        escapeHtml(JSON.stringify(data, null, 2)) + '</pre></div></div>';
  }

  function renderHeader(data) {
    el.headerCard.innerHTML =
      '<div>' +
        '<div class="title">' + escapeHtml(data.target || '?') + '</div>' +
        '<div class="subtitle">' +
          escapeHtml(data.scan_type || 'scan').toUpperCase() + ' &middot; ' +
          escapeHtml(data.created || '') +
        '</div>' +
      '</div>' +
      '<div class="badge">' + escapeHtml(data.scan_type || 'scan') + '</div>';
  }

  function renderSummary(data) {
    const open = collectOpenPorts(data);
    const dns = data.dns || {};
    const stats = [
      { label: 'Open Ports', num: open.length, cls: '' },
      { label: 'A Records', num: rrCount(dns, 'A'), cls: 'info' },
      { label: 'AAAA', num: rrCount(dns, 'AAAA'), cls: 'info' },
      { label: 'NS', num: rrCount(dns, 'NS'), cls: 'info' },
      { label: 'MX', num: rrCount(dns, 'MX'), cls: 'info' },
      { label: 'TXT', num: rrCount(dns, 'TXT'), cls: 'info' },
      { label: 'Subdomains', num: (data.subdomains && data.subdomains.found || []).length, cls: 'purple' },
      { label: 'WHOIS', num: (data.whois && !data.whois.error) ? 'Yes' : 'No', cls: 'warn' },
    ];

    let html =
      '<div class="card"><h3>Target Overview</h3>' +
        '<dl class="kv">' +
          kv('Target', data.target) +
          kv('Scan Type', (data.scan_type || '').toUpperCase()) +
          kv('Timestamp', data.created) +
          (data.port_scan && data.port_scan.ip ? kv('Resolved IP', data.port_scan.ip) : '') +
          (data.nmap && data.nmap.command ? kv('Nmap Command', '<code>' + escapeHtml(data.nmap.command) + '</code>') : '') +
        '</dl>' +
      '</div>';

    html += '<div class="card"><h3>Statistics</h3><div class="stat-grid">' +
      stats.map(s => (
        '<div class="stat ' + s.cls + '">' +
          '<div class="num">' + s.num + '</div>' +
          '<div class="label">' + s.label + '</div>' +
        '</div>'
      )).join('') +
      '</div></div>';

    if (open.length) {
      html += '<div class="card"><h3>Service Distribution</h3>' + renderPortChart(open) + '</div>';
    }
    return html;
  }

  function renderPortChart(ports) {
    const buckets = {};
    for (const p of ports) {
      const key = p.service || 'unknown';
      buckets[key] = (buckets[key] || 0) + 1;
    }
    const entries = Object.entries(buckets).sort((a, b) => b[1] - a[1]).slice(0, 14);
    if (!entries.length) return '<div class="muted">No open ports.</div>';
    const max = Math.max.apply(null, entries.map(e => e[1]));
    const bw = 50, gap = 18, labelH = 28, numH = 16;
    const w = entries.length * (bw + gap) + gap;
    const h = 200;
    const barArea = h - labelH - numH;
    const bars = entries.map((e, i) => {
      const bh = Math.max(2, (e[1] / max) * barArea);
      const x = gap + i * (bw + gap);
      const y = h - labelH - bh;
      return (
        '<g>' +
          '<rect x="' + x + '" y="' + y + '" width="' + bw + '" height="' + bh +
            '" fill="url(#barGrad)" rx="2"/>' +
          '<text x="' + (x + bw / 2) + '" y="' + (y - 6) + '" text-anchor="middle" ' +
            'fill="#5ee2a4" font-size="11" font-weight="700">' + e[1] + '</text>' +
          '<text x="' + (x + bw / 2) + '" y="' + (h - 10) + '" text-anchor="middle" ' +
            'fill="#8aa0b5" font-size="10">' + escapeHtml(e[0]).slice(0, 9) + '</text>' +
        '</g>'
      );
    }).join('');
    return (
      '<svg class="chart" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="xMidYMid meet">' +
        '<defs><linearGradient id="barGrad" x1="0" y1="0" x2="0" y2="1">' +
          '<stop offset="0" stop-color="#5ee2a4" stop-opacity="0.9"/>' +
          '<stop offset="1" stop-color="#3fa177" stop-opacity="0.4"/>' +
        '</linearGradient></defs>' +
        bars +
      '</svg>'
    );
  }

  function renderChanges(data) {
    // Prefer an auto-diff attached by the scheduler. Fall back to a
    // `diff` session document (same shape as the `recon diff` CLI writes).
    let diff = data && data.diff_against_previous;
    let prior = null;
    let source = 'auto';
    if (!diff && data && data.diff && data.scan_type === 'diff') {
      diff = data.diff;
      source = 'diff-session';
    }
    if (!diff) {
      if (data && data.diff_error) {
        return '<div class="card"><h3>Changes</h3>' +
          '<p class="muted">Auto-diff failed: ' + escapeHtml(data.diff_error) + '</p></div>';
      }
      return '<div class="card"><h3>Changes</h3>' +
        '<p class="muted">No delta recorded for this session.</p>' +
        '<p class="muted">Tip: schedule a recurring scan with ' +
        '<code>recon schedule add TARGET full --every 1h</code> and the toolkit ' +
        'will auto-diff each run against the previous one.</p></div>';
    }

    const pAdded = diff.ports && diff.ports.added || [];
    const pRemoved = diff.ports && diff.ports.removed || [];
    const sAdded = diff.subdomains && diff.subdomains.added || [];
    const sRemoved = diff.subdomains && diff.subdomains.removed || [];
    const dnsDelta = diff.dns || {};
    const unchanged = (diff.ports && diff.ports.unchanged) || 0;
    const empty = !pAdded.length && !pRemoved.length
      && !sAdded.length && !sRemoved.length
      && !Object.keys(dnsDelta).length;

    const baseLabel = (diff.a && (diff.a.id || diff.a.created)) || '-';
    const newLabel = (diff.b && (diff.b.id || diff.b.created)) || '-';

    let html =
      '<div class="card"><h3>Auto-Diff</h3>' +
        '<dl class="kv">' +
          kv('Target', diff.target || data.target) +
          kv('Baseline', baseLabel) +
          kv('This Scan', newLabel) +
          kv('Source', source === 'auto'
            ? 'auto (scheduled recurring scan)' : 'recon diff session') +
        '</dl>' +
      '</div>';

    const stats = [
      { label: 'Ports Added', num: pAdded.length, cls: pAdded.length ? '' : 'info' },
      { label: 'Ports Removed', num: pRemoved.length, cls: pRemoved.length ? 'crit' : 'info' },
      { label: 'Ports Unchanged', num: unchanged, cls: 'info' },
      { label: 'Subs Added', num: sAdded.length, cls: sAdded.length ? 'purple' : 'info' },
      { label: 'Subs Removed', num: sRemoved.length, cls: sRemoved.length ? 'crit' : 'info' },
      { label: 'DNS Types Changed', num: Object.keys(dnsDelta).length, cls: 'warn' },
    ];
    html += '<div class="card"><h3>Delta Summary</h3><div class="stat-grid">' +
      stats.map(s => (
        '<div class="stat ' + s.cls + '">' +
          '<div class="num">' + s.num + '</div>' +
          '<div class="label">' + s.label + '</div>' +
        '</div>'
      )).join('') +
      '</div></div>';

    if (empty) {
      html += '<div class="card"><h3>No Changes</h3>' +
        '<p class="muted">The target\'s posture is identical to the previous scan.</p></div>';
      return html;
    }

    if (pAdded.length || pRemoved.length) {
      let rows = '';
      for (const p of pAdded) {
        rows +=
          '<tr>' +
            '<td><span class="pill open">added</span></td>' +
            '<td><code>' + escapeHtml(p[0] || '') + '</code></td>' +
            '<td><code>' + escapeHtml(String(p[1] || '')) + '</code></td>' +
            '<td>' + escapeHtml(p[2] || 'tcp') + '</td>' +
          '</tr>';
      }
      for (const p of pRemoved) {
        rows +=
          '<tr>' +
            '<td><span class="pill closed">removed</span></td>' +
            '<td><code>' + escapeHtml(p[0] || '') + '</code></td>' +
            '<td><code>' + escapeHtml(String(p[1] || '')) + '</code></td>' +
            '<td>' + escapeHtml(p[2] || 'tcp') + '</td>' +
          '</tr>';
      }
      html +=
        '<div class="card"><h3>Port Changes <span class="count">' +
          (pAdded.length + pRemoved.length) + '</span></h3>' +
        '<table><thead><tr>' +
          '<th>Change</th><th>Host</th><th>Port</th><th>Proto</th>' +
        '</tr></thead><tbody>' + rows + '</tbody></table></div>';
    }

    if (sAdded.length || sRemoved.length) {
      let rows = '';
      for (const s of sAdded) {
        rows += '<tr><td><span class="pill open">added</span></td>' +
                '<td><code>' + escapeHtml(s) + '</code></td></tr>';
      }
      for (const s of sRemoved) {
        rows += '<tr><td><span class="pill closed">removed</span></td>' +
                '<td><code>' + escapeHtml(s) + '</code></td></tr>';
      }
      html +=
        '<div class="card"><h3>Subdomain Changes <span class="count">' +
          (sAdded.length + sRemoved.length) + '</span></h3>' +
        '<table><thead><tr><th>Change</th><th>Subdomain</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table></div>';
    }

    const dnsTypes = Object.keys(dnsDelta);
    if (dnsTypes.length) {
      let rows = '';
      for (const t of dnsTypes) {
        const added = (dnsDelta[t] && dnsDelta[t].added) || [];
        const removed = (dnsDelta[t] && dnsDelta[t].removed) || [];
        for (const v of added) {
          rows +=
            '<tr>' +
              '<td><span class="pill open">added</span></td>' +
              '<td>' + escapeHtml(t) + '</td>' +
              '<td><code>' + escapeHtml(formatVal(safeParse(v))) + '</code></td>' +
            '</tr>';
        }
        for (const v of removed) {
          rows +=
            '<tr>' +
              '<td><span class="pill closed">removed</span></td>' +
              '<td>' + escapeHtml(t) + '</td>' +
              '<td><code>' + escapeHtml(formatVal(safeParse(v))) + '</code></td>' +
            '</tr>';
        }
      }
      html +=
        '<div class="card"><h3>DNS Changes</h3>' +
        '<table><thead><tr><th>Change</th><th>Type</th><th>Value</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table></div>';
    }

    const expiry = diff.whois_expiry;
    if (expiry && (expiry.before || expiry.after) && expiry.before !== expiry.after) {
      html +=
        '<div class="card"><h3>WHOIS Expiry Shift</h3><dl class="kv">' +
          kv('Before', expiry.before || '-') +
          kv('After', expiry.after || '-') +
        '</dl></div>';
    }

    return html;
  }

  function safeParse(v) {
    if (typeof v !== 'string') return v;
    try { return JSON.parse(v); } catch (e) { return v; }
  }

  function renderNmap(data) {
    if (!data.nmap) {
      return '<div class="card"><h3>Nmap</h3><p class="muted">No Nmap data in this session.</p>' +
        '<p class="muted">Run: <code>python recon.py scan TARGET</code> with Nmap installed.</p></div>';
    }
    const n = data.nmap;
    if (n.error) {
      return '<div class="card"><h3>Nmap Error</h3><pre>' + escapeHtml(n.error) + '</pre></div>';
    }
    const hosts = n.hosts || [];
    let html =
      '<div class="card"><h3>Nmap Run Info</h3><dl class="kv">' +
        kv('Command', '<code>' + escapeHtml(n.command || '-') + '</code>') +
        kv('Profile', n.profile) +
        kv('Version', n.version) +
        kv('Started', n.start) +
      '</dl></div>';

    for (const h of hosts) {
      html +=
        '<div class="card">' +
          '<h3>' + escapeHtml(h.address || '?') +
            ' <span class="pill open">' + escapeHtml(h.state || '') + '</span>' +
          '</h3>';
      if (h.hostnames && h.hostnames.length) {
        html += '<p style="margin-bottom:10px">Hostnames: ' +
          h.hostnames.map(escapeHtml).join(', ') + '</p>';
      }
      if (h.os) {
        html += '<p style="margin-bottom:10px">OS: ' + escapeHtml(h.os.name) +
          ' <span class="muted">(' + escapeHtml(h.os.accuracy) + '% confidence)</span></p>';
      }
      if (h.ports && h.ports.length) {
        html +=
          '<table><thead><tr>' +
            '<th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Version</th>' +
          '</tr></thead><tbody>';
        for (const p of h.ports) {
          const version = [p.product, p.version, p.extra_info]
            .filter(Boolean).join(' ') || '-';
          html +=
            '<tr>' +
              '<td><code>' + p.port + '</code></td>' +
              '<td>' + escapeHtml(p.protocol || '') + '</td>' +
              '<td><span class="pill ' + escapeHtml(p.state || '') + '">' +
                escapeHtml(p.state || '') + '</span></td>' +
              '<td>' + escapeHtml(p.service || '-') + '</td>' +
              '<td>' + escapeHtml(version) + '</td>' +
            '</tr>';
        }
        html += '</tbody></table>';
      } else {
        html += '<p class="muted">No ports reported.</p>';
      }
      html += '</div>';
    }
    return html;
  }

  function renderPorts(data) {
    const ports = collectOpenPorts(data);
    if (!ports.length) {
      return '<div class="card"><h3>Ports</h3><p class="muted">No port data in this session.</p></div>';
    }
    let rows = '';
    for (const p of ports) {
      const extra = p.banner || [p.product, p.version].filter(Boolean).join(' ') || '-';
      rows +=
        '<tr>' +
          '<td><code>' + p.port + '</code></td>' +
          '<td>' + escapeHtml(p.protocol || 'tcp') + '</td>' +
          '<td><span class="pill ' + escapeHtml(p.state || 'open') + '">' +
            escapeHtml(p.state || 'open') + '</span></td>' +
          '<td>' + escapeHtml(p.service || '-') + '</td>' +
          '<td>' + escapeHtml(extra) + '</td>' +
        '</tr>';
    }
    return (
      '<div class="card"><h3>Open Ports <span class="count">' + ports.length + '</span></h3>' +
      '<table><thead><tr>' +
        '<th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Banner / Version</th>' +
      '</tr></thead><tbody>' + rows + '</tbody></table></div>'
    );
  }

  function renderDns(data) {
    if (!data.dns) {
      return '<div class="card"><h3>DNS</h3><p class="muted">No DNS data. Run: ' +
        '<code>python recon.py dns TARGET</code></p></div>';
    }
    const dns = data.dns;
    if (dns.error) {
      return '<div class="card"><h3>DNS Error</h3><pre>' + escapeHtml(dns.error) + '</pre></div>';
    }

    const types = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'CNAME', 'SOA', 'CAA'];
    let html = '';
    for (const t of types) {
      const rec = dns[t];
      if (!rec) continue;
      const answers = rec.answers || [];
      if (!answers.length) continue;
      let rows = '';
      for (const a of answers) {
        rows +=
          '<tr>' +
            '<td>' + escapeHtml(a.name || '') + '</td>' +
            '<td><code>' + (a.ttl != null ? a.ttl : '-') + '</code></td>' +
            '<td><code>' + escapeHtml(formatVal(a.value)) + '</code></td>' +
          '</tr>';
      }
      html +=
        '<div class="card"><h3>' + t + ' Records <span class="count">' + answers.length + '</span></h3>' +
        '<table><thead><tr><th>Name</th><th>TTL</th><th>Value</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table></div>';
    }

    if (dns.reverse && dns.reverse.length) {
      let rows = '';
      for (const r of dns.reverse) {
        const names = (r.ptr || []).map(p => formatVal(p.value)).join(', ') || '-';
        rows +=
          '<tr>' +
            '<td><code>' + escapeHtml(r.ip) + '</code></td>' +
            '<td>' + escapeHtml(names) + '</td>' +
          '</tr>';
      }
      html +=
        '<div class="card"><h3>Reverse DNS (PTR)</h3>' +
        '<table><thead><tr><th>IP</th><th>PTR</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table></div>';
    }

    return html || '<div class="card"><h3>DNS</h3><p class="muted">No records returned.</p></div>';
  }

  function renderSubs(data) {
    if (!data.subdomains) {
      return '<div class="card"><h3>Subdomains</h3><p class="muted">No subdomain enumeration. ' +
        'Run: <code>python recon.py dns TARGET --wordlist config/wordlists/subdomains.txt</code></p></div>';
    }
    const sub = data.subdomains;
    if (sub.error) {
      return '<div class="card"><h3>Subdomain Error</h3><pre>' + escapeHtml(sub.error) + '</pre></div>';
    }
    const found = sub.found || [];
    let html =
      '<div class="card"><h3>Subdomain Enumeration</h3><dl class="kv">' +
        kv('Domain', sub.domain) +
        kv('Wordlist', sub.wordlist) +
        kv('Tested', sub.tested || 0) +
        kv('Found', found.length) +
      '</dl></div>';
    if (found.length) {
      let rows = '';
      for (const f of found) {
        rows +=
          '<tr>' +
            '<td><code>' + escapeHtml(f.subdomain) + '</code></td>' +
            '<td>' + escapeHtml(f.ips.join(', ')) + '</td>' +
          '</tr>';
      }
      html +=
        '<div class="card"><h3>Discovered <span class="count">' + found.length + '</span></h3>' +
        '<table><thead><tr><th>Subdomain</th><th>IPs</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table></div>';
    }
    return html;
  }

  function renderWhois(data) {
    if (!data.whois) {
      return '<div class="card"><h3>WHOIS</h3><p class="muted">No WHOIS data. ' +
        'Run: <code>python recon.py whois TARGET</code></p></div>';
    }
    const w = data.whois;
    if (w.error) {
      return '<div class="card"><h3>WHOIS Error</h3><pre>' + escapeHtml(w.error) + '</pre></div>';
    }
    const fields = w.fields || {};
    const keys = Object.keys(fields);
    let fieldHtml = '';
    if (keys.length) {
      for (const k of keys) {
        const v = fields[k];
        const display = Array.isArray(v) ? v.join(', ') : v;
        fieldHtml += '<dt>' + escapeHtml(k) + '</dt><dd>' + escapeHtml(display) + '</dd>';
      }
    } else {
      fieldHtml = '<dd class="muted">(no fields parsed)</dd>';
    }
    return (
      '<div class="card"><h3>Parsed Fields <span class="count">' + keys.length + '</span></h3>' +
      '<dl class="kv">' + fieldHtml + '</dl></div>' +
      '<div class="card"><h3>Raw WHOIS Response</h3><pre>' + escapeHtml(w.raw || '') + '</pre></div>'
    );
  }

  // ---------- helpers ----------

  function collectOpenPorts(data) {
    const out = [];
    if (data.nmap && Array.isArray(data.nmap.hosts)) {
      for (const h of data.nmap.hosts) {
        for (const p of (h.ports || [])) {
          if (p.state === 'open') out.push(p);
        }
      }
    }
    if (data.port_scan && Array.isArray(data.port_scan.ports)) {
      for (const p of data.port_scan.ports) out.push(p);
    }
    return out;
  }

  function rrCount(dns, type) {
    return ((dns[type] || {}).answers || []).length;
  }

  function kv(label, value) {
    if (value === null || value === undefined || value === '') return '';
    return '<dt>' + escapeHtml(label) + '</dt><dd>' + value + '</dd>';
  }

  function activateTab(name) {
    const tabs = document.querySelectorAll('.tab');
    for (const t of tabs) t.classList.toggle('active', t.dataset.tab === name);
    const panels = document.querySelectorAll('.panel');
    for (const p of panels) p.classList.toggle('active', p.id === 'panel-' + name);
  }

  function escapeHtml(s) {
    if (s === null || s === undefined) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function formatVal(v) {
    if (v === null || v === undefined) return '';
    if (typeof v === 'object') return JSON.stringify(v);
    return String(v);
  }

  // ---------- events ----------

  document.addEventListener('click', (e) => {
    if (e.target && e.target.matches && e.target.matches('.tab')) {
      activateTab(e.target.dataset.tab);
    }
  });

  el.refresh.addEventListener('click', loadIndex);
  el.filter.addEventListener('input', (e) => {
    state.filterText = e.target.value;
    applyFilter();
  });

  // Auto-refresh sessions every 10s so running scans show up live.
  setInterval(loadIndex, 10000);

  loadIndex();
})();
