// Dashboard: client-side filtering of server-rendered rows, scope previews, and background sync jobs.
(function () {
  const rows = Array.from(document.querySelectorAll('#objects tbody tr'));
  const q = document.getElementById('q');
  const risk = document.getElementById('f-risk');
  const flag = document.getElementById('f-flag');
  const showLow = document.getElementById('f-low');
  const count = document.getElementById('count');
  const noMatch = document.getElementById('no-match');

  const tiles = Array.from(document.querySelectorAll('.tile'));
  let tileTag = '';

  function applyFilters() {
    if (!q) return;
    const text = q.value.trim().toLowerCase();
    let shown = 0;
    for (const tr of rows) {
      const ok =
        (!risk.value || tr.dataset.risk === risk.value) &&
        (showLow.checked || risk.value === 'LOW' || tr.dataset.risk !== 'LOW') &&
        (!flag.value || tr.dataset.flags.split(' ').includes(flag.value)) &&
        (!tileTag || (tr.dataset.tags || '').split(' ').includes(tileTag)) &&
        (!text || tr.textContent.toLowerCase().includes(text));
      tr.hidden = !ok;
      if (ok) shown++;
    }
    count.textContent = shown + ' of ' + rows.length + ' shown';
    if (noMatch) noMatch.hidden = shown !== 0 || rows.length === 0;
  }
  // ---- guests: sort by invitation date (rows without a date go last)
  const sortBy = document.getElementById('f-sort');
  if (sortBy) {
    const body = document.querySelector('#objects tbody');
    const original = rows.slice();
    sortBy.addEventListener('change', () => {
      const dir = sortBy.value === 'old' ? 1 : -1;
      const list = sortBy.value ? rows.slice().sort((a, b) => {
        const x = a.dataset.invited, y = b.dataset.invited;
        if (!x || !y) return (x ? 0 : 1) - (y ? 0 : 1);
        return x < y ? -dir : x > y ? dir : 0;
      }) : original;
      list.forEach((tr) => body.appendChild(tr));
    });
  }

  // summary tiles filter the table: by tag (apps) or by flag code (other tabs); a second click clears it
  tiles.forEach((t) => t.addEventListener('click', () => {
    const on = t.getAttribute('aria-pressed') !== 'true' && (t.dataset.tag || t.dataset.flag);
    tiles.forEach((x) => x.setAttribute('aria-pressed', 'false'));
    tileTag = ''; if (flag) flag.value = '';
    if (on) {
      t.setAttribute('aria-pressed', 'true');
      if (t.dataset.tag) tileTag = t.dataset.tag; else if (flag) flag.value = t.dataset.flag;
    }
    if (q) applyFilters();
  }));

  if (q) {
    [q, risk, flag, showLow].forEach((el) => el.addEventListener('input', applyFilters));
    applyFilters();
  }

  // ---- company chips on the Guests tab: one click filters the table by that domain
  document.querySelectorAll('.chip.dom').forEach((b) => b.addEventListener('click', () => {
    if (!q) return;
    q.value = b.dataset.q;
    q.dispatchEvent(new Event('input', { bubbles: true }));
  }));

  // ---- scope preview (instant, from the local inventory)
  const areas = Array.from(document.querySelectorAll('.scope textarea'));
  const timers = {};
  async function preview(area) {
    const box = document.getElementById('pv-' + area.dataset.kind);
    if (!area.value.trim()) { box.textContent = 'No pattern: nothing selected.'; return; }
    const r = await (await fetch('/scope/preview?kind=' + area.dataset.kind + '&patterns=' + encodeURIComponent(area.value))).json();
    const extra = r.selected > r.matched ? ' (+' + (r.selected - r.matched) + ' privileged, always included)' : '';
    box.textContent = r.matched + ' of ' + r.total + ' match' + extra + ' - ' + r.already_scanned + ' already scanned'
      + (r.sample.length ? ': ' + r.sample.join(', ') + (r.matched > r.sample.length ? ', ...' : '') : '');
  }
  areas.forEach((a) => {
    a.addEventListener('input', () => { clearTimeout(timers[a.id]); timers[a.id] = setTimeout(() => preview(a), 300); });
    preview(a);
  });

  // ---- background jobs
  const buttons = Array.from(document.querySelectorAll('#inventory, .scan, .analyse'));
  const progress = document.getElementById('sync-progress');
  let timer = null;

  async function poll() {
    try {
      const s = await (await fetch('/sync/status')).json();
      if (s.running) { progress.textContent = ' ' + (s.progress || 'Starting') + '...'; return; }
      clearInterval(timer);
      if (s.status === 'failed') {
        progress.textContent = ' Failed: ' + (s.error || 'unknown error');
        buttons.forEach((b) => (b.disabled = false));
      } else {
        location.reload();
      }
    } catch (e) {
      progress.textContent = ' Lost contact with the server; retrying...';
    }
  }

  function watch() {
    buttons.forEach((b) => (b.disabled = true));
    progress.textContent = ' Starting...';
    timer = setInterval(poll, 1500);
    poll();
  }

  async function post(url, body) {
    buttons.forEach((b) => (b.disabled = true));
    const csrf = document.querySelector('meta[name=csrf-token]').content;
    await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: JSON.stringify(body || {}) });
    watch();
  }

  const inv = document.getElementById('inventory');
  if (inv) inv.addEventListener('click', () => post('/sync/inventory'));
  document.querySelectorAll('.analyse').forEach((b) => b.addEventListener('click', () => post('/sync/analyse/' + b.dataset.tab)));
  document.querySelectorAll('.scan').forEach((b) => b.addEventListener('click', () =>
    post('/sync/scan/' + b.dataset.kind, { patterns: (document.getElementById('scope-' + b.dataset.kind) || { value: '' }).value })));
  if (document.getElementById('freshness').dataset.syncing === 'true') watch();
})();
