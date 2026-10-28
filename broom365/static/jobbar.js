// A bar at the top of every page (except the dashboard, which shows its own) while a job (counting or analysing) runs on the server.
// The work does not depend on this page: it keeps going if you leave.
(function () {
  if (document.getElementById('sync-progress')) return;
  const bar = document.createElement('div');
  bar.className = 'jobbar';
  bar.hidden = true;
  bar.setAttribute('role', 'status');
  document.body.insertBefore(bar, document.body.firstChild);
  let timer = null;

  function show(text, done) {
    bar.hidden = false;
    bar.classList.toggle('done', !!done);
    bar.innerHTML = '';
    const msg = document.createElement('span');
    msg.textContent = text;
    bar.appendChild(msg);
    const link = document.createElement('a');
    link.href = '/';
    link.textContent = done ? 'Open the dashboard' : 'Dashboard';
    bar.appendChild(link);
    if (done) {
      const close = document.createElement('button');
      close.type = 'button';
      close.textContent = 'Close';
      close.addEventListener('click', () => { bar.hidden = true; });
      bar.appendChild(close);
    }
  }

  async function poll(first) {
    try {
      const s = await (await fetch('/sync/status')).json();
      if (s.running) {
        show((s.progress || 'Working') + '... You can keep browsing: it goes on in the server.', false);
        if (!timer) timer = setInterval(() => poll(false), 2000);
        return;
      }
      if (timer) {
        clearInterval(timer);
        timer = null;
        show(s.status === 'failed' ? 'The job failed: ' + (s.error || 'unknown error') : 'The job finished.', true);
      }
    } catch (e) {
      if (!first && timer) show('Lost contact with the server; retrying...', false);
    }
  }
  poll(true);
})();
