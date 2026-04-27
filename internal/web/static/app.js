let mailboxPollTimer = null;
let checkEventSource = null;
let mailboxEventSource = null;

function resolveThemePreference(preference) {
  if (preference === 'dark' || preference === 'light') return preference;
  if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) return 'dark';
  return 'light';
}

function applyThemePreference(preference) {
  const selected = preference || localStorage.getItem('mailprobe-theme') || 'auto';
  const resolved = resolveThemePreference(selected);
  document.documentElement.dataset.bsTheme = resolved;
  document.documentElement.dataset.themePreference = selected;

  const icon = document.querySelector('#theme-toggle .theme-icon');
  if (icon) {
    icon.textContent = selected === 'auto' ? '◐' : (resolved === 'dark' ? '☾' : '☀');
  }
}

function setupThemeToggle() {
  applyThemePreference(localStorage.getItem('mailprobe-theme') || 'auto');

  const button = document.getElementById('theme-toggle');
  if (button) {
    button.addEventListener('click', () => {
      const current = document.documentElement.dataset.themePreference || 'auto';
      const next = current === 'auto' ? 'dark' : (current === 'dark' ? 'light' : 'auto');
      localStorage.setItem('mailprobe-theme', next);
      applyThemePreference(next);
    });
  }

  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
      if ((localStorage.getItem('mailprobe-theme') || 'auto') === 'auto') {
        applyThemePreference('auto');
      }
    });
  }
}

async function copyAddress() {
  const text = document.getElementById('mail-address')?.innerText?.trim();
  if (!text) return;
  const ok = await writeClipboardWithFallback(text);
  if (ok) {
    setTransientStatus('Adresse kopiert.', 'ok');
    return;
  }
  setTransientStatus('Kopieren fehlgeschlagen. Bitte manuell markieren und kopieren.', 'warn');
}

async function writeClipboardWithFallback(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_) {
      // fallback below
    }
  }

  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.position = 'absolute';
  ta.style.left = '-9999px';
  document.body.appendChild(ta);
  ta.select();

  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch (_) {
    ok = false;
  } finally {
    document.body.removeChild(ta);
  }
  return ok;
}

async function fetchMailboxStatus(token) {
  const res = await fetch(`/api/mailboxes/${token}/status`, { cache: 'no-store' });
  if (!res.ok) {
    throw new Error('status fetch failed');
  }
  return res.json();
}

async function createMailbox() {
  const res = await fetch('/api/mailboxes', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    cache: 'no-store',
    body: '{}',
  });
  if (!res.ok) {
    throw new Error('mailbox create failed');
  }
  return res.json();
}

function formatExpiry(value) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  const locale = navigator.language || 'de-DE';
  return d.toLocaleString(locale, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZoneName: 'short',
  });
}

function updateMailboxIdentity(data) {
  const panel = document.getElementById('check-panel');
  const address = document.getElementById('mail-address');
  const expires = document.getElementById('mail-expires-at');
  const link = document.getElementById('mailbox-direct-link');
  const statusCard = document.getElementById('status-card');

  if (panel) panel.dataset.token = data.token;
  if (address) address.textContent = data.address;
  if (expires) {
    expires.dataset.time = data.expires_at;
    expires.textContent = formatExpiry(data.expires_at);
  }
  if (link) {
    link.href = data.mailbox_url;
    link.textContent = data.mailbox_url;
  }
  if (statusCard) {
    statusCard.dataset.token = data.token;
    statusCard.dataset.latestMessageId = '0';
  }
  sessionStorage.setItem(`mailprobe:lastmsg:${data.token}`, '0');
}

async function createNewAddress() {
  const button = document.getElementById('new-address-btn');
  if (!button) return;
  const oldText = button.textContent;
  button.disabled = true;
  button.textContent = 'Erzeuge Adresse ...';
  closeCheckStream();
  closeMailboxStream();
  if (mailboxPollTimer) {
    clearInterval(mailboxPollTimer);
    mailboxPollTimer = null;
  }
  try {
    const data = await createMailbox();
    updateMailboxIdentity(data);
    setCheckUIState(false, 'Neue Testadresse ist bereit.', 'ok');
    setupMailboxPolling();
  } catch (_) {
    setTransientStatus('Neue Adresse konnte nicht erzeugt werden.', 'warn');
  } finally {
    button.disabled = false;
    button.textContent = oldText;
  }
}

function updateMailboxStatusText(data) {
  const statusText = document.getElementById('status-text');
  if (!statusText) return;

  if (data.latest_report_path) {
    statusText.innerHTML = `Neue Mail analysiert (Score: ${data.latest_score}/10). <a href="${data.latest_report_path}">Report öffnen</a>`;
    return;
  }
  if (data.latest_message_id) {
    statusText.textContent = 'Mail empfangen, Analyse läuft noch.';
    return;
  }
  statusText.textContent = 'Warte auf eingehende E-Mail ...';
}

function setCheckUIState(active, message, tone) {
  const status = document.getElementById('check-status');
  const loader = document.getElementById('check-loader');
  const button = document.getElementById('check-btn');
  if (!status || !loader || !button) return;

  status.textContent = message;
  status.classList.remove('is-ok', 'is-warn');
  if (tone === 'ok') status.classList.add('is-ok');
  if (tone === 'warn') status.classList.add('is-warn');

  if (active) {
    loader.classList.remove('d-none');
    loader.classList.add('is-active');
    button.disabled = true;
  } else {
    loader.classList.add('d-none');
    loader.classList.remove('is-active');
    button.disabled = false;
  }
}

function setTransientStatus(message, tone) {
  const checkStatus = document.getElementById('check-status');
  if (checkStatus) {
    checkStatus.textContent = message;
    checkStatus.classList.remove('is-ok', 'is-warn');
    if (tone === 'ok') checkStatus.classList.add('is-ok');
    if (tone === 'warn') checkStatus.classList.add('is-warn');
    return;
  }

  const mailboxStatus = document.getElementById('status-text');
  if (mailboxStatus) {
    mailboxStatus.textContent = message;
    return;
  }

  const toast = document.createElement('div');
  toast.className = `copy-toast ${tone === 'ok' ? 'is-ok' : 'is-warn'}`;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 2200);
}

function closeCheckStream() {
  if (checkEventSource) {
    checkEventSource.close();
    checkEventSource = null;
  }
}

function handleCheckStatusEvent(data) {
  if (data.latest_report_path) {
    setCheckUIState(false, 'Report ist bereit. Weiterleitung...', 'ok');
    closeCheckStream();
    window.location.href = data.latest_report_path;
    return;
  }
  if (data.latest_message_id) {
    setCheckUIState(true, 'Mail ist eingegangen. Analyse läuft ...', 'warn');
    return;
  }
  setCheckUIState(true, 'Noch keine E-Mail eingegangen. Ich warte weiter ...', 'warn');
}

function startCheckLoop() {
  const panel = document.getElementById('check-panel');
  const token = panel?.dataset?.token;
  if (!token) return;

  setCheckUIState(true, 'Prüfe Eingang ...', 'warn');
  closeCheckStream();

  if (window.EventSource) {
    const es = new EventSource(`/api/mailboxes/${token}/events`);
    checkEventSource = es;

    es.addEventListener('status', (evt) => {
      try {
        const data = JSON.parse(evt.data);
        handleCheckStatusEvent(data);
      } catch (_) {
        setCheckUIState(false, 'Ungültige Event-Daten erhalten.', 'warn');
      }
    });

    es.addEventListener('error', () => {
      setCheckUIState(false, 'Event-Stream unterbrochen. Bitte erneut auf Check klicken.', 'warn');
      closeCheckStream();
    });
    return;
  }

  // Fallback for browsers without EventSource support.
  if (mailboxPollTimer) clearInterval(mailboxPollTimer);
  const runFallback = async () => {
    try {
      const data = await fetchMailboxStatus(token);
      handleCheckStatusEvent(data);
      if (data.latest_report_path && mailboxPollTimer) {
        clearInterval(mailboxPollTimer);
        mailboxPollTimer = null;
      }
    } catch (_) {
      setCheckUIState(false, 'Check fehlgeschlagen. Bitte erneut klicken.', 'warn');
      if (mailboxPollTimer) {
        clearInterval(mailboxPollTimer);
        mailboxPollTimer = null;
      }
    }
  };
  runFallback();
  mailboxPollTimer = setInterval(runFallback, 2500);
}

function setupCheckButton() {
  const button = document.getElementById('check-btn');
  if (!button) return;
  button.addEventListener('click', startCheckLoop);
}

function closeMailboxStream() {
  if (mailboxEventSource) {
    mailboxEventSource.close();
    mailboxEventSource = null;
  }
}

function setupNewAddressButton() {
  const button = document.getElementById('new-address-btn');
  if (!button) return;
  button.addEventListener('click', createNewAddress);
}

function setupCopyButtons() {
  document.querySelectorAll('[data-copy]').forEach((button) => {
    button.addEventListener('click', async () => {
      const ok = await writeClipboardWithFallback(button.getAttribute('data-copy') || '');
      const original = button.textContent;
      button.textContent = ok ? 'Kopiert' : 'Fehler';
      button.classList.toggle('is-ok', ok);
      button.classList.toggle('is-warn', !ok);
      setTimeout(() => {
        button.textContent = original;
        button.classList.remove('is-ok', 'is-warn');
      }, 1600);
    });
  });
}

function localizeStaticTimes() {
  document.querySelectorAll('[data-time]').forEach((el) => {
    el.textContent = formatExpiry(el.dataset.time);
  });
}

function setupMailboxPolling() {
  const card = document.getElementById('status-card');
  if (!card) return;

  closeMailboxStream();
  const token = card.dataset.token;
  const stateKey = `mailprobe:lastmsg:${token}`;
  if (!sessionStorage.getItem(stateKey)) {
    sessionStorage.setItem(stateKey, card.dataset.latestMessageId || '0');
  }

  const onStatus = (data) => {
    const lastKnown = sessionStorage.getItem(stateKey) || '0';
    const latest = String(data.latest_message_id || '0');
    if (latest !== '0' && latest !== lastKnown) {
      sessionStorage.setItem(stateKey, latest);
      location.reload();
      return;
    }
    updateMailboxStatusText(data);
  };

  if (window.EventSource) {
    const es = new EventSource(`/api/mailboxes/${token}/events`);
    mailboxEventSource = es;
    es.addEventListener('status', (evt) => {
      try {
        onStatus(JSON.parse(evt.data));
      } catch (_) {
        document.getElementById('status-text').textContent = 'Statusabfrage fehlgeschlagen. Bitte Seite neu laden.';
      }
    });
    es.addEventListener('error', () => {
      es.close();
      if (mailboxEventSource === es) mailboxEventSource = null;
      document.getElementById('status-text').textContent = 'Event-Stream unterbrochen. Wechsle auf Polling.';
      startMailboxPollingFallback(token, onStatus);
    });
    return;
  }

  startMailboxPollingFallback(token, onStatus);
}

function startMailboxPollingFallback(token, onStatus) {
  if (mailboxPollTimer) clearInterval(mailboxPollTimer);
  const run = async () => {
    try {
      const data = await fetchMailboxStatus(token);
      onStatus(data);
    } catch (_) {
      const statusText = document.getElementById('status-text');
      if (statusText) statusText.textContent = 'Statusabfrage fehlgeschlagen. Bitte Seite neu laden.';
    }
  };
  run();
  mailboxPollTimer = setInterval(run, 5000);
}

setupThemeToggle();
setupCheckButton();
setupNewAddressButton();
setupCopyButtons();
localizeStaticTimes();
setupMailboxPolling();
