let mailboxPollTimer = null;
let checkPollTimer = null;

async function copyAddress() {
  const text = document.getElementById('mail-address')?.innerText?.trim();
  if (!text) return;
  await navigator.clipboard.writeText(text);
}

async function fetchMailboxStatus(token) {
  const res = await fetch(`/api/mailboxes/${token}/status`, { cache: 'no-store' });
  if (!res.ok) {
    throw new Error('status fetch failed');
  }
  return res.json();
}

async function pollMailboxStatus() {
  const card = document.getElementById('status-card');
  if (!card) return;

  const token = card.dataset.token;
  const statusText = document.getElementById('status-text');
  const stateKey = `mailprobe:lastmsg:${token}`;

  if (!sessionStorage.getItem(stateKey)) {
    sessionStorage.setItem(stateKey, card.dataset.latestMessageId || '0');
  }

  try {
    const data = await fetchMailboxStatus(token);
    const lastKnown = sessionStorage.getItem(stateKey) || '0';
    const latest = String(data.latest_message_id || '0');

    if (latest !== '0' && latest !== lastKnown) {
      sessionStorage.setItem(stateKey, latest);
      location.reload();
      return;
    }

    if (data.latest_report_path) {
      statusText.innerHTML = `Neue Mail analysiert (Score: ${data.latest_score}/10). <a href="${data.latest_report_path}">Report oeffnen</a>`;
      return;
    }

    if (data.latest_message_id) {
      statusText.textContent = 'Mail empfangen, Analyse laeuft noch.';
      return;
    }

    statusText.textContent = 'Warte auf eingehende E-Mail ...';
  } catch (_) {
    statusText.textContent = 'Statusabfrage fehlgeschlagen. Bitte Seite neu laden.';
  }
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

async function runCheckOnce(token) {
  try {
    const data = await fetchMailboxStatus(token);

    if (data.latest_report_path) {
      setCheckUIState(false, 'Report ist bereit. Weiterleitung...', 'ok');
      window.location.href = data.latest_report_path;
      return true;
    }

    if (data.latest_message_id) {
      setCheckUIState(true, 'Mail ist eingegangen. Analyse laeuft ...', 'warn');
      return false;
    }

    setCheckUIState(true, 'Noch keine E-Mail eingegangen. Ich warte weiter ...', 'warn');
    return false;
  } catch (_) {
    setCheckUIState(false, 'Check fehlgeschlagen. Bitte erneut klicken.', 'warn');
    return true;
  }
}

function startCheckLoop() {
  const panel = document.getElementById('check-panel');
  const token = panel?.dataset?.token;
  if (!token) return;

  if (checkPollTimer) {
    clearInterval(checkPollTimer);
    checkPollTimer = null;
  }

  setCheckUIState(true, 'Pruefe Eingang ...', 'warn');

  runCheckOnce(token).then((done) => {
    if (done) return;
    checkPollTimer = setInterval(async () => {
      const finished = await runCheckOnce(token);
      if (finished && checkPollTimer) {
        clearInterval(checkPollTimer);
        checkPollTimer = null;
      }
    }, 2500);
  });
}

function setupCheckButton() {
  const button = document.getElementById('check-btn');
  if (!button) return;
  button.addEventListener('click', startCheckLoop);
}

function setupMailboxPolling() {
  const card = document.getElementById('status-card');
  if (!card) return;

  if (mailboxPollTimer) {
    clearInterval(mailboxPollTimer);
  }

  pollMailboxStatus();
  mailboxPollTimer = setInterval(pollMailboxStatus, 5000);
}

setupCheckButton();
setupMailboxPolling();