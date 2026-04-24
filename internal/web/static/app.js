async function copyAddress() {
  const text = document.getElementById('mail-address')?.innerText?.trim();
  if (!text) return;
  await navigator.clipboard.writeText(text);
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
    const res = await fetch(`/api/mailboxes/${token}/status`, { cache: 'no-store' });
    if (!res.ok) {
      statusText.textContent = 'Statusabfrage fehlgeschlagen. Bitte Seite neu laden.';
      return;
    }

    const data = await res.json();
    const lastKnown = sessionStorage.getItem(stateKey) || '0';
    const latest = String(data.latest_message_id || '0');

    if (latest !== '0' && latest !== lastKnown) {
      sessionStorage.setItem(stateKey, latest);
      location.reload();
      return;
    }

    if (data.latest_report_id) {
      statusText.innerHTML = `Neue Mail analysiert (Score: ${data.latest_score}/10). <a href="/report/${data.latest_report_id}">Report oeffnen</a>`;
      return;
    }

    if (data.latest_message_id) {
      statusText.textContent = 'Mail empfangen, Analyse laeuft oder ist ohne Report abgeschlossen.';
      return;
    }

    statusText.textContent = 'Warte auf eingehende E-Mail ...';
  } catch (_) {
    statusText.textContent = 'Statusabfrage fehlgeschlagen. Bitte Seite neu laden.';
  }
}

setInterval(pollMailboxStatus, 5000);
pollMailboxStatus();