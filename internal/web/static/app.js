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
  try {
    const res = await fetch(`/api/mailboxes/${token}/status`, { cache: 'no-store' });
    if (!res.ok) return;
    const data = await res.json();
    if (data.latest_report_id) {
      statusText.innerHTML = `Neue Mail analysiert (Score: ${data.latest_score}/10). <a href="/report/${data.latest_report_id}">Report öffnen</a>`;
      return;
    }
    if (data.latest_message_id) {
      statusText.textContent = 'Mail empfangen, Analyse läuft oder ist ohne Report abgeschlossen.';
      return;
    }
    statusText.textContent = 'Warte auf eingehende E-Mail ...';
  } catch (_) {
    // keep silent for polling
  }
}

setInterval(pollMailboxStatus, 5000);
pollMailboxStatus();
