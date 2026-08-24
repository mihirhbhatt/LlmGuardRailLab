const messages = document.querySelector('#messages');
const promptBox = document.querySelector('#prompt');
const form = document.querySelector('#chat-form');
const flag = document.querySelector('#flag');

function addMessage(label, text, blocked = false) {
  messages.querySelector('.empty')?.remove();
  const item = document.createElement('div');
  item.className = `message${blocked ? ' blocked' : ''}`;
  item.innerHTML = `<div class="label">${label}</div><div></div>`;
  item.lastElementChild.textContent = text;
  messages.append(item);
  messages.scrollTop = messages.scrollHeight;
}

function renderTrace(record) {
  const stages = [['adaptive', record.stages.adaptive], ['input', record.stages.input], ['output', record.stages.output]];
  document.querySelector('#trace').innerHTML = stages.filter(([, stage]) => stage).map(([name, stage]) =>
    `<div class="trace-row"><span>${name.toUpperCase()}</span><span class="${stage.verdict === 'allow' ? 'ok' : 'bad'}">${stage.verdict} · ${stage.latency_ms}ms</span></div>`).join('') || '<span class="muted">No guard stages recorded.</span>';
}

async function refreshStats() {
  const stats = await fetch('/api/stats').then(response => response.json());
  document.querySelector('#entries').textContent = stats.entries ?? 0;
  document.querySelector('#hits').textContent = stats.total_proactive_hits ?? 0;
  document.querySelector('#signatures').textContent = stats.mined_signatures ?? 0;
  document.querySelector('#model').textContent = `${stats.backend || 'local'} · guarded`;
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  const prompt = promptBox.value.trim();
  if (!prompt) return;
  addMessage('YOU', prompt);
  promptBox.value = '';
  const sendButton = form.querySelector('.send');
  sendButton.disabled = true;
  sendButton.innerHTML = 'Guarding <span>...</span>';
  document.querySelector('#model').textContent = 'guarding live message';
  try {
    const response = await fetch('/api/chat', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({prompt}) });
    const record = await response.json();
    if (record.error) addMessage('PIPELINE ERROR', record.error, true);
    else {
      const label = record.blocked_at ? `BLOCKED @ ${record.blocked_at.toUpperCase()}` : (record.model || 'ASSISTANT').toUpperCase();
      addMessage(label, record.final_text, Boolean(record.blocked_at));
      renderTrace(record);
      const timing = record.inference_ms ? `Inference: ${(record.inference_ms / 1000).toFixed(1)}s · Guards: ${record.guard_ms.toFixed(1)}ms` : 'Blocked before inference';
      document.querySelector('#trace').insertAdjacentHTML('afterbegin', `<div class="timing">${timing}</div>`);
      flag.disabled = false;
    }
  } catch (error) {
    addMessage('CONNECTION ERROR', `Could not reach the guard server: ${error.message}`, true);
  } finally {
    sendButton.disabled = false;
    sendButton.innerHTML = 'Send <span>↗</span>';
    refreshStats();
  }
});

flag.addEventListener('click', async () => { await fetch('/api/flag', {method:'POST'}); flag.disabled = true; refreshStats(); });
document.querySelector('#reset').addEventListener('click', async () => { await fetch('/api/reset', {method:'POST'}); refreshStats(); });
refreshStats().catch(() => { document.querySelector('#model').textContent = 'pipeline unavailable'; });