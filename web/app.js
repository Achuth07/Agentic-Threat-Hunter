const activityList = document.getElementById('activity-list');
const input = document.getElementById('chat-input');
const sendBtn = document.getElementById('send-btn');
const resultsPre = document.getElementById('results');
const resultsCard = document.getElementById('results-card');
const findings = document.getElementById('findings');
const appRoot = document.querySelector('.app');
const toggleSidebarBtn = document.getElementById('toggle-sidebar');
const navLinks = document.querySelectorAll('.nav-item');

function wsUrl() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  return `${proto}://${location.host}/ws`;
}

let ws;
function connect() {
  ws = new WebSocket(wsUrl());
  ws.onopen = () => pushActivity({
    icon: '🔌', title: 'Connected', detail: 'WebSocket ready', status: 'done'
  });
  ws.onclose = () => pushActivity({
    icon: '⚠️', title: 'Disconnected', detail: 'Reconnecting shortly…', status: 'error'
  });
  ws.onmessage = (ev) => handleMessage(ev);
}

function iconFor(name) {
  const map = { search: '🔍', robot: '🤖', code: '🧩', bolt: '⚡', check: '✅' };
  return map[name] || '•';
}

function pushActivity({ icon, title, detail, status }) {
  const li = document.createElement('li');
  li.className = 'activity-item';
  li.innerHTML = `
    <div class="icon">${icon || '•'}</div>
    <div>
      <div class="title">${title}</div>
      <div class="detail">${detail || ''}</div>
    </div>
    <div class="chip ${status}">${status}</div>
  `;
  activityList.prepend(li);
}

function addFinding(text, severity) {
  const row = document.createElement('div');
  row.className = 'finding';
  row.innerHTML = `
    <div>${text}</div>
    <span class="severity ${severity}">${severity.toUpperCase()}</span>
  `;
  findings.prepend(row);
}

function handleMessage(ev) {
  let msg;
  try { msg = JSON.parse(ev.data); } catch { return; }

  if (msg.type === 'activity') {
    pushActivity({ icon: iconFor(msg.icon), title: msg.title, detail: msg.detail, status: msg.status });
  } else if (msg.type === 'error') {
    pushActivity({ icon: '⛔', title: msg.title, detail: msg.detail, status: 'error' });
    addFinding(`${msg.title}: ${msg.detail}`, 'medium');
  } else if (msg.type === 'final') {
    const pretty = JSON.stringify({ spl: msg.spl, count: msg.count, results: msg.results }, null, 2);
    resultsPre.textContent = pretty;
    resultsCard.style.display = 'block';
    const sev = msg.count > 0 ? 'high' : 'resolved';
    addFinding(msg.count > 0 ? 'Potential findings detected in latest search' : 'No findings in latest search', sev);
    // sample stat tweaks
    const analyzed = document.getElementById('stat-analyzed');
    analyzed.textContent = Number(analyzed.textContent) + (msg.count || 0);
  }
}

function send() {
  const text = input.value.trim();
  if (!text || ws.readyState !== 1) return;
  ws.send(text);
  pushActivity({ icon: '🗣️', title: 'You asked', detail: text, status: 'done' });
  input.value = '';
}

sendBtn.addEventListener('click', send);
input.addEventListener('keydown', (e) => { if (e.key === 'Enter') send(); });

connect();

// Sidebar toggle and nav state
function setSidebar(state) {
  appRoot.dataset.sidebar = state;
  localStorage.setItem('sidebar', state);
}

toggleSidebarBtn?.addEventListener('click', () => {
  const next = appRoot.dataset.sidebar === 'expanded' ? 'collapsed' : 'expanded';
  setSidebar(next);
});

setSidebar(localStorage.getItem('sidebar') || 'collapsed');

navLinks.forEach((a) => {
  a.addEventListener('click', (e) => {
    e.preventDefault();
    navLinks.forEach(n => n.classList.remove('active'));
    a.classList.add('active');
    // For now we’re only implementing Agentic Chat in this SPA
  });
});
