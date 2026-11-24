let authToken = localStorage.getItem('gg_token') || null;
let currentUser = localStorage.getItem('gg_user') || null;
let authMode = 'login';

const luaInput = document.getElementById('luaInput');
const charCount = document.getElementById('charCount');
const protectBtn = document.getElementById('protectBtn');
const outputPanel = document.getElementById('outputPanel');
const loadstringOutput = document.getElementById('loadstringOutput');
const copyBtn = document.getElementById('copyBtn');
const authModal = document.getElementById('authModal');
const openAuthBtn = document.getElementById('openAuthBtn');
const closeAuthBtn = document.getElementById('closeAuthBtn');
const authForm = document.getElementById('authForm');
const authError = document.getElementById('authError');
const authSubmitBtn = document.getElementById('authSubmitBtn');
const navUserArea = document.getElementById('navUserArea');
const toastEl = document.getElementById('toast');

function showToast(msg) {
  toastEl.textContent = msg;
  toastEl.classList.remove('hidden');
  setTimeout(() => toastEl.classList.add('hidden'), 3000);
}

function updateNavUI() {
  if (authToken && currentUser) {
    navUserArea.innerHTML = `
      <span class="badge-live"><span class="pulse-dot"></span> ${currentUser.toUpperCase()}</span>
      <button class="btn-ghost" id="logoutBtn">Logout</button>
    `;
    document.getElementById('logoutBtn').addEventListener('click', () => {
      authToken = null;
      currentUser = null;
      localStorage.removeItem('gg_token');
      localStorage.removeItem('gg_user');
      updateNavUI();
      showToast('Logged out');
    });
  } else {
    navUserArea.innerHTML = `
      <span class="badge-live"><span class="pulse-dot"></span> SHIELD ACTIVE</span>
      <button class="btn-ghost" id="openAuthBtn">Sign In</button>
    `;
    document.getElementById('openAuthBtn').addEventListener('click', () => {
      authModal.classList.remove('hidden');
    });
  }
}

updateNavUI();

luaInput.addEventListener('input', () => {
  charCount.textContent = `${luaInput.value.length} bytes`;
});

if (openAuthBtn) {
  openAuthBtn.addEventListener('click', () => authModal.classList.remove('hidden'));
}

closeAuthBtn.addEventListener('click', () => authModal.classList.add('hidden'));

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    authMode = btn.dataset.tab;
    authSubmitBtn.textContent = authMode === 'login' ? 'Sign In' : 'Create Account';
    authError.classList.add('hidden');
  });
});

authForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  authError.classList.add('hidden');

  const username = document.getElementById('authUsername').value;
  const password = document.getElementById('authPassword').value;

  try {
    const res = await fetch('/api/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: authMode, username, password })
    });
    const data = await res.json();

    if (!res.ok) {
      authError.textContent = data.error || 'Authentication failed';
      authError.classList.remove('hidden');
      return;
    }

    authToken = data.token;
    currentUser = data.username;
    localStorage.setItem('gg_token', authToken);
    localStorage.setItem('gg_user', currentUser);
    authModal.classList.add('hidden');
    updateNavUI();
    showToast(`Welcome, ${currentUser}`);
  } catch {
    authError.textContent = 'Network error';
    authError.classList.remove('hidden');
  }
});

protectBtn.addEventListener('click', async () => {
  if (!authToken) {
    authModal.classList.remove('hidden');
    showToast('Please login or create an account first');
    return;
  }

  const script = luaInput.value;
  if (!script.trim()) {
    showToast('Enter a Lua script to protect');
    return;
  }

  protectBtn.disabled = true;

  try {
    const res = await fetch('/api/protect', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`
      },
      body: JSON.stringify({
        script,
        options: {
          antiBootstrap: document.getElementById('antiBootstrap').checked,
          antiDump: document.getElementById('antiDump').checked,
          antiEnvLog: document.getElementById('antiEnvLog').checked,
          antiHook: document.getElementById('antiHook').checked
        }
      })
    });

    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'Protection failed');
      return;
    }

    loadstringOutput.textContent = data.loadstring;
    outputPanel.classList.remove('hidden');
    showToast('Payload encrypted & loader generated');
  } catch {
    showToast('Server error');
  } finally {
    protectBtn.disabled = false;
  }
});

copyBtn.addEventListener('click', () => {
  navigator.clipboard.writeText(loadstringOutput.textContent);
  showToast('Loadstring copied to clipboard');
});
