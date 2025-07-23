const API_BASE = "https://pggjs0c8-8000.inc1.devtunnels.ms";

// Account management
const loginForm = document.getElementById('login-form');
const userInfo = document.getElementById('user-info');
const loginBtn = document.getElementById('login-btn');
const logoutBtn = document.getElementById('logout-btn');
const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const userEmail = document.getElementById('user-email');

loginBtn.onclick = async () => {
  const email = emailInput.value;
  const password = passwordInput.value;
  const res = await fetch(`${API_BASE}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  const data = await res.json();
  if (res.ok && data.success) {
    chrome.storage.sync.set({ token: data.token, user_email: email });
    loginForm.style.display = 'none';
    userInfo.style.display = 'block';
    userEmail.textContent = email;
    loadHistory();
  } else {
    alert(data.detail || 'Login failed');
  }
};

logoutBtn.onclick = () => {
  chrome.storage.sync.remove(['token', 'user_email']);
  loginForm.style.display = 'block';
  userInfo.style.display = 'none';
  userEmail.textContent = '';
};

// Show user info if logged in
chrome.storage.sync.get('user_email', ({ user_email }) => {
  if (user_email) {
    loginForm.style.display = 'none';
    userInfo.style.display = 'block';
    userEmail.textContent = user_email;
    loadHistory();
  }
});

// Scan URL
const scanBtn = document.getElementById('scan-btn');
const scanUrlInput = document.getElementById('scan-url');
const scanResult = document.getElementById('scan-result');
scanBtn.onclick = async () => {
  const url = scanUrlInput.value;
  const res = await fetch(`${API_BASE}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url })
  });
  const data = await res.json();
  if (res.ok && data.results) {
    scanResult.textContent = `Threat Level: ${data.results.threat_level}`;
  } else {
    scanResult.textContent = data.detail || 'Scan failed';
  }
};

// Load scan history
function loadHistory() {
  const historyList = document.getElementById('history-list');
  fetch(`${API_BASE}/api/history?limit=10`)
    .then(res => res.json())
    .then(data => {
      historyList.innerHTML = '';
      data.forEach(item => {
        const li = document.createElement('li');
        li.textContent = `${item.url} - ${item.threat_level || 'N/A'}`;
        historyList.appendChild(li);
      });
    });
}

// Report suspicious site
const reportBtn = document.getElementById('report-btn');
reportBtn.onclick = () => {
  const url = prompt('Enter the suspicious URL to report:');
  if (url) {
    fetch(`${API_BASE}/api/report_blacklist`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, reason: 'Reported from extension' })
    })
      .then(res => res.json())
      .then(data => alert(data.message || 'Reported!'));
  }
};

// Settings and emergency disable
const settingsBtn = document.getElementById('settings-btn');
settingsBtn.onclick = () => {
  chrome.runtime.openOptionsPage();
};
const emergencyBtn = document.getElementById('emergency-btn');
emergencyBtn.onclick = () => {
  chrome.storage.sync.set({ emergency_disabled: true }, () => alert('Protection disabled!'));
}; 
