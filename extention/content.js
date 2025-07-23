// WebShield Content Script
const WEBSHIELD_WHITELIST = [
  "pggjs0c8-8000.inc1.devtunnels.ms",
  // Add any other trusted domains here
];

(function() {
  const url = window.location.href;
  const hostname = new URL(url).hostname;
  if (WEBSHIELD_WHITELIST.includes(hostname)) {
    // Do nothing for trusted domains
    return;
  }
  if (!url.startsWith('https://')) {
    if (document.body) {
      showWarningOverlay();
      chrome.runtime.sendMessage({ type: 'THREAT_ALERT', url, level: 'high' });
    } else {
      window.addEventListener('DOMContentLoaded', () => {
        showWarningOverlay();
        chrome.runtime.sendMessage({ type: 'THREAT_ALERT', url, level: 'high' });
      });
    }
  } else {
    updateSafeBrowsingIcon('safe');
  }
})();

function showWarningOverlay() {
  const overlay = document.createElement('div');
  overlay.style = 'position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.9);z-index:999999;color:white;display:flex;flex-direction:column;align-items:center;justify-content:center;font-size:2rem;';
  overlay.innerHTML = `
    <div>
      ⚠️ WebShield Blocked This Site<br>
      <span style='color:red;'>No valid SSL certificate detected (not HTTPS)</span><br>
      <button id='ws-allow-btn' style='margin-top:2rem;padding:1rem 2rem;font-size:1rem;'>Allow Anyway</button>
      <button id='ws-block-btn' style='margin-top:2rem;margin-left:1rem;padding:1rem 2rem;font-size:1rem;background:red;color:white;'>Block</button>
    </div>
  `;
  document.body.appendChild(overlay);

  document.getElementById('ws-allow-btn').onclick = () => {
    overlay.remove();
  };

  document.getElementById('ws-block-btn').onclick = () => {
    fetch('https://pggjs0c8-8000.inc1.devtunnels.ms/api/report_blacklist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: window.location.href, reason: 'Blocked by user from extension (no SSL)' })
    }).catch(err => {
      console.error('Backend error:', err);
    });
    chrome.runtime.sendMessage({ type: 'GET_TAB_ID' }, (tabId) => {
      console.log('Received tabId:', tabId);
      if (tabId) {
        chrome.runtime.sendMessage({ type: 'CLOSE_TAB', tabId });
      } else {
        console.error('No tabId received');
      }
    });
  };
}

function updateSafeBrowsingIcon(status) {
  chrome.runtime.sendMessage({ type: 'UPDATE_ICON', status });
} 
