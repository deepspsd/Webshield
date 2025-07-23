// WebShield Extension Background Script
const API_BASE = "https://pggjs0c8-8000.inc1.devtunnels.ms";

// Listen for messages from content/popup/options
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  console.log('Background received message:', msg, sender);
  if (msg.type === 'CHECK_URL') {
    checkUrl(msg.url, sendResponse);
    return true;
  }
  if (msg.type === 'REPORT_URL') {
    reportUrl(msg.url, msg.reason, sendResponse);
    return true;
  }
  if (msg.type === 'GET_HISTORY') {
    getHistory(sendResponse);
    return true;
  }
  if (msg.type === 'SYNC_SETTINGS') {
    syncSettings(msg.settings, sendResponse);
    return true;
  }
  if (msg.type === 'THREAT_ALERT') {
    showThreatNotification(msg.url, msg.level);
    return true;
  }
  if (msg.type === 'GET_TAB_ID') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      console.log('Queried tabs:', tabs);
      sendResponse(tabs[0]?.id);
    });
    return true;
  }
  if (msg.type === 'CLOSE_TAB' && msg.tabId) {
    console.log('Closing tab:', msg.tabId);
    chrome.tabs.remove(msg.tabId);
  }
});

// Real-time URL check
async function checkUrl(url, cb) {
  try {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    cb(data);
  } catch (e) {
    cb({ error: 'Network error' });
  }
}

// Report suspicious URL
async function reportUrl(url, reason, cb) {
  try {
    const res = await fetch(`${API_BASE}/api/report_blacklist`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, reason })
    });
    const data = await res.json();
    cb(data);
  } catch (e) {
    cb({ error: 'Network error' });
  }
}

// Get scan history
async function getHistory(cb) {
  try {
    const res = await fetch(`${API_BASE}/api/history?limit=20`);
    const data = await res.json();
    cb(data);
  } catch (e) {
    cb([]);
  }
}

// Sync settings
function syncSettings(settings, cb) {
  chrome.storage.sync.set({ settings }, () => cb({ success: true }));
}

// Show threat notification
function showThreatNotification(url, level) {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: 'WebShield Threat Blocked',
    message: `Blocked a ${level} risk site: ${url}`
  });
}

// Context menu for quick scan/report
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'scan-url',
    title: 'Scan this URL with WebShield',
    contexts: ['link']
  });
  chrome.contextMenus.create({
    id: 'report-url',
    title: 'Report this site as suspicious',
    contexts: ['link']
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'scan-url') {
    chrome.runtime.sendMessage({ type: 'CHECK_URL', url: info.linkUrl });
  }
  if (info.menuItemId === 'report-url') {
    chrome.runtime.sendMessage({ type: 'REPORT_URL', url: info.linkUrl, reason: 'User reported from extension' });
  }
}); 
