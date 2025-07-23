// Notification preferences
const notifPref = document.getElementById('notif-pref');
const saveNotif = document.getElementById('save-notif');
saveNotif.onclick = () => {
  chrome.storage.sync.set({ notifPref: notifPref.value }, () => alert('Saved!'));
};

// Whitelist management
const whitelistList = document.getElementById('whitelist-list');
const addWhitelist = document.getElementById('add-whitelist');
const addWhitelistBtn = document.getElementById('add-whitelist-btn');
function loadWhitelist() {
  chrome.storage.sync.get('whitelist', ({ whitelist = [] }) => {
    whitelistList.innerHTML = '';
    whitelist.forEach(domain => {
      const li = document.createElement('li');
      li.textContent = domain;
      const btn = document.createElement('button');
      btn.textContent = 'Remove';
      btn.onclick = () => {
        chrome.storage.sync.get('whitelist', ({ whitelist = [] }) => {
          const newList = whitelist.filter(d => d !== domain);
          chrome.storage.sync.set({ whitelist: newList }, loadWhitelist);
        });
      };
      li.appendChild(btn);
      whitelistList.appendChild(li);
    });
  });
}
addWhitelistBtn.onclick = () => {
  const domain = addWhitelist.value.trim();
  if (domain) {
    chrome.storage.sync.get('whitelist', ({ whitelist = [] }) => {
      whitelist.push(domain);
      chrome.storage.sync.set({ whitelist }, loadWhitelist);
      addWhitelist.value = '';
    });
  }
};
loadWhitelist();

// Sync settings
const syncBtn = document.getElementById('sync-btn');
syncBtn.onclick = () => {
  chrome.runtime.sendMessage({ type: 'SYNC_SETTINGS', settings: { notifPref: notifPref.value } }, (res) => {
    if (res && res.success) alert('Settings synced!');
  });
}; 
