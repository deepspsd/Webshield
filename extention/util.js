// Utility functions for WebShield Extension
export function getToken(cb) {
  chrome.storage.sync.get('token', ({ token }) => cb(token));
}
export function setToken(token, cb) {
  chrome.storage.sync.set({ token }, cb);
} 
