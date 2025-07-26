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
  
  // Check SSL settings before proceeding
  chrome.storage.sync.get(['ssl_check_enabled', 'ssl_block_invalid', 'ssl_strictness'], (settings) => {
    const sslCheckEnabled = settings.ssl_check_enabled !== false;
    const sslBlockInvalid = settings.ssl_block_invalid !== false;
    const sslStrictness = settings.ssl_strictness || 'moderate';
    
    if (!sslCheckEnabled) {
      // SSL checking disabled, just update icon
      updateSafeBrowsingIcon('safe');
      return;
    }
    
    // Enhanced SSL checking with detailed certificate validation
    if (!url.startsWith('https://')) {
      if (document.body) {
        showWarningOverlay('no-https');
        chrome.runtime.sendMessage({ type: 'THREAT_ALERT', url, level: 'high' });
      } else {
        window.addEventListener('DOMContentLoaded', () => {
          showWarningOverlay('no-https');
          chrome.runtime.sendMessage({ type: 'THREAT_ALERT', url, level: 'high' });
        });
      }
    } else {
      // For HTTPS sites, perform detailed SSL certificate validation
      chrome.runtime.sendMessage({ type: 'CHECK_SSL_CERTIFICATE', url }, (sslResult) => {
        if (sslResult && sslResult.valid) {
          updateSafeBrowsingIcon('safe');
          // Check if SSL indicator should be shown
          chrome.storage.sync.get('ssl_show_indicator', (indicatorSettings) => {
            if (indicatorSettings.ssl_show_indicator !== false) {
              showSSLInfo(sslResult);
            }
          });
        } else {
          // Handle invalid SSL based on strictness setting
          if (sslStrictness === 'strict' || (sslStrictness === 'moderate' && sslBlockInvalid)) {
            showWarningOverlay('invalid-ssl', sslResult);
            chrome.runtime.sendMessage({ type: 'THREAT_ALERT', url, level: 'medium' });
          } else {
            // Lenient mode - just show warning but don't block
            showSSLWarning(sslResult);
            updateSafeBrowsingIcon('warning');
          }
        }
      });
    }
  });
})();

function showWarningOverlay(type, sslDetails = null) {
  const overlay = document.createElement('div');
  overlay.style = 'position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.9);z-index:999999;color:white;display:flex;flex-direction:column;align-items:center;justify-content:center;font-size:2rem;';
  
  let title, message, buttonText;
  
  if (type === 'no-https') {
    title = '⚠️ WebShield Blocked This Site';
    message = '<span style="color:red;">No valid SSL certificate detected (not HTTPS)</span>';
    buttonText = 'Allow Anyway';
  } else if (type === 'invalid-ssl') {
    title = '⚠️ WebShield SSL Certificate Warning';
    message = `<span style="color:orange;">SSL certificate issues detected</span><br>
               <span style="font-size:1rem;color:yellow;">${sslDetails?.error || 'Certificate validation failed'}</span>`;
    buttonText = 'Proceed Anyway';
  }
  
  overlay.innerHTML = `
    <div>
      ${title}<br>
      ${message}<br>
      <button id='ws-allow-btn' style='margin-top:2rem;padding:1rem 2rem;font-size:1rem;'>${buttonText}</button>
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
      body: JSON.stringify({ 
        url: window.location.href, 
        reason: type === 'no-https' ? 'Blocked by user from extension (no SSL)' : 'Blocked by user from extension (invalid SSL)' 
      })
    }).catch(err => {
      console.error('Backend error:', err);
    });
    chrome.runtime.sendMessage({ type: 'GET_TAB_ID' }, (tabId) => {
      if (tabId) {
        chrome.runtime.sendMessage({ type: 'CLOSE_TAB', tabId });
      }
    });
  };
}

function showSSLWarning(sslResult) {
  // Create a warning indicator for lenient mode
  const warningIndicator = document.createElement('div');
  warningIndicator.id = 'webshield-ssl-warning';
  warningIndicator.style = `
    position: fixed;
    top: 10px;
    right: 10px;
    background: rgba(255, 193, 7, 0.9);
    color: black;
    padding: 8px 12px;
    border-radius: 20px;
    font-size: 12px;
    z-index: 10000;
    cursor: pointer;
    transition: opacity 0.3s;
  `;
  warningIndicator.innerHTML = '⚠️ SSL Warning';
  warningIndicator.title = `SSL Issue: ${sslResult?.error || 'Certificate validation failed'}`;
  
  // Auto-hide after 8 seconds
  setTimeout(() => {
    warningIndicator.style.opacity = '0.3';
  }, 8000);
  
  // Show details on click
  warningIndicator.onclick = () => {
    showSSLDetails(sslResult, true);
  };
  
  document.body.appendChild(warningIndicator);
}

function showSSLInfo(sslResult) {
  // Create a subtle SSL status indicator
  const sslIndicator = document.createElement('div');
  sslIndicator.id = 'webshield-ssl-indicator';
  sslIndicator.style = `
    position: fixed;
    top: 10px;
    right: 10px;
    background: rgba(0, 128, 0, 0.9);
    color: white;
    padding: 8px 12px;
    border-radius: 20px;
    font-size: 12px;
    z-index: 10000;
    cursor: pointer;
    transition: opacity 0.3s;
  `;
  sslIndicator.innerHTML = '🔒 SSL Valid';
  sslIndicator.title = `Issuer: ${sslResult.issuer?.organizationName || 'Unknown'}\nExpires: ${sslResult.expires || 'Unknown'}`;
  
  // Auto-hide after 5 seconds
  setTimeout(() => {
    sslIndicator.style.opacity = '0.3';
  }, 5000);
  
  // Show details on click
  sslIndicator.onclick = () => {
    showSSLDetails(sslResult, false);
  };
  
  document.body.appendChild(sslIndicator);
}

function showSSLDetails(sslResult, isWarning = false) {
  const detailsOverlay = document.createElement('div');
  detailsOverlay.style = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    background: rgba(0,0,0,0.8);
    z-index: 10001;
    display: flex;
    align-items: center;
    justify-content: center;
  `;
  
  const statusColor = isWarning ? 'orange' : 'green';
  const statusText = isWarning ? 'Warning ⚠️' : 'Valid ✓';
  const statusIcon = isWarning ? '⚠️' : '🔒';
  
  detailsOverlay.innerHTML = `
    <div style="background: white; color: black; padding: 20px; border-radius: 10px; max-width: 500px;">
      <h3 style="margin: 0 0 15px 0; color: ${statusColor};">${statusIcon} SSL Certificate Details</h3>
      <p><strong>Status:</strong> <span style="color: ${statusColor};">${statusText}</span></p>
      <p><strong>Issuer:</strong> ${sslResult.issuer?.organizationName || 'Unknown'}</p>
      <p><strong>Expires:</strong> ${sslResult.expires || 'Unknown'}</p>
      ${sslResult.error ? `<p style="color: red;"><strong>Error:</strong> ${sslResult.error}</p>` : ''}
      <button onclick="this.parentElement.parentElement.remove()" style="margin-top: 15px; padding: 8px 16px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer;">Close</button>
    </div>
  `;
  
  document.body.appendChild(detailsOverlay);
}

function updateSafeBrowsingIcon(status) {
  chrome.runtime.sendMessage({ type: 'UPDATE_ICON', status });
} 
