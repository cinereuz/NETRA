const API_BASE = 'http://localhost:5000';

// Badge per kategori
const BADGE = {
  'aman':                { text: '✓',   color: '#16a34a' },
  'phishing':            { text: 'PSH', color: '#dc2626' },
  'judi_online':         { text: 'JDL', color: '#ea580c' },
  'suspicious':          { text: '?',   color: '#ca8a04' },
  'domain_tidak_ada':    { text: '✗',   color: '#475569' },
  'tidak_dapat_diakses': { text: '~',   color: '#3b82f6' },
};


function updateBadge(tabId, kategori) {
  const cfg = BADGE[kategori] || { text: '?', color: '#64748b' };

  chrome.action.setBadgeText({
    tabId, text: cfg.text
  });

  chrome.action.setBadgeBackgroundColor({
    tabId, color: cfg.color
  });
}


chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;

  if (!tab.url) return;

  if (!tab.url.startsWith('http://') && !tab.url.startsWith('https://')) return;

  try {
    const res = await fetch(`${API_BASE}/api/check`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url: tab.url }),
    });

    if (!res.ok) return;

    const data     = await res.json();
    const kategori = data.kategori || data.category || 'suspicious';

    updateBadge(tabId, kategori);

    if (kategori === 'phishing' || kategori === 'judi_online') {

      const urlPendek = tab.url.length > 50
        ? tab.url.substring(0, 50) + '...'
        : tab.url;

      chrome.notifications.create(`netra-${tabId}-${Date.now()}`, {
        type:     'basic',
        iconUrl:  'icons/icon48.png',
        title:    '⚠️ NETRA — Peringatan Ancaman!',
        message:  kategori === 'phishing'
          ? `🔴 Situs PHISHING terdeteksi!\n${urlPendek}`
          : `🟠 Situs JUDI ONLINE terdeteksi!\n${urlPendek}`,
        priority: 2
      });
    }

  } catch {
    chrome.action.setBadgeText({ tabId, text: '' });
  }

});

chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === 'install') {
    console.log('✅ NETRA berhasil diinstall!');
  } else if (reason === 'update') {
    console.log('🔄 NETRA diupdate!');
  }
});