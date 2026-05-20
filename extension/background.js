const API_BASE = 'http://localhost:5000';

// Badge per kategori
const BADGE = {
  aman: { text: '✓', color: '#16a34a' },
  phishing: { text: 'PSH', color: '#dc2626' },
  judi_online: { text: 'JDL', color: '#ea580c' },
  suspicious: { text: '?', color: '#ca8a04' },
  domain_tidak_ada: { text: '✗', color: '#475569' },
  tidak_dapat_diakses: { text: '~', color: '#3b82f6' },
};

const KATEGORI_BAHAYA = ['phishing', 'judi_online'];

function updateBadge(tabId, kategori) {
  const cfg = BADGE[kategori] || { text: '?', color: '#64748b' };

  chrome.action.setBadgeText({
    tabId,
    text: cfg.text,
  });

  chrome.action.setBadgeBackgroundColor({
    tabId,
    color: cfg.color,
  });
}

function storageKey(url) {
  return `netra_aman::${url}`;
}

async function sudahDilaporkanAman(url) {
  const key = storageKey(url);
  const result = await chrome.storage.local.get({ [key]: false });
  return result[key] === true;
}

async function simpanDilaporkanAman(url) {
  const key = storageKey(url);
  await chrome.storage.local.set({ [key]: true });
}

async function hapusDilaporkanAman(url) {
  const key = storageKey(url);
  await chrome.storage.local.remove(key);
}

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  if (!tab.url) return;
  if (!tab.url.startsWith('http://') && !tab.url.startsWith('https://')) return;

  // Skip URL lokal/development
  const urlObj = new URL(tab.url);
  if (
    urlObj.hostname === 'localhost' ||
    urlObj.hostname === '127.0.0.1' ||
    urlObj.hostname.endsWith('.local')
  ) {
    chrome.action.setBadgeText({ tabId, text: '' });
    return;
  }
  const sudahAman = await sudahDilaporkanAman(tab.url);

  try {
    const res = await fetch(`${API_BASE}/api/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: tab.url }),
    });

    if (!res.ok) return;

    const data = await res.json();
    const kategori = data.kategori || data.category || 'suspicious';

    updateBadge(tabId, kategori);

    if (KATEGORI_BAHAYA.includes(kategori) && !sudahAman) {
      chrome.tabs
        .sendMessage(tabId, {
          type: 'NETRA_BAHAYA',
          kategori: kategori,
          confidence: data.confidence,
          method: data.method,
          url: tab.url,
        })
        .catch(() => {});
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

chrome.runtime.onMessage.addListener((message, sender) => {
  if (message.type === 'NETRA_TUTUP_TAB') {
    if (sender.tab && sender.tab.id) {
      setTimeout(() => {
        chrome.tabs.remove(sender.tab.id);
      }, 100);
    }
  }

  if (message.type === 'NETRA_SIMPAN_AMAN') {
    simpanDilaporkanAman(message.url).catch(() => {});
  }

  if (message.type === 'NETRA_HAPUS_AMAN') {
    hapusDilaporkanAman(message.url).catch(() => {});
  }

  return true;
});