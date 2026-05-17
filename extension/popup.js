// Konfigurasi
const API_BASE = 'http://localhost:5000';

// Tampilan per kategori: ikon emoji, teks label, nama class CSS
const RESULT_CONFIG = {
  'aman':                { icon: '🟢', label: 'AMAN',                css: 'aman'                },
  'phishing':            { icon: '🔴', label: 'PHISHING',            css: 'phishing'            },
  'judi_online':         { icon: '🟠', label: 'JUDI ONLINE',         css: 'judi_online'         },
  'suspicious':          { icon: '🟡', label: 'MENCURIGAKAN',        css: 'suspicious'          },
  'domain_tidak_ada':    { icon: '⚫', label: 'DOMAIN TIDAK ADA',    css: 'domain_tidak_ada'    },
  'tidak_dapat_diakses': { icon: '🔵', label: 'TIDAK DAPAT DIAKSES', css: 'tidak_dapat_diakses' },
};


// Referensi Elemen HTML
const el = {
  statusDot:       document.getElementById('statusDot'),
  currentUrl:      document.getElementById('currentUrl'),
  btnCheck:        document.getElementById('btnCheck'),
  loadingBox:      document.getElementById('loadingBox'),
  resultBox:       document.getElementById('resultBox'),
  resultIcon:      document.getElementById('resultIcon'),
  resultLabel:     document.getElementById('resultLabel'),
  resultConfidence:document.getElementById('resultConfidence'),
  resultMethod:    document.getElementById('resultMethod'),
  resultDetail:    document.getElementById('resultDetail'),
  btnReportArea:   document.getElementById('btnReportArea'),
  btnToggleReport: document.getElementById('btnToggleReport'),
  reportSection:   document.getElementById('reportSection'),
  reportCategory:  document.getElementById('reportCategory'),
  btnCancelReport: document.getElementById('btnCancelReport'),
  btnSubmitReport: document.getElementById('btnSubmitReport'),
  notification:    document.getElementById('notification'),
  footerStats:     document.getElementById('footerStats'),
};


// State Aplikasi
let state = {
  currentUrl:    '',
  lastResult:    null,
  reportVisible: false,
};

//   HELPER (Fungsi kecil yang sering dipakai)
// Tampil / sembunyikan elemen
function show(el) { el.style.display = 'block'; }
function hide(el) { el.style.display = 'none';  }

// Menampilkan notifikasi sementara
function tampilNotif(pesan, tipe = 'success', durasi = 3000) {
  el.notification.textContent = pesan;
  el.notification.className   = `notification ${tipe}`;
  show(el.notification);
  setTimeout(() => hide(el.notification), durasi);
}

// Memotong URL panjang agar muat ditampilkan di popup
function potongUrl(url, max = 55) {
  return url.length <= max ? url : url.substring(0, max) + '...';
}

// Cek apakah server Flask sedang jalan
async function cekServer() {
  try {
    const res = await fetch(`${API_BASE}/`);
    el.statusDot.className = res.ok ? 'status-dot online' : 'status-dot offline';
    el.statusDot.title     = res.ok ? '✅ Server terhubung' : '❌ Server error';
  } catch {
    el.statusDot.className = 'status-dot offline';
    el.statusDot.title     = '❌ Server tidak terhubung — jalankan app.py';
  }
}


//   FUNGSI CEK URL
// Menampilkan hasil deteksi ke UI popup
function tampilHasil(data) {
  const kategori = data.kategori || data.category || 'suspicious';
  const config   = RESULT_CONFIG[kategori] || RESULT_CONFIG['suspicious'];

  el.resultIcon.textContent  = config.icon;
  el.resultLabel.textContent = config.label;

  el.resultConfidence.textContent = (data.confidence != null)
    ? `Confidence: ${parseFloat(data.confidence).toFixed(1)}%`
    : '';

  el.resultMethod.textContent = data.method
    ? `Terdeteksi via: ${data.method}`
    : '';

  el.resultDetail.textContent = data.detail || '';

  el.resultBox.className = `result-box ${config.css}`;

  show(el.resultBox);
  show(el.btnReportArea);

  state.lastResult = data;
}

// Mengirim URL ke backend NETRA untuk dianalisis
async function cekUrl(url) {

  hide(el.resultBox);
  hide(el.btnReportArea);
  hide(el.reportSection);
  hide(el.notification);
  show(el.loadingBox);
  el.btnCheck.disabled    = true;
  el.btnCheck.textContent = '⏳ Menganalisis...';
  state.reportVisible     = false;

  try {
    const response = await fetch(`${API_BASE}/api/check`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url }),
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const data = await response.json();
    tampilHasil(data);

  } catch (err) {
    console.error('NETRA cekUrl error:', err);
    tampilHasil({
      kategori: 'tidak_dapat_diakses',
      detail:   'Tidak bisa konek ke server NETRA. Pastikan app.py sudah dijalankan.'
    });

  } finally {
    hide(el.loadingBox);
    el.btnCheck.disabled    = false;
    el.btnCheck.textContent = '🔍 Analisis URL Ini';
  }
}

//   CROWDSOURCING (Kirim Laporan)
function toggleLaporan() {
  state.reportVisible = !state.reportVisible;

  if (state.reportVisible) {
    show(el.reportSection);
    el.btnToggleReport.textContent = '✕ Tutup Form Laporan';
  } else {
    hide(el.reportSection);
    el.btnToggleReport.textContent = '📢 Laporkan URL Ini';
  }
}

async function kirimLaporan() {
  const kategori = el.reportCategory.value;

  if (!kategori) {
    tampilNotif('❗ Pilih kategori dulu!', 'error');
    return;
  }

  el.btnSubmitReport.disabled    = true;
  el.btnSubmitReport.textContent = '⏳ Mengirim...';

  try {
    const response = await fetch(`${API_BASE}/report`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url:      state.currentUrl,
        kategori: kategori,
      }),
    });

    const data = await response.json();

    if (response.ok) {
      tampilNotif('✅ Laporan terkirim! Terima kasih 🛡️', 'success');
      el.reportCategory.value        = '';
      hide(el.reportSection);
      state.reportVisible            = false;
      el.btnToggleReport.textContent = '📢 Laporkan URL Ini';
      muatStats();
    } else {
      tampilNotif('❌ ' + (data.error || 'Gagal kirim laporan'), 'error');
    }

  } catch {
    tampilNotif('❌ Tidak bisa konek ke server', 'error');
  } finally {
    el.btnSubmitReport.disabled    = false;
    el.btnSubmitReport.textContent = '📤 Kirim Laporan';
  }
}

async function muatStats() {
  try {
    const res  = await fetch(`${API_BASE}/stats`);
    const data = await res.json();
    el.footerStats.textContent =
      `📊 ${data.total_prediksi || 0} prediksi | ${data.total_laporan_user || 0} laporan`;
  } catch {
    el.footerStats.textContent = '⚠️ Server tidak terhubung';
  }
}

//   EVENT LISTENERS

el.btnCheck.addEventListener('click', () => {
  if (state.currentUrl) cekUrl(state.currentUrl);
});

el.btnToggleReport.addEventListener('click', toggleLaporan);

el.btnCancelReport.addEventListener('click', () => {
  hide(el.reportSection);
  state.reportVisible            = false;
  el.btnToggleReport.textContent = '📢 Laporkan URL Ini';
});

el.btnSubmitReport.addEventListener('click', kirimLaporan);

//   INIT
(async function init() {
  // 1. Cek status server
  await cekServer();

  // 2. Ambil URL tab aktif
  const [tab] = await chrome.tabs.query({
    active: true, currentWindow: true
  });

  if (tab && tab.url) {
    state.currentUrl = tab.url;
    el.currentUrl.textContent = potongUrl(state.currentUrl);
    el.currentUrl.title       = state.currentUrl;

    // 3. Auto-cek URL langsung saat popup dibuka
    await cekUrl(state.currentUrl);
  } else {
    el.currentUrl.textContent = '⚠️ Tidak bisa baca URL tab ini';
    el.btnCheck.disabled      = true;
  }

  // 4. Muat statistik di footer
  muatStats();

})();