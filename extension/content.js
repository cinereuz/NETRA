const API_BASE = 'http://localhost:5000';
const OVERLAY_ID = 'netra-warning-overlay';

// Konfigurasi per kategori bahaya
const CONFIG_BAHAYA = {
  phishing: {
    ikonBesar: '🚫',
    judul: 'PERINGATAN: Situs Phising!',
    desc: 'Situs ini terindikasi sebagai situs PHISHING yang bertujuan mencuri data pribadi,akun, atau informasi keuangan kamu.',
    warna: '#e53535',
    bgCard: '#ffffff',
    bgUrl: '#e53535',
    bgStats: '#e53535',
    bgBtn: '#c8c8c8',
  },
  judi_online: {
    ikonBesar: '⚠️',
    judul: 'PERINGATAN: Situs Judi Online',
    desc: 'Situs ini terindikasi sebagai situs JUDI ONLINE yang ilegal di Indonesia dan berpotensi merugikan.',
    warna: '#f0923a',
    bgCard: '#ffffff',
    bgUrl: '#f0923a',
    bgStats: '#f0923a',
    bgBtn: '#c8c8c8',
  },
};

// FUNGSI UTAMA (Menampilkan overlay peringatan)
function tampilkanOverlay(data) {
  if (document.getElementById(OVERLAY_ID)) return;

  const cfg = CONFIG_BAHAYA[data.kategori] || CONFIG_BAHAYA['phishing'];
  const confidence = data.confidence
    ? `${parseFloat(data.confidence).toFixed(1)}%`
    : '—';

  const overlay = document.createElement('div');
  overlay.id = OVERLAY_ID;

  // Style overlay
  overlay.style.cssText = `
    position: fixed !important;
    top: 0 !important; left: 0 !important;
    width: 100vw !important; height: 100vh !important;
    background: rgba(0,0,0,0.45) !important;
    z-index: 2147483647 !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    font-family: 'DM Sans', 'Segoe UI', sans-serif !important;
    backdrop-filter: blur(3px) !important;
  `;

  // innerHTML (seluruh isi card peringatan)
  overlay.innerHTML = `
    <style>
      /* Font import untuk overlay */
      @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600;700;900&display=swap');

      /* Animasi masuk card */
      @keyframes netraCardIn {
        from { transform: translateY(-20px) scale(0.97); opacity: 0; }
        to   { transform: translateY(0) scale(1); opacity: 1; }
      }

      /* Style tombol aksi */
      .netra-btn {
        padding: 13px 16px;
        border-radius: 10px;
        border: none;
        font-family: 'DM Sans', 'Segoe UI', sans-serif;
        font-size: 14px;
        font-weight: 700;
        cursor: pointer;
        transition: filter 0.15s, transform 0.15s;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 7px;
        background: #c8c8c8;
        color: #1a1a1a;
      }
      .netra-btn:hover {
        filter: brightness(0.93);
        transform: translateY(-1px);
      }
      .netra-btn:active {
        transform: translateY(0);
      }

      /* Dropdown laporan */
      .netra-select {
        width: 100%;
        padding: 11px 14px;
        background: #e8e8e8;
        color: #1a1a1a;
        border: none;
        border-radius: 8px;
        font-family: 'DM Sans', 'Segoe UI', sans-serif;
        font-size: 13px;
        font-weight: 500;
        margin-bottom: 10px;
        cursor: pointer;
      }
    </style>

    <!-- Card putih di tengah -->
    <div id="netra-card" style="
      background: ${cfg.bgCard};
      border-radius: 18px;
      padding: 28px 24px 22px;
      max-width: 440px;
      width: 92%;
      text-align: center;
      box-shadow: 0 8px 40px rgba(0,0,0,0.22);
      animation: netraCardIn 0.28s ease;
      position: relative;
    ">

      <!-- Ikon besar di atas -->
      <div style="font-size: 52px; margin-bottom: 10px; line-height: 1;">
        ${cfg.ikonBesar}
      </div>

      <!-- Badge NETRA -->
      <div style="
        display: inline-flex;
        align-items: center;
        gap: 7px;
        background: #f0f0f0;
        border-radius: 20px;
        padding: 5px 14px;
        font-size: 11px;
        font-weight: 700;
        color: #333;
        margin-bottom: 14px;
        letter-spacing: 0.8px;
      ">
        <img src="${chrome.runtime.getURL('icons/icon-logo.png')}" style="height:18px; width:auto;">
        NETRA SECURITY ALERT
      </div>

      <!-- Judul peringatan -->
      <div style="
        font-size: 20px;
        font-weight: 900;
        color: ${cfg.warna};
        margin-bottom: 10px;
        line-height: 1.3;
        font-family: 'DM Sans', 'Segoe UI', sans-serif;
      ">${cfg.judul}</div>

      <!-- Deskripsi -->
      <div style="
        font-size: 13px;
        color: #444;
        margin-bottom: 16px;
        line-height: 1.6;
      ">${cfg.desc}</div>

      <!-- Kotak URL terdeteksi (latar warna) -->
      <div style="
        background: ${cfg.bgUrl};
        border-radius: 10px;
        padding: 10px 14px;
        margin-bottom: 10px;
        text-align: left;
      ">
        <div style="
          font-size: 10px;
          font-weight: 800;
          color: rgba(255,255,255,0.85);
          letter-spacing: 1px;
          margin-bottom: 4px;
          text-transform: uppercase;
        ">URL TERDETEKSI</div>
        <div style="
          font-size: 11px;
          color: #ffffff;
          font-weight: 600;
          word-break: break-all;
          line-height: 1.4;
        ">${data.url}</div>
      </div>

      <!-- Confidence & Detection Method (2 kotak berdampingan) -->
      <div style="display: flex; gap: 8px; margin-bottom: 14px;">
        <div style="
          flex: 1;
          background: ${cfg.bgStats};
          border-radius: 10px;
          padding: 10px 8px;
          text-align: center;
        ">
          <div style="
            font-size: 18px;
            font-weight: 900;
            color: #ffffff;
            line-height: 1;
          ">${confidence}</div>
          <div style="
            font-size: 10px;
            font-weight: 700;
            color: rgba(255,255,255,0.80);
            margin-top: 3px;
            letter-spacing: 0.5px;
          ">Confidence</div>
        </div>
        <div style="
          flex: 1;
          background: ${cfg.bgStats};
          border-radius: 10px;
          padding: 10px 8px;
          text-align: center;
        ">
          <div style="
            font-size: 12px;
            font-weight: 800;
            color: #ffffff;
            line-height: 1.3;
            word-break: break-all;
          ">${data.method || '—'}</div>
          <div style="
            font-size: 10px;
            font-weight: 700;
            color: rgba(255,255,255,0.80);
            margin-top: 3px;
            letter-spacing: 0.5px;
          ">Detection Method</div>
        </div>
      </div>

      <!-- Tombol Tinggalkan + Laporkan (berdampingan) -->
      <div style="display: flex; gap: 8px; margin-bottom: 8px;">
        <button class="netra-btn" id="netra-btn-leave" style="flex:1;">
          📄 Tinggalkan Halaman
        </button>
        <button class="netra-btn" id="netra-btn-report" style="flex:1;">
          📢 Laporkan
        </button>
      </div>

      <!-- Tombol Abaikan (penuh lebar, lebih kecil) -->
      <button class="netra-btn" id="netra-btn-ignore" style="
        width: 100%;
        font-size: 12px;
        font-weight: 600;
        color: #555;
        background: #e8e8e8;
        padding: 10px;
      ">
        Saya mengerti risikonya - Abaikan peringatan ini
      </button>

    </div>
  `;

  document.body.appendChild(overlay);

  // Event Listener Tombol
  // Tombol "Tinggalkan Halaman"
  document.getElementById('netra-btn-leave').addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'https://google.com';
    }
  });

  // Tombol "Laporkan"
  document.getElementById('netra-btn-report').addEventListener('click', () => {
    tampilkanFormLaporan(data);
  });

  // Tombol "Abaikan"
  document.getElementById('netra-btn-ignore').addEventListener('click', () => {
    tutupOverlay();
  });
}

// FORM LAPORAN
function tampilkanFormLaporan(data) {
  const card = document.getElementById('netra-card');
  if (!card) return;
  card.innerHTML = `
    <style>
      @keyframes netraCardIn {
        from { transform: translateY(-10px); opacity: 0; }
        to   { transform: translateY(0); opacity: 1; }
      }
      #netra-card { animation: netraCardIn 0.2s ease; }

      .netra-btn {
        padding: 12px 16px;
        border-radius: 10px;
        border: none;
        font-family: 'DM Sans', 'Segoe UI', sans-serif;
        font-size: 14px;
        font-weight: 700;
        cursor: pointer;
        transition: filter 0.15s;
        background: #c8c8c8;
        color: #1a1a1a;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 7px;
      }
      .netra-btn:hover { filter: brightness(0.92); }

      .netra-select {
        width: 100%;
        padding: 11px 14px;
        background: #e8e8e8;
        color: #1a1a1a;
        border: none;
        border-radius: 10px;
        font-family: 'DM Sans', 'Segoe UI', sans-serif;
        font-size: 13px;
        font-weight: 600;
        margin-bottom: 12px;
        cursor: pointer;
      }
    </style>

    <!-- Ikon megaphone -->
    <div style="font-size: 40px; margin-bottom: 10px; line-height:1;">📢</div>

    <!-- Judul form (merah/oranye sesuai kategori asal) -->
    <div style="
      font-size: 18px;
      font-weight: 900;
      color: #e53535;
      margin-bottom: 8px;
      font-family: 'DM Sans', 'Segoe UI', sans-serif;
    ">Laporkan URL ini</div>

    <!-- Deskripsi -->
    <div style="
      font-size: 12px;
      color: #555;
      margin-bottom: 16px;
      line-height: 1.6;
    ">
      Pilih kategori yang paling tepat untuk URL ini. Laporan
      kamu membantu melindungi pengguna lain.
    </div>

    <!-- Kotak URL merah -->
    <div style="
      background: #e53535;
      border-radius: 10px;
      padding: 10px 14px;
      margin-bottom: 10px;
      font-size: 11px;
      color: #ffffff;
      font-weight: 600;
      word-break: break-all;
      text-align: left;
    ">${data.url}</div>

    <!-- Dropdown kategori (auto-select kategori deteksi asal) -->
    <select class="netra-select" id="netra-report-kategori">
      <option value="">— Pilih kategori —</option>
      <option value="phishing"   ${data.kategori === 'phishing'   ? 'selected' : ''}>
        🔴 Phising (penipuan)
      </option>
      <option value="judi_online" ${data.kategori === 'judi_online' ? 'selected' : ''}>
        🟠 Judi Online
      </option>
      <option value="aman">
        🟢 Aman (deteksi salah)
      </option>
    </select>

    <!-- Tombol Kembali + Kirim Laporan -->
    <div style="display: flex; gap: 8px;">
      <button class="netra-btn" id="netra-btn-back" style="flex:1;">
        ← Kembali
      </button>
      <button class="netra-btn" id="netra-btn-kirim" style="flex:2;">
        💬 Kirim Laporan
      </button>
    </div>

    <!-- Status pengiriman laporan -->
    <div id="netra-report-status" style="
      margin-top: 10px;
      font-size: 12px;
      min-height: 16px;
      font-family: 'DM Sans', 'Segoe UI', sans-serif;
    "></div>
  `;

  // Tombol Kembali
  document.getElementById('netra-btn-back').addEventListener('click', () => {
    tutupOverlay();
    tampilkanOverlay(data);
  });

  // Tombol Kirim Laporan
  document.getElementById('netra-btn-kirim').addEventListener('click', async () => {
    const kategori = document.getElementById('netra-report-kategori').value;
    const statusEl = document.getElementById('netra-report-status');

    if (!kategori) {
      statusEl.style.color = '#e53535';
      statusEl.textContent = '❗ Pilih kategori dulu!';
      return;
    }

    const btnKirim = document.getElementById('netra-btn-kirim');
    btnKirim.disabled    = true;
    btnKirim.textContent = '⏳ Mengirim...';

    try {
      const res = await fetch(`${API_BASE}/report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: data.url, kategori }),
      });

      const result = await res.json();

      if (res.ok) {
        if (result.status === 'duplikat') {
          statusEl.style.color = '#2563eb';
          statusEl.textContent = 'ℹ️ Kamu sudah pernah melaporkan URL ini.';
        } else {
          statusEl.style.color = '#16a34a';
          statusEl.textContent = '✅ Laporan terkirim! Terima kasih.';
        }

        btnKirim.disabled    = true;
        btnKirim.textContent = '✓ Selesai';

        const kategoriDipilih = document.getElementById('netra-report-kategori').value;

        setTimeout(() => {
          if (kategoriDipilih === 'aman') {
            chrome.runtime.sendMessage({
              type: 'NETRA_SIMPAN_AMAN',
              url: data.url,
            }).catch(() => {});
            tutupOverlay();
          } else {
            chrome.runtime.sendMessage({ type: 'NETRA_TUTUP_TAB' }).catch(() => {
              window.location.href = 'https://google.com';
            });
          }
        }, 2000);

      } else {
        statusEl.style.color = '#e53535';
        statusEl.textContent = '❌ ' + (result.error || 'Gagal kirim laporan');
        btnKirim.disabled    = false;
        btnKirim.textContent = '💬 Kirim Laporan';
      }

    } catch {
      statusEl.style.color = '#e53535';
      statusEl.textContent = '❌ Tidak bisa konek ke server NETRA';
      btnKirim.disabled    = false;
      btnKirim.textContent = '💬 Kirim Laporan';
    }
  });
}

// ── Tutup overlay dengan animasi fade out ────────────────────
function tutupOverlay() {
  const overlay = document.getElementById(OVERLAY_ID);
  if (overlay) {
    overlay.style.opacity    = '0';
    overlay.style.transition = 'opacity 0.2s ease';
    setTimeout(() => overlay.remove(), 200);
  }
}

// LISTENER
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'NETRA_BAHAYA') {
    tampilkanOverlay(message);
    sendResponse({ status: 'overlay_ditampilkan' });
  }
});