const API_BASE = 'http://localhost:5000';

const OVERLAY_ID = 'netra-warning-overlay';

// Konfigurasi tampilan per kategori
const CONFIG_BAHAYA = {
  phishing: {
    ikon: '🔴',
    judul: 'PERINGATAN: Situs Phishing!',
    desc: 'Situs ini terindikasi sebagai situs PHISHING yang bertujuan mencuri data pribadi, akun, atau informasi keuangan kamu.',
    warna: '#dc2626',
    bg: 'rgba(69, 10, 10, 0.97)',
    border: '#dc2626',
  },
  judi_online: {
    ikon: '🟠',
    judul: 'PERINGATAN: Situs Judi Online!',
    desc: 'Situs ini terindikasi sebagai situs JUDI ONLINE yang ilegal di Indonesia dan berpotensi merugikan.',
    warna: '#ea580c',
    bg: 'rgba(67, 20, 7, 0.97)',
    border: '#ea580c',
  },
};

function tampilkanOverlay(data) {
  if (document.getElementById(OVERLAY_ID)) return;

  const cfg = CONFIG_BAHAYA[data.kategori] || CONFIG_BAHAYA['phishing'];
  const confidence = data.confidence ? `${parseFloat(data.confidence).toFixed(1)}%` : '—';

  const overlay = document.createElement('div');
  overlay.id = OVERLAY_ID;

  overlay.style.cssText = `
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    width: 100vw !important;
    height: 100vh !important;
    background: rgba(0, 0, 0, 0.85) !important;
    z-index: 2147483647 !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif !important;
    backdrop-filter: blur(4px) !important;
  `;

  overlay.innerHTML = `
    <div id="netra-card" style="
      background: ${cfg.bg};
      border: 2px solid ${cfg.border};
      border-radius: 16px;
      padding: 32px;
      max-width: 480px;
      width: 90%;
      text-align: center;
      box-shadow: 0 0 60px rgba(0,0,0,0.8), 0 0 30px ${cfg.warna}44;
      position: relative;
      animation: netraSlideIn 0.3s ease;
    ">

      <!-- Animasi CSS -->
      <style>
        @keyframes netraSlideIn {
          from { transform: translateY(-30px); opacity: 0; }
          to   { transform: translateY(0);     opacity: 1; }
        }
        @keyframes netraPulse {
          0%, 100% { box-shadow: 0 0 60px rgba(0,0,0,0.8), 0 0 30px ${cfg.warna}44; }
          50%       { box-shadow: 0 0 60px rgba(0,0,0,0.8), 0 0 50px ${cfg.warna}88; }
        }
        #netra-card { animation: netraSlideIn 0.3s ease, netraPulse 2s ease-in-out infinite; }

        .netra-btn {
          padding: 10px 20px;
          border-radius: 8px;
          border: none;
          font-size: 14px;
          font-weight: 700;
          cursor: pointer;
          transition: all 0.2s;
          font-family: 'Segoe UI', sans-serif;
        }
        .netra-btn:hover { transform: translateY(-2px); filter: brightness(1.1); }
        .netra-btn-danger {
          background: ${cfg.warna};
          color: white;
          flex: 2;
        }
        .netra-btn-report {
          background: #7c3aed;
          color: white;
          flex: 1;
        }
        .netra-btn-ignore {
          background: transparent;
          color: #64748b;
          border: 1px solid #334155 !important;
          flex: 1;
          font-size: 12px;
        }
      </style>

      <!-- Ikon besar -->
      <div style="font-size: 56px; margin-bottom: 12px; line-height: 1;">
        ⚠️
      </div>

      <!-- Badge NETRA -->
      <div style="
        display: inline-block;
        background: rgba(255,255,255,0.08);
        border: 1px solid rgba(255,255,255,0.15);
        border-radius: 20px;
        padding: 4px 14px;
        font-size: 11px;
        color: #94a3b8;
        margin-bottom: 14px;
        letter-spacing: 1px;
      ">🛡️ NETRA SECURITY ALERT</div>

      <!-- Judul -->
      <div style="
        font-size: 20px;
        font-weight: 800;
        color: ${cfg.warna};
        margin-bottom: 12px;
        letter-spacing: 0.5px;
        line-height: 1.3;
      ">${cfg.judul}</div>

      <!-- Deskripsi -->
      <div style="
        font-size: 13px;
        color: #94a3b8;
        margin-bottom: 16px;
        line-height: 1.6;
      ">${cfg.desc}</div>

      <!-- Info URL -->
      <div style="
        background: rgba(0,0,0,0.3);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 8px;
        padding: 10px 14px;
        margin-bottom: 8px;
        text-align: left;
      ">
        <div style="font-size: 10px; color: #475569; margin-bottom: 4px; text-transform: uppercase; letter-spacing: 1px;">
          URL Terdeteksi
        </div>
        <div style="
          font-size: 11px;
          color: #60a5fa;
          font-family: monospace;
          word-break: break-all;
          max-height: 40px;
          overflow: hidden;
        ">${data.url}</div>
      </div>

      <!-- Info confidence & method -->
      <div style="
        display: flex;
        gap: 8px;
        margin-bottom: 20px;
      ">
        <div style="
          flex: 1;
          background: rgba(0,0,0,0.3);
          border-radius: 6px;
          padding: 8px;
          font-size: 11px;
          color: #64748b;
          text-align: center;
        ">
          <div style="font-size: 16px; font-weight: 700; color: ${cfg.warna};">
            ${confidence}
          </div>
          <div>Confidence</div>
        </div>
        <div style="
          flex: 2;
          background: rgba(0,0,0,0.3);
          border-radius: 6px;
          padding: 8px;
          font-size: 11px;
          color: #64748b;
          text-align: center;
        ">
          <div style="font-size: 12px; font-weight: 600; color: #94a3b8;">
            ${data.method || '—'}
          </div>
          <div>Detection Method</div>
        </div>
      </div>

      <!-- Tombol aksi -->
      <div style="display: flex; gap: 8px;">
        <!-- Tombol utama: tinggalkan halaman -->
        <button class="netra-btn netra-btn-danger" id="netra-btn-leave">
          🚪 Tinggalkan Halaman
        </button>

        <!-- Tombol laporkan -->
        <button class="netra-btn netra-btn-report" id="netra-btn-report">
          📢 Laporkan
        </button>
      </div>

      <!-- Tombol abaikan — kecil di bawah -->
      <button class="netra-btn netra-btn-ignore" id="netra-btn-ignore"
              style="width: 100%; margin-top: 8px;">
        Saya mengerti risikonya — Abaikan peringatan ini
      </button>

    </div>
  `;

  document.body.appendChild(overlay);

  // Event Listeners Tombol
  document.getElementById('netra-btn-leave').addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'https://google.com';
    }
  });

  document.getElementById('netra-btn-report').addEventListener('click', () => {
    tampilkanFormLaporan(data);
  });

  document.getElementById('netra-btn-ignore').addEventListener('click', () => {
    tutupOverlay();
  });
}

function tampilkanFormLaporan(data) {
  const card = document.getElementById('netra-card');
  if (!card) return;

  card.innerHTML = `
    <style>
      @keyframes netraSlideIn {
        from { transform: translateY(-20px); opacity: 0; }
        to   { transform: translateY(0);     opacity: 1; }
      }
      #netra-card { animation: netraSlideIn 0.2s ease; }
      .netra-btn {
        padding: 10px 20px;
        border-radius: 8px;
        border: none;
        font-size: 14px;
        font-weight: 700;
        cursor: pointer;
        transition: all 0.2s;
        font-family: 'Segoe UI', sans-serif;
      }
      .netra-btn:hover { filter: brightness(1.1); }
      .netra-select {
        width: 100%;
        padding: 10px 12px;
        background: rgba(0,0,0,0.4);
        color: #e2e8f0;
        border: 1px solid #475569;
        border-radius: 8px;
        font-size: 13px;
        margin-bottom: 12px;
        cursor: pointer;
      }
    </style>

    <div style="font-size: 32px; margin-bottom: 12px;">📢</div>

    <div style="font-size: 16px; font-weight: 700; color: #f1f5f9; margin-bottom: 8px;">
      Laporkan URL Ini
    </div>

    <div style="font-size: 12px; color: #64748b; margin-bottom: 16px; line-height: 1.5;">
      Pilih kategori yang paling tepat untuk URL ini.
      Laporan kamu membantu melindungi pengguna lain.
    </div>

    <!-- URL info -->
    <div style="
      background: rgba(0,0,0,0.3);
      border-radius: 6px;
      padding: 8px 12px;
      margin-bottom: 14px;
      font-size: 11px;
      color: #60a5fa;
      font-family: monospace;
      word-break: break-all;
      text-align: left;
    ">${data.url}</div>

    <!-- Dropdown kategori -->
    <select class="netra-select" id="netra-report-kategori">
      <option value="">— Pilih kategori —</option>
      <option value="phishing"   ${data.kategori === 'phishing' ? 'selected' : ''}>
        🔴 Phishing (penipuan)
      </option>
      <option value="judi_online" ${data.kategori === 'judi_online' ? 'selected' : ''}>
        🟠 Judi Online
      </option>
      <option value="aman">
        🟢 Aman (deteksi salah)
      </option>
    </select>

    <!-- Tombol -->
    <div style="display: flex; gap: 8px;">
      <button class="netra-btn" id="netra-btn-back" style="
        flex: 1;
        background: transparent;
        color: #64748b;
        border: 1px solid #334155;
      ">← Kembali</button>

      <button class="netra-btn" id="netra-btn-kirim" style="
        flex: 2;
        background: #7c3aed;
        color: white;
      ">📤 Kirim Laporan</button>
    </div>

    <div id="netra-report-status" style="
      margin-top: 10px;
      font-size: 12px;
      min-height: 16px;
    "></div>
  `;

  document.getElementById('netra-btn-back').addEventListener('click', () => {
    tutupOverlay();
    tampilkanOverlay(data);
  });

  document.getElementById('netra-btn-kirim').addEventListener('click', async () => {
    const kategori = document.getElementById('netra-report-kategori').value;
    const statusEl = document.getElementById('netra-report-status');

    if (!kategori) {
      statusEl.style.color = '#f87171';
      statusEl.textContent = '❗ Pilih kategori dulu!';
      return;
    }

    const btnKirim = document.getElementById('netra-btn-kirim');
    btnKirim.disabled = true;
    btnKirim.textContent = '⏳ Mengirim...';

    try {
      const res = await fetch(`${API_BASE}/report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: data.url,
          kategori: kategori,
        }),
      });

      const result = await res.json();

      if (res.ok) {
        if (result.status === 'duplikat') {
          statusEl.style.color = '#60a5fa';
          statusEl.textContent = 'ℹ️ Kamu sudah pernah melaporkan URL ini.';
        } else {
          statusEl.style.color = '#4ade80';
          statusEl.textContent = '✅ Laporan terkirim! Terima kasih.';
        }

        btnKirim.disabled = true;
        btnKirim.textContent = '✓ Selesai';
        const kategoriDipilih = document.getElementById('netra-report-kategori').value;

        setTimeout(() => {
          if (kategoriDipilih === 'aman') {
            tutupOverlay();
          } else {
            chrome.runtime.sendMessage({ type: 'NETRA_TUTUP_TAB' }).catch(() => {
              window.location.href = 'https://google.com';
            });
          }
        }, 2000);
      } else {
        statusEl.style.color = '#f87171';
        statusEl.textContent = '❌ ' + (result.error || 'Gagal kirim laporan');
        btnKirim.disabled = false;
        btnKirim.textContent = '📤 Kirim Laporan';
      }
    } catch {
      statusEl.style.color = '#f87171';
      statusEl.textContent = '❌ Tidak bisa konek ke server NETRA';
      btnKirim.disabled = false;
      btnKirim.textContent = '📤 Kirim Laporan';
    }
  });
}

function tutupOverlay() {
  const overlay = document.getElementById(OVERLAY_ID);
  if (overlay) {
    overlay.style.opacity = '0';
    overlay.style.transition = 'opacity 0.2s ease';
    setTimeout(() => overlay.remove(), 200);
  }
}

//   LISTENER
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'NETRA_BAHAYA') {
    tampilkanOverlay(message);
    sendResponse({ status: 'overlay_ditampilkan' });
  }
});
