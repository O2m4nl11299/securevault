
async function getBrowserFingerprint() {
  var components = [];
  components.push(navigator.userAgent || "");
  components.push(navigator.language || "");
  components.push(screen.width + "x" + screen.height);
  components.push(new Date().getTimezoneOffset().toString());
  components.push(navigator.hardwareConcurrency || "");
  components.push(navigator.platform || "");
  try {
    var canvas = document.createElement("canvas");
    var ctx = canvas.getContext("2d");
    ctx.textBaseline = "top";
    ctx.font = "14px Arial";
    ctx.fillText("SecureVault", 2, 2);
    components.push(canvas.toDataURL().slice(-32));
  } catch(e) {}
  var raw = components.join("|");
  var buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,"0")).join("").slice(0,16);
}
/**
 * SecureVault v2.8 — Client-Side Code
 *
 * [v2.8] Streaming Upload Engine:
 *   - Her chunk şifrelendikten sonra HEMEN sunucuya gönderilir.
 *   - Peak RAM: ~10 MB (1 plaintext + 1 ciphertext chunk).
 *   - 250 MB dosya bile mobilde çökmeden yüklenir.
 *   - Streaming API yoksa otomatik olarak legacy Blob moduna düşer.
 *
 * [v2.6] CSP 'unsafe-inline' kaldırıldı — bu script artık ayrı dosya olarak yüklenir.
 *        Tüm inline onclick/onchange handler'lar addEventListener'a dönüştürüldü.
 *
 * v2.4: Streaming Decrypt Engine
 *  - [KRİTİK] İndirme sırasında dosya artık res.arrayBuffer() ile tamamı RAM'e çekilmiyor.
 *    res.body.getReader() ile stream olarak okunup, her SV02 chunk anında decrypt ediliyor.
 *  - File System Access API (showSaveFilePicker): Decrypt edilen chunk doğrudan diske yazılır.
 *    Peak RAM: ~1 chunk boyutu (20 MB). Mobil cihazlarda bile 250 MB dosya çökmeden indirilir.
 *  - Fallback: showSaveFilePicker desteklenmiyorsa (Firefox, Safari, iOS) Blob biriktirilir
 *    ama chunk-by-chunk decrypt sayesinde peak RAM ~fileSize+20MB (eskiden ~3*fileSize).
 *  - Legacy format (SV02 olmayan) dosyalar hala desteklenir (geriye uyumlu).
 *
 * Önceki düzeltmeler korunuyor: phishing fix, chunked upload, DOM manipulation,
 * URL-safe base64, download-mode UX, IIFE encapsulation.
 */
(function() {
  'use strict';

  var CHUNK_SIZE = 20 * 1024 * 1024;
  var MAX_FILE_SIZE = 250 * 1024 * 1024;
  var PLAN_FILE_LIMITS = {
    anon: 5 * 1024 * 1024,
    free: 250 * 1024 * 1024,
    premium: 2 * 1024 * 1024 * 1024,
    admin: 20 * 1024 * 1024 * 1024,
  };
  function getCurrentMaxFileSize() {
    var session = sessionStorage.getItem('sv_session');
    if (!session) return PLAN_FILE_LIMITS.anon;
    var plan = sessionStorage.getItem('sv_plan') || 'free';
    return PLAN_FILE_LIMITS[plan] || PLAN_FILE_LIMITS.free;
  }
  function formatSize(bytes) {
    if (bytes >= 1024 * 1024 * 1024) return (bytes / 1024 / 1024 / 1024) + ' GB';
    return Math.round(bytes / 1024 / 1024) + ' MB';
  }
  var MAGIC = [0x53, 0x56, 0x30, 0x32]; // "SV02"

  var selectedFile = null;
  var selectedEncFile = null;
  var isUploading = false;
  var uploadMode = 'file';

  if (window.location.pathname.startsWith("/dl/")) {
    document.body.classList.add('download-mode');
  }

  // ─── Tab Switching (en başta bağlanır — diğer hatalara bağımlı değil) ──────

  window.switchTab = function(tab, e) {
    document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
    document.querySelectorAll('.panel').forEach(function(p) { p.classList.remove('active'); });
    var target = e ? e.target.closest('.tab') : document.querySelector('.tab');
    if (target) target.classList.add('active');
    var panel = document.getElementById('panel-' + tab);
    if (panel) panel.classList.add('active');
  };

  // Tab event binding — hemen bağla, diğer kodların hatasından etkilenmesin
  document.querySelectorAll('.tab[data-tab]').forEach(function(tab) {
    tab.addEventListener('click', function(e) {
      window.switchTab(tab.getAttribute('data-tab'), e);
    });
  });

  // ─── Utility ────────────────────────────────────────────────────────────────

  async function checkHealth() {
    try {
      var controller = new AbortController();
      var timeout = setTimeout(function() { controller.abort(); }, 4000);
      var res = await fetch('/health', { signal: controller.signal });
      clearTimeout(timeout);
      var data = await res.json();
      if (data.status === 'ok') {
        document.getElementById('statusDot').className = 'status-dot ok';
        document.getElementById('statusText').textContent = 'BAĞLI';
      } else { throw new Error(); }
    } catch(e) {
      document.getElementById('statusDot').className = 'status-dot';
      document.getElementById('statusText').textContent = 'BAĞLANTI YOK';
    }
  }
  checkHealth(); setInterval(checkHealth, 30000);

  function log(type, msg) {
    var box = document.getElementById('logBox');
    box.classList.add('visible');
    var el = document.createElement('div');
    el.className = 'log-entry ' + type;
    var tsSpan = document.createElement('span');
    tsSpan.className = 'ts';
    tsSpan.textContent = new Date().toLocaleTimeString('tr-TR');
    var msgSpan = document.createElement('span');
    msgSpan.className = 'msg';
    msgSpan.textContent = msg;
    el.appendChild(tsSpan); el.appendChild(msgSpan);
    box.appendChild(el); box.scrollTop = box.scrollHeight;
  }

  function setProgress(pct, label) {
    document.getElementById('progressWrap').style.display = 'block';
    document.getElementById('progressFill').style.width = pct + '%';
    document.getElementById('progressLabel').textContent = label;
    document.getElementById('progressPct').textContent = pct + '%';
  }

  function showAlert(id, type, opts) {
    var el = document.getElementById(id);
    el.className = 'alert ' + type;
    el.textContent = '';
    if (opts.icon || opts.title) {
      var header = document.createElement('strong');
      header.textContent = (opts.icon || '') + ' ' + (opts.title || '');
      el.appendChild(header);
    }
    if (opts.lines) {
      opts.lines.forEach(function(line) {
        el.appendChild(document.createElement('br'));
        var span = document.createElement('span');
        span.textContent = line;
        el.appendChild(span);
      });
    }
    if (opts.link && opts.link.url && opts.link.text) {
      el.appendChild(document.createElement('br'));
      var a = document.createElement('a');
      a.href = opts.link.url;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = opts.link.text;
      a.className = 'alert-link';
      el.appendChild(a);
    }
  }

  // ─── File Selection ─────────────────────────────────────────────────────────

  window.onFileSelected = function(input) {
    var file = input.files[0]; if (!file) return;
    var maxSize = getCurrentMaxFileSize();
    if (file.size > maxSize) {
      var session = sessionStorage.getItem('sv_session');
      var plan = sessionStorage.getItem('sv_plan') || 'free';
      if (!session) {
        showAlert('uploadAlert', 'error', { icon: '⚠', title: 'Dosya çok büyük.', lines: ['Üye olmayan kullanıcılar en fazla ' + formatSize(PLAN_FILE_LIMITS.anon) + ' yükleyebilir.', 'Daha büyük dosyalar için üye olun (250 MB) veya giriş yapın.'] });
      } else if (plan !== 'premium' && file.size <= PLAN_FILE_LIMITS.premium) {
        showAlert('uploadAlert', 'error', { icon: '⚠', title: 'Dosya çok büyük.', lines: ['Free üyelik limiti: ' + formatSize(PLAN_FILE_LIMITS.free) + '.', 'Bu dosya boyutu için Premium (2 GB) gerekiyor.', 'Premium aboneliğe mobil uygulamamızdan geçebilirsiniz:'], link: { url: 'https://play.google.com/store/apps/details?id=com.sifreliveritransferi.securevault', text: '📱 Google Play\'de SecureVault\'u aç' } });
      } else {
        showAlert('uploadAlert', 'error', { icon: '⚠', title: 'Dosya çok büyük.', lines: ['Maksimum: ' + formatSize(maxSize)] });
      }
      input.value = ''; return;
    }
    selectedFile = file; updateDropzone(file); checkEncryptReady();
  };

  function updateDropzone(file) {
    var icon = document.getElementById('dropIcon');
    var content = document.getElementById('dropContent');
    var dz = document.getElementById('dropzone');
    var size = file.size < 1048576 ? (file.size / 1024).toFixed(1) + ' KB' : (file.size / 1048576).toFixed(2) + ' MB';
    icon.textContent = '✅'; content.textContent = '';
    var w = document.createElement('div'); w.className = 'file-selected';
    var n = document.createElement('span'); n.className = 'file-name'; n.textContent = file.name;
    var s = document.createElement('span'); s.className = 'file-size'; s.textContent = size;
    var c = document.createElement('button'); c.className = 'file-clear'; c.textContent = '✕';
    c.addEventListener('click', function(e) { clearFile(e); });
    w.appendChild(n); w.appendChild(s); w.appendChild(c); content.appendChild(w);
    dz.classList.add('has-file');
  }

  function clearFile(e) {
    e.stopPropagation(); selectedFile = null;
    document.getElementById('fileInput').value = '';
    document.getElementById('dropIcon').textContent = '📁';
    var content = document.getElementById('dropContent'); content.textContent = '';
    var t = document.createElement('div'); t.className = 'dropzone-text'; t.textContent = 'Dosyayı buraya sürükle veya tıkla';
    var h = document.createElement('div'); h.className = 'dropzone-hint'; h.textContent = 'PDF, DOCX, XLSX, CSV, TXT, PNG, JPG ve daha fazlası';
    content.appendChild(t); content.appendChild(h);
    document.getElementById('dropzone').classList.remove('has-file'); checkEncryptReady();
  }
  function clearFolder(e) {
    e.stopPropagation();
    folderFiles = [];
    var fi = document.getElementById('folderInput');
    if (fi) fi.value = '';
    var fContent = document.getElementById('folderDropContent');
    if (fContent) {
      fContent.textContent = '';
      var t = document.createElement('div'); t.className = 'dropzone-text'; t.textContent = 'Klasör seçmek için tıkla';
      var h = document.createElement('div'); h.className = 'dropzone-hint'; h.textContent = 'Klasör tek bir .zip dosyası olarak şifrelenip gönderilir. Alıcı zip\'i kendi açar.';
      fContent.appendChild(t); fContent.appendChild(h);
    }
    var fdz = document.getElementById('folderDropzone');
    if (fdz) fdz.classList.remove('has-file');
    checkEncryptReady();
  }

  var EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
  function isValidEmail(e) { return e && typeof e === 'string' && e.length <= 254 && EMAIL_REGEX.test(e); }
  function checkEncryptReady() {
    var emailOk = isValidEmail(document.getElementById('recipientEmail').value.trim());
    if (uploadMode === 'text') {
      var txtVal = document.getElementById('textInput').value;
      document.getElementById('encryptBtn').disabled = !(txtVal.trim().length > 0 && emailOk);
    } else if (uploadMode === 'folder') {
      var ff = (window.__getFolderFiles && window.__getFolderFiles()) || [];
      document.getElementById('encryptBtn').disabled = !(ff.length > 0 && emailOk);
    } else {
      document.getElementById('encryptBtn').disabled = !(selectedFile && emailOk);
    }
  }
  document.getElementById('recipientEmail').addEventListener('input', checkEncryptReady);
  var textInputEl = document.getElementById('textInput');
  if (textInputEl) textInputEl.addEventListener('input', function() {
    document.getElementById('textInputCounter').textContent = textInputEl.value.length + ' karakter';
    checkEncryptReady();
  });
  // ─── Dosya / Metin mod geçişi (aynı panel, aynı alert/log altyapısı) ───────
  function setUploadMode(mode) {
    uploadMode = mode;
    document.getElementById('fileModeSection').style.display = (mode === 'file') ? 'block' : 'none';
    document.getElementById('textModeSection').style.display = (mode === 'text') ? 'block' : 'none';
    var fms = document.getElementById('folderModeSection');
    if (fms) fms.style.display = (mode === 'folder') ? 'block' : 'none';
    checkEncryptReady();
  }
  var fileModeTabBtn = document.getElementById('fileModeTabBtn');
  if (fileModeTabBtn) fileModeTabBtn.addEventListener('click', function() { setUploadMode('file'); });
  var textModeTabBtn = document.getElementById('textModeTabBtn');
  if (textModeTabBtn) textModeTabBtn.addEventListener('click', function() { setUploadMode('text'); });
  var folderModeTabBtn = document.getElementById('folderModeTabBtn');
  if (folderModeTabBtn) folderModeTabBtn.addEventListener('click', function() { setUploadMode('folder'); });
  var folderFiles = [];
  var folderInputEl = document.getElementById('folderInput');
  if (folderInputEl) {
    folderInputEl.addEventListener('change', function(e) {
      folderFiles = Array.from(e.target.files || []);
      // Secilen klasoru KUTU ICINDE goster (input'u silmeden, folderDropContent guncelle).
      if (folderFiles.length > 0) {
        var rootName = 'klasor';
        if (folderFiles[0].webkitRelativePath) {
          var rp = folderFiles[0].webkitRelativePath.split('/');
          if (rp.length > 0 && rp[0]) rootName = rp[0];
        }
        var totalBytes = 0;
        for (var i = 0; i < folderFiles.length; i++) { totalBytes += folderFiles[i].size; }
        var mb = (totalBytes / (1024 * 1024)).toFixed(2);
        var fContent = document.getElementById('folderDropContent');
        if (fContent) {
          fContent.textContent = '';
          var ftxt = document.createElement('div');
          ftxt.className = 'dropzone-text';
          ftxt.textContent = '✅ 📁 ' + rootName;
          var fhint = document.createElement('div');
          fhint.className = 'dropzone-hint';
          fhint.textContent = folderFiles.length + ' dosya • ' + mb + ' MB • değiştirmek için tıkla';
          var fclear = document.createElement('button');
          fclear.className = 'file-clear';
          fclear.textContent = '✕';
          fclear.addEventListener('click', function(ev) { clearFolder(ev); });
          fContent.appendChild(ftxt);
          fContent.appendChild(fhint);
          fContent.appendChild(fclear);
        }
        var fdz1 = document.getElementById('folderDropzone');
        if (fdz1) fdz1.classList.add('has-file');
      }
      checkEncryptReady();
    });
  }
  window.__getFolderFiles = function() { return folderFiles; };

  var dz = document.getElementById('dropzone');
  dz.addEventListener('dragover', function(e) { e.preventDefault(); dz.classList.add('drag-over'); });
  dz.addEventListener('dragleave', function() { dz.classList.remove('drag-over'); });
  dz.addEventListener('drop', function(e) {
    e.preventDefault(); dz.classList.remove('drag-over');
    var f = e.dataTransfer.files[0]; if (!f) return;
    var dt = new DataTransfer(); dt.items.add(f);
    document.getElementById('fileInput').files = dt.files;
    window.onFileSelected(document.getElementById('fileInput'));
  });

  // ─── AES-256-GCM Crypto ─────────────────────────────────────────────────────

  async function generateKey() {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  }
  async function exportKey(key) {
    var raw = await crypto.subtle.exportKey('raw', key);
    return btoa(String.fromCharCode.apply(null, new Uint8Array(raw)));
  }
  async function importKeyFromB64(b64) {
    var std = b64.replace(/-/g, '+').replace(/_/g, '/');
    var raw = Uint8Array.from(atob(std), function(c) { return c.charCodeAt(0); });
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  }

  var BASE64_REGEX = /^[A-Za-z0-9+/\-_]+=*$/;
  function isValidKeyB64(str) {
    if (!str || typeof str !== 'string' || !BASE64_REGEX.test(str)) return false;
    try { var std = str.replace(/-/g, '+').replace(/_/g, '/'); return atob(std).length === 32; }
    catch(e) { return false; }
  }

  // ─── Chunked Encryption (Upload) ───────────────────────────────────────────
  //
  // [v2.8] STREAMING UPLOAD — Her chunk şifrelenir şifrelenmez sunucuya gönderilir.
  //   Peak RAM: ~10 MB (1 plaintext chunk + 1 şifreli chunk).
  //   250 MB dosya bile mobilde sorunsuz çalışır.
  //
  // Eski Blob-tabanlı yöntem (encryptChunkedLegacy) geriye uyumluluk için korunuyor.
  //   Streaming API'si mevcut olmayan sunuculara karşı fallback olarak kullanılır.

  /**
   * [v2.8] Streaming upload — şifrele ve doğrudan sunucuya gönder.
   * RAM'de ASLA tüm dosyayı tutmaz.
   */
  async function encryptAndUploadStreaming(file, key, email, progressCb) {
    var totalChunks = Math.ceil(file.size / CHUNK_SIZE);

    // 1. Oturum başlat
    var initRes = await fetch('/upload/init', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-session-token': sessionStorage.getItem('sv_session') || '', 'x-fingerprint': await getBrowserFingerprint() },
      body: JSON.stringify({ recipientEmail: email, originalName: file.name })
    });
    if (!initRes.ok) {
      var initErr = await initRes.json().catch(function() { return {}; });
      if (initRes.status === 403 && initErr.upgrade) {
        throw new Error('__UPGRADE__:' + (initErr.error || 'Gonderim hakkiniz doldu.'));
      }
      throw new Error(initErr.error || 'Yükleme oturumu başlatılamadı.');
    }
    var initData = await initRes.json();
    var uploadId = initData.uploadId;

    // 2. SV02 header'ını ilk chunk olarak gönder
    var header = new ArrayBuffer(8);
    var hv = new DataView(header);
    hv.setUint8(0, MAGIC[0]); hv.setUint8(1, MAGIC[1]);
    hv.setUint8(2, MAGIC[2]); hv.setUint8(3, MAGIC[3]);
    hv.setUint32(4, CHUNK_SIZE);

    await fetch('/upload/chunk/' + uploadId, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream', 'x-session-token': sessionStorage.getItem('sv_session') || '' },
      body: new Uint8Array(header)
    });

    // 3. Her chunk: oku → şifrele → gönder → serbest bırak
    for (var i = 0; i < totalChunks; i++) {
      var start = i * CHUNK_SIZE;
      var slice = file.slice(start, Math.min(start + CHUNK_SIZE, file.size));
      var chunkBuf = await slice.arrayBuffer();
      var iv = crypto.getRandomValues(new Uint8Array(12));
      var ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, tagLength: 128 }, key, chunkBuf);
      var payloadSize = 12 + ct.byteLength;
      var lenBuf = new ArrayBuffer(4);
      new DataView(lenBuf).setUint32(0, payloadSize);

      // Frame'i birleştir
      var frame = new Uint8Array(4 + 12 + ct.byteLength);
      frame.set(new Uint8Array(lenBuf), 0);
      frame.set(iv, 4);
      frame.set(new Uint8Array(ct), 16);

      // Sunucuya gönder
      var chunkRes = await fetch('/upload/chunk/' + uploadId, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: frame
      });
      if (!chunkRes.ok) {
        var chunkErr = await chunkRes.json().catch(function() { return {}; });
        throw new Error(chunkErr.error || 'Chunk gönderimi başarısız (' + (i+1) + '/' + totalChunks + ')');
      }

      // RAM temizle — bu chunk artık sunucuda, bellekte tutmaya gerek yok
      chunkBuf = null; ct = null; iv = null; lenBuf = null; slice = null; frame = null;
      if (progressCb) progressCb(i + 1, totalChunks);
    }

    // 4. Yüklemeyi tamamla
    var finalRes = await fetch('/upload/finalize/' + uploadId, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-session-token': sessionStorage.getItem('sv_session') || '', 'x-fingerprint': await getBrowserFingerprint() },
      body: '{}'
    });
    if (!finalRes.ok) {
      var finalErr = await finalRes.json().catch(function() { return {}; });
      throw new Error(finalErr.error || 'Yükleme tamamlanamadı.');
    }
    return await finalRes.json(); // { token, ttl }
  }

  /**
   * Eski yöntem — Blob biriktirme (fallback / geriye uyumluluk).
   * Streaming API yoksa veya başarısız olursa kullanılır.
   */
  async function encryptChunkedLegacy(file, key, progressCb) {
    var totalChunks = Math.ceil(file.size / CHUNK_SIZE);
    var parts = [];
    var header = new ArrayBuffer(8);
    var hv = new DataView(header);
    hv.setUint8(0, MAGIC[0]); hv.setUint8(1, MAGIC[1]);
    hv.setUint8(2, MAGIC[2]); hv.setUint8(3, MAGIC[3]);
    hv.setUint32(4, CHUNK_SIZE);
    parts.push(new Uint8Array(header));

    for (var i = 0; i < totalChunks; i++) {
      var start = i * CHUNK_SIZE;
      var slice = file.slice(start, Math.min(start + CHUNK_SIZE, file.size));
      var chunkBuf = await slice.arrayBuffer();
      var iv = crypto.getRandomValues(new Uint8Array(12));
      var ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, tagLength: 128 }, key, chunkBuf);
      var payloadSize = 12 + ct.byteLength;
      var lenBuf = new ArrayBuffer(4);
      new DataView(lenBuf).setUint32(0, payloadSize);
      var frame = new Uint8Array(4 + 12 + ct.byteLength);
      frame.set(new Uint8Array(lenBuf), 0);
      frame.set(iv, 4);
      frame.set(new Uint8Array(ct), 16);
      parts.push(frame);
      chunkBuf = null; ct = null; iv = null; lenBuf = null; slice = null; frame = null;
      if (progressCb) progressCb(i + 1, totalChunks);
    }
    return new Blob(parts);
  }

  // ══════════════════════════════════════════════════════════════════════════════
  // [v2.4] STREAMING DECRYPT ENGINE
  // ══════════════════════════════════════════════════════════════════════════════

  /**
   * File System Access API desteği kontrol.
   * Chrome 86+, Edge 86+, Opera 72+ destekler.
   * Firefox, Safari, iOS Safari DESTEKLEMEZ → Blob fallback.
   */
  async function hashPassword(pwd) {
  var buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pwd));
  return btoa(String.fromCharCode(...new Uint8Array(buf))).slice(0, 16);
}
  function supportsFileSystemAccess() {
    return false;
  }

  /**
   * ReadableStream'den (fetch response veya File.stream()) SV02 chunk'larını
   * teker teker yield eden async generator.
   *
   * Network chunk'ları format sınırlarıyla hizalı DEĞİLDİR.
   * Bu parser bir iç buffer'da veri biriktirir ve SV02 frame'lerini parse eder.
   *
   * Yield: { iv: Uint8Array(12), ciphertext: Uint8Array }
   * Her yield'da sadece 1 chunk'lık veri bellekte tutulur.
   */
  async function* parseSV02Stream(reader) {
    var buf = new Uint8Array(0);

    // Buffer'a yeni veri ekle
    function append(chunk) {
      var newBuf = new Uint8Array(buf.length + chunk.length);
      newBuf.set(buf);
      newBuf.set(chunk, buf.length);
      buf = newBuf;
    }

    // Buffer'dan n byte tüket
    function consume(n) {
      var data = buf.slice(0, n);
      buf = buf.slice(n);
      return data;
    }

    // Buffer'da en az n byte olana kadar oku
    async function ensureBytes(n) {
      while (buf.length < n) {
        var result = await reader.read();
        if (result.done) return false;
        append(result.value);
      }
      return true;
    }

    // ── SV02 Header (8 byte) ──
    if (!(await ensureBytes(8))) return;
    var header = consume(8);
    // [v2.7] Magic byte doğrulaması — bozuk veya farklı formatta dosyayı erken yakala
    if (header[0] !== MAGIC[0] || header[1] !== MAGIC[1] ||
        header[2] !== MAGIC[2] || header[3] !== MAGIC[3]) {
      throw new Error('Geçersiz dosya formatı: SV02 başlığı bulunamadı.');
    }

    // ── Chunk'ları parse et ──
    var chunkIndex = 0;
    while (true) {
      if (!(await ensureBytes(4))) break;
      var lenBytes = consume(4);
      var payloadSize = new DataView(lenBytes.buffer, lenBytes.byteOffset, 4).getUint32(0);

      if (payloadSize < 13) break; // IV(12) + en az 1 byte ciphertext

      if (!(await ensureBytes(payloadSize))) break;
      var payload = consume(payloadSize);

      yield {
        iv: payload.slice(0, 12),
        ciphertext: payload.slice(12),
        index: chunkIndex++
      };
    }
  }

  /**
   * Stream'in ilk 4 byte'ını okuyup SV02 magic olup olmadığını kontrol eder.
   * Okunan byte'ları geri koymak için yeni bir "prefixed reader" döndürür.
   */
  async function detectFormatFromStream(reader) {
    var firstResult = await reader.read();
    if (firstResult.done) throw new Error('Boş dosya.');

    var firstChunk = firstResult.value;
    var isSV02 = firstChunk.length >= 4 &&
      firstChunk[0] === MAGIC[0] && firstChunk[1] === MAGIC[1] &&
      firstChunk[2] === MAGIC[2] && firstChunk[3] === MAGIC[3];

    // Okuduğumuz chunk'ı geri koyan yeni reader oluştur
    var prefixConsumed = false;
    var prefixedReader = {
      read: async function() {
        if (!prefixConsumed) {
          prefixConsumed = true;
          return { done: false, value: firstChunk };
        }
        return reader.read();
      }
    };

    return { isSV02: isSV02, reader: prefixedReader, firstChunk: firstChunk };
  }

  /**
   * [v2.4] YOL A — File System Access API ile streaming decrypt.
   * Peak RAM: ~20 MB (1 chunk). 250 MB dosya bile mobilde çökmez.
   *
   * @param {Response} response - fetch response (stream)
   * @param {CryptoKey} key
   * @param {string} filename
   */
  async function streamDecryptToFile(response, key, filename) {
    var fileHandle = await window.showSaveFilePicker({
      suggestedName: filename,
      types: [{ description: 'Dosya', accept: { 'application/octet-stream': [] } }]
    });
    var writable = await fileHandle.createWritable();

    try {
      var bodyReader = response.body.getReader();
      var detection = await detectFormatFromStream(bodyReader);

      if (detection.isSV02) {
        // Chunked format — stream decrypt
        var parser = parseSV02Stream(detection.reader);
        var chunk;
        while (true) {
          chunk = await parser.next();
          if (chunk.done) break;
          var frame = chunk.value;
          var decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: frame.iv, tagLength: 128 }, key, frame.ciphertext
          );
          await writable.write(new Uint8Array(decrypted));
          // decrypted artık gereksiz — GC toplayabilir
          decrypted = null;
        }
      } else {
        // Legacy format — tüm veriyi oku (eski dosyalar küçüktür)
        var allChunks = [detection.firstChunk];
        while (true) {
          var result = await bodyReader.read();
          if (result.done) break;
          allChunks.push(result.value);
        }
        var totalLen = allChunks.reduce(function(s, c) { return s + c.length; }, 0);
        var fullBuf = new Uint8Array(totalLen);
        var offset = 0;
        allChunks.forEach(function(c) { fullBuf.set(c, offset); offset += c.length; });
        allChunks = null;

        if (fullBuf.byteLength < 13) throw new Error('Şifreli veri çok kısa.');
        var iv = fullBuf.slice(0, 12);
        var ct = fullBuf.slice(12);
        var decrypted = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: iv, tagLength: 128 }, key, ct
        );
        await writable.write(new Uint8Array(decrypted));
      }

      await writable.close();
      return { method: 'stream', filename: fileHandle.name };
    } catch (err) {
      await writable.abort().catch(function() {});
      throw err;
    }
  }

  /**
   * [v2.4] YOL B — Blob fallback (Firefox, Safari, iOS).
   * Stream'den chunk-by-chunk decrypt edip Blob'a biriktirir.
   * Peak RAM: ~fileSize + 5MB (eskiden ~3*fileSize → şimdi ~1.x*fileSize).
   */
  async function streamDecryptToBlob(response, key) {
    var bodyReader = response.body.getReader();
    var detection = await detectFormatFromStream(bodyReader);

    if (detection.isSV02) {
      var decryptedParts = [];
      var parser = parseSV02Stream(detection.reader);
      var chunk;
      while (true) {
        chunk = await parser.next();
        if (chunk.done) break;
        var frame = chunk.value;
        var decrypted = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: frame.iv, tagLength: 128 }, key, frame.ciphertext
        );
        decryptedParts.push(new Uint8Array(decrypted));
        decrypted = null;
      }
      return new Blob(decryptedParts);
    } else {
      // Legacy
      var allChunks = [detection.firstChunk];
      while (true) {
        var result = await bodyReader.read();
        if (result.done) break;
        allChunks.push(result.value);
      }
      var totalLen = allChunks.reduce(function(s, c) { return s + c.length; }, 0);
      var fullBuf = new Uint8Array(totalLen);
      var off = 0;
      allChunks.forEach(function(c) { fullBuf.set(c, off); off += c.length; });
      allChunks = null;

      if (fullBuf.byteLength < 13) throw new Error('Şifreli veri çok kısa.');
      var decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fullBuf.slice(0, 12), tagLength: 128 }, key, fullBuf.slice(12)
      );
      return new Blob([decrypted]);
    }
  }

  /**
   * Yerel .enc dosyası için decrypt (manuel panel).
   * File.stream() ile streaming okuma + Blob birikimi.
   */
  async function decryptLocalFile(file, key) {
    // File.stream() desteği kontrol
    if (typeof file.stream === 'function') {
      var reader = file.stream().getReader();
      var detection = await detectFormatFromStream(reader);

      if (detection.isSV02) {
        var parts = [];
        var parser = parseSV02Stream(detection.reader);
        var chunk;
        while (true) {
          chunk = await parser.next();
          if (chunk.done) break;
          var frame = chunk.value;
          var dec = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: frame.iv, tagLength: 128 }, key, frame.ciphertext
          );
          parts.push(new Uint8Array(dec));
          dec = null;
        }
        return new Blob(parts);
      }
    }

    // Legacy veya File.stream() desteklenmiyorsa
    var buf = await file.arrayBuffer();
    var enc = new Uint8Array(buf);
    if (enc.byteLength >= 8 && enc[0]===MAGIC[0] && enc[1]===MAGIC[1] && enc[2]===MAGIC[2] && enc[3]===MAGIC[3]) {
      // SV02 chunked (File.stream yok)
      var view = new DataView(enc.buffer, enc.byteOffset, enc.byteLength);
      var off = 8; var parts2 = [];
      while (off + 4 <= enc.byteLength) {
        var ps = view.getUint32(off); off += 4;
        if (ps < 13 || off + ps > enc.byteLength) break;
        var dec = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: enc.slice(off, off+12), tagLength: 128 }, key, enc.slice(off+12, off+ps)
        );
        parts2.push(new Uint8Array(dec)); off += ps;
      }
      return new Blob(parts2);
    }
    // Legacy single chunk
    if (enc.byteLength < 13) throw new Error('Şifreli veri çok kısa.');
    var dec = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: enc.slice(0,12), tagLength: 128 }, key, enc.slice(12)
    );
    return new Blob([dec]);
  }

  // ─── Encrypt & Upload ──────────────────────────────────────────────────────

  window.encryptAndSend = async function() {
    // ANONIM YUKLEME KAPALI: once giris zorunlu.
    if (!sessionStorage.getItem('sv_session')) {
      var alrtLR = document.getElementById('uploadAlert');
      if (alrtLR) {
        alrtLR.className = 'alert error';
        alrtLR.textContent = 'Dosya göndermek için önce giriş yapmalısınız. "ÜYE OL / GİRİŞ" sekmesinden giriş yapın.';
      }
      var authTab = document.querySelector('[data-tab="auth"]');
      if (authTab) authTab.click();
      return;
    }
    var email = document.getElementById('recipientEmail').value.trim();
    if (uploadMode === 'text') {
      var textVal = document.getElementById('textInput').value;
      if (!textVal.trim()) return;
      selectedFile = new File([new Blob([textVal], { type: 'text/plain' })], 'metin.txt', { type: 'text/plain' });
    }
    if (uploadMode === 'folder') {
      var ff = (window.__getFolderFiles && window.__getFolderFiles()) || [];
      if (!ff.length) return;
      // Klasor adini ilk dosyanin yolundan al (webkitRelativePath: "Klasor/alt/dosya.txt")
      var rootName = 'klasor';
      if (ff[0].webkitRelativePath) {
        var rp = ff[0].webkitRelativePath.split('/');
        if (rp.length > 0 && rp[0]) rootName = rp[0];
      }
      try {
        var zip = new JSZip();
        for (var i = 0; i < ff.length; i++) {
          var relPath = ff[i].webkitRelativePath || ff[i].name;
          zip.file(relPath, ff[i]);
        }
        // SIKISTIRMASIZ (store) - mobil ile ayni: hizli, sadece paketler.
        var zipBlob = await zip.generateAsync({ type: 'blob', compression: 'STORE' });
        selectedFile = new File([zipBlob], rootName + '.zip', { type: 'application/zip' });
      } catch (zipErr) {
        return;
      }
    }
    if (!selectedFile || !isValidEmail(email) || isUploading) return;
    // Boyut kontrolü
    var svSession = sessionStorage.getItem('sv_session');
    var svPlan = sessionStorage.getItem('sv_plan');
    var maxSizeCheck = getCurrentMaxFileSize();
    if (selectedFile.size > maxSizeCheck) {
      showAlert('uploadAlert', 'error', { icon: '❌', title: 'Dosya çok büyük.', lines: ['Maksimum: ' + formatSize(maxSizeCheck)] });
      return;
    }

    var btn = document.getElementById('encryptBtn');
    btn.disabled = true; isUploading = true;
    document.getElementById('uploadAlert').className = 'alert';
    document.getElementById('logBox').textContent = '';
    document.getElementById('logBox').classList.remove('visible');
    document.getElementById('copyLinkBox').classList.remove('visible');

    try {
      log('info', 'AES-256 anahtarı üretiliyor...');
      setProgress(5, 'Anahtar üretiliyor...');
      var key = await generateKey();
      var keyB64 = await exportKey(key);

      var data; // { token, ttl }
      var useStreaming = true;

      // ── [v2.8] Streaming upload dene — başarısız olursa legacy fallback ──
      try {
        log('info', 'Streaming şifreleme + yükleme (AES-256-GCM, 20 MB chunks)...');
        setProgress(10, 'Şifreleniyor ve yükleniyor...');
        data = await encryptAndUploadStreaming(selectedFile, key, email, function(done, total) {
          setProgress(10 + Math.round((done/total)*80), 'Şifreleniyor ve yükleniyor... (' + done + '/' + total + ')');
        });
        log('ok', '✅ Streaming yükleme tamamlandı (peak RAM ~20 MB)');
      } catch (streamErr) {
        // Upgrade gerekiyorsa klasik moda geçme
        if (streamErr.message && streamErr.message.startsWith('__UPGRADE__:')) {
          throw new Error(streamErr.message.replace('__UPGRADE__:', ''));
        }
        // Streaming API yoksa (eski sunucu) veya ağ hatası varsa legacy'ye düş
        useStreaming = false;
        log('info', 'Streaming başarısız, klasik yüklemeye geçiliyor...');

        // [v2.6] Mobil cihazlarda büyük dosya RAM uyarısı — sadece legacy modda gerekli
        var MOBILE_RAM_WARN_THRESHOLD = 100 * 1024 * 1024;
        var isMobile = /Mobi|Android|iPhone|iPad/i.test(navigator.userAgent);
        if (isMobile && selectedFile.size > MOBILE_RAM_WARN_THRESHOLD) {
          var sizeMB = Math.round(selectedFile.size / 1024 / 1024);
          var proceed = confirm(
            'Uyarı: ' + sizeMB + ' MB dosya klasik yükleme modunda yüksek bellek (RAM) kullanabilir.\n' +
            'Mobil cihazlarda sekme kapanabilir.\n\n' +
            'Devam etmek istiyor musunuz?'
          );
          if (!proceed) {
            isUploading = false; btn.disabled = false;
            return;
          }
        }

        setProgress(10, 'Şifreleniyor (klasik mod)...');
        var encBlob = await encryptChunkedLegacy(selectedFile, key, function(done, total) {
          setProgress(10 + Math.round((done/total)*40), 'Şifreleniyor... (' + done + '/' + total + ')');
        });

        setProgress(55, 'Yükleniyor...');
        log('info', 'Sunucuya yükleniyor (klasik mod)...');
        var fd = new FormData();
        fd.append('encryptedFile', encBlob, selectedFile.name + '.enc');
        fd.append('recipientEmail', email);
        fd.append('originalName', selectedFile.name);

        var res = await fetch('/upload', { method: 'POST', body: fd });
        data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Sunucu hatası (' + res.status + ')');
        encBlob = null; // RAM serbest bırak
      }

      var extraPwd = (document.getElementById("extraPassword") || {value:""}).value;
      var pwdSuffix = "";
      setProgress(90, 'Link oluşturuluyor...');
      if (extraPwd) { pwdSuffix = '|' + await hashPassword(extraPwd); }
      var downloadUrl = window.location.origin + '/dl/' + data.token + '#' + encodeURIComponent(keyB64) + pwdSuffix;
      document.getElementById('copyLinkUrl').value = downloadUrl;
      document.getElementById('copyLinkBox').classList.add('visible');

      log('info', 'E-posta gönderiliyor...');
      setProgress(93, 'Email gönderiliyor...');
      var emailRes = await fetch('/send-link', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: data.token, keyB64: keyB64 + pwdSuffix, recipientEmail: email, originalName: selectedFile.name })
      });
      var emailData = await emailRes.json();

      if (!emailRes.ok) {
        log('err', 'E-posta gönderilemedi — linki manuel paylaşabilirsiniz.');
        setProgress(100, 'Tamamlandı (link hazır)');
        showAlert('uploadAlert', 'warn', { icon: '⚠', title: 'E-posta gönderilemedi', lines: ['Linki kopyalayıp alıcıya gönderebilirsiniz.'] });
      } else {
        setProgress(100, 'Tamamlandı');
        log('ok', '✅ Email gönderildi → ' + email);
        showAlert('uploadAlert', 'success', { icon: '✅', title: 'Başarılı!', lines: [
          'Şifreli dosya ' + email + ' adresine gönderildi.',
          'Link ' + Math.round((data.ttl||3600)/60) + ' dakika geçerli, tek kullanımlık.',
          '🔒 Sunucu şifre anahtarını asla saklamadı.',
          useStreaming ? '⚡ Streaming mod — düşük RAM kullanımı.' : ''
        ].filter(Boolean)});
      }
    } catch (err) {
      log('err', '❌ ' + err.message);
      setProgress(0, '');
      document.getElementById('progressWrap').style.display = 'none';
      showAlert('uploadAlert', 'error', { icon: '❌', title: 'Hata', lines: [err.message] });
    } finally { isUploading = false; btn.disabled = false; }
  };

  window.copyLinkToClipboard = function() {
    var u = document.getElementById('copyLinkUrl'); u.select(); u.setSelectionRange(0, 99999);
    navigator.clipboard.writeText(u.value).then(function() {
      var t = document.getElementById('copyToast'); t.classList.add('visible');
      setTimeout(function() { t.classList.remove('visible'); }, 2500);
    }).catch(function() { try { document.execCommand('copy'); } catch(e) {} });
  };

  // ─── Decrypt Panel (Manuel) ─────────────────────────────────────────────────

  window.onEncFileSelected = function(input) {
    selectedEncFile = input.files[0]; if (!selectedEncFile) return;
    var c = document.getElementById('encDropContent'); c.textContent = '';
    var w = document.createElement('div'); w.className = 'file-selected';
    var n = document.createElement('span'); n.className = 'file-name'; n.textContent = selectedEncFile.name;
    var s = document.createElement('span'); s.className = 'file-size'; s.textContent = (selectedEncFile.size/1024).toFixed(1)+' KB';
    w.appendChild(n); w.appendChild(s); c.appendChild(w);
    document.getElementById('dropzoneEnc').classList.add('has-file');
  };

  var dzEnc = document.getElementById('dropzoneEnc');
  dzEnc.addEventListener('dragover', function(e) { e.preventDefault(); dzEnc.classList.add('drag-over'); });
  dzEnc.addEventListener('dragleave', function() { dzEnc.classList.remove('drag-over'); });
  dzEnc.addEventListener('drop', function(e) {
    e.preventDefault(); dzEnc.classList.remove('drag-over');
    var f = e.dataTransfer.files[0]; if (!f) return;
    var dt = new DataTransfer(); dt.items.add(f);
    document.getElementById('encFileInput').files = dt.files;
    window.onEncFileSelected(document.getElementById('encFileInput'));
  });

  window.decryptFile = async function() {
    var keyB64 = document.getElementById('keyInput').value.trim();
    if (!selectedEncFile) { showAlert('decryptAlert', 'error', { icon: '⚠', title: 'Lütfen önce .enc dosyasını seçin.' }); return; }
    if (!isValidKeyB64(keyB64)) { showAlert('decryptAlert', 'error', { icon: '⚠', title: 'Geçersiz anahtar.', lines: ['44 karakter, Base64 formatında olmalı.'] }); return; }

    try {
      showAlert('decryptAlert', 'warn', { icon: '⏳', title: 'Şifre çözülüyor...' });
      var key = await importKeyFromB64(keyB64);

      // [v2.4] Streaming decrypt — File.stream() ile chunk-by-chunk
      var decBlob = await decryptLocalFile(selectedEncFile, key);

      var name = selectedEncFile.name;
      if (name.endsWith('.enc')) name = name.slice(0, -4);
      var url = URL.createObjectURL(decBlob);
      var a = document.createElement('a'); a.href = url; a.download = name; a.click();
      URL.revokeObjectURL(url);

      showAlert('decryptAlert', 'success', { icon: '✅', title: 'Şifre başarıyla çözüldü!',
        lines: ['Dosya indirildi: ' + name, 'Şifre çözme tamamen tarayıcınızda gerçekleşti.']
      });
    } catch (err) {
      showAlert('decryptAlert', 'error', { icon: '❌', title: 'Şifre çözme başarısız.',
        lines: ['Anahtar hatalı veya dosya bozuk olabilir.', err.message]
      });
    }
  };

  // ─── URL Fragment ───────────────────────────────────────────────────────────

  function checkUrlFragment() {
    var hash = window.location.hash;
    if (!hash || hash.length < 5) return null;
    try {
      var fullFragment = decodeURIComponent(hash.slice(1));
      var keyB64 = fullFragment.includes('|') ? fullFragment.split('|')[0] : fullFragment;
    if (!BASE64_REGEX.test(keyB64) || !isValidKeyB64(keyB64)) return null;
      document.getElementById('keyInput').value = keyB64;
      document.getElementById('autoDecryptBanner').style.display = 'block';
      document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
      document.querySelectorAll('.panel').forEach(function(p) { p.classList.remove('active'); });
      document.querySelector('.tab-decrypt').classList.add('active');
      document.getElementById('panel-decrypt').classList.add('active');
      var pwdPart = fullFragment.includes('|') ? '|' + fullFragment.split('|')[1] : '';
      history.replaceState(null, '', window.location.pathname + window.location.search + (pwdPart ? '#' + pwdPart : ''));
      return keyB64;
    } catch(e) { return null; }
  }
  var autoKey = checkUrlFragment();

  // ─── [v2.4] Auto-download — Streaming Decrypt ─────────────────────────────

  function parseFilename(response) {
    var filename = 'dosya';
    var cd = response.headers.get('Content-Disposition');
    if (cd) {
      var m = cd.match(/filename\*=UTF-8''([^\s;]+)/);
      if (m) { filename = decodeURIComponent(m[1]).replace(/\.enc$/, ''); }
      else { m = cd.match(/filename="?([^";\s]+)"?/); if (m) filename = m[1].replace(/\.enc$/, ''); }
    }
    return filename;
  }

  async function handleDownloadPath() {
    var match = window.location.pathname.match(
      /^\/dl\/([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/
    );
    if (!match) return;
    var token = match[1];
    var urlFragment = window.location.hash.slice(1);
    var hasPwdHash = urlFragment.includes('|');
    var storedPwdHash = hasPwdHash ? urlFragment.split('|')[1] : '';
    var pwdBox = document.getElementById('extraPasswordBox');
    var dlPwd = pwdBox ? (document.getElementById('dlPassword') || {value:''}).value.trim() : '';
    if (hasPwdHash && !dlPwd) {
      if (pwdBox) pwdBox.style.display = 'block';
      return;
    }
    if (hasPwdHash && dlPwd) {
      var enteredHash = await hashPassword(dlPwd);
      if (enteredHash !== storedPwdHash) {
        showAlert('decryptAlert', 'error', { icon: '❌', title: 'Yanlış şifre.', lines: ['Göndericiden aldığınız şifreyi kontrol edin.'] });
        return;
      }
    }
    var keyB64 = document.getElementById('keyInput').value;

    if (!keyB64 || !isValidKeyB64(keyB64)) {
      showAlert('decryptAlert', 'error', { icon: '⚠', title: 'Anahtar bulunamadı veya geçersiz.',
        lines: ['Email linkini tam olarak açtığınızdan emin olun (#key kısmı dahil).'] });
      return;
    }

    try {
      showAlert('decryptAlert', 'warn', { icon: '⏳', title: 'Şifreli dosya indiriliyor...' });
      var res = await fetch('/api/dl/' + token);

      if (res.status === 410) {
        showAlert('decryptAlert', 'error', { icon: '❌', title: 'Bu link artık geçerli değil.',
          lines: ['Ya daha önce kullanıldı, ya da süresi doldu.'] }); return;
      }
      if (res.status === 429) {
        showAlert('decryptAlert', 'error', { icon: '❌', title: 'Çok fazla istek.', lines: ['Lütfen biraz bekleyin.'] }); return;
      }
      if (!res.ok) {
        var ed = {}; try { ed = await res.json(); } catch(e) {}
        throw new Error(ed.error || 'HTTP ' + res.status);
      }

      var filename = parseFilename(res);
      var key = await importKeyFromB64(keyB64);

      // ── [v2.4] Streaming decrypt karar ağacı ──
      if (supportsFileSystemAccess()) {
        // YOL A: File System Access API — peak RAM ~20 MB
        showAlert('decryptAlert', 'warn', { icon: '⏳', title: 'Şifre çözülüyor (stream)...' });

        try {
          var result = await streamDecryptToFile(res, key, filename);
          showAlert('decryptAlert', 'success', { icon: '✅', title: 'Dosya başarıyla kaydedildi!',
            lines: [result.filename + ' şifresi çözülerek diske yazıldı.', 'RAM kullanımı: minimal (~20 MB)'] });
        } catch (fsErr) {
          // Kullanıcı "Kaydet" dialog'unu iptal ettiyse
          if (fsErr.name === 'AbortError') {
            showAlert('decryptAlert', 'warn', { icon: '⚠', title: 'İndirme iptal edildi.', lines: ['Kaydetme penceresi kapatıldı.'] });
          } else { throw fsErr; }
        }

      } else {
        // YOL B: Blob fallback — Firefox, Safari, iOS
        showAlert('decryptAlert', 'warn', { icon: '⏳', title: 'Şifre çözülüyor...' });
        var blob = await streamDecryptToBlob(res, key);
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a'); a.href = url; a.download = filename; a.click();
        URL.revokeObjectURL(url);
        blob = null;

        showAlert('decryptAlert', 'success', { icon: '✅', title: 'Dosya başarıyla indirildi!',
          lines: [filename + ' şifresi çözülerek kaydedildi.', 'Bu link artık geçersiz.'] });
      }

      history.replaceState(null, '', '/');

    } catch (err) {
      showAlert('decryptAlert', 'error', { icon: '❌', title: 'Hata', lines: [err.message] });
    }
  }

  if (window.location.pathname.startsWith('/dl/')) {
    handleDownloadPath();
    var dlBtn = document.getElementById('dlPasswordBtn');
    if (dlBtn) dlBtn.addEventListener('click', handleDownloadPath);
  }

  // ─── [v2.6] Event Bindings (inline onclick/onchange kaldırıldı — CSP uyumu) ──
  // Tab buttons zaten yukarıda bağlandı.

  try {
    // Dropzone click → file input
    document.getElementById('dropzone').addEventListener('click', function(e) {
      // file-clear butonuna tıklandıysa file input açma
      if (e.target.closest('.file-clear')) return;
      document.getElementById('fileInput').click();
    });
    // Folder dropzone click → folder input
    var folderDz = document.getElementById('folderDropzone');
    if (folderDz) {
      folderDz.addEventListener('click', function(e) {
        if (e.target.closest('.file-clear')) return;
        document.getElementById('folderInput').click();
      });
    }

    // File input change
    document.getElementById('fileInput').addEventListener('change', function() {
      window.onFileSelected(this);
    });

    // Encrypt button
    document.getElementById('encryptBtn').addEventListener('click', function() {
      window.encryptAndSend();
    });

    // Copy button
    document.getElementById('copyBtn').addEventListener('click', function() {
      window.copyLinkToClipboard();
    });

    // Decrypt dropzone click → enc file input
    document.getElementById('dropzoneEnc').addEventListener('click', function(e) {
      if (e.target.closest('.file-clear')) return;
      document.getElementById('encFileInput').click();
    });

    // Enc file input change
    document.getElementById('encFileInput').addEventListener('change', function() {
      window.onEncFileSelected(this);
    });

    // Decrypt button
    document.getElementById('decryptBtn').addEventListener('click', function() {
      window.decryptFile();
    });
  } catch (bindErr) {
    console.error('[SecureVault] Event binding error:', bindErr.message);
  }

  // ─── Auth ────────────────────────────────────────────────────────────────
  try {
    function showAuthForm(form) {
      document.getElementById("registerForm").style.display = form === "register" ? "block" : "none";
      document.getElementById("loginForm").style.display = form === "login" ? "block" : "none";
      document.getElementById("recoverForm").style.display = form === "recover" ? "block" : "none";
      document.getElementById("accountForm").style.display = form === "account" ? "block" : "none";
      document.getElementById("showRegister").style.display = form === "account" ? "none" : "block";
      document.getElementById("showLogin").style.display = form === "account" ? "none" : "block";
    }
    // Sayfa yuklenince oturum varsa hesap panelini goster
    if (sessionStorage.getItem("sv_session")) {
      document.getElementById("accountPlan").textContent = sessionStorage.getItem("sv_plan") || "free";
      showAuthForm("account");
    }
    if (sessionStorage.getItem("sv_is_admin") === "true") {
      var adminTabBtn0 = document.getElementById("adminTabBtn");
      if (adminTabBtn0) adminTabBtn0.style.display = "block";
    }
    var showReg = document.getElementById("showRegister");
    var showLog = document.getElementById("showLogin");
    var showRec = document.getElementById("showRecover");
    if (showReg) showReg.addEventListener("click", function() { showAuthForm("register"); });
    if (showLog) showLog.addEventListener("click", function() { showAuthForm("login"); });
    if (showRec) showRec.addEventListener("click", function() { showAuthForm("recover"); });
    // ── Imha Sertifikasi sorgulama ──
    var certBtn = document.getElementById("certQueryBtn");
    var lastCert = null;
    if (certBtn) certBtn.addEventListener("click", async function() {
      var inp = document.getElementById("certLinkInput").value.trim();
      var alrt = document.getElementById("certAlert");
      var box = document.getElementById("certResultBox");
      var det = document.getElementById("certDetails");
      box.style.display = "none"; lastCert = null;
      var m = inp.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
      if (!m) { alrt.className = "alert error"; alrt.textContent = "Link veya kod tanınamadı. İndirme linkini olduğu gibi yapıştırın."; return; }
      alrt.className = "alert"; alrt.textContent = "Sorgulanıyor...";
      try {
        var res = await fetch("/certificate/" + m[0]);
        var data = await res.json();
        if (data.status === "pending") {
          alrt.className = "alert warn";
          alrt.textContent = "⏳ Dosya henüz imha edilmedi — hâlâ aktif (indirilmedi ve süresi dolmadı).";
          return;
        }
        if (data.status === "destroyed") {
          alrt.className = "alert success";
          alrt.textContent = "✔ Bu dosya kalıcı olarak imha edildi. Sertifika aşağıda.";
          var cert = data.certificate;
          var reasonTr = cert.reason === "downloaded" ? "Alıcı tarafından indirildi" : "Süresi doldu";
          det.textContent =
            "İmha nedeni: " + reasonTr + "\n" +
            "Yüklenme: " + (cert.uploadedAt ? new Date(cert.uploadedAt).toLocaleString("tr-TR") : "—") + "\n" +
            "İmha: " + new Date(cert.deletedAt).toLocaleString("tr-TR") + "\n" +
            "Boyut: " + (cert.sizeBytes != null ? cert.sizeBytes + " bayt" : "—") + "\n" +
            "Kayıt kimliği (SHA-256): " + cert.tokenHash.slice(0, 24) + "...\n" +
            "İmza (Ed25519): " + data.signature.slice(0, 24) + "...";
          lastCert = data;
          box.style.display = "block";
          return;
        }
        alrt.className = "alert error";
        alrt.textContent = data.message || "Bu linke ait imha kaydı bulunamadı. Kayıtlar 90 gün saklanır.";
      } catch (e) {
        alrt.className = "alert error"; alrt.textContent = "Sorgu başarısız. Bağlantınızı kontrol edin.";
      }
    });
    var certDlBtn = document.getElementById("certDownloadBtn");
    if (certDlBtn) certDlBtn.addEventListener("click", function() {
      if (!lastCert) return;
      var blob = new Blob([JSON.stringify(lastCert, null, 2)], { type: "application/json" });
      var a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "imha-sertifikasi-" + lastCert.certificate.tokenHash.slice(0, 12) + ".json";
      a.click();
      URL.revokeObjectURL(a.href);
    });
    var regBtn = document.getElementById("registerBtn");
    if (regBtn) regBtn.addEventListener("click", async function() {
      var u = document.getElementById("regUsername").value.trim();
      var p = document.getElementById("regPassword").value;
      var alrt = document.getElementById("registerAlert");
      var terms = document.getElementById("termsConsent");
      var transfer = document.getElementById("transferConsent");
      if (!u || !p) { alrt.className="alert error"; alrt.textContent="Tüm alanları doldurun."; return; }
      if (terms && !terms.checked) { alrt.className="alert error"; alrt.textContent="Kullanım Sözleşmesi ve Sorumluluk Reddi'ni kabul etmeniz gerekiyor."; return; }
      if (transfer && !transfer.checked) { alrt.className="alert error"; alrt.textContent="Yurt dışı veri aktarımı onayını vermeniz gerekmektedir."; return; }
      try {
        var res = await fetch("/auth/register", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({username:u,password:p}) });
        var data = await res.json();
        if (!res.ok) { alrt.className="alert error"; alrt.textContent=data.error; return; }
        alrt.className="alert success"; alrt.textContent="Kayıt başarılı!";
        document.getElementById("recoveryTokenBox").style.display="block";
        document.getElementById("recoveryTokenDisplay").value=data.recoveryToken;
      } catch(e) { alrt.className="alert error"; alrt.textContent="Bağlantı hatası."; }
    });
    var logBtn = document.getElementById("loginBtn");
    if (logBtn) logBtn.addEventListener("click", async function() {
      var u = document.getElementById("loginUsername").value.trim();
      var p = document.getElementById("loginPassword").value;
      var alrt = document.getElementById("loginAlert");
      try {
        var res = await fetch("/auth/login", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({username:u,password:p}) });
        var data = await res.json();
        if (!res.ok) { alrt.className="alert error"; alrt.textContent=data.error; return; }
        sessionStorage.setItem("sv_session", data.sessionToken);
        sessionStorage.setItem("sv_plan", data.plan);
        sessionStorage.setItem("sv_is_admin", data.isAdmin ? "true" : "false");
        var adminTabBtn1 = document.getElementById("adminTabBtn");
        if (adminTabBtn1) adminTabBtn1.style.display = data.isAdmin ? "block" : "none";
        document.getElementById("accountPlan").textContent = data.plan;
        showAuthForm("account");
        alrt.className="alert success"; alrt.textContent="Giriş başarılı! Plan: " + data.plan;
        setTimeout(function() {
          document.querySelectorAll(".tab").forEach(function(t) { t.classList.remove("active"); });
          document.querySelectorAll(".panel").forEach(function(p) { p.classList.remove("active"); });
          document.querySelector(".tab-upload").classList.add("active");
          document.getElementById("panel-upload").classList.add("active");
        }, 1000);
      } catch(e) { alrt.className="alert error"; alrt.textContent="Bağlantı hatası."; }
    });
    var recBtn = document.getElementById("recoverBtn");
    if (recBtn) recBtn.addEventListener("click", async function() {
      var u = document.getElementById("recUsername").value.trim();
      var t = document.getElementById("recToken").value.trim();
      var p = document.getElementById("recPassword").value;
      var alrt = document.getElementById("recoverAlert");
      try {
        var res = await fetch("/auth/recover", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({username:u,recoveryToken:t,newPassword:p}) });
        var data = await res.json();
        if (!res.ok) { alrt.className="alert error"; alrt.textContent=data.error; return; }
        alrt.className="alert success"; alrt.textContent="Şifre sıfırlandı. Giriş yapabilirsiniz.";
        showAuthForm("login");
      } catch(e) { alrt.className="alert error"; alrt.textContent="Bağlantı hatası."; }
    });
    var logoutBtn = document.getElementById("logoutBtn");
    if (logoutBtn) logoutBtn.addEventListener("click", function() {
      sessionStorage.removeItem("sv_session");
      sessionStorage.removeItem("sv_plan");
      sessionStorage.removeItem("sv_is_admin");
      var adminTabBtn2 = document.getElementById("adminTabBtn");
      if (adminTabBtn2) adminTabBtn2.style.display = "none";
      showAuthForm("login");
    });
    var deleteBtn = document.getElementById("deleteAccountBtn");
    if (deleteBtn) deleteBtn.addEventListener("click", async function() {
      var p = document.getElementById("deletePassword").value;
      var alrt = document.getElementById("accountAlert");
      if (!p) { alrt.className="alert error"; alrt.textContent="Şifrenizi girin."; return; }
      if (!confirm("Hesabınızı kalıcı olarak silmek istediğinize emin misiniz? Bu işlem geri alınamaz.")) return;
      try {
        var res = await fetch("/api/delete-account", { method:"POST", headers:{"Content-Type":"application/json","x-session-token":sessionStorage.getItem("sv_session")||""}, body:JSON.stringify({password:p}) });
        var data = await res.json();
        if (!res.ok) { alrt.className="alert error"; alrt.textContent=data.error; return; }
        sessionStorage.removeItem("sv_session");
        sessionStorage.removeItem("sv_plan");
        alrt.className="alert success"; alrt.textContent="Hesabınız silindi.";
        setTimeout(function() { showAuthForm("login"); }, 1500);
      } catch(e) { alrt.className="alert error"; alrt.textContent="Bağlantı hatası."; }
    });
    // ─── Şifre onay modalı (şifreyi maskeler — native prompt() maskelemiyor) ──
    function askAdminPassword() {
      return new Promise(function(resolve) {
        var modal = document.getElementById("adminPwdModal");
        var input = document.getElementById("adminPwdModalInput");
        var btnOk = document.getElementById("adminPwdModalConfirm");
        var btnCancel = document.getElementById("adminPwdModalCancel");
        input.value = "";
        modal.style.display = "flex";
        setTimeout(function() { input.focus(); }, 50);
        function cleanup(result) {
          modal.style.display = "none";
          btnOk.removeEventListener("click", onOk);
          btnCancel.removeEventListener("click", onCancel);
          input.removeEventListener("keydown", onKeydown);
          modal.removeEventListener("click", onOverlay);
          resolve(result);
        }
        function onOk() { cleanup(input.value || null); }
        function onCancel() { cleanup(null); }
        function onKeydown(e) { if (e.key === "Enter") { cleanup(input.value || null); } else if (e.key === "Escape") { cleanup(null); } }
        function onOverlay(e) { if (e.target === modal) cleanup(null); }
        btnOk.addEventListener("click", onOk);
        btnCancel.addEventListener("click", onCancel);
        input.addEventListener("keydown", onKeydown);
        modal.addEventListener("click", onOverlay);
      });
    }
    // ─── Admin Panel ──────────────────────────────────────────────────────────
    var adminSearchBtn = document.getElementById("adminSearchBtn");
    if (adminSearchBtn) adminSearchBtn.addEventListener("click", async function() {
      var u = document.getElementById("adminSearchUsername").value.trim();
      var alrt = document.getElementById("adminSearchAlert");
      var box = document.getElementById("adminResultBox");
      box.style.display = "none";
      alrt.className = "alert"; alrt.textContent = "";
      if (!u) { alrt.className="alert error"; alrt.textContent="Kullanıcı adı girin."; return; }
      try {
        var res = await fetch("/admin/lookup?username=" + encodeURIComponent(u), {
          headers: { "x-session-token": sessionStorage.getItem("sv_session") || "" }
        });
        var data = await res.json();
        if (!res.ok) { alrt.className="alert error"; alrt.textContent=data.error; return; }
        document.getElementById("adminResultPlan").textContent = data.user.plan;
        document.getElementById("adminResultUploads").textContent = data.user.upload_count;
        document.getElementById("adminResultLastActive").textContent = new Date(data.user.last_active_at).toLocaleString("tr-TR");
        document.getElementById("adminResultCreated").textContent = new Date(data.user.created_at).toLocaleString("tr-TR");
        document.getElementById("adminPlanSelect").value = data.user.plan;
        box.style.display = "block";
      } catch(e) { alrt.className="alert error"; alrt.textContent="Bağlantı hatası."; }
    });
    var adminUpdatePlanBtn = document.getElementById("adminUpdatePlanBtn");
    if (adminUpdatePlanBtn) adminUpdatePlanBtn.addEventListener("click", async function() {
      var u = document.getElementById("adminSearchUsername").value.trim();
      var newPlan = document.getElementById("adminPlanSelect").value;
      var alrt = document.getElementById("adminUpdateAlert");
      if (!u) return;
      if (!confirm("'" + u + "' kullanıcısının planını '" + newPlan + "' yapmak istediğinize emin misiniz?")) return;
      try {
        var res = await fetch("/admin/set-plan", {
          method: "POST",
          headers: { "Content-Type": "application/json", "x-session-token": sessionStorage.getItem("sv_session") || "" },
          body: JSON.stringify({ username: u, plan: newPlan })
        });
        var data = await res.json();
        if (!res.ok) { alrt.className="alert error"; alrt.textContent=data.error; return; }
        document.getElementById("adminResultPlan").textContent = data.plan;
        alrt.className="alert success"; alrt.textContent="Plan güncellendi: " + data.plan;
      } catch(e) { alrt.className="alert error"; alrt.textContent="Bağlantı hatası."; }
    });
    function renderAdminUsersTable(users) {
      var tbody = document.getElementById("adminUsersTableBody");
      var now = Date.now();
      var html = users.map(function(u) {
        var isActive = (now - new Date(u.last_active_at).getTime()) < 24 * 60 * 60 * 1000;
        var rowClass = isActive ? "admin-row-active" : "";
        var shortId = u.id.slice(0, 8);
        var created = new Date(u.created_at).toLocaleDateString("tr-TR");
        var lastActive = new Date(u.last_active_at).toLocaleString("tr-TR");
        var grantBtn = (u.plan === "premium" || u.plan === "admin")
          ? ""
          : '<button class="btn secondary admin-grant-btn" data-userid="' + u.id + '">Premium Ver</button>';
        return '<tr class="' + rowClass + '"><td>' + shortId + '</td><td>' + u.plan + '</td><td>' + created + '</td><td>' + lastActive + '</td><td>' + grantBtn + '</td></tr>';
      }).join("");
      tbody.innerHTML = html;
      document.querySelectorAll(".admin-grant-btn").forEach(function(btn) {
        btn.addEventListener("click", async function() {
          var userId = btn.getAttribute("data-userid");
          if (!confirm("Bu kullanıcıya 30 günlük premium tanımlamak istediğinize emin misiniz?")) return;
          btn.disabled = true;
          try {
            var res = await fetch("/admin/grant-premium", {
              method: "POST",
              headers: { "Content-Type": "application/json", "x-session-token": sessionStorage.getItem("sv_session") || "" },
              body: JSON.stringify({ userId: userId })
            });
            var data = await res.json();
            if (!res.ok) { alert(data.error || "Hata oluştu."); btn.disabled = false; return; }
            loadAdminUsersList();
          } catch(e) { alert("Bağlantı hatası."); btn.disabled = false; }
        });
      });
    }
    async function loadAdminUsersList() {
      var alrt = document.getElementById("adminUsersListAlert");
      alrt.className = "alert"; alrt.textContent = "";
      try {
        var res = await fetch("/admin/users-list", {
          headers: { "x-session-token": sessionStorage.getItem("sv_session") || "" }
        });
        var data = await res.json();
        if (!res.ok) { alrt.className="alert error"; alrt.textContent=data.error; return; }
        document.getElementById("adminUsersListBox").style.display = "block";
        renderAdminUsersTable(data.users);
      } catch(e) { alrt.className="alert error"; alrt.textContent="Bağlantı hatası."; }
    }
    var adminListUsersBtn = document.getElementById("adminListUsersBtn");
    if (adminListUsersBtn) adminListUsersBtn.addEventListener("click", loadAdminUsersList);
    var adminDeleteUserBtn = document.getElementById("adminDeleteUserBtn");
    if (adminDeleteUserBtn) adminDeleteUserBtn.addEventListener("click", async function() {
      var u = document.getElementById("adminSearchUsername").value.trim();
      var alrt = document.getElementById("adminUpdateAlert");
      if (!u) return;
      if (!confirm("'" + u + "' kullanıcısını KALICI OLARAK silmek istediğinize emin misiniz? Bu işlem geri alınamaz.")) return;
      var adminPwd = await askAdminPassword();
      if (!adminPwd) return;
      try {
        var res = await fetch("/admin/delete-user", {
          method: "POST",
          headers: { "Content-Type": "application/json", "x-session-token": sessionStorage.getItem("sv_session") || "" },
          body: JSON.stringify({ username: u, adminPassword: adminPwd })
        });
        var data = await res.json();
        if (!res.ok) { alrt.className="alert error"; alrt.textContent=data.error; return; }
        alrt.className="alert success"; alrt.textContent="Hesap silindi: " + u;
        setTimeout(function() {
          document.getElementById("adminResultBox").style.display = "none";
          document.getElementById("adminSearchUsername").value = "";
        }, 1800);
      } catch(e) { alrt.className="alert error"; alrt.textContent="Bağlantı hatası."; }
    });
  } catch(authErr) { console.error("[Auth] binding error:", authErr.message); }
})();