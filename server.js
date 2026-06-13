/**
 * SecureVault v2.9 — Zero-Knowledge One-Time File Sharing (R2 Edition)
 *
 * v2.9 Changes (R2 + Cloudflare integration):
 * - STORAGE: Yerel disk yerine Cloudflare R2 (S3-uyumlı API).
 *   Streaming upload → R2 multipart upload (her flush bir part olur).
 *   Download → R2'den GetObject ile pipe.
 *   Cleanup → DeleteObject + AbortMultipartUpload.
 * - PROXY: Cloudflare arkasındayız → req.ip için CF-Connecting-IP
 *   (TRUST_PROXY=1 + nginx real_ip_module ile elde edilir).
 * - SMTP: Hostinger smtp.hostinger.com:465 SSL.
 * - PART BUFFERING: İstemci chunk boyutu R2 5MB minimum'unu garantiletmiyor
 *   (kötü niyetli istemci 1MB chunk gönderebilir → R2 reddeder).
 *   Sunucu chunk'ları 5MB'a kadar buffer'lar, sonra R2'ye part olarak yükler.
 *   Son part (finalize'da) boyutu ne olursa olsun yüklenir (R2 izin verir).
 *
 * Önceki versiyonların güvenlik özellikleri korunuyor:
 *   - Client-side AES-256-GCM (sunucu plaintext görmüyor)
 *   - Anahtar URL fragment'inde, asla sunucuya gitmiyor
 *   - Tek kullanımlık token (Lua atomic GET+DEL)
 *   - Path traversal koruması (artık R2 key validation)
 *   - Race condition kapalı (Lua claim, mutex isWriting)
 *   - Rate limiter (Redis ZSET sliding window + in-memory fallback)
 *   - Helmet CSP, secLog filtering, IP hashing
 */

require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const multer = require("multer");
const { v4: uuidv4 } = require("uuid");
const Redis = require("ioredis");
const nodemailer = require("nodemailer");
const path = require("path");
const crypto = require("crypto");

const {
  S3Client,
  CreateMultipartUploadCommand,
  UploadPartCommand,
  CompleteMultipartUploadCommand,
  AbortMultipartUploadCommand,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
} = require("@aws-sdk/client-s3");

// ─── Config ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "127.0.0.1"; // Loopback — nginx önümüzde
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const TOKEN_TTL_SECONDS = parseInt(process.env.TOKEN_TTL_SECONDS || "3600");
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE || String(250 * 1024 * 1024));

// R2 multipart minimum part size — son part hariç
const R2_MIN_PART_SIZE = 5 * 1024 * 1024; // 5 MiB

// ─── R2 / S3 Client ──────────────────────────────────────────────────────────
const R2_BUCKET = process.env.R2_BUCKET;
const R2_ENDPOINT = process.env.R2_ENDPOINT; // https://<ACCOUNT_ID>.r2.cloudflarestorage.com
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;

if (!R2_BUCKET || !R2_ENDPOINT || !R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY) {
  console.error("[FATAL] R2 yapılandırması eksik. .env dosyasında R2_BUCKET, R2_ENDPOINT, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY tanımlı olmalı.");
  process.exit(1);
}

const s3 = new S3Client({
  region: "auto",
  endpoint: R2_ENDPOINT,
  credentials: {
    accessKeyId: R2_ACCESS_KEY_ID,
    secretAccessKey: R2_SECRET_ACCESS_KEY,
  },
  // R2, AWS S3'ün checksum sağlama protokolünün bir alt kümesini destekler.
  // Yeni AWS SDK varsayılan checksum'larını kapatmak gerekebilir:
  requestChecksumCalculation: "WHEN_REQUIRED",
  responseChecksumValidation: "WHEN_REQUIRED",
});

// ─── R2 helpers ──────────────────────────────────────────────────────────────

/**
 * R2 key sadece sistem tarafından üretilmiş UUID + .enc olabilir.
 * Path traversal'ın R2 versiyonu — saldırgan ../../etc gibi key gönderemesin.
 */
const R2_KEY_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.enc$/;

function isValidR2Key(key) {
  return typeof key === "string" && R2_KEY_REGEX.test(key);
}

async function deleteR2Object(key) {
  if (!isValidR2Key(key)) return;
  try {
    await s3.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: key }));
  } catch (err) {
    secLog("warn", "r2_delete_failed", { key: key.slice(0, 8) + "...", err: err.message });
  }
}

async function abortR2Multipart(key, uploadId) {
  if (!isValidR2Key(key) || !uploadId) return;
  try {
    await s3.send(new AbortMultipartUploadCommand({
      Bucket: R2_BUCKET, Key: key, UploadId: uploadId,
    }));
  } catch (err) {
    // Hata durumunda da R2 lifecycle policy 7 günde otomatik abort eder
    secLog("warn", "r2_abort_failed", { key: key.slice(0, 8) + "...", err: err.message });
  }
}

// ─── Setup ────────────────────────────────────────────────────────────────────
const app = express();

// trust proxy — nginx + Cloudflare zinciri arkasındayız.
// nginx, set_real_ip_from CF-IPs ile gerçek IP'yi X-Real-IP/CF-Connecting-IP'den alır.
// Burada "1" → bir hop'a güven (nginx). nginx zaten CF'den gelen header'ı doğrular.
if (process.env.TRUST_PROXY === "1" || process.env.TRUST_PROXY === "true") {
  app.set("trust proxy", 1);
}

// ─── Redis ────────────────────────────────────────────────────────────────────
const redis = new Redis(process.env.REDIS_URL || "redis://localhost:6379", {
  maxRetriesPerRequest: 3,
  lazyConnect: true,
});

redis.on("error", (err) => console.error("[Redis] Connection error:", err.message));
redis.on("connect", () => console.log("[Redis] Connected"));

// ─── Email Transporter ────────────────────────────────────────────────────────
let transporter;

if (process.env.SENDGRID_API_KEY) {
  transporter = nodemailer.createTransport({
    host: "smtp.sendgrid.net", port: 587,
    auth: { user: "apikey", pass: process.env.SENDGRID_API_KEY },
    connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 30000,
  });
} else {
  // Hostinger varsayılanı: 465 SSL. STARTTLS isteyen ortamda 587 + secure:false.
  const smtpUser = process.env.SMTP_USER || "";
  const smtpPass = process.env.SMTP_PASS || "";
  if (!smtpUser || !smtpPass) {
    console.warn("[SMTP] ⚠ SMTP_USER veya SMTP_PASS ayarlanmamış. E-posta gönderimi başarısız olacak.");
  }
  const smtpPort = parseInt(process.env.SMTP_PORT || "465");
  const smtpSecure = process.env.SMTP_SECURE
    ? process.env.SMTP_SECURE === "true"
    : smtpPort === 465;

  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || "smtp.hostinger.com",
    port: smtpPort,
    secure: smtpSecure,             // 465 → true (SSL), 587 → false (STARTTLS)
    auth: { user: smtpUser, pass: smtpPass },
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 30000,
    tls: {
      // Sertifika hatalarını YOK SAYMA — TLS doğrulamasını zorla
      rejectUnauthorized: true,
      minVersion: "TLSv1.2",
    },
  });

  // Başlangıçta SMTP bağlantısını doğrula (production'da)
  if (process.env.NODE_ENV === "production") {
    transporter.verify().then(
      () => console.log("[SMTP] Hostinger bağlantısı doğrulandı"),
      (err) => console.error("[SMTP] Doğrulama hatası:", err.message)
    );
  }
}

// ─── Rate Limiter (Redis ZSET Sliding Window + memory fallback) ──────────────

function createRateLimiter({ windowMs, maxRequests, message, prefix }) {
  const memoryFallback = new Map();
  const MEMORY_CLEANUP_INTERVAL = 60000;
  let lastCleanup = Date.now();

  function memoryCheck(ip) {
    const now = Date.now();
    if (now - lastCleanup > MEMORY_CLEANUP_INTERVAL) {
      lastCleanup = now;
      for (const [k, v] of memoryFallback) {
        if (now - v.firstReq > windowMs) memoryFallback.delete(k);
      }
    }
    const entry = memoryFallback.get(ip) || { count: 0, firstReq: now };
    if (now - entry.firstReq > windowMs) { entry.count = 0; entry.firstReq = now; }
    entry.count++;
    memoryFallback.set(ip, entry);
    return entry.count;
  }

  return async (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    const cutoff = now - windowMs;
    const key = `ratelimit:${prefix}:${ip}`;

    try {
      const results = await redis.pipeline()
        .zremrangebyscore(key, 0, cutoff)
        .zadd(key, now, `${now}:${crypto.randomBytes(4).toString("hex")}`)
        .zcard(key)
        .pexpire(key, windowMs)
        .exec();

      const count = results[2][1];
      if (count > maxRequests) {
        secLog("warn", "rate_limit_exceeded", { ip, endpoint: req.path });
        return res.status(429).json({ error: message });
      }
      next();
    } catch (err) {
      secLog("warn", "rate_limiter_redis_fallback", { ip, err: err.message });
      const count = memoryCheck(ip);
      if (count > maxRequests) return res.status(429).json({ error: message });
      next();
    }
  };
}

const uploadLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, maxRequests: 10, prefix: "upload",
  message: "Çok fazla istek. 15 dakika sonra tekrar deneyin.",
});
const downloadLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, maxRequests: 30, prefix: "download",
  message: "Çok fazla indirme isteği.",
});
const sendLinkLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, maxRequests: 10, prefix: "sendlink",
  message: "Çok fazla e-posta gönderim isteği.",
});

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: [],
      },
    },
    crossOriginEmbedderPolicy: false,
    strictTransportSecurity: process.env.NODE_ENV === "production"
      ? { maxAge: 63072000, includeSubDomains: true, preload: true } : false,
  })
);

app.disable("x-powered-by");
app.use(express.json({ limit: "10kb" }));

// ─── Multer (sadece legacy /upload — RAM'de tutar, R2'ye stream'lenir) ──────
const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext !== ".enc") {
      return cb(new Error("Sadece .enc uzantılı şifreli dosyalar kabul edilir."), false);
    }
    cb(null, true);
  },
  limits: { files: 1, fileSize: MAX_FILE_SIZE },
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sanitizeFilename(name) {
  if (!name || typeof name !== "string") return "file.bin";
  return path.basename(name).replace(/[\x00-\x1f\x7f<>:"/\\|?*]/g, "_").slice(0, 255) || "file.bin";
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function secLog(level, event, meta = {}) {
  const safeMeta = { ...meta };
  if (safeMeta.ip && safeMeta.ip.length > 12) {
    safeMeta.ip = hashIp(safeMeta.ip);
  }
  delete safeMeta.keyB64;
  delete safeMeta.password;
  delete safeMeta.key;
  delete safeMeta.r2SecretAccessKey;

  try {
    console.log(JSON.stringify({
      ts: new Date().toISOString(), level, event, ip: safeMeta.ip || "-", ...safeMeta,
    }));
  } catch {
    console.log(JSON.stringify({
      ts: new Date().toISOString(), level, event, serializationError: true,
    }));
  }
}

const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

function isValidEmail(email) {
  if (!email || typeof email !== "string") return false;
  if (email.length > 254) return false;
  return EMAIL_REGEX.test(email);
}

function hashIp(ip) {
  return crypto.createHash("sha256").update(String(ip)).digest("hex").slice(0, 12);
}

function isValidKeyB64(str) {
  if (!str || typeof str !== "string") return false;
  if (!/^[A-Za-z0-9+/\-_]+=*$/.test(str)) return false;
  try {
    const standardB64 = str.replace(/-/g, "+").replace(/_/g, "/");
    const buf = Buffer.from(standardB64, "base64");
    if (buf.toString("base64") !== standardB64) return false;
    return buf.length === 32;
  } catch { return false; }
}

function buildContentDisposition(filename) {
  const asciiName = filename.replace(/[^\x20-\x7E]/g, "_");
  const utf8Name = encodeURIComponent(filename).replace(/['()]/g, (c) =>
    "%" + c.charCodeAt(0).toString(16).toUpperCase()
  );
  return `attachment; filename="${asciiName}"; filename*=UTF-8''${utf8Name}`;
}

const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function isValidToken(token) {
  return typeof token === "string" && UUID_V4_REGEX.test(token);
}

// ─── Routes ───────────────────────────────────────────────────────────────────

app.use(express.static(path.join(__dirname, "public")));

app.get("/health", async (req, res) => {
  try {
    await redis.ping();
    // R2 ping — bucket head (her seferinde yapma; cache'liyoruz aslında ama health'te şart değil)
    res.json({ status: "ok", redis: "ok", r2: "configured", ts: new Date().toISOString() });
  } catch {
    res.status(503).json({ status: "error" });
  }
});

/**
 * POST /upload — Tek seferde yükleme (legacy, küçük dosyalar için).
 * Multer memoryStorage → R2'ye PutObject.
 * Büyük dosyalar için /upload/init + /upload/chunk + /upload/finalize tercih edilir.
 */
app.post("/upload", uploadLimiter, upload.single("encryptedFile"), async (req, res) => {
  const ip = req.ip;
  if (!req.file) return res.status(400).json({ error: "Dosya yüklenmedi." });

  const { recipientEmail, originalName } = req.body;
  if (!isValidEmail(recipientEmail)) {
    return res.status(400).json({ error: "Geçersiz email adresi." });
  }

  const safeName = sanitizeFilename(originalName);
  const token = uuidv4();
  const r2Key = `${uuidv4()}.enc`;

  try {
    await s3.send(new PutObjectCommand({
      Bucket: R2_BUCKET, Key: r2Key, Body: req.file.buffer,
      ContentType: "application/octet-stream",
    }));
  } catch (err) {
    secLog("error", "r2_put_failed", { ip, err: err.message });
    return res.status(503).json({ error: "Depolama kullanılamıyor." });
  }

  const metadata = JSON.stringify({
    r2Key, originalName: safeName, size: req.file.size,
    uploadedAt: Date.now(), ip: hashIp(ip),
    recipientEmail, emailSent: false,
  });

  try {
    await redis.setex(`token:${token}`, TOKEN_TTL_SECONDS, metadata);
    await redis.setex(`r2key:${token}`, TOKEN_TTL_SECONDS + 60, r2Key);
  } catch (err) {
    await deleteR2Object(r2Key);
    secLog("error", "redis_write_failed", { ip, err: err.message });
    return res.status(503).json({ error: "Depolama kullanılamıyor. Tekrar deneyin." });
  }

  secLog("info", "upload_success", {
    ip, token: token.slice(0, 8) + "...", size: req.file.size,
    recipient: recipientEmail.replace(/(.{2}).+(@.+)/, "$1***$2"),
  });

  res.json({ token, ttl: TOKEN_TTL_SECONDS });
});

// ═══════════════════════════════════════════════════════════════════════════════
// STREAMING UPLOAD — R2 Multipart edition
// ═══════════════════════════════════════════════════════════════════════════════
//
// Akış:
//   POST /upload/init            → R2 CreateMultipartUpload, uploadId döner
//   POST /upload/chunk/:id × N   → buffer >= 5MB ise R2 UploadPart, parts[] biriktir
//   POST /upload/finalize/:id    → kalan buffer'ı son part olarak yükle, CompleteMultipartUpload
//
// Hata yolları:
//   Stale session     → AbortMultipartUpload
//   Chunk hata        → AbortMultipartUpload + session sil
//   Finalize hata     → AbortMultipartUpload + session sil
//   Sunucu kapatılırsa → R2 lifecycle policy 7 günde otomatik abort

const uploadSessions = new Map();
const UPLOAD_SESSION_TTL = 10 * 60 * 1000;

const sessionCleanupInterval = setInterval(async () => {
  const now = Date.now();
  for (const [id, session] of uploadSessions) {
    if (now - session.createdAt > UPLOAD_SESSION_TTL) {
      await abortR2Multipart(session.r2Key, session.r2UploadId);
      uploadSessions.delete(id);
      secLog("info", "stale_upload_session_cleaned", { uploadId: id.slice(0, 8) + "..." });
    }
  }
}, 2 * 60 * 1000);

/**
 * POST /upload/init — Streaming yüklemeyi başlat (R2 multipart create).
 */
app.post("/upload/init", uploadLimiter, async (req, res) => {
  const ip = req.ip;
  const { recipientEmail, originalName } = req.body;

  if (!isValidEmail(recipientEmail)) {
    return res.status(400).json({ error: "Geçersiz email adresi." });
  }

  const uploadId = uuidv4();
  const r2Key = `${uuidv4()}.enc`;

  let r2UploadId;
  try {
    const result = await s3.send(new CreateMultipartUploadCommand({
      Bucket: R2_BUCKET, Key: r2Key,
      ContentType: "application/octet-stream",
    }));
    r2UploadId = result.UploadId;
  } catch (err) {
    secLog("error", "r2_create_multipart_failed", { ip, err: err.message });
    return res.status(503).json({ error: "Depolama kullanılamıyor." });
  }

  uploadSessions.set(uploadId, {
    r2Key,
    r2UploadId,
    parts: [],                  // [{ PartNumber, ETag }]
    buffer: Buffer.alloc(0),    // 5MB'a ulaşana kadar biriktir
    originalName: sanitizeFilename(originalName),
    recipientEmail,
    ip: hashIp(ip),
    createdAt: Date.now(),
    totalBytes: 0,
    chunkCount: 0,
    finalized: false,
    isWriting: false,
  });

  secLog("info", "streaming_upload_init", {
    ip, uploadId: uploadId.slice(0, 8) + "...",
    recipient: recipientEmail.replace(/(.{2}).+(@.+)/, "$1***$2"),
  });

  res.json({ uploadId });
});

/**
 * POST /upload/chunk/:uploadId — Tek bir şifreli chunk al.
 * Chunk session.buffer'a eklenir; buffer >= 5MB ise R2'ye part olarak gönderilir.
 */
app.post("/upload/chunk/:uploadId",
  express.raw({ type: "application/octet-stream", limit: "10mb" }),
  async (req, res) => {
    const { uploadId } = req.params;
    const session = uploadSessions.get(uploadId);

    if (!session || session.finalized) {
      return res.status(404).json({ error: "Geçersiz veya süresi dolmuş yükleme oturumu." });
    }
    if (session.ip !== hashIp(req.ip)) {
      secLog("warn", "chunk_ip_mismatch", { ip: req.ip, uploadId: uploadId.slice(0, 8) + "..." });
      return res.status(403).json({ error: "Erişim reddedildi." });
    }
    if (session.isWriting) {
      return res.status(429).json({ error: "Önceki chunk işlemde; veriler sırayla gönderilmelidir." });
    }

    const chunkData = req.body;
    if (!chunkData || !chunkData.length) {
      return res.status(400).json({ error: "Boş chunk." });
    }
    if (session.totalBytes + chunkData.length > MAX_FILE_SIZE) {
      await abortR2Multipart(session.r2Key, session.r2UploadId);
      uploadSessions.delete(uploadId);
      return res.status(413).json({ error: `Dosya çok büyük. Maksimum: ${Math.round(MAX_FILE_SIZE / 1024 / 1024)} MB` });
    }

    session.isWriting = true;
    try {
      session.buffer = Buffer.concat([session.buffer, chunkData]);
      session.totalBytes += chunkData.length;
      session.chunkCount++;

      // Buffer 5MB veya üstüyse R2'ye part olarak gönder.
      // Bu while loop, kötü niyetli istemcinin tek istekte çok büyük chunk göndermesine de dayanır
      // (express.raw 10MB limit, yine de defensive bir loop).
      while (session.buffer.length >= R2_MIN_PART_SIZE) {
        const partNum = session.parts.length + 1;
        const partBody = session.buffer.subarray(0, R2_MIN_PART_SIZE);
        session.buffer = session.buffer.subarray(R2_MIN_PART_SIZE);

        const partResult = await s3.send(new UploadPartCommand({
          Bucket: R2_BUCKET, Key: session.r2Key,
          UploadId: session.r2UploadId,
          PartNumber: partNum, Body: partBody,
        }));

        session.parts.push({ PartNumber: partNum, ETag: partResult.ETag });
      }

      res.json({ received: chunkData.length, total: session.totalBytes });
    } catch (err) {
      await abortR2Multipart(session.r2Key, session.r2UploadId);
      uploadSessions.delete(uploadId);
      secLog("error", "chunk_upload_failed", { uploadId: uploadId.slice(0, 8) + "...", err: err.message });
      return res.status(500).json({ error: "Chunk yükleme hatası." });
    } finally {
      session.isWriting = false;
    }
  }
);

/**
 * POST /upload/finalize/:uploadId — Yüklemeyi tamamla.
 * Kalan buffer'ı son part olarak yükle, CompleteMultipartUpload, token oluştur.
 */
app.post("/upload/finalize/:uploadId", async (req, res) => {
  const { uploadId } = req.params;
  const session = uploadSessions.get(uploadId);

  if (!session || session.finalized) {
    return res.status(404).json({ error: "Geçersiz veya süresi dolmuş yükleme oturumu." });
  }
  if (session.ip !== hashIp(req.ip)) {
    return res.status(403).json({ error: "Erişim reddedildi." });
  }
  if (session.totalBytes === 0) {
    await abortR2Multipart(session.r2Key, session.r2UploadId);
    uploadSessions.delete(uploadId);
    return res.status(400).json({ error: "Dosya boş — hiç chunk gönderilmedi." });
  }

  session.finalized = true;

  try {
    // 1. Kalan buffer'ı son part olarak gönder (5MB'dan küçük olabilir — son part için OK)
    if (session.buffer.length > 0) {
      const partNum = session.parts.length + 1;
      const partResult = await s3.send(new UploadPartCommand({
        Bucket: R2_BUCKET, Key: session.r2Key,
        UploadId: session.r2UploadId,
        PartNumber: partNum, Body: session.buffer,
      }));
      session.parts.push({ PartNumber: partNum, ETag: partResult.ETag });
      session.buffer = Buffer.alloc(0);
    }

    if (session.parts.length === 0) {
      await abortR2Multipart(session.r2Key, session.r2UploadId);
      uploadSessions.delete(uploadId);
      return res.status(400).json({ error: "Hiçbir part yüklenmedi." });
    }

    // 2. Multipart'ı tamamla
    await s3.send(new CompleteMultipartUploadCommand({
      Bucket: R2_BUCKET, Key: session.r2Key,
      UploadId: session.r2UploadId,
      MultipartUpload: {
        Parts: session.parts.map(p => ({ PartNumber: p.PartNumber, ETag: p.ETag })),
      },
    }));
  } catch (err) {
    await abortR2Multipart(session.r2Key, session.r2UploadId);
    uploadSessions.delete(uploadId);
    secLog("error", "r2_complete_multipart_failed", { uploadId: uploadId.slice(0, 8) + "...", err: err.message });
    return res.status(500).json({ error: "Yükleme tamamlama hatası." });
  }

  // 3. Token oluştur
  const token = uuidv4();
  const metadata = JSON.stringify({
    r2Key: session.r2Key,
    originalName: session.originalName,
    size: session.totalBytes,
    uploadedAt: Date.now(),
    ip: session.ip,
    recipientEmail: session.recipientEmail,
    emailSent: false,
  });

  try {
    await redis.setex(`token:${token}`, TOKEN_TTL_SECONDS, metadata);
    await redis.setex(`r2key:${token}`, TOKEN_TTL_SECONDS + 60, session.r2Key);
  } catch (err) {
    await deleteR2Object(session.r2Key);
    uploadSessions.delete(uploadId);
    secLog("error", "redis_write_failed", { ip: req.ip, err: err.message });
    return res.status(503).json({ error: "Depolama kullanılamıyor. Tekrar deneyin." });
  }

  uploadSessions.delete(uploadId);

  secLog("info", "streaming_upload_finalized", {
    ip: req.ip, token: token.slice(0, 8) + "...",
    size: session.totalBytes, chunks: session.chunkCount, parts: session.parts.length,
    recipient: session.recipientEmail.replace(/(.{2}).+(@.+)/, "$1***$2"),
  });

  res.json({ token, ttl: TOKEN_TTL_SECONDS });
});

/**
 * POST /send-link — Lua atomic claim + Hostinger SMTP üzerinden e-posta.
 * Önceki versiyonlarla aynı; sadece downloadUrl'in yapısı değişmedi.
 */
app.post("/send-link", sendLinkLimiter, async (req, res) => {
  const ip = req.ip;
  let { token, keyB64, recipientEmail, originalName } = req.body;

  if (!isValidToken(token)) return res.status(400).json({ error: "Geçersiz token formatı." });
  if (!isValidEmail(recipientEmail)) return res.status(400).json({ error: "Geçersiz email adresi." });
  if (!isValidKeyB64(keyB64)) return res.status(400).json({ error: "Geçersiz şifreleme anahtarı." });

  const LUA_CLAIM_EMAIL = `
    local raw = redis.call('GET', KEYS[1])
    if not raw then return '{"error":"NOT_FOUND"}' end
    local meta = cjson.decode(raw)
    if meta.emailSent then return '{"error":"ALREADY_SENT"}' end
    if meta.ip ~= ARGV[1] then return '{"error":"IP_MISMATCH"}' end
    if meta.recipientEmail ~= ARGV[2] then return '{"error":"EMAIL_MISMATCH"}' end
    meta.emailSent = true
    local ttl = redis.call('TTL', KEYS[1])
    if ttl > 0 then redis.call('SETEX', KEYS[1], ttl, cjson.encode(meta)) end
    return raw
  `;

  let raw;
  try {
    raw = await redis.eval(LUA_CLAIM_EMAIL, 1, `token:${token}`, hashIp(ip), recipientEmail);
  } catch (err) {
    secLog("error", "redis_claim_failed", { ip, err: err.message });
    return res.status(503).json({ error: "Depolama kullanılamıyor." });
  }

  let parsed;
  try { parsed = JSON.parse(raw); } catch { parsed = {}; }

  if (parsed.error === "NOT_FOUND")    return res.status(404).json({ error: "Token bulunamadı veya süresi dolmuş." });
  if (parsed.error === "ALREADY_SENT") return res.status(409).json({ error: "Bu token için e-posta zaten gönderildi." });
  if (parsed.error === "IP_MISMATCH")  { secLog("warn", "send_link_ip_mismatch", { ip }); return res.status(403).json({ error: "Yetkiniz yok." }); }
  if (parsed.error === "EMAIL_MISMATCH") { secLog("warn", "send_link_email_mismatch", { ip }); return res.status(400).json({ error: "E-posta upload sırasında belirtilenle eşleşmiyor." }); }

  let meta;
  try { meta = JSON.parse(raw); } catch { return res.status(500).json({ error: "Bozuk metadata." }); }

  const downloadUrl = `${BASE_URL}/dl/${token}#${encodeURIComponent(keyB64)}`;
  const safeName = sanitizeFilename(originalName || meta.originalName);
  const ttlDisplay = TOKEN_TTL_SECONDS < 3600
    ? `${Math.round(TOKEN_TTL_SECONDS / 60)} dakika`
    : `${Math.round(TOKEN_TTL_SECONDS / 3600)} saat`;

  const mailOptions = {
    from: `"SecureVault" <${process.env.SMTP_FROM || process.env.SMTP_USER}>`,
    to: recipientEmail,
    subject: "Şifreli dosya paylaşıldı — SecureVault",
    html: `
<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="font-family:monospace;background:#0a0a0a;color:#e0e0e0;padding:40px;max-width:600px;margin:0 auto;">
  <h2 style="color:#4ade80;letter-spacing:2px;">SECUREVAULT</h2>
  <p style="color:#888;font-size:12px;letter-spacing:1px;">AES-256-GCM · ZERO-KNOWLEDGE · ONE-TIME LINK</p>
  <hr style="border-color:#222;margin:24px 0;">
  <p>Sizinle şifreli bir dosya paylaşıldı: <strong style="color:#fff;">${escHtml(safeName)}</strong></p>
  <p style="color:#888;font-size:13px;">
    Bu link <strong style="color:#f59e0b;">${escHtml(ttlDisplay)}</strong> içinde geçersiz olur
    ve yalnızca <strong style="color:#f59e0b;">tek bir kez</strong> kullanılabilir.
  </p>
  <div style="margin:32px 0;text-align:center;">
    <a href="${escHtml(downloadUrl)}" style="background:#4ade80;color:#000;padding:14px 32px;text-decoration:none;font-weight:bold;letter-spacing:2px;font-size:13px;display:inline-block;">DOSYAYI INDIR</a>
  </div>
  <p style="color:#555;font-size:11px;">
    Link çalışmıyorsa bu URL'i kopyalayın:<br>
    <span style="color:#888;word-break:break-all;">${escHtml(downloadUrl)}</span>
  </p>
  <hr style="border-color:#222;margin:24px 0;">
  <p style="color:#444;font-size:10px;">
    Bu mesaj SecureVault sistemi tarafından otomatik gönderilmiştir.<br>
    Dosya içeriği şifreli olarak Cloudflare R2'de saklanmaktadır; şifre anahtarına hiçbir zaman erişimimiz olmamıştır.
  </p>
</body></html>`,
  };

  try { await transporter.sendMail(mailOptions); }
  catch (err) {
    secLog("error", "email_send_failed", { ip, err: err.message });
    return res.status(502).json({ error: "E-posta servisinde bir sorun oluştu. Lütfen daha sonra tekrar deneyin." });
  }

  keyB64 = undefined;
  if (req.body) req.body.keyB64 = undefined;

  secLog("info", "send_link_success", {
    ip, token: token.slice(0, 8) + "...",
    recipient: recipientEmail.replace(/(.{2}).+(@.+)/, "$1***$2"),
  });

  res.json({ message: "Email gönderildi" });
});

/**
 * GET /api/dl/:token — Tek kullanımlık indirme (R2'den stream).
 * Atomic GET+DEL Redis, sonra R2 GetObject, sonra res'e pipe, sonra R2 silme.
 */
app.get("/api/dl/:token", downloadLimiter, async (req, res) => {
  const { token } = req.params;
  const ip = req.ip;

  if (!isValidToken(token)) {
    secLog("warn", "invalid_token_format", { ip });
    return res.status(400).json({ error: "Geçersiz token formatı." });
  }

  let raw;
  try {
    const lua = `local val=redis.call('GET',KEYS[1]) if val then redis.call('DEL',KEYS[1]) end return val`;
    raw = await redis.eval(lua, 1, `token:${token}`);
  } catch (err) {
    secLog("error", "redis_read_failed", { ip, err: err.message });
    return res.status(503).json({ error: "Depolama kullanılamıyor." });
  }

  if (!raw) {
    secLog("warn", "token_not_found_or_expired", { ip, token: token.slice(0, 8) + "..." });
    return res.status(410).json({ error: "Bu link artık geçerli değil — ya kullanıldı, ya da süresi doldu." });
  }

  let meta;
  try { meta = JSON.parse(raw); }
  catch { return res.status(500).json({ error: "Bozuk metadata." }); }

  const { r2Key, originalName, size } = meta;

  if (!isValidR2Key(r2Key)) {
    secLog("error", "invalid_r2_key_in_metadata", { ip, token: token.slice(0, 8) + "..." });
    return res.status(403).json({ error: "Erişim reddedildi." });
  }

  let r2Object;
  try {
    r2Object = await s3.send(new GetObjectCommand({ Bucket: R2_BUCKET, Key: r2Key }));
  } catch (err) {
    secLog("error", "r2_get_failed", { ip, token: token.slice(0, 8) + "...", err: err.message });
    return res.status(404).json({ error: "Dosya bulunamadı." });
  }

  secLog("info", "download_started", {
    ip, token: token.slice(0, 8) + "...", originalName, size,
  });

  res.setHeader("Content-Type", "application/octet-stream");
  res.setHeader("Content-Disposition", buildContentDisposition(sanitizeFilename(originalName) + ".enc"));
  if (r2Object.ContentLength) res.setHeader("Content-Length", r2Object.ContentLength);
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("X-Content-Type-Options", "nosniff");

  let cleanedUp = false;
  async function cleanupR2() {
    if (cleanedUp) return;
    cleanedUp = true;
    await deleteR2Object(r2Key);
    redis.del(`r2key:${token}`).catch(() => {});
    secLog("info", "r2_object_deleted_after_download", { token: token.slice(0, 8) + "..." });
  }

  // r2Object.Body Node.js'te bir Readable stream'dir (SDK v3)
  const stream = r2Object.Body;

  stream.on("error", (err) => {
    secLog("error", "stream_error", { ip, err: err.message });
    if (!res.headersSent) res.status(500).end();
  });

  res.on("finish", cleanupR2);
  res.on("close", cleanupR2);

  stream.pipe(res);
});

// ── SPA fallback ──
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ── Global error handler ──
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      secLog("warn", "file_too_large", { ip: req.ip });
      return res.status(413).json({ error: `Dosya çok büyük. Maksimum: ${Math.round(MAX_FILE_SIZE / 1024 / 1024)} MB` });
    }
    secLog("warn", "multer_error", { code: err.code, msg: err.message });
    return res.status(400).json({ error: `Yükleme hatası: ${err.message}` });
  }
  secLog("error", "unhandled_error", { msg: err.message });
  if (!res.headersSent) res.status(500).json({ error: "Beklenmeyen sunucu hatası." });
});

// ─── Start ────────────────────────────────────────────────────────────────────
let server;
let redisSub;

async function start() {
  try { await redis.connect(); }
  catch (err) {
    console.error("[Redis] Could not connect:", err.message);
    process.exit(1);
  }

  // EXPIRE worker — token süresi dolduğunda R2'den dosyayı sil
  try {
    await redis.config("SET", "notify-keyspace-events", "Ex");
    redisSub = new Redis(process.env.REDIS_URL || "redis://localhost:6379", {
      maxRetriesPerRequest: 3, lazyConnect: false,
    });
    redisSub.on("error", (err) => console.error("[Redis EXPIRE Worker] Error:", err.message));

    await redisSub.subscribe("__keyevent@0__:expired");

    redisSub.on("message", async (channel, expiredKey) => {
      if (!expiredKey.startsWith("token:")) return;
      const token = expiredKey.replace("token:", "");
      const r2KeyKey = `r2key:${token}`;
      try {
        const r2Key = await redis.get(r2KeyKey);
        if (r2Key && isValidR2Key(r2Key)) {
          await deleteR2Object(r2Key);
          secLog("info", "expire_worker_r2_deleted", { token: token.slice(0, 8) + "..." });
        }
        await redis.del(r2KeyKey);
      } catch (err) {
        secLog("warn", "expire_worker_error", { token: token.slice(0, 8) + "...", err: err.message });
      }
    });

    console.log("[Redis EXPIRE Worker] Active — listening for token expirations");
  } catch (err) {
    console.warn("[Redis EXPIRE Worker] Could not start:", err.message);
  }

  server = app.listen(PORT, HOST, () => {
    console.log(`\n✅ SecureVault v2.9 (R2) running on http://${HOST}:${PORT}`);
    console.log(`   Token TTL     : ${TOKEN_TTL_SECONDS}s`);
    console.log(`   Max file size : ${Math.round(MAX_FILE_SIZE / 1024 / 1024)} MB`);
    console.log(`   Storage       : Cloudflare R2 (${R2_BUCKET})`);
    console.log(`   Base URL      : ${BASE_URL}\n`);
  });
}

function gracefulShutdown(signal) {
  console.log(`[Shutdown] ${signal} received. Closing connections...`);
  clearInterval(sessionCleanupInterval);

  // Aktif streaming session'ları abort et — R2'de yarım kalmış multipart bırakma
  (async () => {
    for (const [id, session] of uploadSessions) {
      await abortR2Multipart(session.r2Key, session.r2UploadId);
    }
    uploadSessions.clear();
  })().catch(() => {});

  if (redisSub) redisSub.quit().catch(() => {});
  if (server) {
    server.close(() => { redis.quit().catch(() => {}); process.exit(0); });
    setTimeout(() => { console.error("[Shutdown] Forced exit."); process.exit(1); }, 10000);
  } else { redis.quit().catch(() => {}); process.exit(0); }
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

start();
