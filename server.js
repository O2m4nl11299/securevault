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
const { Pool } = require("pg");
const argon2 = require("argon2");
const { randomBytes } = require("crypto");

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
// ─── PostgreSQL ───────────────────────────────────────────────────────────────
const db = new Pool({
  host: process.env.DB_HOST || "127.0.0.1",
  port: parseInt(process.env.DB_PORT || "5432"),
  database: process.env.DB_NAME || "securevault",
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: false,
  max: 10,
});
db.on("error", (err) => console.error("[DB] Pool error:", err.message));
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "127.0.0.1"; // Loopback — nginx önümüzde
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const TOKEN_TTL_SECONDS = parseInt(process.env.TOKEN_TTL_SECONDS || "3600");
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE || String(250 * 1024 * 1024));
// Plan bazli dosya boyutu ve gonderim limitleri
const PLAN_FILE_LIMITS = {
  anon: 5 * 1024 * 1024,            // 5 MB
  free: MAX_FILE_SIZE,               // 250 MB
  premium: 2 * 1024 * 1024 * 1024,   // 2 GB
  admin: 20 * 1024 * 1024 * 1024,    // 20 GB (sadece admin hesaplar icin, streaming yolu)
};
const PLAN_SEND_LIMITS = {
  anon: 3,    // 24 saatte 3 gonderim (anonim yukleme kapali, kullanilmiyor)
  free: 4,    // 24 saatte 4 gonderim
  premium: 20, // 24 saatte 20 gonderim
};

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
        styleSrc: ["'self'", "https://fonts.googleapis.com"],
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
  limits: { files: 1, fileSize: PLAN_FILE_LIMITS.premium },
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

app.get("/kvkk", (req, res) => res.sendFile(path.join(__dirname, "public", "kvkk.html")));
app.get("/sozlesme", (req, res) => res.sendFile(path.join(__dirname, "public", "sozlesme.html")));
app.get("/sartlar", (req, res) => res.sendFile(path.join(__dirname, "public", "sartlar.html")));
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
  // Plan ve limit kontrolu
  const sessionTokenCL = req.headers["x-session-token"] || "";
  let userPlanCL = "anon";
  let userIdCL = null;
  if (sessionTokenCL) {
    try {
      const sd = await redis.get("session:" + sessionTokenCL);
      if (sd) {
        const parsedCL = JSON.parse(sd);
        userPlanCL = parsedCL.plan || "free";
        userIdCL = parsedCL.userId;
      }
    } catch(e) {}
  }
  if (sessionTokenCL && userPlanCL === "anon") {
    return res.status(401).json({ error: "Oturum süresi doldu. Lütfen tekrar giriş yapın.", sessionExpired: true });
  }
  // ANONIM YUKLEME KAPALI: gecerli oturum yoksa reddet.
  if (userPlanCL === "anon") {
    return res.status(401).json({ error: "Dosya göndermek için giriş yapmanız gerekiyor.", loginRequired: true });
  }
  // Dosya boyutu kontrolu (plan bazli)
  const maxSizeCL = PLAN_FILE_LIMITS[userPlanCL] || PLAN_FILE_LIMITS.free;
  if (req.file.size > maxSizeCL) {
    return res.status(413).json({ error: `Dosya çok büyük. Maksimum: ${Math.round(maxSizeCL / 1024 / 1024)} MB` });
  }
  if (userPlanCL === "anon") {
    const fpCL = req.headers["x-fingerprint"] || "";
    const anonKeyCL = "anon_uploads:" + hashIp(ip) + (fpCL ? ":" + fpCL : "");
    const countCL = parseInt(await redis.get(anonKeyCL) || "0");
    if (countCL >= PLAN_SEND_LIMITS.anon) {
      return res.status(403).json({ error: "Ücretsiz gönderim hakkınız doldu. Daha fazla göndermek için üye olun.", upgrade: true });
    }
    await redis.incr(anonKeyCL);
    await redis.expire(anonKeyCL, 86400);
  } else if (userPlanCL === "free") {
    const freeKeyCL = "free_uploads:" + userIdCL;
    const fcountCL = parseInt(await redis.get(freeKeyCL) || "0");
    if (fcountCL >= PLAN_SEND_LIMITS.free) {
      return res.status(403).json({ error: "Günlük gönderim hakkınız doldu. Premium'a geçerek sınırsız gönderin.", upgrade: true });
    }
    await redis.incr(freeKeyCL);
    await redis.expire(freeKeyCL, 86400);
  }

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

  // Plan ve limit kontrolu
  const sessionToken = req.headers["x-session-token"] || "";
  let userPlan = "anon";
  let userId = null;
  if (sessionToken) {
    try {
      const sessionData = await redis.get("session:" + sessionToken);
      if (sessionData) {
        const parsed = JSON.parse(sessionData);
        userPlan = parsed.plan || "free";
        userId = parsed.userId;
        await db.query("UPDATE users SET last_active_at = NOW() WHERE id = $1", [userId]);
      }
    } catch(e) {}
  }
  if (sessionToken && userPlan === "anon") {
    return res.status(401).json({ error: "Oturum süresi doldu. Lütfen tekrar giriş yapın.", sessionExpired: true });
  }
  // ANONIM YUKLEME KAPALI: gecerli oturum yoksa reddet.
  if (userPlan === "anon") {
    return res.status(401).json({ error: "Dosya göndermek için giriş yapmanız gerekiyor.", loginRequired: true });
  }
  const maxFileSize = PLAN_FILE_LIMITS[userPlan] || PLAN_FILE_LIMITS.free;
  if (userPlan === "anon") {
    const fingerprint = req.headers["x-fingerprint"] || "";
    const anonKey = "anon_uploads:" + hashIp(ip) + (fingerprint ? ":" + fingerprint : "");
    const count = parseInt(await redis.get(anonKey) || "0");
    if (count >= PLAN_SEND_LIMITS.anon) {
      return res.status(403).json({ error: "Ücretsiz gönderim hakkınız doldu. Daha fazla göndermek için üye olun.", upgrade: true });
    }
    req._anonKey = anonKey;
  } else if (userPlan === "free") {
    const freeKey = "free_uploads:" + userId;
    const fcount = parseInt(await redis.get(freeKey) || "0");
    if (fcount >= PLAN_SEND_LIMITS.free) {
      return res.status(403).json({ error: "Günlük gönderim hakkınız doldu. Premium'a geçerek daha fazla gönderin.", upgrade: true });
    }
    req._freeKey = freeKey;
  } else if (userPlan === "premium") {
    const premiumKey = "premium_uploads:" + userId;
    const pcount = parseInt(await redis.get(premiumKey) || "0");
    if (pcount >= PLAN_SEND_LIMITS.premium) {
      return res.status(403).json({ error: "Günlük gönderim limitinize ulaştınız (20/gün). Yarın tekrar deneyebilirsiniz." });
    }
    req._premiumKey = premiumKey;
  }
  // ESZAMANLI YUKLEME YASAGI: ayni hesap ayni anda tek yukleme yapabilir.
  // Normal bitiste finalize kilidi siler; coken/yarim kalan yukleme icin
  // 15 dk (900 sn) guvenlik agi TTL'i kilidi otomatik acar.
  if (userId) {
    const lockKey = "upload_lock:" + userId;
    const locked = await redis.set(lockKey, "1", "NX", "EX", 900);
    if (locked === null) {
      return res.status(409).json({ error: "Zaten devam eden bir yüklemeniz var. Lütfen tamamlanmasını bekleyin." });
    }
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
    maxFileSize,
    userPlan,
    userId,
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
  express.raw({ type: "application/octet-stream", limit: "25mb" }),
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
    if (session.totalBytes + chunkData.length > session.maxFileSize) {
      await abortR2Multipart(session.r2Key, session.r2UploadId);
      uploadSessions.delete(uploadId);
      return res.status(413).json({ error: `Dosya çok büyük. Maksimum: ${Math.round(session.maxFileSize / 1024 / 1024)} MB` });
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
  // ESZAMANLI KILIDI KALDIR: bu hesabin yuklemesi tamamlaniyor.
  if (session.userId) {
    try { await redis.del("upload_lock:" + session.userId); } catch (e) {}
  }

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

  // Plan bazli gonderim sayacini artir
  if (!req.headers["x-session-token"]) {
    const fp = req.headers["x-fingerprint"] || "";
    const anonKey = "anon_uploads:" + hashIp(req.ip) + (fp ? ":" + fp : "");
    await redis.incr(anonKey);
    await redis.expire(anonKey, 86400);
  } else if (session.userPlan === "free" && session.userId) {
    const freeKey = "free_uploads:" + session.userId;
    await redis.incr(freeKey);
    await redis.expire(freeKey, 86400);
  } else if (session.userPlan === "premium" && session.userId) {
    const premiumKey = "premium_uploads:" + session.userId;
    await redis.incr(premiumKey);
    await redis.expire(premiumKey, 86400);
  }
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
  const keyParts = keyB64.split("|");
  const actualKey = keyParts[0];
  const pwdHash = keyParts[1] || "";
  if (!isValidKeyB64(actualKey)) return res.status(400).json({ error: "Geçersiz şifreleme anahtarı." });
  keyB64 = actualKey;

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

  const downloadUrl = `${BASE_URL}/dl/${token}#${encodeURIComponent(keyB64)}${pwdHash ? "|" + pwdHash : ""}`;
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
// ─── Auth Endpoints ───────────────────────────────────────────────────────────

// POST /auth/register
app.post("/auth/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Kullanıcı adı ve şifre gerekli." });
  if (username.length < 3 || username.length > 32) return res.status(400).json({ error: "Kullanıcı adı 3-32 karakter olmalı." });
  if (password.length < 8) return res.status(400).json({ error: "Şifre en az 8 karakter olmalı." });
  try {
    const usernameHash = crypto.createHash("sha256").update(username.toLowerCase().trim()).digest("hex");
    const passwordHash = await argon2.hash(password, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 4 });
    const recoveryToken = randomBytes(32).toString("hex");
    const recoveryTokenHash = crypto.createHash("sha256").update(recoveryToken).digest("hex");
    await db.query("INSERT INTO users (username_hash, password_hash, recovery_token_hash) VALUES ($1, $2, $3)", [usernameHash, passwordHash, recoveryTokenHash]);
    return res.json({ success: true, recoveryToken });
  } catch (err) {
    if (err.code === "23505") return res.status(409).json({ error: "Bu kullanıcı adı alınmış." });
    secLog("error", "register_failed", { err: err.message });
    return res.status(500).json({ error: "Kayıt başarısız." });
  }
});

// POST /auth/login
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Kullanıcı adı ve şifre gerekli." });
  try {
    const usernameHash = crypto.createHash("sha256").update(username.toLowerCase().trim()).digest("hex");
    const result = await db.query("SELECT id, password_hash, plan, upload_count, is_admin FROM users WHERE username_hash = $1", [usernameHash]);
    if (result.rows.length === 0) return res.status(401).json({ error: "Kullanıcı adı veya şifre hatalı." });
    const user = result.rows[0];
    const valid = await argon2.verify(user.password_hash, password);
    if (!valid) return res.status(401).json({ error: "Kullanıcı adı veya şifre hatalı." });
    await db.query("UPDATE users SET last_active_at = NOW() WHERE id = $1", [user.id]);
    const sessionToken = randomBytes(32).toString("hex");
    await redis.setex("session:" + sessionToken, 86400, JSON.stringify({ userId: user.id, plan: user.plan }));
    return res.json({ success: true, sessionToken, plan: user.plan, isAdmin: !!user.is_admin });
  } catch (err) {
    secLog("error", "login_failed", { err: err.message });
    return res.status(500).json({ error: "Giriş başarısız." });
  }
});

// POST /auth/recover
app.post("/auth/recover", async (req, res) => {
  const { username, recoveryToken, newPassword } = req.body;
  if (!username || !recoveryToken || !newPassword) return res.status(400).json({ error: "Tüm alanlar gerekli." });
  if (newPassword.length < 8) return res.status(400).json({ error: "Şifre en az 8 karakter olmalı." });
  try {
    const usernameHash = crypto.createHash("sha256").update(username.toLowerCase().trim()).digest("hex");
    const recoveryTokenHash = crypto.createHash("sha256").update(recoveryToken.trim()).digest("hex");
    const result = await db.query("SELECT id FROM users WHERE username_hash = $1 AND recovery_token_hash = $2", [usernameHash, recoveryTokenHash]);
    if (result.rows.length === 0) return res.status(401).json({ error: "Kullanıcı adı veya kurtarma kodu hatalı." });
    const passwordHash = await argon2.hash(newPassword, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 4 });
    await db.query("UPDATE users SET password_hash = $1, last_active_at = NOW() WHERE id = $2", [passwordHash, result.rows[0].id]);
    return res.json({ success: true });
  } catch (err) {
    secLog("error", "recover_failed", { err: err.message });
    return res.status(500).json({ error: "Kurtarma başarısız." });
  }
});

// POST /api/delete-account
app.post("/api/delete-account", async (req, res) => {
  const { password } = req.body;
  const sessionToken = req.headers["x-session-token"] || "";
  if (!sessionToken) return res.status(401).json({ error: "Oturum bulunamadı." });
  if (!password) return res.status(400).json({ error: "Şifre gerekli." });
  try {
    const sessionData = await redis.get("session:" + sessionToken);
    if (!sessionData) return res.status(401).json({ error: "Oturum süresi dolmuş." });
    const { userId } = JSON.parse(sessionData);
    const result = await db.query("SELECT password_hash FROM users WHERE id = $1", [userId]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Kullanıcı bulunamadı." });
    const valid = await argon2.verify(result.rows[0].password_hash, password);
    if (!valid) return res.status(401).json({ error: "Şifre hatalı." });
    await db.query("DELETE FROM users WHERE id = $1", [userId]);
    await redis.del("session:" + sessionToken);
    return res.json({ success: true });
  } catch (err) {
    secLog("error", "delete_account_failed", { err: err.message });
    return res.status(500).json({ error: "Hesap silme başarısız." });
  }
});

// ─── Admin middleware ───────────────────────────────────────────────────────
async function requireAdmin(req, res, next) {
  const sessionToken = req.headers["x-session-token"] || "";
  if (!sessionToken) return res.status(401).json({ error: "Oturum bulunamadı." });
  try {
    const sessionData = await redis.get("session:" + sessionToken);
    if (!sessionData) return res.status(401).json({ error: "Oturum süresi dolmuş." });
    const { userId } = JSON.parse(sessionData);
    const result = await db.query("SELECT is_admin FROM users WHERE id = $1", [userId]);
    if (result.rows.length === 0 || !result.rows[0].is_admin) {
      return res.status(403).json({ error: "Yetkiniz yok." });
    }
    req._adminUserId = userId;
    next();
  } catch (err) {
    secLog("error", "admin_auth_failed", { err: err.message });
    return res.status(500).json({ error: "Yetkilendirme hatası." });
  }
}
// GET /admin/lookup?username=...
app.get("/admin/lookup", requireAdmin, async (req, res) => {
  const username = (req.query.username || "").toString();
  if (!username) return res.status(400).json({ error: "Kullanıcı adı gerekli." });
  try {
    const usernameHash = crypto.createHash("sha256").update(username.toLowerCase().trim()).digest("hex");
    const result = await db.query("SELECT plan, upload_count, last_active_at, created_at, is_admin FROM users WHERE username_hash = $1", [usernameHash]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Kullanıcı bulunamadı." });
    return res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    secLog("error", "admin_lookup_failed", { err: err.message });
    return res.status(500).json({ error: "Sorgu başarısız." });
  }
});
// POST /admin/set-plan
app.post("/admin/set-plan", requireAdmin, async (req, res) => {
  const { username, plan } = req.body;
  const ALLOWED_PLANS = ["free", "premium", "admin"];
  if (!username || !ALLOWED_PLANS.includes(plan)) {
    return res.status(400).json({ error: "Geçersiz istek." });
  }
  try {
    const usernameHash = crypto.createHash("sha256").update(username.toLowerCase().trim()).digest("hex");
    const result = await db.query("UPDATE users SET plan = $1 WHERE username_hash = $2 RETURNING id, plan", [plan, usernameHash]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Kullanıcı bulunamadı." });
    secLog("info", "admin_plan_changed", { adminUserId: req._adminUserId, targetUserId: result.rows[0].id, targetPlan: plan });
    return res.json({ success: true, plan: result.rows[0].plan });
  } catch (err) {
    secLog("error", "admin_set_plan_failed", { err: err.message });
    return res.status(500).json({ error: "Güncelleme başarısız." });
  }
});
// POST /admin/delete-user
app.post("/admin/delete-user", requireAdmin, async (req, res) => {
  const { username, adminPassword } = req.body;
  if (!username) return res.status(400).json({ error: "Kullanıcı adı gerekli." });
  if (!adminPassword) return res.status(400).json({ error: "Onay için kendi şifreniz gerekli." });
  try {
    const adminResult = await db.query("SELECT password_hash FROM users WHERE id = $1", [req._adminUserId]);
    if (adminResult.rows.length === 0) return res.status(401).json({ error: "Yetkilendirme hatası." });
    const adminValid = await argon2.verify(adminResult.rows[0].password_hash, adminPassword);
    if (!adminValid) return res.status(401).json({ error: "Şifreniz hatalı." });
    const usernameHash = crypto.createHash("sha256").update(username.toLowerCase().trim()).digest("hex");
    const result = await db.query("DELETE FROM users WHERE username_hash = $1 RETURNING id", [usernameHash]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Kullanıcı bulunamadı." });
    secLog("info", "admin_user_deleted", { adminUserId: req._adminUserId, targetUserId: result.rows[0].id });
    return res.json({ success: true });
  } catch (err) {
    secLog("error", "admin_delete_user_failed", { err: err.message });
    return res.status(500).json({ error: "Silme başarısız." });
  }
});
// GET /admin/users-list
app.get("/admin/users-list", requireAdmin, async (req, res) => {
  try {
    const result = await db.query(
      "SELECT id, plan, created_at, last_active_at FROM users ORDER BY created_at DESC LIMIT 1000"
    );
    return res.json({ success: true, users: result.rows });
  } catch (err) {
    secLog("error", "admin_users_list_failed", { err: err.message });
    return res.status(500).json({ error: "Liste alınamadı." });
  }
});
// POST /admin/grant-premium — hedef kullanıcıya 30 günlük premium tanır (admin manuel verme)
app.post("/admin/grant-premium", requireAdmin, async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: "userId gerekli." });
  try {
    const userCheck = await db.query("SELECT id FROM users WHERE id = $1", [userId]);
    if (userCheck.rows.length === 0) return res.status(404).json({ error: "Kullanıcı bulunamadı." });

    const transactionId = "admin-grant-" + crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    await db.query(
      `INSERT INTO subscriptions (user_id, platform, product_id, transaction_id, status, expires_at, auto_renewing)
       VALUES ($1, 'admin_grant', 'admin_monthly', $2, 'active', $3, false)`,
      [userId, transactionId, expiresAt]
    );
    await db.query("UPDATE users SET plan = 'premium' WHERE id = $1", [userId]);

    secLog("info", "admin_premium_granted", { adminUserId: req._adminUserId, targetUserId: userId, expiresAt });
    return res.json({ success: true, plan: "premium", expiresAt });
  } catch (err) {
    secLog("error", "admin_grant_premium_failed", { err: err.message });
    return res.status(500).json({ error: "İşlem başarısız." });
  }
});
// ─── TEST/GELISTIRME MODU: Gercek Google Play Developer API hazir olunca ──────
// bu fonksiyonu service account + googleapis ile gercek dogrulamaya cevir.
// Su an purchaseToken'i her zaman "gecerli" kabul eder, sure productId'den hesaplanir.
async function verifyGooglePurchase(purchaseToken, productId) {
  // Guvenlik kapisi: gercek Google API hazir olana kadar varsayilan KAPALI.
  // Test etmek icin .env'de ALLOW_FAKE_PURCHASE_VERIFICATION=true yapip servisi yeniden baslat.
  if (process.env.ALLOW_FAKE_PURCHASE_VERIFICATION !== "true") {
    return null;
  }
  const DURATIONS_DAYS = { premium_weekly: 7, premium_monthly: 30 };
  const days = DURATIONS_DAYS[productId];
  if (!days || !purchaseToken) return null;
  return {
    valid: true,
    expiresAt: new Date(Date.now() + days * 24 * 60 * 60 * 1000),
    autoRenewing: true,
  };
}
// POST /api/verify-purchase
app.post("/api/verify-purchase", async (req, res) => {
  const sessionToken = req.headers["x-session-token"] || "";
  if (!sessionToken) return res.status(401).json({ error: "Oturum bulunamadı." });
  const { platform, productId, purchaseToken } = req.body || {};
  const ALLOWED_PLATFORMS = ["google_play"];
  const ALLOWED_PRODUCTS = ["premium_weekly", "premium_monthly"];
  if (!ALLOWED_PLATFORMS.includes(platform)) return res.status(400).json({ error: "Desteklenmeyen platform." });
  if (!ALLOWED_PRODUCTS.includes(productId)) return res.status(400).json({ error: "Geçersiz ürün." });
  if (!purchaseToken) return res.status(400).json({ error: "purchaseToken gerekli." });
  try {
    const sessionData = await redis.get("session:" + sessionToken);
    if (!sessionData) return res.status(401).json({ error: "Oturum süresi doldu. Lütfen tekrar giriş yapın.", sessionExpired: true });
    const { userId } = JSON.parse(sessionData);

    const verification = await verifyGooglePurchase(purchaseToken, productId);
    if (!verification || !verification.valid) {
      return res.status(400).json({ error: "Satın alma doğrulanamadı." });
    }

    await db.query(
      `INSERT INTO subscriptions (user_id, platform, product_id, transaction_id, status, expires_at, auto_renewing)
       VALUES ($1, $2, $3, $4, 'active', $5, $6)
       ON CONFLICT (platform, transaction_id)
       DO UPDATE SET status = 'active', expires_at = $5, auto_renewing = $6, updated_at = NOW()`,
      [userId, platform, productId, purchaseToken, verification.expiresAt, verification.autoRenewing]
    );

    await db.query("UPDATE users SET plan = 'premium' WHERE id = $1", [userId]);

    secLog("info", "purchase_verified", { userId, platform, productId });
    return res.json({ success: true, plan: "premium", expiresAt: verification.expiresAt });
  } catch (err) {
    secLog("error", "verify_purchase_failed", { err: err.message });
    return res.status(500).json({ error: "Doğrulama başarısız." });
  }
});
// ─── TEST/GELISTIRME MODU: Gercek Google Play RTDN entegrasyonu icin ──────────
// service account hazir olunca, notificationType'a gore Google Play Developer
// API'sinden GUNCEL durumu (gracePeriodEndDate vb.) cekip kullanmak daha dogru olur.
// Su an basit bir notificationType -> status haritasi kullanilir.
const RTDN_STATUS_MAP = {
  1: "active",       // RECOVERED
  2: "active",       // RENEWED
  3: "cancelled",    // CANCELED - hala expires_at'e kadar erisimi var, sadece yenilenmeyecek
  4: "active",       // PURCHASED
  5: "on_hold",       // ON_HOLD
  6: "grace_period",  // IN_GRACE_PERIOD
  7: "active",       // RESTARTED
  10: "paused",      // PAUSED
  12: "revoked",     // REVOKED - aninda erisim kesilir
  13: "expired",     // EXPIRED
};
// Bu durumlar premium erisim verir (cancelled dahil - donem bitene kadar erisim suer)
const RTDN_GRANTS_PREMIUM = new Set(["active", "grace_period", "on_hold", "cancelled"]);
// POST /api/google-rtdn — Google Cloud Pub/Sub push subscription buraya gonderir
app.post("/api/google-rtdn", async (req, res) => {
  try {
    const message = req.body && req.body.message;
    if (!message || !message.data) {
      return res.status(400).json({ error: "Geçersiz Pub/Sub mesajı." });
    }
    if (process.env.ALLOW_FAKE_PURCHASE_VERIFICATION !== "true") {
      secLog("warn", "rtdn_received_but_stub_disabled", {});
      return res.status(200).json({ ok: true });
    }
    const decoded = Buffer.from(message.data, "base64").toString("utf8");
    const payload = JSON.parse(decoded);
    const notif = payload.subscriptionNotification;
    if (!notif || !notif.purchaseToken) {
      return res.status(200).json({ ok: true });
    }
    const newStatus = RTDN_STATUS_MAP[notif.notificationType] || null;
    if (!newStatus) {
      return res.status(200).json({ ok: true });
    }
    const sub = await db.query(
      "SELECT user_id FROM subscriptions WHERE platform='google_play' AND transaction_id=$1",
      [notif.purchaseToken]
    );
    if (sub.rows.length === 0) {
      secLog("warn", "rtdn_unknown_purchase_token", {});
      return res.status(200).json({ ok: true });
    }
    const userId = sub.rows[0].user_id;
    await db.query(
      "UPDATE subscriptions SET status=$1, updated_at=NOW() WHERE platform='google_play' AND transaction_id=$2",
      [newStatus, notif.purchaseToken]
    );
    const planShouldBe = RTDN_GRANTS_PREMIUM.has(newStatus) ? "premium" : "free";
    await db.query("UPDATE users SET plan=$1 WHERE id=$2", [planShouldBe, userId]);
    secLog("info", "rtdn_processed", { userId, newStatus, notificationType: notif.notificationType });
    return res.status(200).json({ ok: true });
  } catch (err) {
    secLog("error", "rtdn_failed", { err: err.message });
    return res.status(500).json({ error: "Webhook işleme hatası." });
  }
});
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ── Global error handler ──
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      secLog("warn", "file_too_large", { ip: req.ip });
      return res.status(413).json({ error: `Dosya çok büyük. Maksimum: ${Math.round(PLAN_FILE_LIMITS.premium / 1024 / 1024)} MB` });
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
