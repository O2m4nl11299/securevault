/**
 * SecureVault — Guvenlik Ozet Raporu
 * Son 12 saatin guvenlik durumunu derleyip e-posta ile gonderir.
 * systemd timer ile 09:00 ve 21:00'de calisir.
 */
require("dotenv").config({ path: "/opt/securevault/.env" });
const { execSync } = require("child_process");
const nodemailer = require("nodemailer");
const { Pool } = require("pg");

const HOURS = 12;
const TO = process.env.ALERT_EMAIL || "tinerciveled@gmail.com";

function sh(cmd, fallback = "") {
  try {
    return execSync(cmd, { encoding: "utf8", timeout: 15000 }).trim();
  } catch (e) {
    return fallback;
  }
}

async function main() {
  const db = new Pool({
    host: process.env.DB_HOST, port: process.env.DB_PORT,
    database: process.env.DB_NAME, user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
  });

  // ── CrowdSec ──
  let bans = [], banReasons = {};
  try {
    const raw = sh("cscli decisions list -o json", "[]");
    const arr = JSON.parse(raw || "[]");
    (Array.isArray(arr) ? arr : []).forEach((a) => {
      (a.decisions || []).forEach((d) => {
        bans.push({ ip: d.value, reason: d.scenario, country: a.source?.cn || "?" });
        const key = (d.scenario || "?").replace("crowdsecurity/", "");
        banReasons[key] = (banReasons[key] || 0) + 1;
      });
    });
  } catch (_) {}
  const bouncerOk = sh("cscli bouncers list -o json", "[]").includes("firewall");

  // ── Giris kayitlari ──
  let logins = 0, uniqueIps = 0, totalUsers = 0;
  try {
    const r1 = await db.query(
      `SELECT COUNT(*)::int AS c, COUNT(DISTINCT ip)::int AS u
       FROM access_logs WHERE created_at > NOW() - INTERVAL '${HOURS} hours'`);
    logins = r1.rows[0].c; uniqueIps = r1.rows[0].u;
    const r2 = await db.query("SELECT COUNT(*)::int AS c FROM users");
    totalUsers = r2.rows[0].c;
  } catch (e) { logins = -1; }

  // ── Dosya trafigi (imha sertifikalari) ──
  let destroyed = 0, byReason = {};
  try {
    const r = await db.query(
      `SELECT reason, COUNT(*)::int AS c FROM deletion_certificates
       WHERE deleted_at > NOW() - INTERVAL '${HOURS} hours' GROUP BY reason`);
    r.rows.forEach((x) => { byReason[x.reason] = x.c; destroyed += x.c; });
  } catch (_) {}

  // ── Uygulama hatalari ──
  const errCount = parseInt(sh(
    `journalctl -u securevault --since "${HOURS} hours ago" --no-pager | grep -c '"level":"error"'`, "0")) || 0;
  const errSample = sh(
    `journalctl -u securevault --since "${HOURS} hours ago" --no-pager | grep '"level":"error"' | tail -3`, "");

  // ── Basarisiz giris denemeleri ──
  const failedLogins = parseInt(sh(
    `journalctl -u securevault --since "${HOURS} hours ago" --no-pager | grep -c 'login_failed\\|invalid_credentials'`, "0")) || 0;

  // ── Sistem ──
  const disk = sh("df -h / | awk 'NR==2{print $5\" dolu (\"$3\"/\"$2\")\"}'", "?");
  const mem = sh("free -m | awk 'NR==2{printf \"%d%% (%dMB/%dMB)\", $3*100/$2, $3, $2}'", "?");
  const uptime = sh("uptime -p", "?");
  const svcOk = sh("systemctl is-active securevault", "?") === "active";
  const sslDays = sh(
    "echo | openssl s_client -servername sifreliveritransferi.com -connect sifreliveritransferi.com:443 2>/dev/null | openssl x509 -noout -enddate | cut -d= -f2", "");

  // ── Rapor ──
  const now = new Date().toLocaleString("tr-TR", { timeZone: "Europe/Istanbul" });
  const banLines = Object.entries(banReasons).map(([k, v]) => `  • ${k}: ${v}`).join("\n") || "  • yok";
  const fileLines = Object.entries(byReason).map(([k, v]) =>
    `  • ${k === "downloaded" ? "indirildi" : "süresi doldu"}: ${v}`).join("\n") || "  • yok";

  const alerts = [];
  if (!svcOk) alerts.push("⚠ SERVİS ÇALIŞMIYOR");
  if (!bouncerOk) alerts.push("⚠ CrowdSec bouncer görünmüyor");
  if (errCount > 10) alerts.push(`⚠ Yüksek hata sayısı: ${errCount}`);
  if (failedLogins > 20) alerts.push(`⚠ Çok sayıda başarısız giriş: ${failedLogins}`);

  const body = `SecureVault — Güvenlik Özeti
${now} (son ${HOURS} saat)
${alerts.length ? "\n" + alerts.join("\n") + "\n" : "\nDurum: normal\n"}
─── SALDIRI SAVUNMASI ───
Aktif ban sayısı: ${bans.length}
Ban sebepleri:
${banLines}
Firewall bouncer: ${bouncerOk ? "aktif ✓" : "GÖRÜNMÜYOR ✗"}

─── HESAP & GİRİŞ ───
Toplam kayıtlı kullanıcı: ${totalUsers}
Giriş sayısı: ${logins < 0 ? "okunamadı" : logins} (farklı IP: ${uniqueIps})
Başarısız giriş denemesi: ${failedLogins}

─── DOSYA TRAFİĞİ ───
İmha edilen dosya: ${destroyed}
${fileLines}

─── SİSTEM ───
Servis: ${svcOk ? "çalışıyor ✓" : "DURMUŞ ✗"}
Disk: ${disk}
RAM: ${mem}
Çalışma süresi: ${uptime}
SSL bitiş: ${sslDays || "okunamadı"}
Uygulama hatası: ${errCount}
${errCount > 0 ? "\nSon hatalar:\n" + errSample : ""}
`;

  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || "465"),
    secure: String(process.env.SMTP_SECURE || "true") === "true",
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });

  await transporter.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: TO,
    subject: `${alerts.length ? "⚠ " : ""}SecureVault Güvenlik Özeti — ${now}`,
    text: body,
  });

  console.log("Rapor gonderildi ->", TO);
  await db.end();
  process.exit(0);
}

main().catch((e) => { console.error("HATA:", e.message); process.exit(1); });
