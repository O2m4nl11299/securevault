// SecureVault sunucu izleme - alarm mail gondericisi
// Kullanim: node alert-mail.js "Konu" "Mesaj govdesi"
require("dotenv").config({ path: "/opt/securevault/.env" });
const nodemailer = require("nodemailer");

const ALERT_TO = process.env.ALERT_EMAIL || "";
const subject = process.argv[2] || "SecureVault Alarm";
const body = process.argv[3] || "(mesaj yok)";

const port = parseInt(process.env.SMTP_PORT || "465");
const secure = (process.env.SMTP_SECURE || "true") === "true" || port === 465;

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.hostinger.com",
  port,
  secure,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  connectionTimeout: 10000,
  tls: { rejectUnauthorized: true, minVersion: "TLSv1.2" },
});

transporter.sendMail({
  from: process.env.SMTP_FROM || process.env.SMTP_USER,
  to: ALERT_TO,
  subject: "[SecureVault] " + subject,
  text: body + "\n\n-- \nSunucu izleme sistemi\n" + new Date().toISOString(),
}).then(() => {
  console.log("Alarm maili gonderildi:", subject);
  process.exit(0);
}).catch((err) => {
  console.error("Mail HATASI:", err.message);
  process.exit(1);
});
