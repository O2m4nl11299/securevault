# SecureVault

> Zero-Knowledge Encrypted File Sharing

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Nedir?

SecureVault, dosyaların **yalnızca alıcı tarafından açılabildiği**, sunucunun içeriği hiçbir zaman görmediği bir dosya paylaşım servisidir.

## Özellikler

- 🔐 **AES-256-GCM** istemci tarafı şifreleme
- 🔑 Şifreleme anahtarı sunucuya **asla gönderilmez** (URL fragment)
- 🗑️ **Tek kullanımlık link** — indirildikten sonra silinir
- ⏱️ **TTL** — 1 saat sonra otomatik sona erer
- 📧 E-posta ile güvenli link gönderimi
- 🔑 **Ek şifre koruması** — ikinci güvenlik katmanı
- ☁️ **Cloudflare R2** depolama
- 👤 Kullanıcı kayıt sistemi (Argon2id)
- 📱 Hesap gerektirmez (alıcı)

## Demo

**[sifreliveritransferi.com](https://sifreliveritransferi.com)**

## Teknik Detaylar

| Özellik | Detay |
|---|---|
| Şifreleme | AES-256-GCM (WebCrypto API) |
| Anahtar | URL fragment (#) — sunucuya gitmez |
| Depolama | Cloudflare R2 |
| Token | UUIDv4, tek kullanımlık |
| TTL | 3600 saniye |
| Max boyut | 250 MB (üye), 5 MB (üye olmayan) |
| Streaming | ✅ 5 MB chunk, düşük RAM |

## Altyapı

- **Node.js** + Express
- **Redis** — token yönetimi
- **PostgreSQL** — kullanıcı yönetimi (Argon2id)
- **Nginx** — reverse proxy, TLS 1.3
- **Cloudflare** — DDoS koruması, WAF
- **Fail2ban** — brute force koruması

## Kurulum

```bash
# Bağımlılıkları yükle
npm install

# .env dosyasını oluştur
cp .env.example .env

# Servisi başlat
node server.js
```

## Lisans

MIT © 2026 SecureVault
