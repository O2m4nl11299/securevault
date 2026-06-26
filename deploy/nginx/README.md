# nginx Yapılandırması

Bu dosya, canlı nginx config'inin (`/etc/nginx/sites-available/securevault.conf`)
versiyon kontrollü bir kopyasıdır. Gerçek dosya sunucuda `/etc/nginx`'tedir.

## Güncelleme
Sunucuda nginx config değişince buraya da kopyala:
## Önemli özellikler
- Cloudflare gerçek IP çözümleme (set_real_ip_from)
- Origin kilidi: Cloudflare dışı doğrudan bağlantılar 403 (geo $is_cloudflare)
- Gözlem logu: cf_observe.log (bypass denemeleri)
- TLS 1.3, HSTS, rate limit zone'ları
