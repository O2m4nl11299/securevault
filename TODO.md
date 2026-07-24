
## Node 22 yükseltmesi (son tarih: Ocak 2027)
AWS SDK v3, Ocak 2027'den sonra Node >=22 gerektirecek. Şu an: Node v20.20.2.
Plan: Kasım-Aralık 2026'da Node 22 LTS'e geç, `npm ci` + tam test (upload/download/R2), sonra deploy.

## Sunucu yapılandırma notları (git dışı, /etc altında)
- CrowdSec nginx acquis daraltıldı: `/etc/crowdsec/acquis.d/setup.nginx.yaml`
  artık glob (`*.log`) yerine açık dosya listesi kullanıyor.
  `cf_observe.log` (Cloudflare gerçek-IP teşhis logu, özel format) bilinçli
  olarak hariç tutuldu — CrowdSec parse edemiyordu, boşuna okuyordu.
  Sunucu yeniden kurulursa bu daraltma tekrar uygulanmalı.
- Güvenlik özet raporu: `scripts/security_report.js` + systemd timer
  (`securevault-report.timer`, 09:00 ve 21:00 Europe/Istanbul).
- Origin kilitleme: UFW'de 80/443 artık yalnızca Cloudflare IP aralıklarına
  açık (geniş `Anywhere` kuralları silindi). Aralıklar haftalık olarak
  `/usr/local/bin/update-cf-ufw.sh` + `cf-ufw-update.timer` ile güncelleniyor.
  Sunucu yeniden kurulursa bu kilit tekrar uygulanmalı; aksi halde gerçek IP
  sızdığında Cloudflare (WAF/DDoS) baypas edilebilir.
