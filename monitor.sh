#!/bin/bash
# SecureVault sunucu izleme - kaynak/servis/guvenlik kontrolu
# Cron ile periyodik calisir. Sorun durumunda bir kez mail atar (spam yapmaz).

cd /opt/securevault
STATE_DIR="/opt/securevault/.monitor_state"
mkdir -p "$STATE_DIR"

alert() {  # alert <durum_anahtari> <konu> <mesaj>
  local key="$1" subject="$2" msg="$3"
  local flag="$STATE_DIR/$key"
  if [ ! -f "$flag" ]; then          # daha once bildirilmediyse
    node /opt/securevault/alert-mail.js "$subject" "$msg" && touch "$flag"
  fi
}
resolve() {  # resolve <durum_anahtari> <konu>
  local key="$1" subject="$2"
  local flag="$STATE_DIR/$key"
  if [ -f "$flag" ]; then             # sorun cozuldu, bir kez bildir
    node /opt/securevault/alert-mail.js "COZULDU: $subject" "Sorun normale dondu." && rm -f "$flag"
  fi
}

# 1) SERVIS CRASH
if systemctl is-active --quiet securevault; then
  resolve "service" "Servis durdu"
else
  alert "service" "Servis DURDU" "securevault servisi calismiyor! Sunucuya baglanip kontrol et: systemctl status securevault"
fi

# 2) DISK (%85 ustu)
DISK=$(df / | awk 'NR==2 {gsub("%",""); print $5}')
if [ "$DISK" -ge 85 ]; then
  alert "disk" "Disk doluyor (%$DISK)" "Kok disk kullanimi %$DISK. Yer acmak gerekebilir."
else
  resolve "disk" "Disk doluyor"
fi

# 3) RAM (%90 ustu)
RAM=$(free | awk '/Mem:/ {printf "%.0f", $3/$2*100}')
if [ "$RAM" -ge 90 ]; then
  alert "ram" "RAM kritik (%$RAM)" "Bellek kullanimi %$RAM. Servis yavaslayabilir."
else
  resolve "ram" "RAM kritik"
fi

# 4) GUVENLIK - CrowdSec son 10 dk'da cok ban yaptiysa (esik: 25)
if command -v cscli >/dev/null 2>&1; then
  BANS=$(cscli decisions list -o json 2>/dev/null | grep -c '"type": *"ban"' || echo 0)
  if [ "$BANS" -ge 25 ]; then
    alert "attack" "Olasi saldiri ($BANS aktif ban)" "CrowdSec su an $BANS aktif ban tutuyor. Yogun saldiri olabilir. Kontrol: cscli decisions list"
  else
    resolve "attack" "Olasi saldiri"
  fi
fi
