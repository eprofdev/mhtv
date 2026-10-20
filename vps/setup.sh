#!/usr/bin/env bash
#
# قنواتي — خادم البناء والتحديث (يُشغَّل مرة واحدة على الـVPS بصلاحية root)
#
#   sudo bash setup.sh tv.example.com            # الفرع main
#   sudo bash setup.sh tv.example.com main
#
# What it sets up, once:
#   * a build user (mhtv) with a READ-ONLY GitHub deploy key for eprofdev/mh-iptv;
#   * JDK 17 (Ubuntu), Android SDK tools from Google (checksum-verified), NDK/CMake
#     through Google's sdkmanager — the same toolchain the GitHub workflow uses;
#   * a NEW signing key generated here, on this server. It never leaves it:
#     no upload, no copy to GitHub. Back it up yourself (see the end of the run);
#   * Caddy (automatic HTTPS) serving the sealed update store at https://DOMAIN/u/,
#     a private download page for first installs, and a private build-status page;
#   * a systemd timer that builds every new commit, verifies the signature against
#     the key generated here, seals the update and publishes it — the app then
#     updates itself in place.
#
# Safe to run again: existing key, deploy key and settings are kept.
set -euo pipefail

DOMAIN="${1:-}"
BRANCH="${2:-main}"
REPO="git@github.com:eprofdev/mh-iptv.git"

die() { echo "خطأ: $*" >&2; exit 1; }
say() { echo -e "\n==> $*"; }

[ "$(id -u)" = 0 ] || die "شغّل السكربت بصلاحية root (sudo)."
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "اكتب اسم الدومين، مثال: sudo bash setup.sh tv.example.com"
[[ "$BRANCH" =~ ^[A-Za-z0-9._/-]+$ ]] || die "اسم فرع غير صالح"
. /etc/os-release
[ "${ID:-}" = ubuntu ] || [ "${ID:-}" = debian ] || die "يدعم Ubuntu/Debian فقط."

ETC=/etc/mhtv
HOME_DIR=/opt/mhtv
WWW=/var/www/mhtv
SDK=$HOME_DIR/sdk
install -d -m 755 "$HOME_DIR" "$WWW"
install -d -m 700 "$ETC"

# ---------------------------------------------------------------- packages
say "تثبيت الحزم (من مستودعات النظام الرسمية)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q openjdk-17-jdk-headless openssl git curl unzip zip python3 python3-cryptography \
  build-essential pkg-config nasm ca-certificates gnupg debian-keyring debian-archive-keyring apt-transport-https

if ! command -v caddy >/dev/null; then
  if ! apt-get install -y -q caddy 2>/dev/null; then
    # Caddy's own apt repository, as its documentation gives it (signed).
    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -q && apt-get install -y -q caddy
  fi
fi

# ---------------------------------------------------------------- memory
MEM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
SWAP_MB=$(awk '/SwapTotal/{print int($2/1024)}' /proc/meminfo)
if [ $((MEM_MB + SWAP_MB)) -lt 7000 ] && [ ! -f /swapfile.mhtv ]; then
  say "الذاكرة ${MEM_MB}MB: إضافة ملف تبديل 4GB لبناء التطبيق"
  fallocate -l 4G /swapfile.mhtv && chmod 600 /swapfile.mhtv && mkswap /swapfile.mhtv >/dev/null && swapon /swapfile.mhtv
  grep -q swapfile.mhtv /etc/fstab || echo "/swapfile.mhtv none swap sw 0 0" >> /etc/fstab
fi
FREE_GB=$(df -BG --output=avail "$HOME_DIR" | tail -1 | tr -dc 0-9)
[ "$FREE_GB" -ge 15 ] || echo "تنبيه: المساحة الحرة ${FREE_GB}GB، يُنصح بـ15GB على الأقل."

# ---------------------------------------------------------------- user
id mhtv >/dev/null 2>&1 || useradd --system --create-home --home-dir "$HOME_DIR/home" --shell /bin/bash mhtv
chown mhtv:mhtv "$HOME_DIR" "$WWW"
install -d -o mhtv -g mhtv -m 700 "$HOME_DIR/home/.ssh"

# ---------------------------------------------------------------- Android SDK
CLT_ZIP=commandlinetools-linux-11076708_latest.zip
CLT_SHA=2d2d50857e4eb553af5a6dc3ad507a17adf43d115264b1afc116f95c92e5e258
if [ ! -x "$SDK/cmdline-tools/latest/bin/sdkmanager" ]; then
  say "أدوات Android من Google (مع التحقق من البصمة)"
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/$CLT_ZIP" "https://dl.google.com/android/repository/$CLT_ZIP"
  echo "$CLT_SHA  $tmp/$CLT_ZIP" | sha256sum -c - || die "بصمة أدوات Android لا تطابق — توقّف."
  install -d -o mhtv -g mhtv "$SDK/cmdline-tools"
  unzip -q "$tmp/$CLT_ZIP" -d "$tmp"
  mv "$tmp/cmdline-tools" "$SDK/cmdline-tools/latest"
  rm -rf "$tmp"
  chown -R mhtv:mhtv "$SDK"
fi
say "حزم SDK"
runuser -u mhtv -- bash -c "yes | ANDROID_HOME=$SDK $SDK/cmdline-tools/latest/bin/sdkmanager --licenses >/dev/null
  ANDROID_HOME=$SDK $SDK/cmdline-tools/latest/bin/sdkmanager --install 'platforms;android-36' 'build-tools;36.0.0' 'build-tools;35.0.0' >/dev/null"

# ---------------------------------------------------------------- deploy key
KEY=$HOME_DIR/home/.ssh/id_ed25519
if [ ! -f "$KEY" ]; then
  runuser -u mhtv -- ssh-keygen -q -t ed25519 -N "" -C "mhtv-build@$DOMAIN" -f "$KEY"
fi
# GitHub's published SSH host key (docs.github.com, "GitHub's SSH key fingerprints").
echo "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl" > "$HOME_DIR/home/.ssh/known_hosts"
chown mhtv:mhtv "$HOME_DIR/home/.ssh/known_hosts"

if ! runuser -u mhtv -- git ls-remote "$REPO" HEAD >/dev/null 2>&1; then
  echo
  echo "================================================================="
  echo " أضف هذا المفتاح للقراءة فقط في GitHub:"
  echo "   github.com/eprofdev/mh-iptv → Settings → Deploy keys → Add deploy key"
  echo "   العنوان: vps-build     ولا تُفعّل «Allow write access»"
  echo
  cat "$KEY.pub"
  echo "================================================================="
  echo "بانتظار إضافة المفتاح… (Ctrl+C للإلغاء ثم أعد التشغيل لاحقاً)"
  until runuser -u mhtv -- git ls-remote "$REPO" HEAD >/dev/null 2>&1; do sleep 10; done
  echo "تم — المفتاح يعمل."
fi

# ---------------------------------------------------------------- signing key (new, stays here)
if [ ! -f "$ETC/release.jks" ]; then
  say "إنشاء مفتاح توقيع جديد على هذا الخادم"
  PASS=$(openssl rand -hex 24)
  keytool -genkeypair -noprompt -keystore "$ETC/release.jks" -storetype PKCS12 \
    -alias qanawati -keyalg RSA -keysize 4096 -validity 10950 \
    -dname "CN=Qanawati, O=MH" -storepass "$PASS" -keypass "$PASS" >/dev/null 2>&1
  CERT=$(keytool -exportcert -keystore "$ETC/release.jks" -storepass "$PASS" -alias qanawati 2>/dev/null | sha256sum | cut -d' ' -f1)
  umask 077
  cat > "$ETC/signing.env" <<EOF
KEYSTORE_PATH=$ETC/release.jks
KEYSTORE_PASSWORD=$PASS
KEY_ALIAS=qanawati
KEY_PASSWORD=$PASS
EOF
  echo "$CERT" > "$ETC/cert.sha256"
fi
chown -R mhtv:mhtv "$ETC"; chmod 700 "$ETC"; chmod 600 "$ETC"/*

# ---------------------------------------------------------------- ports + site config
port_busy() { ss -Hltn "sport = :$1" | grep -q . && ! ss -Hltnp "sport = :$1" | grep -q caddy; }
if port_busy 80; then die "المنفذ 80 مستخدم من برنامج آخر؛ Caddy يحتاجه لإصدار شهادة HTTPS. أوقف ذلك البرنامج أو انقله ثم أعد التشغيل."; fi
HTTPS_PORT=443
if port_busy 443; then HTTPS_PORT=8443; echo "المنفذ 443 مستخدم (ربما خادم VPN) — سيُستخدم 8443."; fi

if [ ! -f "$ETC/site.env" ]; then
  cat > "$ETC/site.env" <<EOF
DOMAIN=$DOMAIN
HTTPS_PORT=$HTTPS_PORT
BRANCH=$BRANCH
DL_TOKEN=$(openssl rand -hex 12)
STATUS_TOKEN=$(openssl rand -hex 12)
EOF
else
  sed -i "s/^DOMAIN=.*/DOMAIN=$DOMAIN/; s/^HTTPS_PORT=.*/HTTPS_PORT=$HTTPS_PORT/; s|^BRANCH=.*|BRANCH=$BRANCH|" "$ETC/site.env"
fi
chown mhtv:mhtv "$ETC/site.env"; chmod 600 "$ETC/site.env"
. "$ETC/site.env"

install -d -o mhtv -g mhtv "$WWW/u" "$WWW/dl/$DL_TOKEN" "$WWW/status/$STATUS_TOKEN"
echo "<!doctype html><meta charset=utf-8><title>.</title>" > "$WWW/index.html"; chown mhtv:mhtv "$WWW/index.html"

PORT_SUFFIX=""; [ "$HTTPS_PORT" = 443 ] || PORT_SUFFIX=":$HTTPS_PORT"
cat > /etc/caddy/Caddyfile <<EOF
{
	https_port $HTTPS_PORT
}

$DOMAIN$PORT_SUFFIX {
	root * $WWW
	encode gzip
	# Sealed store and status: always fresh, never cached by anyone.
	@fresh path /u/index.bin /status/*
	header @fresh Cache-Control "no-store"
	header /u/* X-Content-Type-Options nosniff
	header /dl/* X-Robots-Tag "noindex, nofollow"
	header Referrer-Policy no-referrer
	# No folder listings anywhere: only exact file names are served.
	file_server
}
EOF
systemctl enable --now caddy >/dev/null 2>&1 || true
systemctl reload caddy || systemctl restart caddy

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow 80/tcp >/dev/null; ufw allow "$HTTPS_PORT"/tcp >/dev/null
fi

# ---------------------------------------------------------------- build service
# The build script comes from the repository itself (vps/build.sh) and keeps
# itself current from there on every run.
if [ ! -d "$HOME_DIR/src/.git" ]; then
  runuser -u mhtv -- git clone -q --branch "$BRANCH" "$REPO" "$HOME_DIR/src"
fi
runuser -u mhtv -- git -C "$HOME_DIR/src" fetch -q origin "$BRANCH"
runuser -u mhtv -- git -C "$HOME_DIR/src" checkout -q -f "origin/$BRANCH"
[ -f "$HOME_DIR/src/vps/build.sh" ] || die "الفرع $BRANCH لا يحتوي vps/build.sh"
install -o mhtv -g mhtv -m 755 "$HOME_DIR/src/vps/build.sh" "$HOME_DIR/build.sh"
cat > /etc/systemd/system/mhtv-build.service <<EOF
[Unit]
Description=Qanawati: build, sign and publish new commits
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=mhtv
Group=mhtv
Nice=10
ExecStart=$HOME_DIR/build.sh
TimeoutStartSec=3h
EOF
cat > /etc/systemd/system/mhtv-build.timer <<EOF
[Unit]
Description=Qanawati: look for new commits every 10 minutes

[Timer]
OnBootSec=3min
OnUnitInactiveSec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now mhtv-build.timer >/dev/null

say "أول بناء يبدأ الآن (قد يستغرق 30–60 دقيقة في المرة الأولى)"
systemctl start --no-block mhtv-build.service

BASE="https://$DOMAIN$PORT_SUFFIX"
cat <<EOF

=================================================================
 تم الإعداد.

 رابط التحميل للتثبيت الأول (احتفظ به لنفسك):
   $BASE/dl/$DL_TOKEN/

 حالة البناء (أرسل هذا الرابط لـClaude ليتابع):
   $BASE/status/$STATUS_TOKEN/status.txt

 بصمة مفتاح التوقيع الجديد (SHA-256):
   $(cat "$ETC/cert.sha256")

 مهم جداً — انسخ مفتاح التوقيع احتياطياً خارج الخادم (مرة واحدة):
   scp root@$DOMAIN:$ETC/release.jks  root@$DOMAIN:$ETC/signing.env  .
 ضياعه يعني أن أي تحديث مستقبلي يتطلب حذف التطبيق من جديد.
=================================================================
EOF
