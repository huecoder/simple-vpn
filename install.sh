#!/bin/bash

# ============================================================
#  VPN AUTO-INSTALLER: VLESS + Reality + Telegram Bot Panel
#  Использование: curl -sSL https://raw.githubusercontent.com/USERNAME/REPO/main/install.sh | bash
# ============================================================

set -e

# ── Цвета ─────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Константы ─────────────────────────────────────────────
# ЗАМЕНИТЬ после получения tree репозитория:
GITHUB_RAW="https://raw.githubusercontent.com/huecoder/simple-vpn/main"

BOT_DIR="/opt/vpn-bot"
XRAY_CONFIG="/usr/local/etc/xray/config.json"
SERVICE_BOT="vpn-telegram-bot"

log_ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
log_info() { echo -e "${BLUE}[→]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# ── Баннер ────────────────────────────────────────────────
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════╗"
echo "║   VLESS Reality VPN + Telegram Panel     ║"
echo "║   github.com/huecoder/simple-vpn         ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"

# ── Проверки ──────────────────────────────────────────────
[[ $EUID -ne 0 ]] && log_err "Запустите от root: sudo bash или войдите как root"

# ── Запрос данных ─────────────────────────────────────────
echo ""
echo -e "${YELLOW}Для начала нужно 2 вещи:${NC}"
echo -e "  1. Токен бота — создайте бота у @BotFather в Telegram (/newbot)"
echo -e "  2. Ваш Telegram ID — узнайте у @userinfobot\n"

read -rp "Вставьте токен бота: " BOT_TOKEN
[[ -z "$BOT_TOKEN" ]] && log_err "Токен не может быть пустым"

read -rp "Вставьте ваш Telegram ID: " ADMIN_ID
[[ -z "$ADMIN_ID" ]] && log_err "ID не может быть пустым"

echo ""
log_info "Начинаем установку, это займёт 1-2 минуты..."
echo ""

# ── Зависимости ───────────────────────────────────────────
log_info "Обновление пакетов и установка зависимостей..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    curl wget unzip python3 python3-pip python3-venv \
    qrencode uuid-runtime openssl jq ufw netcat-openbsd
log_ok "Зависимости установлены"

# ── Xray ──────────────────────────────────────────────────
log_info "Установка Xray-core..."
bash <(curl -Ls https://github.com/XTLS/Xray-install/raw/main/install-release.sh) --without-geodata
log_ok "Xray установлен: $(xray version 2>/dev/null | head -1)"

# ── Ключи и параметры ─────────────────────────────────────
log_info "Генерация ключей Reality..."

# Ждём пока xray точно доступен
for i in {1..10}; do
    which xray >/dev/null 2>&1 && xray x25519 >/dev/null 2>&1 && break
    sleep 2
done

KEYS=$(xray x25519 2>/dev/null)
# Новый формат (v26+): PrivateKey / Password
# Старый формат: Private key / Public key
PRIVATE_KEY=$(echo "$KEYS" | grep -i "^PrivateKey\|^Private key" | awk '{print $NF}')
PUBLIC_KEY=$(echo "$KEYS"  | grep -i "^Password\|^Public key"    | awk '{print $NF}')

# Проверяем что ключи не пустые
if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
    log_err "Не удалось сгенерировать ключи Reality. Попробуйте: xray x25519"
fi

log_ok "Ключи сгенерированы"
log_ok "Public Key: $PUBLIC_KEY"

UUID=$(uuidgen)
SHORT_ID=$(openssl rand -hex 8)
SHORT_ID2=$(openssl rand -hex 4)
SHORT_ID3=$(openssl rand -hex 6)

# Публичный IP
PUBLIC_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || \
            curl -s --max-time 5 https://ifconfig.me  2>/dev/null || \
            curl -s --max-time 5 https://icanhazip.com 2>/dev/null)
[[ -z "$PUBLIC_IP" ]] && read -rp "Не удалось определить IP, введите вручную: " PUBLIC_IP
log_ok "IP сервера: $PUBLIC_IP"

# Порт: ищем свободный начиная с 443
VPN_PORT=443
for p in 443 8443 2053 2083 2087; do
    if ! ss -tlnp | grep -q ":${p} "; then VPN_PORT=$p; break; fi
done
log_ok "Порт: $VPN_PORT"

# ── Тест SNI ──────────────────────────────────────────────
log_info "Подбор рабочего SNI с этого сервера (~20 сек)..."

SNI_CANDIDATES=(
    "dl.delivery.mp.microsoft.com"
    "update.microsoft.com"
    "support.microsoft.com"
    "swscan.apple.com"
    "mesu.apple.com"
    "www.amazon.com"
    "aws.amazon.com"
    "speed.cloudflare.com"
)

WORKING_SNIS=()
for sni in "${SNI_CANDIDATES[@]}"; do
    echo -ne "  ${sni}... "
    if nc -z -w 3 "$sni" 443 2>/dev/null && \
       timeout 3 bash -c "echo | openssl s_client -connect ${sni}:443 -servername ${sni} 2>/dev/null" | grep -q "CONNECTED"; then
        echo -e "${GREEN}✓${NC}"
        WORKING_SNIS+=("$sni")
    else
        echo -e "${RED}✗${NC}"
    fi
done

if [[ ${#WORKING_SNIS[@]} -gt 0 ]]; then
    CHOSEN_SNI="${WORKING_SNIS[0]}"
    SNI_JSON=$(printf '"%s",' "${WORKING_SNIS[@]:0:5}" | sed 's/,$//')
    FINGERPRINT="chrome"
    log_ok "SNI: $CHOSEN_SNI"
else
    log_warn "Рабочих SNI не найдено — используем пустой SNI"
    CHOSEN_SNI=""
    SNI_JSON=""
    FINGERPRINT=""
fi

DEST="${CHOSEN_SNI:-www.microsoft.com}:443"

# ── Конфиг Xray ───────────────────────────────────────────
log_info "Настройка Xray..."
mkdir -p /usr/local/etc/xray /var/log/xray

cat > "$XRAY_CONFIG" <<EOF
{
  "log": { "loglevel": "warning", "access": "/var/log/xray/access.log", "error": "/var/log/xray/error.log" },
  "stats": {},
  "api": { "tag": "api", "services": ["StatsService"] },
  "policy": {
    "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } },
    "system": { "statsInboundUplink": true, "statsInboundDownlink": true }
  },
  "inbounds": [
    {
      "tag": "vless-in",
      "port": ${VPN_PORT},
      "protocol": "vless",
      "settings": { "clients": [], "decryption": "none" },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${DEST}",
          "xver": 0,
          "serverNames": [${SNI_JSON}],
          "privateKey": "${PRIVATE_KEY}",
          "shortIds": ["${SHORT_ID}", "${SHORT_ID2}", "${SHORT_ID3}"]
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
    },
    {
      "listen": "127.0.0.1", "port": 62789,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" },
      "tag": "api"
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct", "settings": { "domainStrategy": "UseIPv4" } },
    { "protocol": "blackhole", "tag": "block" }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "inboundTag": ["api"], "outboundTag": "api" },
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "block" }
    ]
  }
}
EOF
log_ok "Конфиг Xray создан"

# ── Файрвол ───────────────────────────────────────────────
log_info "Настройка файрвола..."
ufw allow ssh        >/dev/null 2>&1 || true
ufw allow "${VPN_PORT}/tcp" >/dev/null 2>&1 || true
ufw --force enable   >/dev/null 2>&1 || true
log_ok "Файрвол настроен (открыт порт $VPN_PORT)"

# ── Запуск Xray ───────────────────────────────────────────
log_info "Запуск Xray..."
systemctl daemon-reload
systemctl enable xray >/dev/null 2>&1
systemctl restart xray
sleep 2
systemctl is-active --quiet xray && log_ok "Xray запущен" || {
    echo ""
    log_err "Xray не запустился. Лог: journalctl -u xray -n 30"
}

# ── Telegram-бот ──────────────────────────────────────────
log_info "Установка Telegram-бота..."
mkdir -p "$BOT_DIR"

# Скачиваем bot.py с GitHub
curl -sSL "${GITHUB_RAW}/bot.py" -o "$BOT_DIR/bot.py"
log_ok "bot.py скачан"

# Python venv + зависимости
python3 -m venv "$BOT_DIR/venv"
"$BOT_DIR/venv/bin/pip" install --quiet python-telegram-bot qrcode pillow
log_ok "Python-зависимости установлены"

# Генерируем VLESS-ссылку
VLESS_PARAMS="encryption=none&flow=xtls-rprx-vision&security=reality&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none"
[[ -n "$CHOSEN_SNI" ]] && VLESS_PARAMS+="&sni=${CHOSEN_SNI}"
[[ -n "$FINGERPRINT" ]] && VLESS_PARAMS+="&fp=${FINGERPRINT}"
VLESS_LINK="vless://${UUID}@${PUBLIC_IP}:${VPN_PORT}?${VLESS_PARAMS}#VPN-Server"

# Сохраняем конфиг для бота
cat > "$BOT_DIR/vpn_config.json" <<EOF
{
  "uuid": "${UUID}",
  "public_ip": "${PUBLIC_IP}",
  "port": ${VPN_PORT},
  "private_key": "${PRIVATE_KEY}",
  "public_key": "${PUBLIC_KEY}",
  "short_id": "${SHORT_ID}",
  "chosen_sni": "${CHOSEN_SNI}",
  "dest": "${DEST}",
  "fingerprint": "${FINGERPRINT}",
  "working_snis": $(printf '%s\n' "${WORKING_SNIS[@]:-}" | jq -R . | jq -s . 2>/dev/null || echo '[]'),
  "vless_link": "${VLESS_LINK}"
}
EOF

# .env для бота
cat > "$BOT_DIR/.env" <<EOF
BOT_TOKEN=${BOT_TOKEN}
ADMIN_IDS=${ADMIN_ID}
EOF
chmod 600 "$BOT_DIR/.env"

# Клиенты (пустой файл)
echo '{"clients": []}' > "$BOT_DIR/clients.json"

# Systemd сервис
cat > "/etc/systemd/system/${SERVICE_BOT}.service" <<EOF
[Unit]
Description=VPN Telegram Bot Panel
After=network.target xray.service

[Service]
Type=simple
WorkingDirectory=${BOT_DIR}
EnvironmentFile=${BOT_DIR}/.env
ExecStart=${BOT_DIR}/venv/bin/python3 ${BOT_DIR}/bot.py
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_BOT" >/dev/null 2>&1
systemctl restart "$SERVICE_BOT"
sleep 2

systemctl is-active --quiet "$SERVICE_BOT" && log_ok "Telegram-бот запущен" || \
    log_warn "Бот не стартовал — проверьте токен: journalctl -u $SERVICE_BOT -n 20"

# ── Итог ──────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           УСТАНОВКА ЗАВЕРШЕНА!                   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}📡 Сервер:${NC} ${PUBLIC_IP}:${VPN_PORT}"
echo -e "${YELLOW}🌐 SNI:${NC}    ${CHOSEN_SNI:-пустой}"
echo ""
echo -e "${YELLOW}🤖 Telegram-бот:${NC} найдите своего бота и напишите /start"
echo ""
echo -e "${YELLOW}🔗 VLESS-ссылка:${NC}"
echo -e "${CYAN}${VLESS_LINK}${NC}"
echo ""
if command -v qrencode &>/dev/null; then
    echo -e "${YELLOW}📷 QR-код:${NC}"
    qrencode -t ANSIUTF8 "$VLESS_LINK"
fi
echo ""
echo -e "${BLUE}Управление:${NC}"
echo -e "  systemctl status xray               — статус VPN"
echo -e "  systemctl status ${SERVICE_BOT}  — статус бота"
echo -e "  journalctl -u xray -f               — логи VPN"
