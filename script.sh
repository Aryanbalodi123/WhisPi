#!/bin/bash
set -e

echo "🕊️ WhisPi Setup - Raspberry Pi Secure Offline Chat"
echo "⚠️  Configures Pi as WiFi hotspot with offline access"
echo ""

if [[ $EUID -eq 0 ]]; then
    echo "❌ Run as regular user, not root"
    exit 1
fi

check_internet() {
    ping -c 1 8.8.8.8 >/dev/null 2>&1
}

check_requirements() {
    if [ ! -f "requirements.txt" ]; then
        echo "❌ requirements.txt not found"
        exit 1
    fi
}

validate_wifi_name() {
    local name="$1"
    [[ ${#name} -ge 1 && ${#name} -le 32 && ! "$name" =~ [[:space:]] ]]
}

validate_wifi_password() {
    local pass="$1"
    [[ ${#pass} -ge 8 && ${#pass} -le 63 ]]
}

validate_domain() {
    local domain="$1"
    [[ ${#domain} -ge 1 && ${#domain} -le 63 && "$domain" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]]
}

validate_ip() {
    local ip="$1"
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi
    IFS='.' read -ra ADDR <<< "$ip"
    for i in "${ADDR[@]}"; do
        [[ $i -ge 0 && $i -le 255 ]] || return 1
    done
    [[ "${ADDR[0]}" == "192" && "${ADDR[1]}" == "168" ]] || 
    [[ "${ADDR[0]}" == "10" ]] || 
    [[ "${ADDR[0]}" == "172" && "${ADDR[1]}" -ge 16 && "${ADDR[1]}" -le 31 ]]
}

validate_pem_password() {
    local pass="$1"
    [[ ${#pass} -ge 6 ]]
}

# Configuration Phase
echo "=== Configuration ==="

while true; do
    read -p "WiFi Name [WhisPiChat]: " WIFI_NAME
    WIFI_NAME=${WIFI_NAME:-WhisPiChat}
    validate_wifi_name "$WIFI_NAME" && break
    echo "❌ Invalid WiFi name (1-32 chars, no spaces)"
done

while true; do
    read -p "WiFi Password [whispi123]: " WIFI_PASS
    WIFI_PASS=${WIFI_PASS:-whispi123}
    validate_wifi_password "$WIFI_PASS" && break
    echo "❌ Invalid password (8-63 characters)"
done

while true; do
    read -p "Domain [whispi.secure]: " SITE_URL
    SITE_URL=${SITE_URL:-whispi.secure}
    validate_domain "$SITE_URL" && break
    echo "❌ Invalid domain format"
done

while true; do
    read -p "Pi IP [192.168.4.1]: " LOCAL_IP
    LOCAL_IP=${LOCAL_IP:-192.168.4.1}
    validate_ip "$LOCAL_IP" && break
    echo "❌ Invalid IP (use private ranges)"
done

while true; do
    read -s -p "RSA Key Password: " PEM_PASS
    echo ""
    validate_pem_password "$PEM_PASS" && break
    echo "❌ Password too short (min 6 chars)"
done

check_requirements

# Package Installation
echo ""
echo "=== Package Installation ==="
if ! check_internet; then
    echo "❌ Internet required for installation"
    exit 1
fi

echo "📦 Installing system packages..."
sudo apt update -qq
sudo apt install -y hostapd dnsmasq openssl python3-flask python3-pip python3-venv \
                    nginx redis-server supervisor build-essential libssl-dev libffi-dev \
                    python3-dev pkg-config >/dev/null 2>&1

echo "🔴 Configuring Redis..."
sudo systemctl enable redis-server >/dev/null 2>&1
sudo systemctl start redis-server

echo "🐍 Setting up Python environment..."
VENV_PATH="$HOME/envs/whispi"
mkdir -p "$HOME/envs"
python3 -m venv "$VENV_PATH"
source "$VENV_PATH/bin/activate"

pip install --upgrade pip wheel >/dev/null 2>&1

echo "📦 Installing Python packages..."
pip install --index-url https://www.piwheels.org/simple/ \
            --extra-index-url https://pypi.org/simple/ \
            --prefer-binary -r requirements.txt >/dev/null 2>&1 || \
pip install --prefer-binary -r requirements.txt >/dev/null 2>&1 || \
pip install -r requirements.txt >/dev/null 2>&1

echo "source $VENV_PATH/bin/activate" > activate_whispi.sh
chmod +x activate_whispi.sh

# Security Setup
echo ""
echo "=== Security Setup ==="
mkdir -p certs

echo "🔐 Generating HTTPS certificate..."
openssl req -newkey rsa:2048 -x509 -sha256 -days 365 -nodes \
    -keyout certs/$SITE_URL-key.pem -out certs/$SITE_URL.pem \
    -subj "/C=IN/ST=Punjab/L=Ludhiana/O=WhisPi/CN=$SITE_URL" >/dev/null 2>&1

echo "🔐 Generating encrypted RSA keypair..."
openssl genrsa -out certs/temp_private.pem 2048 >/dev/null 2>&1
openssl rsa -in certs/temp_private.pem -out certs/rsa_private.pem -aes256 -passout pass:$PEM_PASS >/dev/null 2>&1
openssl rsa -in certs/temp_private.pem -pubout -out certs/rsa_public.pem >/dev/null 2>&1

rm certs/temp_private.pem

chmod 600 certs/*.pem certs/*-key.pem
chmod 644 certs/rsa_public.pem

# Environment Configuration
echo ""
echo "=== Environment Setup ==="
cat > .env << EOF
SECRET_KEY=whispi-$(openssl rand -hex 32)
DEBUG=False
HOST=127.0.0.1
PORT=8000

SSL_CERT_PATH=$(pwd)/certs/$SITE_URL.pem
SSL_KEY_PATH=$(pwd)/certs/$SITE_URL-key.pem

PRIVATE_KEY_PATH=$(pwd)/certs/rsa_private.pem
PUBLIC_KEY_PATH=$(pwd)/certs/rsa_public.pem
PRIVATE_KEY_PASSWORD=$PEM_PASS

REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_URL=redis://localhost:6379

SESSION_TYPE=redis
SESSION_KEY_PREFIX=whispi:
SESSION_LIFETIME_HOURS=24
EOF

# Nginx Configuration
echo ""
echo "=== Web Server Setup ==="
sudo rm -f /etc/nginx/sites-enabled/default

sudo bash -c "cat > /etc/nginx/sites-available/whispi << EOF
server {
    listen 80;
    server_name $SITE_URL;
    return 301 https://\\\$host\\\$request_uri;
}

server {
    listen 443 ssl;
    server_name $SITE_URL;
    ssl_certificate $(pwd)/certs/$SITE_URL.pem;
    ssl_certificate_key $(pwd)/certs/$SITE_URL-key.pem;
    
    location /static/ {
        alias $(pwd)/static/;
        expires 1y;
        access_log off;
    }
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        include proxy_params;
        proxy_redirect off;
    }
}
EOF"

sudo ln -sf /etc/nginx/sites-available/whispi /etc/nginx/sites-enabled/
sudo nginx -t >/dev/null 2>&1

# Gunicorn Configuration
mkdir -p config
cat > config/gunicorn.py << EOF
import multiprocessing

bind = "127.0.0.1:8000"
workers = min(4, multiprocessing.cpu_count() * 2 + 1)
worker_class = "sync"
timeout = 30
keepalive = 2
max_requests = 1000
max_requests_jitter = 100
accesslog = "/var/log/whispi/access.log"
errorlog = "/var/log/whispi/error.log"
loglevel = "info"
proc_name = "whispi"
preload_app = True
EOF

sudo mkdir -p /var/log/whispi
sudo chown $USER:$USER /var/log/whispi

# Supervisor Configuration
sudo bash -c "cat > /etc/supervisor/conf.d/whispi.conf << EOF
[program:whispi]
command=$VENV_PATH/bin/gunicorn -c $(pwd)/config/gunicorn.py main:app
directory=$(pwd)
user=$USER
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/whispi/supervisor.log
stdout_logfile_maxbytes=10MB
stdout_logfile_backups=5
environment=PATH=\"$VENV_PATH/bin\"
EOF"

# Network Configuration
echo ""
echo "=== Network Setup ==="

echo "💾 Backing up configurations..."
sudo cp /etc/dhcpcd.conf /etc/dhcpcd.conf.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true

echo "🛠️ Configuring network interfaces..."
sudo bash -c "cat >> /etc/dhcpcd.conf << EOF

# WhisPi Hotspot Configuration
interface wlan0
    static ip_address=$LOCAL_IP/24
    nohook wpa_supplicant
EOF"

sudo bash -c "cat > /etc/dnsmasq.conf << EOF
interface=wlan0
dhcp-range=${LOCAL_IP%.*}.10,${LOCAL_IP%.*}.50,255.255.255.0,24h
address=/$SITE_URL/$LOCAL_IP
address=/www.$SITE_URL/$LOCAL_IP
no-resolv
no-poll
EOF"

sudo bash -c "cat > /etc/hostapd/hostapd.conf << EOF
interface=wlan0
ssid=$WIFI_NAME
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=$WIFI_PASS
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOF"

sudo sed -i 's|#DAEMON_CONF=""|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd

# Service Management Scripts
echo ""
echo "=== Creating Management Scripts ==="

cat > 01_start_services.sh << 'EOF'
#!/bin/bash
echo "🚀 Starting WhisPi services..."
sudo systemctl start redis-server nginx supervisor >/dev/null 2>&1
sudo supervisorctl reread >/dev/null 2>&1
sudo supervisorctl update >/dev/null 2>&1
sudo supervisorctl start whispi >/dev/null 2>&1
echo "✅ Services started"
EOF
chmod +x 01_start_services.sh

cat > 02_stop_services.sh << 'EOF'
#!/bin/bash
echo "🛑 Stopping WhisPi services..."
sudo supervisorctl stop whispi >/dev/null 2>&1
sudo systemctl stop nginx supervisor >/dev/null 2>&1
echo "✅ Services stopped"
EOF
chmod +x 02_stop_services.sh

cat > 03_enable_hotspot.sh << EOF
#!/bin/bash
echo "🚀 Enabling hotspot mode..."
read -p "This will disable internet. Continue? (y/N): " -n 1 -r
echo
if [[ \$REPLY =~ ^[Yy]\$ ]]; then
    echo "🔧 Configuring hotspot..."
    sudo systemctl disable wpa_supplicant >/dev/null 2>&1
    
    # Uncomment hotspot config in dhcpcd.conf
    sudo sed -i '/# WhisPi Hotspot Configuration/,/nohook wpa_supplicant/ s/^#//' /etc/dhcpcd.conf
    
    sudo systemctl enable hostapd dnsmasq >/dev/null 2>&1
    sudo systemctl restart dhcpcd >/dev/null 2>&1
    sleep 2
    sudo systemctl start hostapd dnsmasq >/dev/null 2>&1
    
    ./01_start_services.sh
    
    echo ""
    echo "✅ Hotspot enabled!"
    echo "📶 Network: $WIFI_NAME"
    echo "🔑 Password: $WIFI_PASS" 
    echo "🌐 URL: https://$SITE_URL"
    echo "📱 IP: https://$LOCAL_IP"
    echo ""
    echo "ℹ️  Reboot recommended for full activation"
else
    echo "❌ Cancelled"
fi
EOF
chmod +x 03_enable_hotspot.sh

cat > 04_restore_wifi.sh << 'EOF'
#!/bin/bash
echo "🔄 Restoring WiFi mode..."

./02_stop_services.sh

sudo systemctl disable hostapd dnsmasq >/dev/null 2>&1
sudo systemctl stop hostapd dnsmasq >/dev/null 2>&1

# Comment out hotspot config in dhcpcd.conf
sudo sed -i '/# WhisPi Hotspot Configuration/,/nohook wpa_supplicant/ s/^/#/' /etc/dhcpcd.conf

sudo systemctl restart dhcpcd >/dev/null 2>&1
sudo systemctl restart wpa_supplicant >/dev/null 2>&1

echo "✅ WiFi restored"
echo "ℹ️  Reboot recommended"
echo "ℹ️  Configure WiFi: sudo raspi-config"
EOF
chmod +x 04_restore_wifi.sh

cat > 05_development_mode.sh << EOF
#!/bin/bash
echo "🧪 Starting development mode..."
source $VENV_PATH/bin/activate
export DEBUG=True
export HOST=0.0.0.0
export PORT=5000
python3 main.py
EOF
chmod +x 05_development_mode.sh

# Service Configuration
echo "🧪 Configuring services..."
sudo systemctl unmask hostapd >/dev/null 2>&1
sudo systemctl enable nginx supervisor redis-server >/dev/null 2>&1
sudo systemctl daemon-reload

# Configuration Summary
cat > whispi_config.txt << EOF
WhisPi Configuration
====================
WiFi Network: $WIFI_NAME
WiFi Password: $WIFI_PASS  
Domain: $SITE_URL
Pi IP: $LOCAL_IP

Files Generated:
- Certificates: ./certs/
- Environment: .env
- Gunicorn config: config/gunicorn.py
- Virtual environment: $HOME/envs/whispi/

Management Scripts:
- ./03_enable_hotspot.sh    (enable hotspot mode)
- ./04_restore_wifi.sh      (restore normal WiFi)
- ./01_start_services.sh    (start WhisPi services)
- ./02_stop_services.sh     (stop WhisPi services)
- ./05_development_mode.sh  (run in development)

Commands:
- Check status: sudo supervisorctl status whispi
- Restart app: sudo supervisorctl restart whispi
- View logs: tail -f /var/log/whispi/supervisor.log

Architecture:
- Nginx (443) → Gunicorn (8000) → Flask App
- Redis for sessions and caching
- Supervisor for process management
EOF

echo ""
echo "🎉 WhisPi setup completed!"
echo ""
echo "📋 Next Steps:"
echo "1️⃣  Run: ./03_enable_hotspot.sh"
echo "2️⃣  Connect to WiFi: $WIFI_NAME"
echo "3️⃣  Visit: https://$SITE_URL"
echo "4️⃣  Accept SSL certificate"
echo ""
echo "🔧 Management:"
echo "• View config: cat whispi_config.txt"
echo "• Restore WiFi: ./04_restore_wifi.sh"
echo "• Development: ./05_development_mode.sh"