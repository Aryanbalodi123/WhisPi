#!/bin/bash
set -e

echo "🕊️ WhisPi Full Setup Script - Raspberry Pi Secure Offline Chat"
echo "⚠️  This script will configure your Pi as a WiFi hotspot and disable internet access"
echo "📋 Setup will be done in phases to prevent system freezing"
echo "🆕 Updated with Nginx and Supervisor support"
echo ""

if [[ $EUID -eq 0 ]]; then
   echo "❌ This script should not be run as root. Please run as regular user."
   exit 1
fi

check_internet() {
    ping -c 1 8.8.8.8 >/dev/null 2>&1
}

check_requirements() {
    if [ ! -f "requirements.txt" ]; then
        echo "❌ requirements.txt not found in current directory!"
        echo "Please make sure requirements.txt is present before running this script."
        exit 1
    else
        echo "✅ Found existing requirements.txt file"
        echo "📦 Packages to be installed:"
        cat requirements.txt | grep -v '^#' | grep -v '^$' | sed 's/^/   • /'
    fi
}

validate_wifi_name() {
    local name="$1"
    if [[ ${#name} -lt 1 || ${#name} -gt 32 ]]; then
        echo "❌ WiFi name must be 1-32 characters long"
        return 1
    fi
    if [[ "$name" =~ [[:space:]] ]]; then
        echo "❌ WiFi name cannot contain spaces"
        return 1
    fi
    if [[ "$name" =~ [^[:print:]] ]]; then
        echo "❌ WiFi name contains invalid characters"
        return 1
    fi
    return 0
}

validate_wifi_password() {
    local pass="$1"
    if [[ ${#pass} -lt 8 || ${#pass} -gt 63 ]]; then
        echo "❌ WiFi password must be 8-63 characters long"
        return 1
    fi
    if [[ "$pass" =~ [^[:print:]] ]]; then
        echo "❌ WiFi password contains invalid characters"
        return 1
    fi
    return 0
}

validate_domain() {
    local domain="$1"
    if [[ ${#domain} -lt 1 || ${#domain} -gt 63 ]]; then
        echo "❌ Domain name must be 1-63 characters long"
        return 1
    fi
    if [[ ! "$domain" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$ ]]; then
        echo "❌ Domain name can only contain lowercase letters, numbers, dots, and hyphens"
        echo "❌ Cannot start or end with hyphen, cannot have consecutive dots"
        return 1
    fi
    return 0
}

validate_ip() {
    local ip="$1"
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "❌ IP address must be in format xxx.xxx.xxx.xxx"
        return 1
    fi
    
    IFS='.' read -ra ADDR <<< "$ip"
    for i in "${ADDR[@]}"; do
        if [[ $i -lt 0 || $i -gt 255 ]]; then
            echo "❌ Each IP octet must be between 0-255"
            return 1
        fi
    done
    
    if [[ "${ADDR[0]}" == "192" && "${ADDR[1]}" == "168" ]]; then
        return 0
    elif [[ "${ADDR[0]}" == "10" ]]; then
        return 0
    elif [[ "${ADDR[0]}" == "172" && "${ADDR[1]}" -ge 16 && "${ADDR[1]}" -le 31 ]]; then
        return 0
    else
        echo "❌ IP must be in private range (192.168.x.x, 10.x.x.x, or 172.16-31.x.x)"
        return 1
    fi
}

validate_pem_password() {
    local pass="$1"
    if [[ ${#pass} -lt 6 ]]; then
        echo "❌ PEM password must be at least 6 characters long"
        return 1
    fi
    if [[ "$pass" =~ [^[:print:]] ]]; then
        echo "❌ PEM password contains invalid characters"
        return 1
    fi
    return 0
}

echo "=== PHASE 1: Configuration ==="

while true; do
    read -p "📶 Wi-Fi Hotspot Name [WhisPiChat]: " WIFI_NAME
    WIFI_NAME=${WIFI_NAME:-WhisPiChat}
    if validate_wifi_name "$WIFI_NAME"; then
        break
    fi
done

while true; do
    read -p "🔑 Wi-Fi Password [whispi123]: " WIFI_PASS
    WIFI_PASS=${WIFI_PASS:-whispi123}
    if validate_wifi_password "$WIFI_PASS"; then
        break
    fi
done

while true; do
    read -p "🌐 Local site domain [whispi.secure]: " SITE_URL
    SITE_URL=${SITE_URL:-whispi.secure}
    if validate_domain "$SITE_URL"; then
        break
    fi
done

while true; do
    read -p "📡 Local IP for Pi [192.168.4.1]: " LOCAL_IP
    LOCAL_IP=${LOCAL_IP:-192.168.4.1}
    if validate_ip "$LOCAL_IP"; then
        break
    fi
done

while true; do
    read -s -p "🔐 Password to protect PEM files (RSA + TLS): " PEM_PASS
    echo ""
    if validate_pem_password "$PEM_PASS"; then
        break
    fi
done

check_requirements

echo ""
echo "=== PHASE 2: System Updates & Package Installation ==="
if check_internet; then
    echo "🌐 Internet connection detected. Installing packages..."
    
    echo "📦 Updating package lists..."
    sudo apt update
    
    echo "📦 Installing system packages..."
    sudo apt install -y hostapd dnsmasq openssl python3-flask python3-pip python3-venv \
                        nginx supervisor
    
    echo "🔧 Installing development dependencies for Python package compilation..."
    sudo apt install -y build-essential libssl-dev libffi-dev python3-dev pkg-config
    echo "✅ Development tools ready for building Python packages"
    
    echo "🐍 Creating Python virtual environment..."
    VENV_PATH="$HOME/envs/whispi"
    mkdir -p "$HOME/envs"
    python3 -m venv "$VENV_PATH"
    source "$VENV_PATH/bin/activate"
    
    echo "⚙️ Installing wheel for faster package builds..."
    pip install --upgrade wheel
    
    echo "📦 Upgrading pip for better prebuilt wheel support..."
    pip install --upgrade pip
    
    echo "🥧 Configuring piwheels for Raspberry Pi optimized packages..."
    pip install --upgrade --index-url https://www.piwheels.org/simple/ --extra-index-url https://pypi.org/simple/ wheel || {
        echo "⚠️  piwheels not available, using standard PyPI"
    }
    
    echo "🚀 Installing Python packages with prebuilt wheels priority..."
    echo "🥧 Using piwheels (Raspberry Pi optimized) + PyPI fallback..."
    
    pip install --index-url https://www.piwheels.org/simple/ \
                --extra-index-url https://pypi.org/simple/ \
                --only-binary=cryptography,bcrypt,cffi,pycparser,lxml \
                --prefer-binary \
                -r requirements.txt || {
        echo "⚠️  Some packages not available as prebuilt wheels from piwheels..."
        echo "🔄 Trying standard PyPI with binary preference..."
        pip install --only-binary=cryptography,bcrypt,cffi,pycparser \
                    --prefer-binary \
                    --no-cache-dir \
                    -r requirements.txt || {
            echo "⚠️  Falling back to source build (this will take longer)..."
            echo "⏳ Building packages from source - please wait..."
            pip install -r requirements.txt
        }
    }
    
    echo "source $VENV_PATH/bin/activate" > activate_whispi.sh
    chmod +x activate_whispi.sh
    
    echo "✅ All packages installed successfully!"
else
    echo "❌ No internet connection. Cannot install packages."
    echo "Please connect to internet and run this script again."
    exit 1
fi

echo ""
echo "=== PHASE 3: Security Setup ==="
echo "🔐 Creating certificates directory..."
mkdir -p certs

echo "🔐 Generating HTTPS certificate for $SITE_URL..."
openssl req -newkey rsa:2048 -x509 -sha256 -days 365 -nodes \
    -keyout certs/$SITE_URL-key.pem -out certs/$SITE_URL.pem \
    -subj "/C=IN/ST=Punjab/L=Ludhiana/O=WhisPi/CN=$SITE_URL"

echo "🔐 Generating RSA key pair for messaging encryption..."
openssl genrsa -out certs/rsa_private_raw.pem 2048
openssl rsa -in certs/rsa_private_raw.pem -out certs/rsa_private.pem -aes256 -passout pass:$PEM_PASS
openssl rsa -in certs/rsa_private_raw.pem -pubout -out certs/rsa_public.pem

openssl rsa -in certs/rsa_private.pem -out certs/private.pem -passin pass:$PEM_PASS
cp certs/rsa_public.pem certs/public.pem

rm certs/rsa_private_raw.pem

chmod 600 certs/*.pem certs/*-key.pem
chmod 644 certs/rsa_public.pem certs/public.pem

echo "✅ Security certificates generated!"

echo ""
echo "=== PHASE 4: Environment Configuration ==="
echo "📝 Creating .env file..."
cat > .env << EOF
SECRET_KEY=whispi-$(openssl rand -hex 32)
DEBUG=False
HOST=127.0.0.1
PORT=8000

SSL_CERT_PATH=$(pwd)/certs/$SITE_URL.pem
SSL_KEY_PATH=$(pwd)/certs/$SITE_URL-key.pem

PRIVATE_KEY_PATH=$(pwd)/certs/private.pem
PUBLIC_KEY_PATH=$(pwd)/certs/public.pem
PRIVATE_KEY_PASSWORD=$PEM_PASS

SESSION_FILE_DIR=/tmp/flask_session
EOF

echo "✅ Environment configuration created!"

echo ""
echo "=== PHASE 5: Nginx Configuration ==="
echo "🌐 Configuring Nginx..."

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
sudo nginx -t || {
    echo "❌ Nginx configuration test failed!"
    exit 1
}

echo "✅ Nginx configured successfully!"

echo ""
echo "=== PHASE 6: Gunicorn Configuration ==="
echo "🦄 Creating Gunicorn configuration..."

mkdir -p config
cat > config/gunicorn.py << EOF
import multiprocessing
import os

bind = "127.0.0.1:8000"
backlog = 2048

workers = min(4, multiprocessing.cpu_count() * 2 + 1)
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2

max_requests = 1000
max_requests_jitter = 100

accesslog = "/var/log/whispi/access.log"
errorlog = "/var/log/whispi/error.log"
loglevel = "info"

proc_name = "whispi"
preload_app = True

limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190
EOF

sudo mkdir -p /var/log/whispi
sudo chown $USER:$USER /var/log/whispi

echo "✅ Gunicorn configured successfully!"

echo ""
echo "=== PHASE 7: Supervisor Configuration ==="
echo "👁️ Creating Supervisor configuration..."

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

echo "✅ Supervisor configured successfully!"

echo ""
echo "=== PHASE 8: Network Configuration ==="

echo "💾 Backing up original network configurations..."
sudo cp /etc/dhcpcd.conf /etc/dhcpcd.conf.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
sudo cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true

echo "🛠️ Configuring static IP on wlan0..."
sudo bash -c "cat >> /etc/dhcpcd.conf << EOF

interface wlan0
    static ip_address=$LOCAL_IP/24
    nohook wpa_supplicant
EOF"

echo "⚙️ Configuring dnsmasq..."
sudo bash -c "cat > /etc/dnsmasq.conf << EOF
interface=wlan0
dhcp-range=${LOCAL_IP%.*}.10,${LOCAL_IP%.*}.50,255.255.255.0,24h
address=/$SITE_URL/$LOCAL_IP
address=/www.$SITE_URL/$LOCAL_IP
no-resolv
no-poll
EOF"

echo "📶 Configuring hostapd..."
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

echo "✅ Network configuration complete!"

echo ""
echo "=== PHASE 9: Service Configuration ==="

echo "📝 Creating WhisPi stack startup script..."
cat > 01_start_whispi_services.sh << 'EOF'
#!/bin/bash
echo "🚀 Starting WhisPi services..."

sudo systemctl start nginx
sudo systemctl start supervisor

sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start whispi

echo "✅ WhisPi services started!"
echo "📊 Status:"
sudo supervisorctl status whispi
EOF
chmod +x 01_start_whispi_services.sh

cat > 02_stop_whispi_services.sh << 'EOF'
#!/bin/bash
echo "🛑 Stopping WhisPi services..."

sudo supervisorctl stop whispi
sudo systemctl stop nginx
sudo systemctl stop supervisor

echo "✅ WhisPi services stopped!"
EOF
chmod +x 02_stop_whispi_services.sh

echo "🧪 Configuring services..."
sudo systemctl unmask hostapd
sudo systemctl enable hostapd
sudo systemctl enable dnsmasq
sudo systemctl enable nginx
sudo systemctl enable supervisor
sudo systemctl daemon-reload

echo "✅ Services configured!"

echo ""
echo "=== PHASE 10: Final Setup ==="

echo "🛠️ Creating recovery script..."
cat > 04_restore_normal_wifi.sh << 'EOF'
#!/bin/bash
echo "🔄 Restoring normal WiFi functionality..."

./02_stop_whispi_services.sh

sudo systemctl stop hostapd
sudo systemctl stop dnsmasq
sudo systemctl disable hostapd
sudo systemctl disable dnsmasq

sudo systemctl enable wpa_supplicant
sudo systemctl start wpa_supplicant

sudo cp /etc/dhcpcd.conf.backup.* /etc/dhcpcd.conf 2>/dev/null || echo "No backup found"
sudo systemctl restart dhcpcd

echo "✅ WiFi restored. You can now connect to regular WiFi networks."
EOF
chmod +x 04_restore_normal_wifi.sh

echo "🚀 Creating final activation script..."
cat > 03_activate_hotspot_mode.sh << EOF
#!/bin/bash
echo "🚀 Activating WhisPi hotspot mode..."
echo "⚠️  This will disable internet connectivity!"
read -p "Continue? (y/N): " -n 1 -r
echo
if [[ \$REPLY =~ ^[Yy]\$ ]]; then
    echo "🛑 Stopping WiFi services..."
    sudo systemctl stop wpa_supplicant.service
    sudo systemctl disable wpa_supplicant.service
    
    echo "🔄 Restarting network services..."
    sudo systemctl restart dhcpcd
    sleep 2
    
    echo "🚀 Starting hotspot services..."
    sudo systemctl start hostapd
    sudo systemctl start dnsmasq
    
    echo "🚀 Starting WhisPi services..."
    ./01_start_whispi_services.sh
    
    echo ""
    echo "✅ WhisPi hotspot activated!"
    echo "📶 WiFi Network: $WIFI_NAME"
    echo "🔑 Password: $WIFI_PASS"
    echo "🌐 Access: https://$SITE_URL"
    echo "📱 Or use IP: https://$LOCAL_IP"
    echo ""
    echo "🔍 Check status: sudo supervisorctl status whispi"
else
    echo "❌ Activation cancelled."
fi
EOF
chmod +x 03_activate_hotspot_mode.sh

cat > 05_run_development_mode.sh << EOF
#!/bin/bash
echo "🧪 Starting WhisPi in development mode..."
source $VENV_PATH/bin/activate
export DEBUG=True
export HOST=0.0.0.0
export PORT=5000
python3 main.py
EOF
chmod +x 05_run_development_mode.sh

echo "💾 Saving configuration..."
cat > whispi_config.txt << EOF
WhisPi Configuration
====================
WiFi Network: $WIFI_NAME
WiFi Password: $WIFI_PASS  
Local Domain: $SITE_URL
Pi IP Address: $LOCAL_IP
PEM Password: [PROTECTED]

Files Generated:
- certificates in ./certs/
- .env (environment variables with PEM password)
- config/gunicorn.py (Gunicorn settings)
- 01_start_whispi_services.sh (start services)
- 02_stop_whispi_services.sh (stop services)  
- 03_activate_hotspot_mode.sh (enable hotspot)
- 04_restore_normal_wifi.sh (restore WiFi)
- 05_run_development_mode.sh (development)
- $HOME/envs/whispi/ (Python virtual environment)

Management Commands:
- Enable hotspot: ./03_activate_hotspot_mode.sh
- Restore WiFi: ./04_restore_normal_wifi.sh
- Start services: ./01_start_whispi_services.sh
- Stop services: ./02_stop_whispi_services.sh
- Development: ./05_run_development_mode.sh
- Check status: sudo supervisorctl status whispi
- Restart app: sudo supervisorctl restart whispi

Architecture:
- Nginx (Port 443) → Gunicorn (Port 8000) → Flask App
- Supervisor for process management
EOF

echo ""
echo "🎉 WhisPi setup completed successfully!"
echo ""
echo "📋 NEXT STEPS:"
echo "1️⃣  Run: ./03_activate_hotspot_mode.sh (this will disable internet)"
echo "2️⃣  Connect devices to WiFi: $WIFI_NAME"
echo "3️⃣  Visit: https://$SITE_URL or https://$LOCAL_IP"
echo "4️⃣  Accept the SSL certificate warning"
echo ""
echo "🔧 MANAGEMENT:"
echo "• Restore WiFi: ./04_restore_normal_wifi.sh"
echo "• Start/stop: ./01_start_whispi_services.sh / ./02_stop_whispi_services.sh"
echo "• Development: ./05_run_development_mode.sh"
echo "• View config: cat whispi_config.txt"
echo ""
echo "⚠️  Important: PEM password is saved in .env file for application use!"