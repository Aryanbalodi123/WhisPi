#!/bin/bash
set -e  # Exit on any error

echo "🕊️ WhisPi Full Setup Script - Raspberry Pi Secure Offline Chat"
echo "⚠️  This script will configure your Pi as a WiFi hotspot and disable internet access"
echo "📋 Setup will be done in phases to prevent system freezing"
echo "🆕 Updated with Nginx, Redis, and Gunicorn support"
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "❌ This script should not be run as root. Please run as regular user."
   exit 1
fi

# Function to check if we're connected to internet
check_internet() {
    ping -c 1 8.8.8.8 >/dev/null 2>&1
}

# Function to create requirements.txt if it doesn't exist
create_requirements() {
    if [ ! -f "requirements.txt" ]; then
        echo "📄 Creating requirements.txt..."
        cat > requirements.txt << 'EOF'
# Web framework and extensions
Flask==2.3.3
Flask-Cors==4.0.0
Flask-Session==0.5.0
Flask-Limiter==3.5.0

# Environment variable support
python-dotenv==1.0.0

# Cryptography and hashing
bcrypt==4.0.1
cryptography==41.0.7

# WSGI server
gunicorn==21.2.0

# Redis support
redis==5.0.1

# Additional utilities
Werkzeug==2.3.7
requests==2.31.0
EOF
    fi
}

# --- Phase 1: Gather user inputs ---
echo "=== PHASE 1: Configuration ==="
read -p "📶 Wi-Fi Hotspot Name [WhisPiChat]: " WIFI_NAME
WIFI_NAME=${WIFI_NAME:-WhisPiChat}
read -p "🔑 Wi-Fi Password [whispi123]: " WIFI_PASS
WIFI_PASS=${WIFI_PASS:-whispi123}
read -p "🌐 Local site domain [whispi.secure]: " SITE_URL
SITE_URL=${SITE_URL:-whispi.secure}
read -p "📡 Local IP for Pi [192.168.4.1]: " LOCAL_IP
LOCAL_IP=${LOCAL_IP:-192.168.4.1}
read -s -p "🔐 Password to protect PEM files (RSA + TLS): " PEM_PASS
echo ""

# --- Phase 2: System updates and package installation (while internet is available) ---
echo ""
echo "=== PHASE 2: System Updates & Package Installation ==="
if check_internet; then
    echo "🌐 Internet connection detected. Installing packages..."
    
    # Update package lists
    echo "📦 Updating package lists..."
    sudo apt update
    
    # Install system packages including Nginx and Redis
    echo "📦 Installing system packages..."
    sudo apt install -y hostapd dnsmasq openssl python3-flask python3-pip python3-venv \
                        nginx redis-server supervisor
    
    # Start and enable Redis
    echo "🔴 Configuring Redis..."
    sudo systemctl enable redis-server
    sudo systemctl start redis-server
    
    # Create virtual environment for better package management
    echo "🐍 Creating Python virtual environment..."
    python3 -m venv whispi_env
    source whispi_env/bin/activate
    
    # Upgrade pip first
    pip install --upgrade pip
    
    # Create and install from requirements.txt
    create_requirements
    echo "📦 Installing Python packages from requirements.txt..."
    pip install -r requirements.txt
    
    # Save the activation command for later use
    echo "source $(pwd)/whispi_env/bin/activate" > activate_whispi.sh
    chmod +x activate_whispi.sh
    
    echo "✅ All packages installed successfully!"
else
    echo "❌ No internet connection. Cannot install packages."
    echo "Please connect to internet and run this script again."
    exit 1
fi

# --- Phase 3: Generate certificates and keys ---
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
rm certs/rsa_private_raw.pem

# Create unencrypted keys for application use
cp certs/rsa_private_raw.pem certs/private.pem 2>/dev/null || \
openssl rsa -in certs/rsa_private.pem -out certs/private.pem -passin pass:$PEM_PASS
cp certs/rsa_public.pem certs/public.pem

# Set proper permissions
chmod 600 certs/*.pem certs/*-key.pem
chmod 644 certs/*.crt

echo "✅ Security certificates generated!"

# --- Phase 4: Create environment configuration ---
echo ""
echo "=== PHASE 4: Environment Configuration ==="
echo "📝 Creating .env file..."
cat > .env << EOF
# Flask Configuration
SECRET_KEY=whispi-$(openssl rand -hex 32)
DEBUG=False
HOST=127.0.0.1
PORT=8000

# SSL Configuration
SSL_CERT_PATH=$(pwd)/certs/$SITE_URL.pem
SSL_KEY_PATH=$(pwd)/certs/$SITE_URL-key.pem

# Encryption Keys
PRIVATE_KEY_PATH=$(pwd)/certs/private.pem
PUBLIC_KEY_PATH=$(pwd)/certs/public.pem

# Redis Configuration
REDIS_URL=redis://localhost:6379

# Session Configuration
SESSION_FILE_DIR=/tmp/flask_session
EOF

echo "✅ Environment configuration created!"

# --- Phase 5: Nginx Configuration ---
echo ""
echo "=== PHASE 5: Nginx Configuration ==="
echo "🌐 Configuring Nginx..."

# Remove default Nginx configuration
sudo rm -f /etc/nginx/sites-enabled/default

# Create WhisPi Nginx configuration
sudo bash -c "cat > /etc/nginx/sites-available/whispi << EOF
# HTTP to HTTPS redirect
server {
    listen 80;
    server_name $SITE_URL;
    return 301 https://\\\$host\\\$request_uri;
}

# HTTPS server
server {
    listen 443 ssl http2;
    server_name $SITE_URL;
    
    # SSL Configuration
    ssl_certificate $(pwd)/certs/$SITE_URL.pem;
    ssl_certificate_key $(pwd)/certs/$SITE_URL-key.pem;
    
    # SSL Security Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection \"1; mode=block\";
    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;
    
    # Proxy to Gunicorn
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \\\$host;
        proxy_set_header X-Real-IP \\\$remote_addr;
        proxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \\\$scheme;
        proxy_buffering off;
        proxy_redirect off;
        
        # WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade \\\$http_upgrade;
        proxy_set_header Connection \"upgrade\";
    }
    
    # Static files (if any)
    location /static/ {
        alias $(pwd)/app/static/;
        expires 1d;
        add_header Cache-Control \"public, immutable\";
    }
}
EOF"

# Enable the site
sudo ln -sf /etc/nginx/sites-available/whispi /etc/nginx/sites-enabled/
sudo nginx -t || {
    echo "❌ Nginx configuration test failed!"
    exit 1
}

echo "✅ Nginx configured successfully!"

# --- Phase 6: Gunicorn Configuration ---
echo ""
echo "=== PHASE 6: Gunicorn Configuration ==="
echo "🦄 Creating Gunicorn configuration..."

mkdir -p config
cat > config/gunicorn.py << EOF
# Gunicorn configuration file
import multiprocessing
import os

# Server socket
bind = "127.0.0.1:8000"
backlog = 2048

# Worker processes
workers = min(4, multiprocessing.cpu_count() * 2 + 1)
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2

# Restart workers after this many requests, to help prevent memory leaks
max_requests = 1000
max_requests_jitter = 100

# Logging
accesslog = "/var/log/whispi/access.log"
errorlog = "/var/log/whispi/error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process naming
proc_name = "whispi"

# Preload application for better performance
preload_app = True

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190
EOF

# Create log directory
sudo mkdir -p /var/log/whispi
sudo chown $USER:$USER /var/log/whispi

echo "✅ Gunicorn configured successfully!"

# --- Phase 7: Supervisor Configuration ---
echo ""
echo "=== PHASE 7: Supervisor Configuration ==="
echo "👁️ Creating Supervisor configuration..."

sudo bash -c "cat > /etc/supervisor/conf.d/whispi.conf << EOF
[program:whispi]
command=$(pwd)/whispi_env/bin/gunicorn -c $(pwd)/config/gunicorn.py main:app
directory=$(pwd)
user=$USER
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/whispi/supervisor.log
stdout_logfile_maxbytes=10MB
stdout_logfile_backups=5
environment=PATH=\"$(pwd)/whispi_env/bin\"
EOF"

echo "✅ Supervisor configured successfully!"

# --- Phase 8: Network configuration ---
echo ""
echo "=== PHASE 8: Network Configuration ==="

# Backup original configurations
echo "💾 Backing up original network configurations..."
sudo cp /etc/dhcpcd.conf /etc/dhcpcd.conf.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
sudo cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true

# Configure static IP
echo "🛠️ Configuring static IP on wlan0..."
sudo bash -c "cat >> /etc/dhcpcd.conf << EOF

# WhisPi Configuration
interface wlan0
    static ip_address=$LOCAL_IP/24
    nohook wpa_supplicant
EOF"

# Configure dnsmasq
echo "⚙️ Configuring dnsmasq..."
sudo bash -c "cat > /etc/dnsmasq.conf << EOF
# WhisPi DNS and DHCP Configuration
interface=wlan0
dhcp-range=${LOCAL_IP%.*}.10,${LOCAL_IP%.*}.50,255.255.255.0,24h
address=/$SITE_URL/$LOCAL_IP
address=/www.$SITE_URL/$LOCAL_IP
# Disable DNS forwarding to external servers
no-resolv
no-poll
EOF"

# Configure hostapd
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

# Update hostapd default configuration
sudo sed -i 's|#DAEMON_CONF=""|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd

echo "✅ Network configuration complete!"

# --- Phase 9: Service configuration ---
echo ""
echo "=== PHASE 9: Service Configuration ==="

# Create a startup script for the complete stack
echo "📝 Creating WhisPi stack startup script..."
cat > start_whispi_stack.sh << 'EOF'
#!/bin/bash
echo "🚀 Starting WhisPi stack..."

# Start Redis
sudo systemctl start redis-server

# Start Nginx
sudo systemctl start nginx

# Start Supervisor (which manages Gunicorn)
sudo systemctl start supervisor

# Reload supervisor to pick up our config
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start whispi

echo "✅ WhisPi stack started!"
echo "📊 Status:"
sudo supervisorctl status whispi
EOF
chmod +x start_whispi_stack.sh

# Create stop script
cat > stop_whispi_stack.sh << 'EOF'
#!/bin/bash
echo "🛑 Stopping WhisPi stack..."

# Stop our application
sudo supervisorctl stop whispi

# Stop services
sudo systemctl stop nginx
sudo systemctl stop supervisor

echo "✅ WhisPi stack stopped!"
EOF
chmod +x stop_whispi_stack.sh

# Enable services but don't start them yet
echo "🧪 Configuring services..."
sudo systemctl unmask hostapd
sudo systemctl enable hostapd
sudo systemctl enable dnsmasq
sudo systemctl enable nginx
sudo systemctl enable supervisor
sudo systemctl enable redis-server
sudo systemctl daemon-reload

echo "✅ Services configured!"

# --- Phase 10: Final preparations ---
echo ""
echo "=== PHASE 10: Final Setup ==="

# Create a recovery script
echo "🛠️ Creating recovery script..."
cat > restore_wifi.sh << 'EOF'
#!/bin/bash
echo "🔄 Restoring normal WiFi functionality..."

# Stop WhisPi services
./stop_whispi_stack.sh

# Stop hotspot services
sudo systemctl stop hostapd
sudo systemctl stop dnsmasq
sudo systemctl disable hostapd
sudo systemctl disable dnsmasq

# Restore WiFi
sudo systemctl enable wpa_supplicant
sudo systemctl start wpa_supplicant

# Restore network configuration
sudo cp /etc/dhcpcd.conf.backup.* /etc/dhcpcd.conf 2>/dev/null || echo "No backup found"
sudo systemctl restart dhcpcd

echo "✅ WiFi restored. You can now connect to regular WiFi networks."
EOF
chmod +x restore_wifi.sh

# Create activation script
echo "🚀 Creating final activation script..."
cat > activate_hotspot.sh << EOF
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
    
    echo "🚀 Starting WhisPi stack..."
    ./start_whispi_stack.sh
    
    echo ""
    echo "✅ WhisPi hotspot activated!"
    echo "📶 WiFi Network: $WIFI_NAME"
    echo "🔑 Password: $WIFI_PASS"
    echo "🌐 Access: https://$SITE_URL"
    echo "📱 Or use IP: https://$LOCAL_IP"
    echo ""
    echo "🔍 Check status with: sudo supervisorctl status whispi"
    echo "📜 View logs with: sudo supervisorctl tail -f whispi"
else
    echo "❌ Activation cancelled."
fi
EOF
chmod +x activate_hotspot.sh

# Create development script
cat > run_development.sh << 'EOF'
#!/bin/bash
echo "🧪 Starting WhisPi in development mode..."
source whispi_env/bin/activate
export DEBUG=True
export HOST=0.0.0.0
export PORT=5000
python3 main.py
EOF
chmod +x run_development.sh

# Save configuration for reference
echo "💾 Saving configuration..."
cat > whispi_config.txt << EOF
WhisPi Configuration (Updated)
==============================
WiFi Network: $WIFI_NAME
WiFi Password: $WIFI_PASS
Local Domain: $SITE_URL
Pi IP Address: $LOCAL_IP
PEM Password: [HIDDEN]

Architecture:
- Nginx: Reverse proxy with SSL termination
- Gunicorn: WSGI server for Python app
- Redis: Session storage and caching
- Supervisor: Process management

Generated Files:
- certificates in ./certs/
- .env (environment variables)
- config/gunicorn.py (Gunicorn settings)
- activate_hotspot.sh (start hotspot mode)
- restore_wifi.sh (restore normal WiFi)
- start_whispi_stack.sh (start all services)
- stop_whispi_stack.sh (stop all services)
- run_development.sh (development mode)
- whispi_env/ (Python virtual environment)

Management Commands:
- Activate hotspot: ./activate_hotspot.sh
- Restore WiFi: ./restore_wifi.sh
- Start stack: ./start_whispi_stack.sh
- Stop stack: ./stop_whispi_stack.sh
- Development: ./run_development.sh
- Check status: sudo supervisorctl status whispi
- View logs: sudo supervisorctl tail -f whispi
- Restart app: sudo supervisorctl restart whispi
EOF

echo ""
echo "🎉 WhisPi setup completed successfully with modern architecture!"
echo ""
echo "📋 NEXT STEPS:"
echo "1️⃣  Run: ./activate_hotspot.sh (this will disable internet)"
echo "2️⃣  Connect your devices to WiFi: $WIFI_NAME"
echo "3️⃣  Visit: https://$SITE_URL or https://$LOCAL_IP"
echo "4️⃣  Accept the SSL certificate warning"
echo ""
echo "🔧 MANAGEMENT:"
echo "• Restore normal WiFi: ./restore_wifi.sh"
echo "• Start/stop stack: ./start_whispi_stack.sh / ./stop_whispi_stack.sh"
echo "• Development mode: ./run_development.sh"
echo "• View config: cat whispi_config.txt"
echo "• Monitor: sudo supervisorctl status"
echo ""
echo "🏗️ ARCHITECTURE:"
echo "• Nginx (Port 443) → Gunicorn (Port 8000) → Flask App"
echo "• Redis for sessions and rate limiting"
echo "• Supervisor for process management"
echo ""
echo "⚠️  Important: Keep the PEM password safe - it's needed for encrypted keys!"