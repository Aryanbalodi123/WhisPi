#!/bin/bash
set -e  # Exit on any error

echo "🕊️ WhisPi Full Setup Script - Raspberry Pi Secure Offline Chat"
echo "⚠️  This script will configure your Pi as a WiFi hotspot and disable internet access"
echo "📋 Setup will be done in phases to prevent system freezing"
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
flask==2.3.3
flask-cors==4.0.0
flask-session==0.5.0
flask-limiter==3.5.0
cryptography==41.0.7
requests==2.31.0
Werkzeug==2.3.7
EOF
    fi
}

# --- Phase 1: Gather user inputs ---
echo "=== PHASE 1: Configuration ==="
read -p "📶 Wi-Fi Hotspot Name [WhisPiChat]: " WIFI_NAME
WIFI_NAME=${WIFI_NAME:-WhisPiChat}
read -p "🔑 Wi-Fi Password [whispi123]: " WIFI_PASS
WIFI_PASS=${WIFI_PASS:-whispi123}
read -p "🌐 Local site domain [whispi.local]: " SITE_URL
SITE_URL=${SITE_URL:-whispi.local}
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
    
    # Install system packages
    echo "📦 Installing system packages..."
    sudo apt install -y hostapd dnsmasq openssl python3-flask python3-pip python3-venv
    
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

echo "🔐 Generating HTTPS certificate..."
openssl req -newkey rsa:2048 -x509 -sha256 -days 365 -nodes \
    -keyout certs/server.key -out certs/server.crt \
    -subj "/C=IN/ST=None/L=Offline/O=WhisPi/CN=$SITE_URL"

# Encrypt the HTTPS key
openssl rsa -in certs/server.key -out certs/server.pem -aes256 -passout pass:$PEM_PASS

echo "🔐 Generating RSA key pair for messaging encryption..."
openssl genrsa -out certs/rsa_private_raw.pem 2048
openssl rsa -in certs/rsa_private_raw.pem -out certs/rsa_private.pem -aes256 -passout pass:$PEM_PASS
openssl rsa -in certs/rsa_private_raw.pem -pubout -out certs/rsa_public.pem
rm certs/rsa_private_raw.pem

# Set proper permissions
chmod 600 certs/*.pem certs/*.key
chmod 644 certs/*.crt

echo "✅ Security certificates generated!"

# --- Phase 4: Network configuration ---
echo ""
echo "=== PHASE 4: Network Configuration ==="

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

# --- Phase 5: Service configuration ---
echo ""
echo "=== PHASE 5: Service Configuration ==="

# Create a startup script for the Flask server
echo "📝 Creating Flask server startup script..."
cat > start_whispi_server.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source whispi_env/bin/activate
export FLASK_APP=app.py
export FLASK_ENV=production
python3 app.py
EOF
chmod +x start_whispi_server.sh

# Create systemd service for WhisPi
echo "🔧 Creating WhisPi systemd service..."
sudo bash -c "cat > /etc/systemd/system/whispi.service << EOF
[Unit]
Description=WhisPi Secure Chat Server
After=network.target
Wants=hostapd.service dnsmasq.service

[Service]
Type=simple
User=pi
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/start_whispi_server.sh
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF"

# Enable services but don't start them yet
echo "🧪 Configuring services..."
sudo systemctl unmask hostapd
sudo systemctl enable hostapd
sudo systemctl enable dnsmasq
sudo systemctl enable whispi
sudo systemctl daemon-reload

echo "✅ Services configured!"

# --- Phase 6: Final preparations ---
echo ""
echo "=== PHASE 6: Final Setup ==="

# Create a recovery script
echo "🛠️ Creating recovery script..."
cat > restore_wifi.sh << 'EOF'
#!/bin/bash
echo "🔄 Restoring normal WiFi functionality..."
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
chmod +x restore_wifi.sh

# Create activation script
echo "🚀 Creating final activation script..."
cat > activate_hotspot.sh << 'EOF'
#!/bin/bash
echo "🚀 Activating WhisPi hotspot mode..."
echo "⚠️  This will disable internet connectivity!"
read -p "Continue? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🛑 Stopping WiFi services..."
    sudo systemctl stop wpa_supplicant.service
    sudo systemctl disable wpa_supplicant.service
    
    echo "🔄 Restarting network services..."
    sudo systemctl restart dhcpcd
    sleep 2
    
    echo "🚀 Starting hotspot services..."
    sudo systemctl start hostapd
    sudo systemctl start dnsmasq
    sudo systemctl start whispi
    
    echo ""
    echo "✅ WhisPi hotspot activated!"
    echo "📶 WiFi Network: $WIFI_NAME"
    echo "🔑 Password: $WIFI_PASS"
    echo "🌐 Access: https://$SITE_URL"
    echo "📱 Or use IP: https://$LOCAL_IP"
else
    echo "❌ Activation cancelled."
fi
EOF
chmod +x activate_hotspot.sh

# Save configuration for reference
echo "💾 Saving configuration..."
cat > whispi_config.txt << EOF
WhisPi Configuration
====================
WiFi Network: $WIFI_NAME
WiFi Password: $WIFI_PASS
Local Domain: $SITE_URL
Pi IP Address: $LOCAL_IP
PEM Password: [HIDDEN]

Generated Files:
- certificates in ./certs/
- activate_hotspot.sh (start hotspot mode)
- restore_wifi.sh (restore normal WiFi)
- start_whispi_server.sh (start Flask server)
- whispi_env/ (Python virtual environment)

To activate hotspot: ./activate_hotspot.sh
To restore WiFi: ./restore_wifi.sh
EOF

echo ""
echo "🎉 WhisPi setup completed successfully!"
echo ""
echo "📋 NEXT STEPS:"
echo "1️⃣  Run: ./activate_hotspot.sh (this will disable internet)"
echo "2️⃣  Connect your devices to WiFi: $WIFI_NAME"
echo "3️⃣  Visit: https://$SITE_URL or https://$LOCAL_IP"
echo "4️⃣  Accept the SSL certificate warning"
echo ""
echo "🔧 MANAGEMENT:"
echo "• Restore normal WiFi: ./restore_wifi.sh"
echo "• Start server manually: ./start_whispi_server.sh"
echo "• View config: cat whispi_config.txt"
echo ""
echo "⚠️  Important: Keep the PEM password safe - it's needed to start the server!"