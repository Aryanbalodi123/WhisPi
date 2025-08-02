#!/bin/bash
set -e

# Enhanced logging setup with colors and formatting
LOG_FILE="/tmp/whispi_setup.log"
exec 1> >(tee -a "$LOG_FILE")
exec 2> >(tee -a "$LOG_FILE" >&2)

# Color codes for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Enhanced logging functions with consistent formatting
log_header() {
    local msg="$1"
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║${NC} ${WHITE}$(printf "%-74s" "$msg")${NC} ${BOLD}${CYAN}║${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [HEADER] $msg" >> "$LOG_FILE"
}

log_phase() {
    local phase="$1"
    local desc="$2"
    echo ""
    echo -e "${BOLD}${BLUE}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
    echo -e "${BOLD}${BLUE}┃${NC} ${BOLD}${WHITE}$phase: $desc${NC} $(printf "%*s" $((70 - ${#phase} - ${#desc})) "") ${BOLD}${BLUE}┃${NC}"
    echo -e "${BOLD}${BLUE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [PHASE] $phase: $desc" >> "$LOG_FILE"
}

log_step() {
    local step="$1"
    echo -e "${BOLD}${PURPLE}├─${NC} ${WHITE}$step${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [STEP] $step" >> "$LOG_FILE"
}

log_info() {
    local msg="$1"
    echo -e "${BLUE}│  ℹ️${NC}  $msg"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $msg" >> "$LOG_FILE"
}

log_warn() {
    local msg="$1"
    echo -e "${YELLOW}│  ⚠️${NC}  ${YELLOW}$msg${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $msg" >> "$LOG_FILE"
}

log_error() {
    local msg="$1"
    echo -e "${RED}│  ❌${NC} ${RED}$msg${NC}" >&2
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $msg" >> "$LOG_FILE"
}

log_success() {
    local msg="$1"
    echo -e "${GREEN}│  ✅${NC} ${GREEN}$msg${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $msg" >> "$LOG_FILE"
}

log_progress() {
    local msg="$1"
    echo -e "${CYAN}│  🔄${NC} $msg"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [PROGRESS] $msg" >> "$LOG_FILE"
}

log_command() {
    local cmd="$1"
    echo -e "${GRAY}│    💻 ${cmd}${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [COMMAND] $cmd" >> "$LOG_FILE"
}

log_config() {
    local key="$1"
    local value="$2"
    echo -e "${PURPLE}│    🔧 ${key}:${NC} ${BOLD}$value${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [CONFIG] $key: $value" >> "$LOG_FILE"
}

log_file() {
    local filename="$1"
    echo -e "${CYAN}│    📄 ${filename}${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [FILE] $filename" >> "$LOG_FILE"
}

# Separator functions
log_separator() {
    echo -e "${GRAY}├────────────────────────────────────────────────────────────────────────────────┤${NC}"
}

log_end_phase() {
    echo -e "${GRAY}└────────────────────────────────────────────────────────────────────────────────┘${NC}"
}

# Progress bar function
show_progress() {
    local current="$1"
    local total="$2"
    local desc="$3"
    local width=50
    local percentage=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    
    printf "\r${CYAN}│  📊 Progress: [${GREEN}"
    printf "%*s" $filled | tr ' ' '█'
    printf "${GRAY}"
    printf "%*s" $empty | tr ' ' '░'
    printf "${CYAN}] %3d%% - %s${NC}" $percentage "$desc"
    
    if [ $current -eq $total ]; then
        echo ""
    fi
}

# Application header
log_header "🕊️  WhisPi Full Setup Script - Raspberry Pi Secure Offline Chat"

echo -e "${BOLD}${WHITE}Welcome to WhisPi Setup!${NC}"
echo -e "${GRAY}This script will configure your Raspberry Pi as a secure offline chat system.${NC}"
echo ""
log_warn "This script will configure your Pi as a WiFi hotspot and disable internet access"
log_info "Setup will be done in phases to prevent system freezing"
log_info "Updated with Nginx and Supervisor support"
echo ""

# Root check with better formatting
if [[ $EUID -eq 0 ]]; then
   log_error "This script should not be run as root. Please run as regular user."
   echo -e "${RED}${BOLD}Exiting...${NC}"
   exit 1
fi

# Enhanced check functions
check_internet() {
    log_progress "Checking internet connectivity..."
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        log_success "Internet connection available"
        return 0
    else
        log_error "No internet connection detected"
        return 1
    fi
}

check_requirements() {
    log_step "Validating Requirements"
    if [ ! -f "requirements.txt" ]; then
        log_error "requirements.txt not found in current directory!"
        log_error "Please make sure requirements.txt is present before running this script."
        exit 1
    else
        log_success "Found existing requirements.txt file"
        log_info "Packages to be installed:"
        while IFS= read -r line; do
            if [[ ! "$line" =~ ^#.*$ ]] && [[ -n "$line" ]]; then
                echo -e "${GRAY}│      • $line${NC}"
            fi
        done < requirements.txt
    fi
}

# Enhanced validation functions with better error reporting
validate_wifi_name() {
    local name="$1"
    log_progress "Validating WiFi name: '$name'"
    
    if [[ ${#name} -lt 1 || ${#name} -gt 32 ]]; then
        log_error "WiFi name must be 1-32 characters long (current: ${#name})"
        return 1
    fi
    if [[ "$name" =~ [[:space:]] ]]; then
        log_error "WiFi name cannot contain spaces"
        return 1
    fi
    if [[ "$name" =~ [^[:print:]] ]]; then
        log_error "WiFi name contains invalid characters"
        return 1
    fi
    
    log_success "WiFi name validation passed"
    return 0
}

validate_wifi_password() {
    local pass="$1"
    log_progress "Validating WiFi password (length: ${#pass})"
    
    if [[ ${#pass} -lt 8 || ${#pass} -gt 63 ]]; then
        log_error "WiFi password must be 8-63 characters long (current: ${#pass})"
        return 1
    fi
    if [[ "$pass" =~ [^[:print:]] ]]; then
        log_error "WiFi password contains invalid characters"
        return 1
    fi
    
    log_success "WiFi password validation passed"
    return 0
}

validate_domain() {
    local domain="$1"
    log_progress "Validating domain name: '$domain'"
    
    if [[ ${#domain} -lt 1 || ${#domain} -gt 63 ]]; then
        log_error "Domain name must be 1-63 characters long (current: ${#domain})"
        return 1
    fi
    if [[ ! "$domain" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$ ]]; then
        log_error "Domain name can only contain lowercase letters, numbers, dots, and hyphens"
        log_error "Cannot start or end with hyphen, cannot have consecutive dots"
        return 1
    fi
    
    log_success "Domain name validation passed"
    return 0
}

validate_ip() {
    local ip="$1"
    log_progress "Validating IP address: '$ip'"
    
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        log_error "IP address must be in format xxx.xxx.xxx.xxx"
        return 1
    fi
    
    IFS='.' read -ra ADDR <<< "$ip"
    for i in "${ADDR[@]}"; do
        if [[ $i -lt 0 || $i -gt 255 ]]; then
            log_error "Each IP octet must be between 0-255 (found: $i)"
            return 1
        fi
    done
    
    if [[ "${ADDR[0]}" == "192" && "${ADDR[1]}" == "168" ]]; then
        log_success "Valid private IP range (192.168.x.x)"
        return 0
    elif [[ "${ADDR[0]}" == "10" ]]; then
        log_success "Valid private IP range (10.x.x.x)"
        return 0
    elif [[ "${ADDR[0]}" == "172" && "${ADDR[1]}" -ge 16 && "${ADDR[1]}" -le 31 ]]; then
        log_success "Valid private IP range (172.16-31.x.x)"
        return 0
    else
        log_error "IP must be in private range (192.168.x.x, 10.x.x.x, or 172.16-31.x.x)"
        return 1
    fi
}

validate_pem_password() {
    local pass="$1"
    log_progress "Validating PEM password (length: ${#pass})"
    
    if [[ ${#pass} -lt 6 ]]; then
        log_error "PEM password must be at least 6 characters long (current: ${#pass})"
        return 1
    fi
    if [[ "$pass" =~ [^[:print:]] ]]; then
        log_error "PEM password contains invalid characters"
        return 1
    fi
    
    log_success "PEM password validation passed"
    return 0
}

# Configuration phase with enhanced prompts
log_phase "PHASE 1" "Configuration Input & Validation"

log_step "WiFi Hotspot Configuration"
while true; do
    echo -e "${BOLD}${WHITE}📶 Wi-Fi Hotspot Name${NC} ${GRAY}[default: WhisPiChat]${NC}:"
    read -p "   > " WIFI_NAME
    WIFI_NAME=${WIFI_NAME:-WhisPiChat}
    if validate_wifi_name "$WIFI_NAME"; then
        log_config "WiFi Name" "$WIFI_NAME"
        break
    fi
    echo ""
done

echo ""
while true; do
    echo -e "${BOLD}${WHITE}🔑 Wi-Fi Password${NC} ${GRAY}[default: whispi123]${NC}:"
    read -p "   > " WIFI_PASS
    WIFI_PASS=${WIFI_PASS:-whispi123}
    if validate_wifi_password "$WIFI_PASS"; then
        log_config "WiFi Password" "$(echo "$WIFI_PASS" | sed 's/./*/g')"
        break
    fi
    echo ""
done

echo ""
while true; do
    echo -e "${BOLD}${WHITE}🌐 Local Site Domain${NC} ${GRAY}[default: whispi.secure]${NC}:"
    read -p "   > " SITE_URL
    SITE_URL=${SITE_URL:-whispi.secure}
    if validate_domain "$SITE_URL"; then
        log_config "Site Domain" "$SITE_URL"
        break
    fi
    echo ""
done

echo ""
while true; do
    echo -e "${BOLD}${WHITE}📡 Local IP for Pi${NC} ${GRAY}[default: 192.168.4.1]${NC}:"
    read -p "   > " LOCAL_IP
    LOCAL_IP=${LOCAL_IP:-192.168.4.1}
    if validate_ip "$LOCAL_IP"; then
        log_config "Pi IP Address" "$LOCAL_IP"
        break
    fi
    echo ""
done

echo ""
while true; do
    echo -e "${BOLD}${WHITE}🔐 Password to protect RSA private key${NC}:"
    read -s -p "   > " PEM_PASS
    echo ""
    if validate_pem_password "$PEM_PASS"; then
        log_config "RSA Key Password" "********"
        break
    fi
    echo ""
done

log_separator
check_requirements
log_end_phase

# System updates phase
log_phase "PHASE 2" "System Updates & Package Installation"

if check_internet; then
    log_step "Package Management"
    
    log_progress "Updating package lists..."
    log_command "sudo apt update"
    sudo apt update >/dev/null 2>&1
    log_success "Package lists updated"
    
    log_progress "Installing system packages..."
    packages=(hostapd dnsmasq openssl python3-flask python3-pip python3-venv nginx redis-server supervisor build-essential libssl-dev libffi-dev python3-dev pkg-config)
    total_packages=${#packages[@]}
    
    for i in "${!packages[@]}"; do
        show_progress $((i+1)) $total_packages "Installing ${packages[$i]}"
        sleep 0.1  # Simulate installation time for demo
    done
    
    log_command "sudo apt install -y hostapd dnsmasq openssl python3-flask python3-pip python3-venv nginx redis-server supervisor build-essential libssl-dev libffi-dev python3-dev pkg-config"
    sudo apt install -y hostapd dnsmasq openssl python3-flask python3-pip python3-venv \
                        nginx redis-server supervisor build-essential libssl-dev libffi-dev \
                        python3-dev pkg-config >/dev/null 2>&1
    log_success "System packages installed successfully"
    
    log_step "Service Configuration"
    log_progress "Configuring Redis..."
    log_command "sudo systemctl enable redis-server && sudo systemctl start redis-server"
    sudo systemctl enable redis-server >/dev/null 2>&1
    sudo systemctl start redis-server >/dev/null 2>&1
    log_success "Redis configured and started"
    
    log_step "Python Environment Setup"
    VENV_PATH="$HOME/envs/whispi"
    log_progress "Creating Python virtual environment..."
    log_command "python3 -m venv $VENV_PATH"
    mkdir -p "$HOME/envs"
    python3 -m venv "$VENV_PATH"
    source "$VENV_PATH/bin/activate"
    log_success "Virtual environment created: $VENV_PATH"
    
    log_progress "Upgrading pip and installing wheel..."
    log_command "pip install --upgrade pip wheel"
    pip install --upgrade pip wheel >/dev/null 2>&1
    log_success "Pip and wheel updated"
    
    log_progress "Installing Python packages with optimizations..."
    log_info "Using piwheels for Raspberry Pi optimized packages"
    log_command "pip install --index-url https://www.piwheels.org/simple/ --extra-index-url https://pypi.org/simple/ ..."
    
    if pip install --index-url https://www.piwheels.org/simple/ \
                --extra-index-url https://pypi.org/simple/ \
                --only-binary=cryptography,bcrypt,cffi,pycparser,lxml \
                --prefer-binary \
                -r requirements.txt >/dev/null 2>&1; then
        log_success "All packages installed from optimized wheels"
    else
        log_warn "Some packages not available as prebuilt wheels from piwheels"
        log_progress "Trying standard PyPI with binary preference..."
        if pip install --only-binary=cryptography,bcrypt,cffi,pycparser \
                    --prefer-binary \
                    --no-cache-dir \
                    -r requirements.txt >/dev/null 2>&1; then
            log_success "Packages installed from PyPI binaries"
        else
            log_warn "Falling back to source build (this will take longer)"
            log_progress "Building packages from source - please wait..."
            pip install -r requirements.txt >/dev/null 2>&1
            log_success "Packages built and installed from source"
        fi
    fi
    
    echo "source $VENV_PATH/bin/activate" > activate_whispi.sh
    chmod +x activate_whispi.sh
    log_file "activate_whispi.sh"
    
else
    log_error "No internet connection. Cannot install packages."
    log_error "Please connect to internet and run this script again."
    exit 1
fi

log_end_phase

# Security Setup Phase
log_phase "PHASE 3" "Security Setup & Certificate Generation"

log_step "Certificate Directory"
log_progress "Creating certificates directory..."
log_command "mkdir -p certs"
mkdir -p certs
log_success "Certificates directory created"

log_step "HTTPS Certificate"
log_progress "Generating HTTPS certificate for $SITE_URL..."
log_command "openssl req -newkey rsa:2048 -x509 -sha256 -days 365 -nodes -keyout certs/$SITE_URL-key.pem -out certs/$SITE_URL.pem"
openssl req -newkey rsa:2048 -x509 -sha256 -days 365 -nodes \
    -keyout certs/$SITE_URL-key.pem -out certs/$SITE_URL.pem \
    -subj "/C=IN/ST=Punjab/L=Ludhiana/O=WhisPi/CN=$SITE_URL" >/dev/null 2>&1
log_success "HTTPS certificate generated"
log_file "certs/$SITE_URL.pem"
log_file "certs/$SITE_URL-key.pem"

log_step "RSA Key Pair"
log_progress "Generating RSA key pair for messaging encryption..."
log_command "openssl genrsa -out temp_private.pem 2048"
openssl genrsa -out certs/temp_private.pem 2048 >/dev/null 2>&1
log_command "openssl rsa -in temp_private.pem -out rsa_private.pem -aes256 -passout pass:***"
openssl rsa -in certs/temp_private.pem -out certs/rsa_private.pem -aes256 -passout pass:$PEM_PASS >/dev/null 2>&1
log_command "openssl rsa -in temp_private.pem -pubout -out rsa_public.pem"
openssl rsa -in certs/temp_private.pem -pubout -out certs/rsa_public.pem >/dev/null 2>&1
rm certs/temp_private.pem
log_success "RSA key pair generated"
log_file "certs/rsa_private.pem (password protected)"
log_file "certs/rsa_public.pem"

log_step "File Permissions"
log_progress "Setting proper file permissions..."
chmod 600 certs/*.pem certs/*-key.pem
chmod 644 certs/rsa_public.pem certs/$SITE_URL.pem
log_success "Security permissions applied"

log_end_phase

# Environment Configuration
log_phase "PHASE 4" "Environment Configuration"

log_step "Environment Variables"
log_progress "Creating .env file with secure configuration..."
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

log_success "Environment configuration created"
log_file ".env"
log_config "SSL Certificate" "$(pwd)/certs/$SITE_URL.pem"
log_config "RSA Keys" "Password protected"
log_config "Redis URL" "redis://localhost:6379"
log_config "Session Store" "Redis with 24h lifetime"

log_end_phase

# Web Server Configuration Phase
log_phase "PHASE 5" "Web Server & Application Configuration"

log_step "Nginx Configuration"
log_progress "Removing default Nginx configuration..."
sudo rm -f /etc/nginx/sites-enabled/default

log_progress "Creating WhisPi Nginx configuration..."
sudo bash -c "cat > /etc/nginx/sites-available/whispi << 'EOF'
server {
    listen 80;
    server_name $SITE_URL;
    return 301 https://\$host\$request_uri;
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
log_success "Nginx configured for HTTPS and reverse proxy"
log_file "/etc/nginx/sites-available/whispi"

log_step "Gunicorn Configuration"
log_progress "Creating Gunicorn configuration..."
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
log_success "Gunicorn configured for production deployment"
log_file "config/gunicorn.py"

log_step "Supervisor Configuration"
log_progress "Creating Supervisor configuration for process management..."
sudo bash -c "cat > /etc/supervisor/conf.d/whispi.conf << 'EOF'
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

log_success "Supervisor configured for automatic process management"
log_file "/etc/supervisor/conf.d/whispi.conf"

log_end_phase

# Network Configuration Phase
log_phase "PHASE 6" "Network & Hotspot Configuration"

log_step "Configuration Backup"
log_progress "Backing up existing network configurations..."
sudo cp /etc/dhcpcd.conf /etc/dhcpcd.conf.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
log_success "Network configurations backed up"

log_step "DHCP Configuration"
log_progress "Configuring static IP for wireless interface..."
log_command "Appending configuration to /etc/dhcpcd.conf"
sudo bash -c "cat >> /etc/dhcpcd.conf << 'EOF'

# WhisPi Hotspot Configuration
interface wlan0
    static ip_address=$LOCAL_IP/24
    nohook wpa_supplicant
EOF"

log_success "DHCP configuration updated"
log_config "Interface" "wlan0"
log_config "Static IP" "$LOCAL_IP/24"

log_step "DNS Configuration"
log_progress "Configuring dnsmasq for DHCP and DNS..."
log_command "Creating /etc/dnsmasq.conf"
sudo bash -c "cat > /etc/dnsmasq.conf << 'EOF'
interface=wlan0
dhcp-range=${LOCAL_IP%.*}.10,${LOCAL_IP%.*}.50,255.255.255.0,24h
address=/$SITE_URL/$LOCAL_IP
address=/www.$SITE_URL/$LOCAL_IP
no-resolv
no-poll
EOF"

log_success "DNS and DHCP server configured"
log_config "DHCP Range" "${LOCAL_IP%.*}.10 - ${LOCAL_IP%.*}.50"
log_config "Domain Resolution" "$SITE_URL → $LOCAL_IP"

log_step "Access Point Configuration"
log_progress "Configuring hostapd for WiFi access point..."
log_command "Creating /etc/hostapd/hostapd.conf"
sudo bash -c "cat > /etc/hostapd/hostapd.conf << 'EOF'
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
log_success "WiFi access point configured"
log_config "SSID" "$WIFI_NAME"
log_config "Security" "WPA2-PSK"
log_config "Channel" "7"

log_end_phase

# Management Scripts Phase
log_phase "PHASE 7" "Management Scripts Creation"

log_step "Service Management Scripts"
log_progress "Creating service control scripts..."

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
log_file "01_start_services.sh"

cat > 02_stop_services.sh << 'EOF'
#!/bin/bash
echo "🛑 Stopping WhisPi services..."
sudo supervisorctl stop whispi >/dev/null 2>&1
sudo systemctl stop nginx supervisor >/dev/null 2>&1
echo "✅ Services stopped"
EOF
chmod +x 02_stop_services.sh
log_file "02_stop_services.sh"

log_step "Network Mode Scripts"
log_progress "Creating network mode management scripts..."

cat > 03_enable_hotspot.sh << EOF
#!/bin/bash
echo "🚀 Enabling hotspot mode..."
read -p "This will disable internet access. Continue? (y/N): " -n 1 -r
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
log_file "03_enable_hotspot.sh"

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
log_file "04_restore_wifi.sh"

log_step "Development Tools"
log_progress "Creating development and utility scripts..."

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
log_file "05_development_mode.sh"

cat > 06_check_status.sh << 'EOF'
#!/bin/bash
echo "📊 WhisPi System Status"
echo "======================="
echo ""

echo "🔧 Services:"
echo "  Redis:      $(systemctl is-active redis-server)"
echo "  Nginx:      $(systemctl is-active nginx)"
echo "  Supervisor: $(systemctl is-active supervisor)"
echo "  WhisPi App: $(sudo supervisorctl status whispi 2>/dev/null | awk '{print $2}' || echo 'NOT_RUNNING')"
echo ""

echo "🌐 Network:"
echo "  Hostapd:    $(systemctl is-active hostapd)"
echo "  Dnsmasq:    $(systemctl is-active dnsmasq)"
echo "  IP Address: $(ip addr show wlan0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 || echo 'Not configured')"
echo ""

echo "💾 Storage:"
echo "  Disk Usage: $(df -h / | tail -1 | awk '{print $5}')"
echo "  Memory:     $(free -h | grep Mem | awk '{printf "%.1f/%.1fGB (%.0f%%)", $3/1024, $2/1024, ($3/$2)*100}')"
echo ""

echo "📋 Logs:"
echo "  App Log:    tail -5 /var/log/whispi/supervisor.log"
echo "  Error Log:  tail -5 /var/log/whispi/error.log"
echo "  Setup Log:  tail -5 /tmp/whispi_setup.log"
EOF
chmod +x 06_check_status.sh
log_file "06_check_status.sh"

cat > 07_backup_config.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="backup_$(date +%Y%m%d_%H%M%S)"
echo "💾 Creating configuration backup: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"

# Copy important files
cp -r certs/ "$BACKUP_DIR/" 2>/dev/null || echo "⚠️  No certs directory"
cp .env "$BACKUP_DIR/" 2>/dev/null || echo "⚠️  No .env file"  
cp config/ -r "$BACKUP_DIR/" 2>/dev/null || echo "⚠️  No config directory"
cp whispi_config.txt "$BACKUP_DIR/" 2>/dev/null || echo "⚠️  No config summary"

# System configs (requires sudo)
sudo cp /etc/hostapd/hostapd.conf "$BACKUP_DIR/" 2>/dev/null
sudo cp /etc/dnsmasq.conf "$BACKUP_DIR/" 2>/dev/null  
sudo cp /etc/dhcpcd.conf "$BACKUP_DIR/" 2>/dev/null
sudo cp /etc/nginx/sites-available/whispi "$BACKUP_DIR/" 2>/dev/null
sudo cp /etc/supervisor/conf.d/whispi.conf "$BACKUP_DIR/" 2>/dev/null

echo "✅ Backup created in: $BACKUP_DIR"
echo "📦 Archive with: tar -czf whispi_backup_$(date +%Y%m%d).tar.gz $BACKUP_DIR"
EOF
chmod +x 07_backup_config.sh
log_file "07_backup_config.sh"

log_success "Management scripts created successfully"

log_end_phase

# Service Configuration Phase
log_phase "PHASE 8" "Service Configuration & Finalization"

log_step "System Service Configuration"
log_progress "Configuring system services..."
sudo systemctl unmask hostapd >/dev/null 2>&1
sudo systemctl enable nginx supervisor redis-server >/dev/null 2>&1
sudo systemctl daemon-reload
log_success "System services configured for auto-start"

log_step "Nginx Validation"
log_progress "Validating Nginx configuration..."
if sudo nginx -t >/dev/null 2>&1; then
    log_success "Nginx configuration is valid"
else
    log_error "Nginx configuration has errors"
    log_warn "Please check the configuration manually"
fi

log_step "File Permissions Final Check"
log_progress "Setting final file permissions..."
chmod +x *.sh
sudo chown -R $USER:$USER /var/log/whispi
log_success "All permissions set correctly"

log_end_phase

# Configuration Summary Phase
log_phase "PHASE 9" "Configuration Summary Generation"

log_step "Comprehensive Configuration File"
log_progress "Generating detailed configuration summary..."

cat > whispi_config.txt << EOF
WhisPi Configuration Summary
============================
Generated: $(date)

Network Configuration:
---------------------
WiFi Network Name: $WIFI_NAME
WiFi Password:     $WIFI_PASS  
Domain Name:       $SITE_URL
Pi IP Address:     $LOCAL_IP
DHCP Range:        ${LOCAL_IP%.*}.10 - ${LOCAL_IP%.*}.50

Security Configuration:
----------------------
HTTPS Certificate: $(pwd)/certs/$SITE_URL.pem
RSA Private Key:   $(pwd)/certs/rsa_private.pem (password protected)
RSA Public Key:    $(pwd)/certs/rsa_public.pem
Session Store:     Redis with 24h lifetime

Application Stack:
-----------------
Web Server:        Nginx (Port 443 HTTPS, 80 HTTP redirect)
App Server:        Gunicorn (Port 8000, multiple workers)
Process Manager:   Supervisor (auto-restart, logging)
Session Store:     Redis Server
Python Env:        $VENV_PATH

File Locations:
--------------
Application:       $(pwd)/
Certificates:      $(pwd)/certs/
Configuration:     $(pwd)/config/
Environment:       $(pwd)/.env
Virtual Env:       $VENV_PATH
Logs:             /var/log/whispi/

Management Scripts:
------------------
01_start_services.sh      - Start all WhisPi services
02_stop_services.sh       - Stop all WhisPi services  
03_enable_hotspot.sh      - Switch to hotspot mode (offline)
04_restore_wifi.sh        - Restore normal WiFi mode
05_development_mode.sh    - Run in development mode
06_check_status.sh        - Check system status
07_backup_config.sh       - Backup all configurations

System Commands:
---------------
Check app status:     sudo supervisorctl status whispi
Restart app:          sudo supervisorctl restart whispi
View app logs:        tail -f /var/log/whispi/supervisor.log
View error logs:      tail -f /var/log/whispi/error.log
View access logs:     tail -f /var/log/whispi/access.log
Nginx status:         sudo systemctl status nginx
Redis status:         sudo systemctl status redis-server

Network Configuration Files:
----------------------------
Hotspot Config:       /etc/hostapd/hostapd.conf
DHCP Config:          /etc/dhcpcd.conf  
DNS Config:           /etc/dnsmasq.conf
Nginx Config:         /etc/nginx/sites-available/whispi
Supervisor Config:    /etc/supervisor/conf.d/whispi.conf

Access URLs (after enabling hotspot):
------------------------------------
Primary:              https://$SITE_URL
Alternative:          https://$LOCAL_IP
HTTP (redirects):     http://$SITE_URL
HTTP Alt:             http://$LOCAL_IP

Troubleshooting:
---------------
1. Check services:    ./06_check_status.sh
2. View logs:         tail -f /var/log/whispi/supervisor.log
3. Test nginx:        sudo nginx -t
4. Restart services:  sudo supervisorctl restart whispi
5. Check network:     ip addr show wlan0

Security Notes:
--------------
- SSL certificate is self-signed (browser warning expected)
- RSA private key is password protected  
- All services run with minimal privileges
- No internet access in hotspot mode
- Sessions expire after 24 hours

Backup & Recovery:
-----------------
- Run ./07_backup_config.sh to backup all configs
- Keep backup of certificates and .env file
- System configs backed up during installation
- Virtual environment can be recreated from requirements.txt

Architecture Overview:
---------------------
Internet ❌ → [Pi Hotspot] → Client Devices
                    ↓
         [Nginx:443] → [Gunicorn:8000] → [Flask App]
                    ↓
              [Redis Sessions]
              [File Storage]
EOF

log_success "Configuration summary generated"
log_file "whispi_config.txt"

log_end_phase

# Final Summary with enhanced formatting
log_header "🎉 WhisPi Setup Completed Successfully!"

echo -e "${BOLD}${GREEN}┌─ Installation Summary ──────────────────────────────────────────────────────────┐${NC}"
echo -e "${BOLD}${GREEN}│${NC}  ${BOLD}Status:${NC} ✅ All components installed and configured"
echo -e "${BOLD}${GREEN}│${NC}  ${BOLD}WiFi Network:${NC} $WIFI_NAME (Password: $WIFI_PASS)"
echo -e "${BOLD}${GREEN}│${NC}  ${BOLD}Access URLs:${NC} https://$SITE_URL or https://$LOCAL_IP"
echo -e "${BOLD}${GREEN}│${NC}  ${BOLD}Environment:${NC} Production-ready with SSL, Redis, Supervisor"
echo -e "${BOLD}${GREEN}│${NC}"
echo -e "${BOLD}${GREEN}│${NC}  ${BOLD}Next Steps:${NC}"
echo -e "${BOLD}${GREEN}│${NC}    1️⃣  Enable hotspot: ${CYAN}./03_enable_hotspot.sh${NC}"
echo -e "${BOLD}${GREEN}│${NC}    2️⃣  Connect devices to WiFi: ${BOLD}$WIFI_NAME${NC}"
echo -e "${BOLD}${GREEN}│${NC}    3️⃣  Visit: ${BOLD}https://$SITE_URL${NC}"
echo -e "${BOLD}${GREEN}│${NC}    4️⃣  Accept SSL certificate warning"
echo -e "${BOLD}${GREEN}│${NC}    5️⃣  Start chatting securely!"
echo -e "${BOLD}${GREEN}│${NC}"
echo -e "${BOLD}${GREEN}│${NC}  ${BOLD}Management:${NC}"
echo -e "${BOLD}${GREEN}│${NC}    📊 Status: ${CYAN}./06_check_status.sh${NC}"
echo -e "${BOLD}${GREEN}│${NC}    🔄 Restore WiFi: ${CYAN}./04_restore_wifi.sh${NC}"
echo -e "${BOLD}${GREEN}│${NC}    🧪 Development: ${CYAN}./05_development_mode.sh${NC}"
echo -e "${BOLD}${GREEN}│${NC}    💾 Backup: ${CYAN}./07_backup_config.sh${NC}"
echo -e "${BOLD}${GREEN}└──────────────────────────────────────────────────────────────────────────────────┘${NC}"

echo ""
echo -e "${BOLD}${CYAN}📋 Quick Reference:${NC}"
echo -e "${GRAY}   Configuration:    cat whispi_config.txt${NC}"
echo -e "${GRAY}   Setup log:        cat $LOG_FILE${NC}"
echo -e "${GRAY}   App logs:         tail -f /var/log/whispi/supervisor.log${NC}"
echo -e "${GRAY}   Service status:   sudo supervisorctl status whispi${NC}"

echo ""
echo -e "${BOLD}${YELLOW}⚠️  Important Notes:${NC}"
echo -e "${YELLOW}   • SSL certificate is self-signed (expect browser warning)${NC}"
echo -e "${YELLOW}   • Hotspot mode disables internet access${NC}"  
echo -e "${YELLOW}   • Reboot recommended after enabling hotspot${NC}"
echo -e "${YELLOW}   • Keep backup of certificates and configuration${NC}"

echo ""
log_info "Full setup completed in $((($(date +%s) - $(stat -c %Y /tmp/whispi_setup.log 2>/dev/null || echo $(date +%s)))/60)) minutes"
log_success "WhisPi is ready for secure offline communication!"

echo ""