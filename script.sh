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
    packages=(hostapd dnsmasq openssl python3-flask python3-pip python3-venv nginx redis-server supervisor)
    total_packages=${#packages[@]}
    
    for i in "${!packages[@]}"; do
        show_progress $((i+1)) $total_packages "Installing ${packages[$i]}"
        sleep 0.1  # Simulate installation time for demo
    done
    
    log_command "sudo apt install -y hostapd dnsmasq openssl python3-flask python3-pip python3-venv nginx redis-server supervisor"
    sudo apt install -y hostapd dnsmasq openssl python3-flask python3-pip python3-venv \
                        nginx redis-server supervisor >/dev/null 2>&1
    log_success "System packages installed successfully"
    
    log_progress "Installing development dependencies..."
    log_command "sudo apt install -y build-essential libssl-dev libffi-dev python3-dev pkg-config"
    sudo apt install -y build-essential libssl-dev libffi-dev python3-dev pkg-config >/dev/null 2>&1
    log_success "Development tools ready for building Python packages"
    
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

# Continue with remaining phases using the same enhanced logging pattern...
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
log_command "openssl genrsa -aes256 -passout pass:*** -out certs/rsa_private.pem 2048"
openssl genrsa -aes256 -passout pass:$PEM_PASS -out certs/rsa_private.pem 2048 >/dev/null 2>&1
log_command "openssl rsa -in certs/rsa_private.pem -passin pass:*** -pubout -out certs/rsa_public.pem"
openssl rsa -in certs/rsa_private.pem -passin pass:$PEM_PASS -pubout -out certs/rsa_public.pem >/dev/null 2>&1
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

RSA_PRIVATE_KEY_PATH=$(pwd)/certs/rsa_private.pem
RSA_PUBLIC_KEY_PATH=$(pwd)/certs/rsa_public.pem
RSA_PRIVATE_KEY_PASSWORD=$PEM_PASS

REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_URL=redis://localhost:6379

SESSION_TYPE=redis
SESSION_KEY_PREFIX=whispi:
SESSION_LIFETIME_HOURS=24
SESSION_FILE_DIR=/tmp/flask_session
EOF

log_success "Environment configuration created"
log_file ".env"
log_config "SSL Certificate" "$(pwd)/certs/$SITE_URL.pem"
log_config "RSA Keys" "Password protected"
log_config "Redis URL" "redis://localhost:6379"
log_config "Session Store" "Redis with 24h lifetime"

log_end_phase

# Final summary with better formatting
log_header "🎉 WhisPi Setup Completed Successfully!"

echo -e "${BOLD}${GREEN}┌─ Setup Summary ─────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${BOLD}${GREEN}│${NC}  ${BOLD}WiFi Network:${NC} $WIFI_NAME"
echo -e "${BOLD}${GREEN}│${NC}  ${BOLD}Access URL:${NC} https://$SITE_URL or https://$LOCAL_IP"
echo -e "${BOLD}${GREEN}│${NC}  ${BOLD}Next Steps:${NC}"
echo -e "${BOLD}${GREEN}│${NC}    1️⃣  Run: ${CYAN}./03_switch_to_hotspot.sh${NC}"
echo -e "${BOLD}${GREEN}│${NC}    2️⃣  Connect devices to WiFi: ${BOLD}$WIFI_NAME${NC}"
echo -e "${BOLD}${GREEN}│${NC}    3️⃣  Visit: ${BOLD}https://$SITE_URL${NC}"
echo -e "${BOLD}${GREEN}│${NC}    4️⃣  Accept SSL certificate warning"
echo -e "${BOLD}${GREEN}└─────────────────────────────────────────────────────────────────────────────────┘${NC}"

echo ""
log_info "Setup log saved to: $LOG_FILE"
log_info "View detailed configuration: cat whispi_config.txt"
echo ""