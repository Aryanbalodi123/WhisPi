# WhisPi

A secure, offline, end-to-end encrypted chat server for Raspberry Pi Zero W. Users connect to the Pi's Wi-Fi hotspot and exchange encrypted messages via `https://whispi.secure` without requiring internet connectivity.

## 🔒 Key Features

- **Standalone Wi-Fi Hotspot**: Pi operates as an independent access point
- **Local HTTPS Domain**: Secure communication via `https://whispi.secure`
- **End-to-End Encryption**: RSA-4096 key exchange + AES-256 message encryption
- **Digital Signatures**: Message authenticity verification
- **Password-Protected Keys**: User private keys encrypted with individual passwords
- **Rate Limiting**: Built-in protection against spam and abuse
- **Completely Offline**: No internet connection required

## 🚀 Quick Setup

### Prerequisites
- Raspberry Pi (tested with Raspberry Pi Zero W)
- Internet connection (for initial setup only)

### Installation
```bash
# Clone the repository
git clone https://github.com/Aryanbalodi123/WhisPi.git
cd WhisPi

# Run automated setup script
bash setup.sh

# Reboot (mandatory)
sudo reboot

# Run server
./start.sh
```

The setup script automatically handles:
- System updates and package installation
- Python environment with optimized packages
- SSL certificate generation
- Network configuration (hostapd, dnsmasq)
- Production web server setup (Nginx + Gunicorn + Supervisor)
- Security configuration with RSA encryption

## 💬 Usage

1. **Connect**: Join the Pi's Wi-Fi network (SSID: `Whispi-Network`)
2. **Access**: Open browser and navigate to `https://whispi.secure`
3. **Register**: Create an account with username and password
4. **Chat**: Send encrypted messages to other users on the network

## 🛡️ Security Architecture

- **Hybrid Encryption**: RSA for key exchange, AES for message payloads
- **Client-Side Encryption**: Messages encrypted before transmission
- **Digital Signatures**: Each message cryptographically signed
- **Local Certificate Authority**: Self-signed certificates for HTTPS
- **Session Management**: Secure server-side session handling

## 🔧 Technical Stack

- **Backend**: Flask (Python)
- **Database**: SQLite
- **Encryption**: RSA-4096 + AES-256-GCM
- **Network**: hostapd + dnsmasq
- **Web Server**: Flask development server with HTTPS

## 📁 Project Structure

```
WhisPi/
├── app/               # Server files 
├── setup.sh           # Automated installation script
├── start.sh           # Server startup script
├── server.py          # Main Flask application
├── static/            # Web interface files
├── certs/             # SSL certificates
├── database.db        # SQLite database
└── requirements.txt   # Python dependencies
```

## 🔄 Management Commands

```bash
# Check system status
./05_check_status.sh

# Enable hotspot mode (disables internet)
./03_enable_hotspot.sh

# Restore normal WiFi mode
./04_restore_wifi.sh

# Backup all configurations
./06_backup_config.sh

# Manual service control
./01_start_services.sh
./02_stop_services.sh
```

## 🌐 Network Configuration

After setup, the Pi will broadcast:
- **SSID**: `Whispi-Network`
- **Password**: `whispi123` (can be changed in setup.sh)
- **IP Range**: 192.168.4.0/24
- **Pi IP**: 192.168.4.1
- **Domain**: whispi.secure → 192.168.4.1

## ⚠️ Security Considerations

- Change default Wi-Fi password in production
- Keep the Pi physically secure
- Regularly update the system: `sudo apt update && sudo apt upgrade`
- Monitor for unauthorized access attempts
- Consider implementing user management for larger deployments

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/new-feature`)
3. Commit changes (`git commit -am 'Add new feature'`)
4. Push to branch (`git push origin feature/new-feature`)
5. Create Pull Request

## ⚠️ Disclaimer

This software is provided for educational and research purposes. Users must ensure compliance with applicable laws and regulations in their jurisdiction. The developers assume no liability for misuse or security vulnerabilities.
