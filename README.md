# Whispi (SecureChat on Raspberry Pi)

A fully offline, end-to-end encrypted chat server and web client hosted on a Raspberry Pi Zero W.  
Users connect to the Pi's Wi-Fi, are redirected to `https://whispi.local`, register/login, and exchange encrypted messages—all without Internet.

---

## 🔒 Features

- **Offline Wi-Fi Hotspot**  
  Pi acts as a standalone access point (no external router required)
- **Local Domain & HTTPS**  
  `whispi.local` with a locally trusted CA certificate  
- **Hybrid Encryption**  
  RSA for key exchange + AES for message payloads  
- **Password-Protected Private Keys**  
  Users' RSA private keys are encrypted on the server with their password  
- **Session-Based Authentication**  
  Flask-Session stores login state server-side  
- **Digital Signatures**  
  RSASSA-PKCS1-v1_5 signatures on each message for authenticity  
- **Rate Limiting**  
  Flask-Limiter to prevent abuse  

---

## 📋 Prerequisites

### On your development machine (to generate CA & certs):
- OpenSSL  
- `ssh` client

### On the Raspberry Pi Zero W:
- Raspberry Pi OS (Lite or Desktop)  
- Python 3.9+  
- `pip` / `venv`  
- Git

---

## 🚀 Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/whispi.git
cd whispi
```

### 2. Create Python virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Generate & trust local CA (on your dev PC)
```bash
# Create CA key & cert
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 \
  -days 3650 -out ca.crt \
  -subj "/CN=Whispi-Local-CA"

# Create server key & CSR
openssl genrsa -out server.key 2048
openssl req -new -key server.key \
  -out server.csr -subj "/CN=whispi.local"

# Sign server cert with CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 -sha256
```

### 4. Install CA certificate on clients
On Windows/Mac/Linux: import `ca.crt` into your OS/browser's trusted root store.

### 5. Copy certificates to Pi
```bash
scp ca.crt server.crt server.key pi@whispi.local:/home/pi/whispi/certs/
```

---

## 🔧 Configure Pi as Wi-Fi Hotspot

Follow Pi Hotspot Configuration to:
- Install & configure `hostapd`
- Set up `dnsmasq` for DHCP & DNS
- Enable automatic redirect to `whispi.local`

> **Note:** You'll lose SSH momentarily during transitions; reconnect to the Pi's SSID.

---

## ⚙️ Database Initialization

On the Pi, in your virtual environment:

```bash
export FLASK_APP=server.py
flask init-db       # creates SQLite schema
```

This sets up tables for users, messages, rate limits, etc.

---

## ▶️ Running the Server

```bash
# Activate environment
cd ~/whispi
source venv/bin/activate

# Launch Flask app with HTTPS
FLASK_ENV=production flask run \
  --host=0.0.0.0 --port=443 \
  --cert=certs/server.crt --key=certs/server.key
```

---

## 💬 Using the Chat

1. Connect your device to the Pi's Wi-Fi SSID
2. In your browser, visit `https://whispi.local`
3. Sign up with a username & password (your RSA private key is encrypted and stored)
4. Log in to see your inbox and compose messages
5. All messages are encrypted and signed; only recipients can decrypt

---

## 🛡️ Security Features

- **End-to-End Encryption**: Messages are encrypted client-side before transmission
- **Digital Signatures**: Each message is cryptographically signed for authenticity
- **Password Protection**: Private keys are encrypted with user passwords
- **Rate Limiting**: Built-in protection against abuse and spam
- **Offline Operation**: No external network dependencies

---

## 🔧 Technical Details

- **Backend**: Flask (Python)
- **Database**: SQLite
- **Encryption**: RSA-4096 + AES-256
- **Certificates**: Self-signed CA with local trust
- **Network**: Hostapd + Dnsmasq for hotspot functionality

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## ⚠️ Disclaimer

This software is provided for educational and research purposes. Users are responsible for ensuring compliance with applicable laws and regulations in their jurisdiction.