## ⚠️ CRITICAL WARNING

**SSH Disconnect Alert**: When switching modes, the Pi will disconnect from Wi-Fi. Have a backup access method ready (e.g., monitor + keyboard).

---

## 🔧 PREREQUISITES

```bash
lsusb | grep -i wireless
iwconfig
cat /etc/os-release
ip addr show wlan0
```

* Raspberry Pi with Wi-Fi (built-in or USB)
* Raspbian Bullseye or newer (headless preferred)
* sudo/root access

---

## 🚀 PART 1: HOTSPOT MODE

### 1. Install Packages

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install hostapd dnsmasq iptables-persistent -y
sudo systemctl stop hostapd dnsmasq wpa_supplicant
```

### 2. Configure Static IP

```bash
sudo nano /etc/dhcpcd.conf
```

Add at the end:

```ini
interface wlan0
    static ip_address=192.168.4.1/24
    nohook wpa_supplicant
noipv6
```

### 3. Configure DHCP (dnsmasq)

```bash
sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.backup
sudo nano /etc/dnsmasq.conf
```

```ini
interface=wlan0
bind-interfaces
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
domain=local
address=/gw.local/192.168.4.1
```

### 4. Configure Access Point (hostapd)

```bash
sudo nano /etc/hostapd/hostapd.conf
```

```ini
interface=wlan0
driver=nl80211
ssid=RaspberryPi-Hotspot
hw_mode=g
channel=7
wmm_enabled=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=SecureHotspot2024!
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
```

```bash
sudo nano /etc/default/hostapd
```

```ini
DAEMON_CONF="/etc/hostapd/hostapd.conf"
```

### 5. Enable NAT + IP Forwarding

```bash
sudo nano /etc/sysctl.conf
```

Uncomment or add:

```ini
net.ipv4.ip_forward=1
```

```bash
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
sudo netfilter-persistent save
```

### 6. Start Services

```bash
sudo systemctl unmask hostapd
sudo systemctl enable hostapd dnsmasq
sudo systemctl restart dhcpcd
sudo systemctl start hostapd dnsmasq
```

### ✅ VERIFY

```bash
ip addr show wlan0
sudo iwlist wlan0 scan | grep RaspberryPi-Hotspot
```

---

## 🔄 PART 2: CLIENT MODE

### 1. Stop Hotspot Services

```bash
sudo systemctl stop hostapd dnsmasq
sudo systemctl disable hostapd dnsmasq
```

### 2. Revert DHCP Config

```bash
sudo nano /etc/dhcpcd.conf
```

Comment out:

```ini
#interface wlan0
#    static ip_address=192.168.4.1/24
#    nohook wpa_supplicant
```

### 3. Configure Wi-Fi Credentials

```bash
sudo nano /etc/wpa_supplicant/wpa_supplicant.conf
```

```ini
country=US
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1

network={
    ssid="Your_WiFi"
    psk="Your_Password"
    key_mgmt=WPA-PSK
}
```

### 4. Enable Client Mode

```bash
sudo systemctl enable wpa_supplicant
sudo systemctl restart dhcpcd wpa_supplicant
```

### ✅ VERIFY

```bash
sudo wpa_cli -i wlan0 status
```

### 5. Reboot

```bash
sudo reboot
```

---

## 🔁 PART 3: SWITCH BACK TO HOTSPOT

### 1. Stop Client Services

```bash
sudo systemctl stop wpa_supplicant
sudo systemctl disable wpa_supplicant
```

### 2. Restore Hotspot DHCP

```bash
sudo nano /etc/dhcpcd.conf
```

Uncomment hotspot config.

### 3. Start Hotspot

```bash
sudo systemctl enable hostapd dnsmasq
sudo systemctl restart dhcpcd
sudo systemctl start hostapd dnsmasq
sudo reboot
```

---

## 🛠️ TROUBLESHOOTING

```bash
sudo systemctl status hostapd dnsmasq
sudo journalctl -u hostapd -f
ip addr show wlan0
sudo iwlist wlan0 scan
sudo wpa_cli -i wlan0 status
```

---
