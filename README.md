<h1 align="center">🧿 WorldEye X</h1>
<h3 align="center">Advanced Cybersecurity Reconnaissance Tool</h3>

<p align="center">
<b>WorldEye X</b> is a modern Python tool for ethical hacking and cyber recon.<br>
Lightweight, fast, and fully CLI-driven — ideal for red teams and CTF challenges. 
</p>

---

## 🚀 Features

- ✅ **TCP Smart Scan** – Fast scan of commonly used ports  
- ✅ **TCP Full Scan** – Full range port scanning (1-1024)  
- ✅ **UDP Port Scan** – Lightweight scanning of DNS, NTP, SNMP etc.  
- ✅ **OS Detection** – TTL-based fingerprinting  
- ✅ **Traceroute** – Discover network path to target  
- ✅ **SSH Brute Force** – Dictionary attack for login discovery  
- ✅ **IPv6 Support** – Native dual stack support  
- ✅ **JSON Export** – Save structured results  
- ✅ **CyberSec ASCII Art** – 3D animated terminal eye logo  

---

## ⚙️ Installation

```bash
git clone https://github.com/omerfaruk-shp/worldeye
cd worldeye
pip install -r requirements.txt
python worldeye.py --help
```

> Python 3.10+ is recommended. No GUI, no Flask. Full terminal control.

---

## 🧪 Usage Examples

```bash
# Smart TCP scan
python worldeye.py -t 192.168.1.100 -m

# Full TCP + UDP + OS + traceroute
python worldeye.py -t 192.168.1.100 -f --udp --os --trace

# SSH brute-force attack
python worldeye.py -t 192.168.1.100 --ssh-brute --userlist users.txt --passlist passwords.txt

# Save output
python worldeye.py -t 192.168.1.100 -m --save results.json
```

---

## 📸 Screenshot

<p align="center">
  <img src="https://raw.githubusercontent.com/omerfaruk-shp/worldeye/main/assets/demo.png" width="700">
</p>

---

## ⚖️ License

MIT License. Use it freely for ethical hacking, labs, and education.

---

<h3 align="center">👁️ WorldEye – See what they hide.</h3>
