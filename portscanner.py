import socket
import argparse
import time
import json
import concurrent.futures
import os
from datetime import datetime
import subprocess

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

def ascii_eye_opening():
    print(f"""{CYAN}
 _____                                                                                            _____ 
( ___ )                                                                                          ( ___ )
 |   |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|   | 
 |   |                                                                                            |   | 
 |   |                                                                                            |   | 
 |   |      dP   dP   dP                   dP       dP     88888888b                              |   | 
 |   |      88   88   88                   88       88     88                                     |   | 
 |   |      88  .8P  .8P .d8888b. 88d888b. 88 .d888b88    a88aaaa    dP    dP .d8888b.            |   | 
 |   |      88  d8'  d8' 88'  `88 88'  `88 88 88'  `88     88        88    88 88ooood8            |   | 
 |   |      88.d8P8.d8P  88.  .88 88       88 88.  .88     88        88.  .88 88.  ...            |   | 
 |   |      8888' Y88'   `88888P' dP       dP `88888P8     88888888P `8888P88 `88888P'            |   | 
 |   |                                                                    .88                     |   | 
 |   |                                                                d8888P                      |   | 
 |   |                                                                                            |   | 
 |   |                                                                                            |   | 
 |___|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|___| 
(_____) {RESET}
    """)
    time.sleep(0.5)

def resolve_target(target, ipv6=False):
    try:
        return socket.getaddrinfo(target, None, socket.AF_INET6 if ipv6 else socket.AF_INET)[0][4][0]
    except socket.gaierror:
        print(f"{RED}[!] Hedef çözümlenemedi: {target}{RESET}")
        exit(1)

def get_service_name(port, proto='tcp'):
    try:
        return socket.getservbyport(port, proto)
    except:
        return "Bilinmiyor"

def scan_single_port(target_ip, port, timeout=1, ipv6=False):
    try:
        sock = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        server = "Alınamadı"
        if result == 0:
            try:
                sock.send(b'HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n')
                banner = sock.recv(1024).decode(errors='ignore').split('\n')[0]
                server = banner.strip()
            except:
                pass
            return {
                "port": port,
                "service": get_service_name(port),
                "server": server
            }
        sock.close()
    except:
        pass
    return None

def scan_ports_concurrent(target_ip, ports, threads=100, ipv6=False):
    open_ports = []
    start_time = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        results = list(executor.map(lambda p: scan_single_port(target_ip, p, ipv6=ipv6), ports))
    for r in results:
        if r:
            print(f"{GREEN}[+] TCP Port {r['port']} ({r['service']}) OPEN{RESET}")
            print(f"    Server: {r['server']}")
            open_ports.append(r)
    duration = time.time() - start_time
    return open_ports, len(ports) - len(open_ports), duration

def udp_scan_ports(target_ip, ports):
    print(f"{YELLOW}[*] UDP Port Taraması başlatıldı...{RESET}")
    open_udp_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(b'', (target_ip, port))
            try:
                data, _ = sock.recvfrom(1024)
                open_udp_ports.append(port)
                print(f"{GREEN}[+] UDP Port {port} OPEN{RESET}")
            except socket.timeout:
                pass
        except:
            pass
    return open_udp_ports

def traceroute_target(target_ip):
    print(f"{CYAN}[*] Traceroute başlatılıyor...{RESET}")
    try:
        result = subprocess.check_output(["tracert" if os.name == "nt" else "traceroute", target_ip], stderr=subprocess.DEVNULL)
        print(result.decode())
    except Exception as e:
        print(f"{RED}[!] Traceroute başarısız: {e}{RESET}")

def os_detection(target_ip):
    print(f"{CYAN}[*] OS Detection başlatılıyor...{RESET}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target_ip, 80))
        ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        if ttl <= 64:
            print(f"{GREEN}[+] Linux / Unix sistem tespit edildi (TTL={ttl}){RESET}")
        elif ttl <= 129:
            print(f"{GREEN}[+] Windows sistem tespit edildi (TTL={ttl}){RESET}")
        else:
            print(f"{YELLOW}[-] OS tespit edilemedi (TTL={ttl}){RESET}")
    except:
        print(f"{RED}[!] OS tespiti başarısız{RESET}")

def ssh_brute_force(target_ip, userlist, passlist):
    import paramiko
    print(f"{YELLOW}[*] SSH Brute Force başlatılıyor...{RESET}")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for user in userlist:
        for pwd in passlist:
            try:
                client.connect(target_ip, port=22, username=user.strip(), password=pwd.strip(), timeout=3)
                print(f"{GREEN}[✔] SSH Başarılı: {user.strip()}:{pwd.strip()}{RESET}")
                return {"user": user.strip(), "password": pwd.strip()}
            except:
                continue
    print(f"{RED}[x] SSH brute force başarısız.{RESET}")
    return None
parser = argparse.ArgumentParser(description="WorldEye X - Full CTF & Recon Tool")
parser.add_argument("-t", "--target", required=True, help="Hedef IP veya domain")
parser.add_argument("-f", "--fullscan", action="store_true", help="1-1024 arası tarama")
parser.add_argument("-m", "--smart", action="store_true", help="Yaygın portları tara")
parser.add_argument("-s", "--save", metavar="out.json", help="JSON çıktısı")
parser.add_argument("-x", "--threads", type=int, default=100, help="Eşzamanlılık seviyesi")
parser.add_argument("--ipv6", action="store_true", help="IPv6 ile tara")
parser.add_argument("--udp", action="store_true", help="UDP portlarını tara")
parser.add_argument("--trace", action="store_true", help="Traceroute yap")
parser.add_argument("--os", action="store_true", help="OS tespiti yap")
parser.add_argument("--ssh-brute", action="store_true", help="SSH brute force")
parser.add_argument("--userlist", help="Kullanıcı adı dosyası")
parser.add_argument("--passlist", help="Parola dosyası")
args = parser.parse_args()

ascii_eye_opening()
target_ip = resolve_target(args.target, ipv6=args.ipv6)
print(f"{YELLOW}Target: {args.target} → IP: {target_ip}{RESET}")

if args.fullscan:
    ports = range(1, 1025)
elif args.smart:
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080, 8443]
else:
    print(f"{RED}[!] -f veya -m seçilmeli{RESET}")
    exit(1)

open_ports, closed_count, duration = scan_ports_concurrent(target_ip, ports, threads=args.threads, ipv6=args.ipv6)
print(f"{CYAN}Süre: {duration:.2f}s | Açık: {len(open_ports)} | Kapalı: {closed_count}{RESET}")

brute_result = None
if args.ssh_brute and args.userlist and args.passlist:
    if os.path.exists(args.userlist) and os.path.exists(args.passlist):
        with open(args.userlist) as f1, open(args.passlist) as f2:
            userlist = f1.readlines()
            passlist = f2.readlines()
            brute_result = ssh_brute_force(target_ip, userlist, passlist)
    else:
        print(f"{RED}[!] userlist/passlist bulunamadı{RESET}")

udp_results = []
if args.udp:
    udp_ports = [53, 123, 161, 500]
    udp_results = udp_scan_ports(target_ip, udp_ports)

if args.os:
    os_detection(target_ip)

if args.trace:
    traceroute_target(target_ip)

if args.save:
    with open(args.save, "w") as f:
        json.dump({
            "target": args.target,
            "ip": target_ip,
            "timestamp": str(datetime.now()),
            "open_ports": open_ports,
            "udp_open_ports": udp_results,
            "ssh_login": brute_result
        }, f, indent=2)
    print(f"{GREEN}[✔] Kayıt tamamlandı: {args.save}{RESET}")