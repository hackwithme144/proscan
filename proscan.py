#!/usr/bin/env python3

import socket
import ipaddress
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ----------------------------
# ARGUMENT PARSER
# ----------------------------
parser = argparse.ArgumentParser(description="ProScan - Network Scanner")
parser.add_argument("-t", "--target", required=True, help="Target IP or Subnet")
parser.add_argument("-p", "--ports", help="Port range (e.g. 1-1000)")
parser.add_argument("--fast", action="store_true", help="Scan common ports only")
args = parser.parse_args()

# ----------------------------
# CONFIG
# ----------------------------
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]

SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    8080: "HTTP-alt"
}

VULN_MAP = {
    21: "Anonymous login / brute force",
    22: "SSH brute force",
    23: "Plaintext credentials (insecure)",
    25: "Email spoofing / relay",
    80: "XSS, SQL Injection",
    443: "SSL/TLS misconfiguration",
    445: "SMB vulnerabilities (EternalBlue)"
}

# ----------------------------
# PORT PARSER
# ----------------------------
def parse_ports(port_input):
    if "-" in port_input:
        start, end = map(int, port_input.split("-"))
        return range(start, end + 1)
    return [int(port_input)]


# ----------------------------
# HOST DISCOVERY
# ----------------------------
def is_host_alive(ip):
    for port in [80, 443, 22]:
        try:
            sock = socket.socket()
            sock.settimeout(0.3)
            if sock.connect_ex((ip, port)) == 0:
                sock.close()
                return True
            sock.close()
        except:
            pass
    return False


def discover_hosts(network):
    print("\n[*] Discovering live hosts...\n")
    live_hosts = []

    for ip in network.hosts():
        ip = str(ip)
        if is_host_alive(ip):
            print(f"[+] {ip} is alive")
            live_hosts.append(ip)

    return live_hosts


# ----------------------------
# BANNER GRABBING (SAFE)
# ----------------------------
def get_http_banner(sock):
    try:
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        return sock.recv(1024).decode(errors="ignore")
    except:
        return None


def get_ftp_banner(sock):
    try:
        return sock.recv(1024).decode(errors="ignore")
    except:
        return None


# ----------------------------
# SCAN SINGLE PORT
# ----------------------------
def scan_port(target, port):
    result = None

    try:
        sock = socket.socket()
        sock.settimeout(0.5)

        if sock.connect_ex((target, port)) == 0:
            result = {
                "port": port,
                "service": SERVICE_MAP.get(port, "Unknown"),
                "banner": None,
                "risk": VULN_MAP.get(port, "General exposure")
            }

            # Service-specific banner grabbing
            if port in [80, 8080, 443]:
                banner = get_http_banner(sock)
                if banner:
                    result["banner"] = banner

            elif port == 21:
                banner = get_ftp_banner(sock)
                if banner:
                    result["banner"] = banner

        sock.close()

    except:
        pass

    return result


# ----------------------------
# SCAN TARGET
# ----------------------------
def scan_target(target, ports):
    print("\n" + "="*60)
    print("              IronScan Network Report")
    print("="*60)

    print(f"\nTarget      : {target}")
    print(f"Scan Time   : {datetime.now()}\n")

    results = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, target, p) for p in ports]

        for f in futures:
            res = f.result()
            if res:
                results.append(res)

    print("-------------------- OPEN PORTS --------------------\n")

    high_risk = []

    for r in results:
        print(f"[+] {r['port']}/tcp")
        print(f"    Service : {r['service']}")

        # Banner parsing
        if r["banner"]:
            lines = r["banner"].split("\n")

            for line in lines:
                if "Server" in line:
                    print(f"    Server  : {line.split(':',1)[1].strip()}")
                elif "Location" in line:
                    print(f"    Endpoint: {line.split(':',1)[1].strip()}")
                elif "FTP" in line or "220" in line:
                    print(f"    Banner  : {line.strip()}")

        print(f"    Risk    : {r['risk']}\n")

        if r["service"] in ["FTP", "HTTP", "SMB"]:
            high_risk.append(r["service"])

    print("----------------------------------------------------\n")

    print("Summary:")
    print(f"  • Total Open Ports   : {len(results)}")

    if high_risk:
        print(f"  • High Risk Services : {', '.join(set(high_risk))}")
    else:
        print("  • No major risks detected")

    print("\n" + "="*60 + "\n")


# ----------------------------
# MAIN
# ----------------------------
def main():
    target_input = args.target

    # Select ports
    if args.fast:
        ports = COMMON_PORTS
    elif args.ports:
        ports = parse_ports(args.ports)
    else:
        ports = COMMON_PORTS

    try:
        network = ipaddress.ip_network(target_input, strict=False)

        if network.num_addresses > 1:
            # Subnet mode
            live_hosts = discover_hosts(network)

            if not live_hosts:
                print("[-] No live hosts found.")
                return

            print("\n[+] Live Hosts:")
            for i, ip in enumerate(live_hosts):
                print(f"{i}. {ip}")

            choice = int(input("Select target index: "))
            target = live_hosts[choice]

        else:
            target = target_input

    except:
        target = target_input

    scan_target(target, ports)


# ----------------------------
# ENTRY
# ----------------------------
if __name__ == "__main__":
    main()
