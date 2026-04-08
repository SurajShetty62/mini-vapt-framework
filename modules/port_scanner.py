import socket
import concurrent.futures
import time

# Well-known port service map
SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
    119: "NNTP", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    194: "IRC", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP Submission", 631: "IPP",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS Proxy",
    1433: "MSSQL", 1521: "Oracle DB", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 6667: "IRC",
    8080: "HTTP Alternate", 8443: "HTTPS Alternate",
    8888: "HTTP Dev", 27017: "MongoDB",
}

# Ports that are high-risk if open
HIGH_RISK_PORTS = {23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017}
MEDIUM_RISK_PORTS = {21, 22, 25, 53, 111, 514, 1080, 2049, 6667, 8080}

def scan_single_port(host: str, port: int, timeout: float = 1.0) -> dict | None:
    """Try to connect to a single port. Returns dict if open, None if closed."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                service = SERVICE_MAP.get(port, "Unknown")
                risk = "HIGH" if port in HIGH_RISK_PORTS else (
                    "MEDIUM" if port in MEDIUM_RISK_PORTS else "LOW"
                )
                banner = grab_banner(host, port)
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner,
                    "risk": risk,
                }
    except (socket.timeout, socket.error, OSError):
        pass
    return None

def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """Try to grab a service banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            if port in (80, 8080, 8443, 8888):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner on connect
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner[:200] if banner else ""
    except Exception:
        return ""

def parse_port_range(port_range: str) -> list[int]:
    """Parse port range string like '1-1024' or '80,443,8080' into list."""
    ports = []
    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-")
                ports.extend(range(int(start), int(end) + 1))
            except ValueError:
                continue
        else:
            try:
                ports.append(int(part))
            except ValueError:
                continue
    return list(set(ports))

def scan_ports(host: str, port_range: str = "1-1024") -> dict:
    """
    Perform multithreaded TCP port scan on the target host.
    """
    start_time = time.time()
    open_ports = []
    findings = []

    # Resolve hostname
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        return {
            "module": "Port Scanner",
            "status": "error",
            "error": f"Could not resolve host '{host}': {str(e)}",
            "findings": [],
            "risk_level": "unknown",
            "open_ports": [],
            "duration": 0,
        }

    ports = parse_port_range(port_range)
    if not ports:
        return {
            "module": "Port Scanner",
            "status": "error",
            "error": "Invalid port range specified.",
            "findings": [],
            "risk_level": "unknown",
            "open_ports": [],
            "duration": 0,
        }

    # Limit scan to prevent abuse
    MAX_PORTS = 2000
    if len(ports) > MAX_PORTS:
        ports = ports[:MAX_PORTS]

    # Multithreaded scan
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {
            executor.submit(scan_single_port, ip, port): port for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])

    # Build findings for high/medium risk ports
    for port_info in open_ports:
        if port_info["risk"] in ("HIGH", "MEDIUM"):
            description = get_port_risk_description(port_info["port"])
            findings.append({
                "type": f"Open {port_info['risk']} Risk Port",
                "severity": port_info["risk"],
                "port": port_info["port"],
                "service": port_info["service"],
                "banner": port_info["banner"],
                "description": description,
                "recommendation": get_port_recommendation(port_info["port"]),
            })

    duration = round(time.time() - start_time, 2)

    # Sort findings: HIGH first, then MEDIUM, then LOW
    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda x: sev_order.get(x.get("severity", "INFO"), 4))

    severities = [f["severity"] for f in findings]
    if "HIGH" in severities:
        risk_level = "HIGH"
    elif "MEDIUM" in severities:
        risk_level = "MEDIUM"
    elif open_ports:
        risk_level = "LOW"
    else:
        risk_level = "NONE"

    return {
        "module": "Port Scanner",
        "status": "completed",
        "target": host,
        "resolved_ip": ip,
        "ports_scanned": len(ports),
        "open_ports": open_ports,
        "findings": findings,
        "risk_level": risk_level,
        "duration": duration,
        "summary": f"{len(open_ports)} open port(s) found. {len(findings)} high/medium risk port(s).",
    }

def get_port_risk_description(port: int) -> str:
    descriptions = {
        23: "Telnet is unencrypted — credentials sent in plaintext.",
        3389: "RDP exposed to internet is a common ransomware/brute-force target.",
        3306: "MySQL port exposed — database directly accessible from network.",
        5432: "PostgreSQL port exposed — database directly accessible from network.",
        6379: "Redis often runs without authentication — full data access possible.",
        27017: "MongoDB often runs without authentication — full data access possible.",
        5900: "VNC exposed — remote desktop access, often weak or no auth.",
        445: "SMB port exposed — EternalBlue and ransomware propagation vector.",
        1433: "MSSQL port exposed — direct database access from network.",
        21: "FTP transmits credentials in plaintext. Use SFTP/FTPS instead.",
        22: "SSH open — ensure key-based auth is enforced, no root login.",
        1080: "SOCKS proxy may allow traffic tunneling through your network.",
    }
    return descriptions.get(port, f"Port {port} is open and potentially accessible.")

def get_port_recommendation(port: int) -> str:
    recs = {
        23: "Disable Telnet; use SSH instead.",
        3389: "Restrict RDP to VPN only; enable NLA and account lockout.",
        3306: "Bind MySQL to 127.0.0.1; never expose to public internet.",
        5432: "Bind PostgreSQL to localhost; use firewall rules.",
        6379: "Enable Redis authentication (requirepass); bind to localhost.",
        27017: "Enable MongoDB authentication; restrict network access.",
        5900: "Use VPN for VNC access; enable strong password.",
        445: "Block SMB on perimeter firewall; patch for EternalBlue (MS17-010).",
        1433: "Bind MSSQL to internal interface; enable firewall rules.",
        21: "Replace FTP with SFTP or FTPS.",
        22: "Disable password auth; use SSH keys; restrict to known IPs.",
        1080: "Disable if not needed; restrict with authentication.",
    }
    return recs.get(port, "Restrict access via firewall; close if not needed.")
