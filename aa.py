#!/usr/bin/env python3
import argparse
import subprocess
import sys
import os
import socket
import shutil
import requests
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

class Colors:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def banner():
    print(f"""{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║         SUBDOMAIN ENUMERATOR v1.0 - Kali Linux               ║
║  Findomain · SubFinder · Aquapone · SubOver · Subbrute       ║
╚══════════════════════════════════════════════════════════════╝
{Colors.RESET}""")

def info(msg):    print(f"{Colors.BLUE}[*]{Colors.RESET} {msg}")
def success(msg): print(f"{Colors.GREEN}[+]{Colors.RESET} {msg}")
def warn(msg):    print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")
def error(msg):   print(f"{Colors.RED}[-]{Colors.RESET} {msg}")
def found(msg):   print(f"{Colors.GREEN}[FOUND]{Colors.RESET} {msg}")

def tool_available(name):
    return shutil.which(name) is not None

def run_command(cmd, timeout=120):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        warn(f"Timeout: {cmd}")
        return ""
    except Exception as e:
        warn(f"Error: {e}")
        return ""

def parse_subdomains(output, domain):
    subdomains = set()
    if not output:
        return subdomains
    for line in output.splitlines():
        line = line.strip().lower()
        for prefix in ["[+]", "[-]", "[*]", "[INF]", "[WRN]", "subdomain:", "host:"]:
            if line.startswith(prefix):
                line = line[len(prefix):].strip()
        if domain in line and " " not in line and len(line) < 255:
            for proto in ["https://", "http://"]:
                if line.startswith(proto):
                    line = line[len(proto):]
            line = line.split("/")[0].strip()
            if line.endswith(f".{domain}") or line == domain:
                subdomains.add(line)
    return subdomains


# ── FINDOMAIN ──
def run_findomain(domain):
    subdomains = set()
    if not tool_available("findomain"):
        warn("Findomain no encontrado. Instalar: apt install findomain")
        return subdomains
    info("Ejecutando Findomain...")
    output = run_command(f"findomain -t {domain} --quiet", timeout=60)
    subdomains = parse_subdomains(output, domain)
    success(f"Findomain encontró {len(subdomains)} subdominios")
    return subdomains


# ── SUBFINDER ──
def run_subfinder(domain):
    subdomains = set()
    if not tool_available("subfinder"):
        warn("SubFinder no encontrado. Instalar: apt install subfinder")
        return subdomains
    info("Ejecutando SubFinder...")
    output = run_command(f"subfinder -d {domain} -silent", timeout=90)
    subdomains = parse_subdomains(output, domain)
    success(f"SubFinder encontró {len(subdomains)} subdominios")
    return subdomains


# ── AQUAPONE (APIs públicas) ──
def run_aquapone(domain):
    subdomains = set()
    info("Ejecutando Aquapone (crt.sh, HackerTarget, BufferOver, RapidDNS)...")

    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20,
                         headers={"User-Agent": "SubdomainEnum/1.0"})
        if r.status_code == 200:
            for entry in r.json():
                for sub in entry.get("name_value", "").split("\n"):
                    sub = sub.strip().lower().lstrip("*.")
                    if sub.endswith(f".{domain}") or sub == domain:
                        subdomains.add(sub)
    except Exception as e:
        warn(f"crt.sh: {e}")

    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
        if r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.splitlines():
                parts = line.split(",")
                if parts and domain in parts[0]:
                    subdomains.add(parts[0].strip().lower())
    except Exception as e:
        warn(f"HackerTarget: {e}")

    try:
        r = requests.get(f"https://dns.bufferover.run/dns?q=.{domain}", timeout=15)
        if r.status_code == 200:
            data = r.json()
            for item in data.get("FDNS_A", []) + data.get("RDNS", []):
                for p in item.split(","):
                    p = p.strip().lower()
                    if p.endswith(f".{domain}"):
                        subdomains.add(p)
    except Exception as e:
        warn(f"BufferOver: {e}")

    try:
        r = requests.get(f"https://rapiddns.io/subdomain/{domain}?full=1#result", timeout=15)
        if r.status_code == 200:
            for s in re.findall(r'[\w\-\.]+\.' + re.escape(domain), r.text):
                subdomains.add(s.lower())
    except Exception as e:
        warn(f"RapidDNS: {e}")

    success(f"Aquapone encontró {len(subdomains)} subdominios")
    return subdomains


# ── SUBOVER / ASSETFINDER ──
def run_subover(domain, known_subdomains=None):
    subdomains = set()
    if tool_available("assetfinder"):
        info("Ejecutando Assetfinder...")
        output = run_command(f"assetfinder --subs-only {domain}", timeout=60)
        subs = parse_subdomains(output, domain)
        subdomains.update(subs)
        success(f"Assetfinder encontró {len(subs)} subdominios")
    else:
        warn("Assetfinder no encontrado. Instalar: go install github.com/tomnomnom/assetfinder@latest")
    if tool_available("subover"):
        info("Ejecutando SubOver...")
        output = run_command(f"subover -list <(echo '{domain}')", timeout=60)
        subdomains.update(parse_subdomains(output, domain))
    else:
        warn("SubOver no encontrado. Instalar: go install github.com/Ice3man543/SubOver@latest")
    return subdomains


# ── SUBBRUTE (DNS brute force) ──
def _resolve_subdomain(sub_domain):
    try:
        socket.setdefaulttimeout(3)
        socket.gethostbyname(sub_domain)
        return sub_domain
    except (socket.gaierror, socket.timeout):
        return None

def run_subbrute(domain, wordlist_path=None, threads=50):
    subdomains = set()
    if tool_available("subbrute"):
        info("Ejecutando Subbrute (nativo)...")
        cmd = f"subbrute {domain}" + (f" -s {wordlist_path}" if wordlist_path and os.path.exists(wordlist_path) else "")
        output = run_command(cmd, timeout=300)
        subs = parse_subdomains(output, domain)
        subdomains.update(subs)
        success(f"Subbrute encontró {len(subs)} subdominios")
        return subdomains

    info("Ejecutando Subbrute (DNS brute force)...")
    default_words = [
        "www", "mail", "ftp", "smtp", "pop", "imap", "vpn", "remote", "api",
        "dev", "staging", "test", "demo", "beta", "alpha", "prod", "production",
        "admin", "portal", "login", "app", "mobile", "m", "cdn", "static",
        "assets", "media", "img", "images", "upload", "downloads", "files",
        "blog", "shop", "store", "news", "support", "help", "docs", "wiki",
        "forum", "community", "gitlab", "jenkins", "jira", "confluence",
        "cpanel", "webmail", "autodiscover", "autoconfig", "ns", "ns1", "ns2",
        "mx", "mx1", "mx2", "smtp1", "smtp2", "pop3", "imap4", "webdav",
        "owa", "exchange", "cloud", "aws", "azure", "gcp", "db", "database",
        "mysql", "postgres", "redis", "mongo", "elastic", "kibana", "grafana",
        "monitor", "status", "metrics", "logs", "backup", "secure", "ssl",
        "git", "svn", "code", "ci", "cd", "build", "deploy", "k8s", "docker",
        "proxy", "lb", "loadbalancer", "gateway", "edge", "origin", "internal",
        "intranet", "extranet", "corp", "office", "hr", "finance", "marketing",
        "auth", "oauth", "sso", "id", "accounts", "account", "my", "user",
        "v1", "v2", "v3", "api1", "api2", "service", "services", "microservice",
        "old", "new", "legacy", "archive", "test1", "test2", "dev1", "dev2",
        "uat", "qa", "sandbox", "preview", "stage", "preprod",
    ]

    if wordlist_path and os.path.exists(wordlist_path):
        info(f"Cargando wordlist: {wordlist_path}")
        with open(wordlist_path, "r", errors="ignore") as f:
            words = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    else:
        words = default_words
        info(f"Usando wordlist interna ({len(words)} palabras)")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_resolve_subdomain, f"{w}.{domain}"): w for w in words}
        for future in as_completed(futures):
            result = future.result()
            if result:
                subdomains.add(result)
                found(result)

    success(f"Subbrute encontró {len(subdomains)} subdominios")
    return subdomains


# ── DNS ZONE TRANSFER ──
def try_zone_transfer(domain):
    subdomains = set()
    if not tool_available("dig"):
        return subdomains
    info("Intentando Zone Transfer (AXFR)...")
    ns_output = run_command(f"dig +short NS {domain}")
    nameservers = [ns.rstrip(".") for ns in ns_output.splitlines() if ns.strip()]
    for ns in nameservers:
        output = run_command(f"dig axfr {domain} @{ns}", timeout=15)
        if "Transfer failed" not in output and "REFUSED" not in output:
            subs = parse_subdomains(output, domain)
            if subs:
                success(f"Zone transfer exitoso en {ns}! {len(subs)} registros")
                subdomains.update(subs)
    return subdomains


# ── ORQUESTADOR ──
def enumerate_subdomains(domain, wordlist=None, output_file=None, selected_tools=None):
    banner()
    start_time = datetime.now()
    all_subdomains = set()
    tools = selected_tools or ["findomain", "subfinder", "aquapone", "subover", "subbrute", "axfr"]

    print(f"{Colors.BOLD}Target: {Colors.CYAN}{domain}{Colors.RESET}")
    print(f"{Colors.BOLD}Inicio: {Colors.WHITE}{start_time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    print("─" * 60)

    steps = [
        ("findomain", "[1/6] FINDOMAIN",             lambda: run_findomain(domain)),
        ("subfinder", "[2/6] SUBFINDER",             lambda: run_subfinder(domain)),
        ("aquapone",  "[3/6] AQUAPONE",              lambda: run_aquapone(domain)),
        ("subover",   "[4/6] SUBOVER / ASSETFINDER", lambda: run_subover(domain, all_subdomains)),
        ("subbrute",  "[5/6] SUBBRUTE",              lambda: run_subbrute(domain, wordlist)),
        ("axfr",      "[6/6] DNS ZONE TRANSFER",     lambda: try_zone_transfer(domain)),
    ]

    for key, label, fn in steps:
        if key in tools:
            print(f"\n{Colors.BOLD}{label}{Colors.RESET}")
            all_subdomains.update(fn())

    elapsed = datetime.now() - start_time
    sorted_subs = sorted(all_subdomains)

    print(f"\n{'═' * 60}")
    print(f"{Colors.BOLD}{Colors.GREEN}RESULTADOS FINALES{Colors.RESET}")
    print(f"{'═' * 60}")
    print(f"  Dominio  : {Colors.CYAN}{domain}{Colors.RESET}")
    print(f"  Total    : {Colors.GREEN}{len(sorted_subs)}{Colors.RESET} subdominios únicos")
    print(f"  Tiempo   : {Colors.WHITE}{elapsed}{Colors.RESET}")
    print(f"{'─' * 60}")
    for sub in sorted_subs:
        print(f"  {Colors.GREEN}•{Colors.RESET} {sub}")

    if output_file is None:
        output_file = f"subdominios_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(output_file, "w") as f:
        f.write(f"# Target : {domain}\n")
        f.write(f"# Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Total  : {len(sorted_subs)} unique subdomains\n")
        f.write(f"# Tools  : {', '.join(tools)}\n\n")
        for sub in sorted_subs:
            f.write(f"{sub}\n")

    print(f"\n{Colors.GREEN}[✓]{Colors.RESET} Guardado en: {Colors.CYAN}{output_file}{Colors.RESET}")
    return sorted_subs


# ── ENTRY POINT ──
def main():
    parser = argparse.ArgumentParser(
        description="Subdomain Enumerator - Kali Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 subdomain_enum.py -d ejemplo.com
  python3 subdomain_enum.py -d ejemplo.com -o resultados.txt
  python3 subdomain_enum.py -d ejemplo.com --wordlist /usr/share/wordlists/dns/subdomains-top1million-5000.txt
  python3 subdomain_enum.py -d ejemplo.com --tools findomain,subfinder,aquapone
        """
    )
    parser.add_argument("-d", "--domain",  required=True, help="Dominio objetivo")
    parser.add_argument("-o", "--output",  default=None,  help="Archivo de salida .txt")
    parser.add_argument("--wordlist",      default=None,  help="Wordlist para Subbrute")
    parser.add_argument("--tools",         default=None,  help="Herramientas: findomain,subfinder,aquapone,subover,subbrute,axfr")
    args = parser.parse_args()

    try:
        import requests
    except ImportError:
        error("Instalar requests: pip3 install requests")
        sys.exit(1)

    selected = [t.strip().lower() for t in args.tools.split(",")] if args.tools else None
    enumerate_subdomains(domain=args.domain, wordlist=args.wordlist,
                         output_file=args.output, selected_tools=selected)

if __name__ == "__main__":
    main()
