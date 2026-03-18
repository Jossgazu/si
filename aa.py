#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           SUBDOMAIN ENUMERATOR - Kali Linux                  ║
║  Herramientas: Findomain, SubFinder, Assetfinder,            ║
║                SubOver, Subbrute + técnicas propias          ║
╚══════════════════════════════════════════════════════════════╝

Uso:
    python3 subdomain_enum.py -d ejemplo.com
    python3 subdomain_enum.py -d ejemplo.com -o resultados.txt
    python3 subdomain_enum.py -d ejemplo.com --wordlist /path/to/wordlist.txt
    python3 subdomain_enum.py -d ejemplo.com --tools findomain,subfinder,subbrute
"""

import argparse
import subprocess
import sys
import os
import json
import socket
import threading
import time
import shutil
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ──────────────────────────────────────────────
# COLORES PARA TERMINAL
# ──────────────────────────────────────────────
class Colors:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

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


# ──────────────────────────────────────────────
# UTILIDADES
# ──────────────────────────────────────────────
def tool_available(name):
    """Verifica si una herramienta está instalada en el sistema."""
    return shutil.which(name) is not None

def run_command(cmd, timeout=120):
    """Ejecuta un comando del sistema y retorna su salida."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        warn(f"Timeout al ejecutar: {cmd}")
        return ""
    except Exception as e:
        warn(f"Error ejecutando comando: {e}")
        return ""

def parse_subdomains(output, domain):
    """Extrae subdominios válidos de una salida de texto."""
    subdomains = set()
    if not output:
        return subdomains
    for line in output.splitlines():
        line = line.strip().lower()
        # Limpiar prefijos comunes de herramientas
        for prefix in ["[+]", "[-]", "[*]", "[INF]", "[WRN]", "subdomain:", "host:"]:
            if line.startswith(prefix):
                line = line[len(prefix):].strip()
        # Validar que sea un subdominio del dominio objetivo
        if domain in line and " " not in line and len(line) < 255:
            # Eliminar protocolos
            for proto in ["https://", "http://"]:
                if line.startswith(proto):
                    line = line[len(proto):]
            # Eliminar rutas
            line = line.split("/")[0].strip()
            if line.endswith(f".{domain}") or line == domain:
                subdomains.add(line)
    return subdomains


# ══════════════════════════════════════════════
# MÓDULO 1: FINDOMAIN
# ══════════════════════════════════════════════
def run_findomain(domain):
    """
    Findomain: usa múltiples fuentes de datos (crt.sh, Virustotal, etc.)
    para descubrir subdominios. Extremadamente rápido.
    """
    subdomains = set()
    if not tool_available("findomain"):
        warn("Findomain no encontrado. Instalar: apt install findomain")
        return subdomains

    info("Ejecutando Findomain...")
    output = run_command(f"findomain -t {domain} --quiet", timeout=60)
    subdomains = parse_subdomains(output, domain)
    success(f"Findomain encontró {len(subdomains)} subdominios")
    return subdomains


# ══════════════════════════════════════════════
# MÓDULO 2: SUBFINDER
# ══════════════════════════════════════════════
def run_subfinder(domain):
    """
    SubFinder: herramienta rápida con múltiples fuentes pasivas.
    Usa APIs de: Shodan, VirusTotal, CertSpotter, HackerTarget, etc.
    """
    subdomains = set()
    if not tool_available("subfinder"):
        warn("SubFinder no encontrado. Instalar: apt install subfinder  o  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        return subdomains

    info("Ejecutando SubFinder...")
    output = run_command(f"subfinder -d {domain} -silent", timeout=90)
    subdomains = parse_subdomains(output, domain)
    success(f"SubFinder encontró {len(subdomains)} subdominios")
    return subdomains


# ══════════════════════════════════════════════
# MÓDULO 3: AQUAPONE (técnica de reconocimiento)
# ══════════════════════════════════════════════
def run_aquapone(domain):
    """
    Aquapone: combinación de técnicas de reconocimiento.
    Implementación propia usando múltiples APIs públicas:
    - crt.sh (Certificate Transparency)
    - HackerTarget
    - BufferOver
    - ThreatCrowd
    - RapidDNS
    """
    subdomains = set()
    info("Ejecutando técnicas Aquapone (APIs múltiples)...")

    # ── crt.sh ──
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=20, headers={"User-Agent": "SubdomainEnum/1.0"}
        )
        if r.status_code == 200:
            data = r.json()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower().lstrip("*.")
                    if sub.endswith(f".{domain}") or sub == domain:
                        subdomains.add(sub)
    except Exception as e:
        warn(f"crt.sh error: {e}")

    # ── HackerTarget ──
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=15
        )
        if r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.splitlines():
                parts = line.split(",")
                if parts and domain in parts[0]:
                    subdomains.add(parts[0].strip().lower())
    except Exception as e:
        warn(f"HackerTarget error: {e}")

    # ── BufferOver ──
    try:
        r = requests.get(
            f"https://dns.bufferover.run/dns?q=.{domain}",
            timeout=15
        )
        if r.status_code == 200:
            data = r.json()
            for item in data.get("FDNS_A", []) + data.get("RDNS", []):
                parts = item.split(",")
                for p in parts:
                    p = p.strip().lower()
                    if p.endswith(f".{domain}"):
                        subdomains.add(p)
    except Exception as e:
        warn(f"BufferOver error: {e}")

    # ── RapidDNS ──
    try:
        r = requests.get(
            f"https://rapiddns.io/subdomain/{domain}?full=1#result",
            timeout=15
        )
        if r.status_code == 200:
            import re
            found_subs = re.findall(r'[\w\-\.]+\.' + re.escape(domain), r.text)
            for s in found_subs:
                subdomains.add(s.lower())
    except Exception as e:
        warn(f"RapidDNS error: {e}")

    success(f"Aquapone (APIs) encontró {len(subdomains)} subdominios")
    return subdomains


# ══════════════════════════════════════════════
# MÓDULO 4: SUBOVER (verificación de takeover)
# ══════════════════════════════════════════════
def run_subover(domain, known_subdomains=None):
    """
    SubOver: verifica si los subdominios son susceptibles a takeover.
    También actúa como descubridor adicional usando assetfinder/amass si disponible.
    """
    subdomains = set()

    # Intentar con assetfinder (herramienta asociada a SubOver workflow)
    if tool_available("assetfinder"):
        info("Ejecutando Assetfinder (parte del workflow SubOver)...")
        output = run_command(f"assetfinder --subs-only {domain}", timeout=60)
        subs = parse_subdomains(output, domain)
        subdomains.update(subs)
        success(f"Assetfinder encontró {len(subs)} subdominios")
    else:
        warn("Assetfinder no encontrado. Instalar: go install github.com/tomnomnom/assetfinder@latest")

    # Intentar con subover directamente
    if tool_available("subover"):
        info("Ejecutando SubOver...")
        output = run_command(f"subover -list <(echo '{domain}')", timeout=60)
        subs = parse_subdomains(output, domain)
        subdomains.update(subs)
    else:
        warn("SubOver no encontrado. Instalar: go install github.com/Ice3man543/SubOver@latest")

    return subdomains


# ══════════════════════════════════════════════
# MÓDULO 5: SUBBRUTE (fuerza bruta por wordlist)
# ══════════════════════════════════════════════
def _resolve_subdomain(sub_domain):
    """Resuelve un subdominio via DNS. Retorna el subdominio si existe."""
    try:
        socket.setdefaulttimeout(3)
        socket.gethostbyname(sub_domain)
        return sub_domain
    except (socket.gaierror, socket.timeout):
        return None

def run_subbrute(domain, wordlist_path=None, threads=50):
    """
    Subbrute: enumeración por fuerza bruta usando wordlist.
    Si subbrute está instalado, lo usa. Si no, implementación propia
    con resolución DNS multihilo.
    """
    subdomains = set()

    # Usar subbrute si está disponible
    if tool_available("subbrute"):
        info("Ejecutando Subbrute (herramienta nativa)...")
        cmd = f"subbrute {domain}"
        if wordlist_path and os.path.exists(wordlist_path):
            cmd += f" -s {wordlist_path}"
        output = run_command(cmd, timeout=300)
        subs = parse_subdomains(output, domain)
        subdomains.update(subs)
        success(f"Subbrute (nativo) encontró {len(subs)} subdominios")
        return subdomains

    # Implementación propia con DNS bruteforce
    info("Ejecutando Subbrute (implementación DNS bruteforce)...")

    # Wordlist por defecto si no se especifica una
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
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        info(f"Wordlist cargada: {len(words)} palabras")
    else:
        words = default_words
        info(f"Usando wordlist interna: {len(words)} palabras")

    candidates = [f"{w}.{domain}" for w in words]
    resolved = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_resolve_subdomain, c): c for c in candidates}
        for future in as_completed(futures):
            result = future.result()
            if result:
                subdomains.add(result)
                resolved += 1
                found(result)

    success(f"Subbrute (DNS brute) encontró {len(subdomains)} subdominios")
    return subdomains


# ══════════════════════════════════════════════
# MÓDULO EXTRA: DNS Zone Transfer intento
# ══════════════════════════════════════════════
def try_zone_transfer(domain):
    """Intenta transferencia de zona DNS (AXFR)."""
    subdomains = set()
    if not tool_available("dig"):
        return subdomains

    info("Intentando transferencia de zona DNS (AXFR)...")
    # Obtener NS records
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


# ══════════════════════════════════════════════
# ORQUESTADOR PRINCIPAL
# ══════════════════════════════════════════════
def enumerate_subdomains(domain, wordlist=None, output_file=None, selected_tools=None):
    banner()
    start_time = datetime.now()
    all_subdomains = set()

    print(f"{Colors.BOLD}Target: {Colors.CYAN}{domain}{Colors.RESET}")
    print(f"{Colors.BOLD}Inicio: {Colors.WHITE}{start_time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    print("─" * 60)

    tools = selected_tools or ["findomain", "subfinder", "aquapone", "subover", "subbrute", "axfr"]

    # ── Findomain ──
    if "findomain" in tools:
        print(f"\n{Colors.BOLD}[1/6] FINDOMAIN{Colors.RESET}")
        subs = run_findomain(domain)
        all_subdomains.update(subs)

    # ── SubFinder ──
    if "subfinder" in tools:
        print(f"\n{Colors.BOLD}[2/6] SUBFINDER{Colors.RESET}")
        subs = run_subfinder(domain)
        all_subdomains.update(subs)

    # ── Aquapone ──
    if "aquapone" in tools:
        print(f"\n{Colors.BOLD}[3/6] AQUAPONE (APIs públicas){Colors.RESET}")
        subs = run_aquapone(domain)
        all_subdomains.update(subs)

    # ── SubOver ──
    if "subover" in tools:
        print(f"\n{Colors.BOLD}[4/6] SUBOVER / ASSETFINDER{Colors.RESET}")
        subs = run_subover(domain, known_subdomains=all_subdomains)
        all_subdomains.update(subs)

    # ── Subbrute ──
    if "subbrute" in tools:
        print(f"\n{Colors.BOLD}[5/6] SUBBRUTE (DNS Brute Force){Colors.RESET}")
        subs = run_subbrute(domain, wordlist_path=wordlist)
        all_subdomains.update(subs)

    # ── Zone Transfer ──
    if "axfr" in tools:
        print(f"\n{Colors.BOLD}[6/6] DNS ZONE TRANSFER (AXFR){Colors.RESET}")
        subs = try_zone_transfer(domain)
        all_subdomains.update(subs)

    # ──────────────────────────────────────────
    # RESULTADOS FINALES
    # ──────────────────────────────────────────
    elapsed = datetime.now() - start_time
    sorted_subs = sorted(all_subdomains)

    print(f"\n{'═' * 60}")
    print(f"{Colors.BOLD}{Colors.GREEN}RESULTADOS FINALES{Colors.RESET}")
    print(f"{'═' * 60}")
    print(f"  Dominio objetivo : {Colors.CYAN}{domain}{Colors.RESET}")
    print(f"  Total único      : {Colors.GREEN}{len(sorted_subs)}{Colors.RESET} subdominios")
    print(f"  Tiempo total     : {Colors.WHITE}{elapsed}{Colors.RESET}")
    print(f"{'─' * 60}")

    for sub in sorted_subs:
        print(f"  {Colors.GREEN}•{Colors.RESET} {sub}")

    # Guardar en archivo TXT (sin duplicados, ordenados)
    if output_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"subdominios_{domain}_{timestamp}.txt"

    with open(output_file, "w") as f:
        f.write(f"# Subdomain Enumeration Results\n")
        f.write(f"# Target : {domain}\n")
        f.write(f"# Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Total  : {len(sorted_subs)} unique subdomains\n")
        f.write(f"# Tools  : {', '.join(tools)}\n")
        f.write(f"{'#' * 50}\n\n")
        for sub in sorted_subs:
            f.write(f"{sub}\n")

    print(f"\n{Colors.GREEN}[✓]{Colors.RESET} Resultados guardados en: {Colors.CYAN}{output_file}{Colors.RESET}")
    return sorted_subs


# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────
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
    parser.add_argument(
        "-d", "--domain", required=True,
        help="Dominio objetivo (ej: example.com)"
    )
    parser.add_argument(
        "-o", "--output", default=None,
        help="Archivo de salida TXT (por defecto: subdominios_<domain>_<timestamp>.txt)"
    )
    parser.add_argument(
        "--wordlist", default=None,
        help="Ruta a wordlist personalizada para Subbrute"
    )
    parser.add_argument(
        "--tools", default=None,
        help="Herramientas a usar separadas por coma: findomain,subfinder,aquapone,subover,subbrute,axfr"
    )

    args = parser.parse_args()

    # Parsear herramientas seleccionadas
    selected = None
    if args.tools:
        selected = [t.strip().lower() for t in args.tools.split(",")]

    # Validar dependencias de Python
    try:
        import requests
    except ImportError:
        error("Módulo 'requests' no encontrado. Instalar: pip3 install requests")
        sys.exit(1)

    # Ejecutar enumeración
    enumerate_subdomains(
        domain=args.domain,
        wordlist=args.wordlist,
        output_file=args.output,
        selected_tools=selected
    )


if __name__ == "__main__":
    main()
