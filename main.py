#!/usr/bin/env python3
"""
enum_subdominios.py
===================
Práctica 2 - Sesión 1: Footprinting y Reconocimiento
Universidad Católica de Santa María - Ing. de Sistemas

Ejecuta 5 herramientas de enumeración de subdominios sobre un dominio objetivo,
consolida los resultados, los deduplica, los ordena alfabéticamente y genera
un archivo .txt con el resultado final.

Herramientas utilizadas:
  1. Sublist3r     — Búsqueda en motores (Google, Bing, Yahoo, Baidu)
  2. Amass         — DNS brute-force + certificados TLS/SSL + alteración de nombres
  3. theHarvester  — OSINT (buscadores, VirusTotal, Shodan, etc.)
  4. Subfinder     — APIs públicas (crt.sh, HackerTarget, VirusTotal, etc.)
  5. DNSRecon      — Enumeración DNS (zona, reversa, SRV, bruteforce)

Uso:
    python3 enum_subdominios.py <dominio> [--output archivo.txt] [--timeout segundos]

Ejemplo:
    python3 enum_subdominios.py hackerone.com
    python3 enum_subdominios.py hackerone.com --output resultados.txt --timeout 120

Requisitos (Kali Linux):
    sudo apt install sublist3r amass theharvester subfinder dnsrecon -y
"""

import argparse
import datetime
import os
import re
import subprocess
import sys
import tempfile


# ──────────────────────────────────────────────
# CONFIGURACIÓN DE COLORES PARA LA TERMINAL
# ──────────────────────────────────────────────
class C:
    """Códigos ANSI para colores en terminal."""
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    GRAY   = "\033[90m"


def banner():
    print(f"""
{C.CYAN}{C.BOLD}
 ███████╗███╗   ██╗██╗   ██╗███╗   ███╗
 ██╔════╝████╗  ██║██║   ██║████╗ ████║
 █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
 ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
 ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
 ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
{C.RESET}{C.GRAY}  Subdomain Enumerator — Práctica 2 UCSM{C.RESET}
""")


# ──────────────────────────────────────────────
# FUNCIONES DE UTILIDAD
# ──────────────────────────────────────────────
def log_info(msg):
    print(f"  {C.BLUE}[*]{C.RESET} {msg}")

def log_ok(msg):
    print(f"  {C.GREEN}[+]{C.RESET} {msg}")

def log_warn(msg):
    print(f"  {C.YELLOW}[!]{C.RESET} {msg}")

def log_error(msg):
    print(f"  {C.RED}[-]{C.RESET} {msg}")

def log_section(titulo):
    print(f"\n{C.BOLD}{C.CYAN}{'─'*55}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}  {titulo}{C.RESET}")
    print(f"{C.CYAN}{'─'*55}{C.RESET}")


def herramienta_disponible(nombre: str) -> bool:
    """Verifica si una herramienta está disponible en el PATH."""
    resultado = subprocess.run(
        ["which", nombre],
        capture_output=True, text=True
    )
    return resultado.returncode == 0


def extraer_subdominios(texto: str, dominio: str) -> set:
    """
    Extrae subdominios válidos del texto de salida de una herramienta.
    Usa regex para encontrar FQDNs que terminen en el dominio objetivo.
    Normaliza a minúsculas y elimina líneas de encabezado/metadatos.
    """
    subdominios = set()

    # Patrón: captura cualquier FQDN que termine con el dominio dado
    # Acepta: sub.dominio.com, a.b.dominio.com, *.dominio.com (wildcards)
    patron = re.compile(
        r'(?:^|[\s,\[\]|:])(\*?[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.'
        + re.escape(dominio) + r')\b',
        re.MULTILINE
    )

    for match in patron.finditer(texto):
        sub = match.group(1).lower().lstrip("*.")
        if sub and sub.endswith(dominio):
            subdominios.add(sub)

    return subdominios


def ejecutar_herramienta(cmd: list, timeout: int, nombre: str) -> str:
    """
    Ejecuta un comando de sistema y retorna su salida (stdout + stderr).
    Captura tanto stdout como stderr porque algunas herramientas
    escriben resultados en stderr (ej. amass).
    """
    log_info(f"Ejecutando: {C.GRAY}{' '.join(cmd)}{C.RESET}")
    try:
        resultado = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        # Combinar stdout y stderr para no perder resultados
        salida = resultado.stdout + "\n" + resultado.stderr
        return salida
    except subprocess.TimeoutExpired:
        log_warn(f"{nombre} alcanzó el tiempo límite ({timeout}s). Usando resultados parciales.")
        return ""
    except FileNotFoundError:
        log_error(f"{nombre} no encontrado. ¿Está instalado?")
        return ""
    except Exception as e:
        log_error(f"Error inesperado en {nombre}: {e}")
        return ""


# ──────────────────────────────────────────────
# TÉCNICA 1: SUBLIST3R
# Motores de búsqueda: Google, Bing, Yahoo, Baidu, Ask
# Tipo: Reconocimiento PASIVO
# ──────────────────────────────────────────────
def ejecutar_sublist3r(dominio: str, timeout: int, directorio_tmp: str) -> set:
    """
    Sublist3r consulta múltiples motores de búsqueda para encontrar
    subdominios indexados públicamente. No genera tráfico directo
    al objetivo (reconocimiento pasivo).
    """
    log_section("TÉCNICA 1: Sublist3r (Motores de búsqueda)")

    if not herramienta_disponible("sublist3r"):
        log_error("sublist3r no está instalado. Instalar con: sudo apt install sublist3r")
        return set()

    archivo_salida = os.path.join(directorio_tmp, "sublist3r_out.txt")

    # -d: dominio objetivo
    # -o: archivo de salida (uno por línea, limpio)
    # -t: número de threads
    # -n: sin colores (para parseo limpio)
    cmd = ["sublist3r", "-d", dominio, "-o", archivo_salida, "-t", "10", "-n"]
    salida = ejecutar_herramienta(cmd, timeout, "Sublist3r")

    # Leer también el archivo de salida que genera sublist3r
    subdominios = extraer_subdominios(salida, dominio)
    if os.path.exists(archivo_salida):
        with open(archivo_salida, "r", errors="ignore") as f:
            subdominios |= extraer_subdominios(f.read(), dominio)

    log_ok(f"Sublist3r encontró: {C.GREEN}{len(subdominios)}{C.RESET} subdominios")
    return subdominios


# ──────────────────────────────────────────────
# TÉCNICA 2: AMASS
# DNS brute-force + TLS/SSL certificates + name alteration
# Tipo: Reconocimiento MIXTO (pasivo + activo)
# ──────────────────────────────────────────────
def ejecutar_amass(dominio: str, timeout: int, directorio_tmp: str) -> set:
    """
    Amass realiza enumeración profunda combinando:
    - Registro de transparencia de certificados TLS (Certificate Transparency Logs)
    - Consultas a múltiples fuentes de datos (ASN, RDAP, BGP)
    - Alteración y mutación de nombres descubiertos
    - Resolución DNS activa
    """
    log_section("TÉCNICA 2: Amass (DNS + TLS Certificates + Brute Force)")

    if not herramienta_disponible("amass"):
        log_error("amass no está instalado. Instalar con: sudo apt install amass")
        return set()

    archivo_salida = os.path.join(directorio_tmp, "amass_out.txt")

    # enum: modo enumeración
    # -d: dominio objetivo
    # -o: archivo de salida
    # -passive: solo fuentes pasivas (más rápido, menos intrusivo)
    cmd = ["amass", "enum", "-d", dominio, "-o", archivo_salida, "-passive"]
    salida = ejecutar_herramienta(cmd, timeout, "Amass")

    subdominios = extraer_subdominios(salida, dominio)
    if os.path.exists(archivo_salida):
        with open(archivo_salida, "r", errors="ignore") as f:
            subdominios |= extraer_subdominios(f.read(), dominio)

    log_ok(f"Amass encontró: {C.GREEN}{len(subdominios)}{C.RESET} subdominios")
    return subdominios


# ──────────────────────────────────────────────
# TÉCNICA 3: THEHARVESTER
# OSINT: buscadores, VirusTotal, Shodan, LinkedIn
# Tipo: Reconocimiento PASIVO
# ──────────────────────────────────────────────
def ejecutar_theharvester(dominio: str, timeout: int, directorio_tmp: str) -> set:
    """
    theHarvester recopila subdominios, correos electrónicos e IPs
    desde múltiples fuentes OSINT públicas como motores de búsqueda,
    VirusTotal, Shodan, Netcraft, entre otros.
    No interactúa directamente con el objetivo.
    """
    log_section("TÉCNICA 3: theHarvester (OSINT)")

    if not herramienta_disponible("theHarvester"):
        log_error("theHarvester no está instalado. Instalar con: sudo apt install theharvester")
        return set()

    archivo_salida = os.path.join(directorio_tmp, "theharvester_out.xml")

    # -d: dominio objetivo
    # -b: fuentes (all = todas las disponibles sin API key)
    # -f: archivo de salida (genera .xml y .json)
    # -l: límite de resultados por fuente
    cmd = [
        "theHarvester",
        "-d", dominio,
        "-b", "bing,google,yahoo,netcraft,virustotal,crtsh",
        "-l", "200",
        "-f", archivo_salida
    ]
    salida = ejecutar_herramienta(cmd, timeout, "theHarvester")

    subdominios = extraer_subdominios(salida, dominio)

    # Leer archivos de salida XML/JSON si fueron generados
    for ext in [".xml", ".json", ""]:
        archivo = archivo_salida + ext if ext else archivo_salida
        if os.path.exists(archivo):
            with open(archivo, "r", errors="ignore") as f:
                subdominios |= extraer_subdominios(f.read(), dominio)

    log_ok(f"theHarvester encontró: {C.GREEN}{len(subdominios)}{C.RESET} subdominios")
    return subdominios


# ──────────────────────────────────────────────
# TÉCNICA 4: SUBFINDER
# APIs públicas: crt.sh, HackerTarget, VirusTotal, DNSDumpster, etc.
# Tipo: Reconocimiento PASIVO
# ──────────────────────────────────────────────
def ejecutar_subfinder(dominio: str, timeout: int, directorio_tmp: str) -> set:
    """
    Subfinder es una herramienta rápida escrita en Go que consulta
    múltiples APIs públicas simultáneamente:
    crt.sh, HackerTarget, VirusTotal, ThreatCrowd, Censys, entre otras.
    Su arquitectura concurrente la hace la más veloz de las cinco.
    """
    log_section("TÉCNICA 4: Subfinder (APIs públicas concurrentes)")

    if not herramienta_disponible("subfinder"):
        log_error("subfinder no está instalado. Instalar con: sudo apt install subfinder")
        return set()

    archivo_salida = os.path.join(directorio_tmp, "subfinder_out.txt")

    # -d: dominio objetivo
    # -o: archivo de salida
    # -silent: sin banner (salida limpia)
    # -t: número de threads concurrentes
    cmd = ["subfinder", "-d", dominio, "-o", archivo_salida, "-silent", "-t", "50"]
    salida = ejecutar_herramienta(cmd, timeout, "Subfinder")

    subdominios = extraer_subdominios(salida, dominio)
    if os.path.exists(archivo_salida):
        with open(archivo_salida, "r", errors="ignore") as f:
            subdominios |= extraer_subdominios(f.read(), dominio)

    log_ok(f"Subfinder encontró: {C.GREEN}{len(subdominios)}{C.RESET} subdominios")
    return subdominios


# ──────────────────────────────────────────────
# TÉCNICA 5: DNSRECON
# Enumeración DNS: registros A, MX, NS, TXT, SRV, zona, reversa
# Tipo: Reconocimiento ACTIVO
# ──────────────────────────────────────────────
def ejecutar_dnsrecon(dominio: str, timeout: int, directorio_tmp: str) -> set:
    """
    DNSRecon realiza enumeración DNS exhaustiva consultando directamente
    los servidores de nombres del objetivo. Es la única técnica
    verdaderamente activa del script — genera tráfico hacia los DNS del objetivo.
    Descubre subdominios que no aparecen en buscadores ni en APIs,
    especialmente subdominios internos expuestos por error.
    """
    log_section("TÉCNICA 5: DNSRecon (Enumeración DNS activa)")

    if not herramienta_disponible("dnsrecon"):
        log_error("dnsrecon no está instalado. Instalar con: sudo apt install dnsrecon")
        return set()

    archivo_salida = os.path.join(directorio_tmp, "dnsrecon_out.json")

    # -d: dominio objetivo
    # -t std: enumeración estándar (A, AAAA, NS, MX, SOA, SRV, TXT)
    # -j: salida en formato JSON (más fácil de parsear)
    # --iw: ignorar wildcard DNS
    cmd = [
        "dnsrecon",
        "-d", dominio,
        "-t", "std",
        "-j", archivo_salida,
        "--iw"
    ]
    salida = ejecutar_herramienta(cmd, timeout, "DNSRecon")

    subdominios = extraer_subdominios(salida, dominio)

    if os.path.exists(archivo_salida):
        with open(archivo_salida, "r", errors="ignore") as f:
            subdominios |= extraer_subdominios(f.read(), dominio)

    log_ok(f"DNSRecon encontró: {C.GREEN}{len(subdominios)}{C.RESET} subdominios")
    return subdominios


# ──────────────────────────────────────────────
# CONSOLIDACIÓN Y GENERACIÓN DEL TXT FINAL
# ──────────────────────────────────────────────
def consolidar_y_guardar(
    resultados: dict,
    dominio: str,
    archivo_salida: str
) -> list:
    """
    Une todos los sets de subdominios de cada herramienta,
    elimina duplicados (usando un set global), ordena alfabéticamente
    y escribe el archivo .txt final con cabecera informativa.
    """
    # Unión de todos los sets — el set Python garantiza unicidad
    todos = set()
    for herramienta, subs in resultados.items():
        todos |= subs

    # Ordenar alfabéticamente (sort lexicográfico — ideal para dominios)
    lista_final = sorted(todos)

    # Generar timestamp para el reporte
    ahora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Escribir el archivo TXT ──
    with open(archivo_salida, "w", encoding="utf-8") as f:
        # Cabecera del reporte
        f.write("=" * 60 + "\n")
        f.write("  REPORTE DE ENUMERACIÓN DE SUBDOMINIOS\n")
        f.write("  Práctica 2 - Sesión 1 | UCSM - Ing. de Sistemas\n")
        f.write("=" * 60 + "\n")
        f.write(f"  Dominio objetivo : {dominio}\n")
        f.write(f"  Fecha/Hora       : {ahora}\n")
        f.write(f"  Total único      : {len(lista_final)} subdominios\n")
        f.write("=" * 60 + "\n\n")

        # Resumen por herramienta
        f.write("── RESULTADOS POR HERRAMIENTA ──\n")
        for herramienta, subs in resultados.items():
            f.write(f"  {herramienta:<15}: {len(subs):>4} subdominios\n")
        f.write(f"\n  {'TOTAL ÚNICO':<15}: {len(lista_final):>4} subdominios\n")
        f.write("\n" + "─" * 60 + "\n\n")

        # Lista final ordenada — un subdominio por línea
        f.write("── SUBDOMINIOS CONSOLIDADOS (orden alfabético) ──\n\n")
        for sub in lista_final:
            f.write(sub + "\n")

        f.write("\n" + "=" * 60 + "\n")
        f.write("  Fin del reporte\n")
        f.write("=" * 60 + "\n")

    return lista_final


# ──────────────────────────────────────────────
# FUNCIÓN PRINCIPAL
# ──────────────────────────────────────────────
def main():
    banner()

    # ── Argumentos de línea de comandos ──
    parser = argparse.ArgumentParser(
        description="Enumera subdominios usando 5 herramientas y consolida resultados en un .txt",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 enum_subdominios.py hackerone.com
  python3 enum_subdominios.py bugcrowd.com --output bugcrowd_subs.txt
  python3 enum_subdominios.py ejemplo.com --timeout 180 --output resultado.txt
        """
    )
    parser.add_argument(
        "dominio",
        help="Dominio objetivo (ej: hackerone.com)"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Nombre del archivo de salida .txt (default: <dominio>_subdominios.txt)"
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=120,
        help="Tiempo máximo por herramienta en segundos (default: 120)"
    )

    args = parser.parse_args()

    # Nombre del archivo de salida
    dominio = args.dominio.strip().lower()
    archivo_salida = args.output or f"{dominio.replace('.', '_')}_subdominios.txt"

    # ── Información inicial ──
    print(f"  {C.BOLD}Dominio objetivo :{C.RESET} {C.CYAN}{dominio}{C.RESET}")
    print(f"  {C.BOLD}Archivo de salida:{C.RESET} {C.CYAN}{archivo_salida}{C.RESET}")
    print(f"  {C.BOLD}Timeout/herram.  :{C.RESET} {C.CYAN}{args.timeout}s{C.RESET}")

    # Verificar herramientas disponibles antes de iniciar
    log_section("VERIFICACIÓN DE HERRAMIENTAS")
    herramientas = {
        "sublist3r"    : "sublist3r",
        "amass"        : "amass",
        "theHarvester" : "theHarvester",
        "subfinder"    : "subfinder",
        "dnsrecon"     : "dnsrecon",
    }
    faltantes = []
    for nombre, cmd in herramientas.items():
        if herramienta_disponible(cmd):
            log_ok(f"{nombre:<15} {C.GREEN}disponible{C.RESET}")
        else:
            log_warn(f"{nombre:<15} {C.YELLOW}NO encontrado{C.RESET}")
            faltantes.append(nombre)

    if faltantes:
        print(f"\n  {C.YELLOW}Instalar faltantes:{C.RESET}")
        print(f"  {C.GRAY}sudo apt install {' '.join(faltantes)} -y{C.RESET}\n")

    # Directorio temporal para archivos intermedios
    with tempfile.TemporaryDirectory() as tmp:

        # ── Ejecutar las 5 herramientas ──
        resultados = {}

        resultados["Sublist3r"]    = ejecutar_sublist3r(dominio, args.timeout, tmp)
        resultados["Amass"]        = ejecutar_amass(dominio, args.timeout, tmp)
        resultados["theHarvester"] = ejecutar_theharvester(dominio, args.timeout, tmp)
        resultados["Subfinder"]    = ejecutar_subfinder(dominio, args.timeout, tmp)
        resultados["DNSRecon"]     = ejecutar_dnsrecon(dominio, args.timeout, tmp)

        # ── Consolidar y guardar ──
        log_section("CONSOLIDACIÓN FINAL")
        lista_final = consolidar_y_guardar(resultados, dominio, archivo_salida)

        # ── Resumen en terminal ──
        print(f"\n  {C.BOLD}Resultados por herramienta:{C.RESET}")
        total_bruto = 0
        for herramienta, subs in resultados.items():
            print(f"    {C.CYAN}{herramienta:<15}{C.RESET} → {C.GREEN}{len(subs):>4}{C.RESET} subdominios")
            total_bruto += len(subs)

        print(f"\n  {C.BOLD}Total bruto (con duplicados) :{C.RESET} {total_bruto}")
        print(f"  {C.BOLD}Total único (consolidado)    :{C.RESET} {C.GREEN}{C.BOLD}{len(lista_final)}{C.RESET}")

        # Preview de los primeros 15 resultados
        if lista_final:
            print(f"\n  {C.BOLD}Preview — primeros {min(15, len(lista_final))} resultados:{C.RESET}")
            for sub in lista_final[:15]:
                print(f"    {C.GRAY}•{C.RESET} {sub}")
            if len(lista_final) > 15:
                print(f"    {C.GRAY}  ... y {len(lista_final) - 15} más{C.RESET}")

        print(f"\n{C.GREEN}{C.BOLD}  [✓] Archivo generado: {archivo_salida}{C.RESET}\n")


if __name__ == "__main__":
    main()
