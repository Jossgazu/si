#!/bin/bash

# =============================================================================
# Script de Enumeración de Subdominios para Kali Linux
# Herramientas: sublist3r, amass, theHarvester, subfinder, dnsrecon
# Versión corregida
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --------------------------------------------------------------------------
# Verificaciones iniciales
# --------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] Este script debe ejecutarse como root${NC}"
    exit 1
fi

if [ -z "$1" ]; then
    echo "Uso: $0 <dominio> [output_file]"
    echo "Ejemplo: $0 example.com subdominios.txt"
    exit 1
fi

TARGET_DOMAIN="$1"
OUTPUT_FILE="${2:-subdominios_${TARGET_DOMAIN}.txt}"
TEMP_DIR="/tmp/subdomain_enum_$$"

# FIX: Asegurarse de que el PATH incluya los binarios de Go
export PATH="$PATH:/root/go/bin:/usr/local/go/bin"

echo -e "${BLUE}[*]===========================================${NC}"
echo -e "${BLUE}[*] Enumeración de Subdominios - Kali Linux${NC}"
echo -e "${BLUE}[*] Dominio objetivo: ${TARGET_DOMAIN}${NC}"
echo -e "${BLUE}[*]===========================================${NC}"

mkdir -p "$TEMP_DIR"

# --------------------------------------------------------------------------
# FIX: Función auxiliar — contar líneas de forma segura
# --------------------------------------------------------------------------
count_lines() {
    local file="$1"
    if [ -f "$file" ]; then
        wc -l < "$file"
    else
        echo 0
    fi
}

# --------------------------------------------------------------------------
# Instalación de herramientas
# --------------------------------------------------------------------------

echo -e "${BLUE}[*] Verificando herramientas...${NC}"

# --- Sublist3r ---
if ! command -v sublist3r &>/dev/null; then
    echo -e "${YELLOW}[!] Instalando sublist3r...${NC}"
    if [ ! -d /opt/Sublist3r ]; then
        git clone https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r 2>/dev/null
    fi
    # FIX: instalar dependencias desde la ruta correcta sin hacer cd persistente
    pip install -r /opt/Sublist3r/requirements.txt -q 2>/dev/null
    # FIX: el enlace apunta al script Python; hay que dar permiso de ejecución
    ln -sf /opt/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
    chmod +x /opt/Sublist3r/sublist3r.py
fi

# --- Amass ---
if ! command -v amass &>/dev/null; then
    echo -e "${YELLOW}[!] Instalando amass...${NC}"
    # FIX: preferir apt; go install como fallback
    apt-get install -y amass -qq 2>/dev/null || \
        go install -v github.com/owasp-amass/amass/v4/...@latest 2>/dev/null
fi

# --- theHarvester ---
if ! command -v theHarvester &>/dev/null; then
    echo -e "${YELLOW}[!] Instalando theHarvester...${NC}"
    if [ ! -d /opt/theHarvester ]; then
        git clone https://github.com/laramies/theHarvester.git /opt/theHarvester 2>/dev/null
    fi
    pip install -r /opt/theHarvester/requirements/base.txt -q 2>/dev/null
    # FIX: versiones modernas usan theHarvester.py
    ln -sf /opt/theHarvester/theHarvester.py /usr/local/bin/theHarvester
    chmod +x /opt/theHarvester/theHarvester.py
fi

# --- Subfinder ---
if ! command -v subfinder &>/dev/null; then
    echo -e "${YELLOW}[!] Instalando subfinder...${NC}"
    apt-get install -y subfinder -qq 2>/dev/null || \
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null
fi

# --- DNSrecon ---
if ! command -v dnsrecon &>/dev/null; then
    echo -e "${YELLOW}[!] Instalando dnsrecon...${NC}"
    apt-get install -y dnsrecon -qq 2>/dev/null
fi

echo -e "${GREEN}[+] Verificación de herramientas completada${NC}"

# =============================================================================
# EJECUCIÓN
# =============================================================================

# --- 1. Sublist3r ---
echo -e "${BLUE}[*] Ejecutando Sublist3r...${NC}"
if command -v sublist3r &>/dev/null; then
    sublist3r -d "$TARGET_DOMAIN" \
              -o "${TEMP_DIR}/sublist3r.txt" \
              -t 20 -e vt 2>/dev/null
    echo -e "${GREEN}[+] Sublist3r completado: $(count_lines "${TEMP_DIR}/sublist3r.txt") subdominios${NC}"
else
    echo -e "${RED}[!] Sublist3r no disponible${NC}"
fi

# --- 2. Amass ---
echo -e "${BLUE}[*] Ejecutando Amass...${NC}"
if command -v amass &>/dev/null; then
    timeout 60 amass enum -passive -d "$TARGET_DOMAIN" \
        -o "${TEMP_DIR}/amass.txt" 2>/dev/null
    echo -e "${GREEN}[+] Amass completado: $(count_lines "${TEMP_DIR}/amass.txt") subdominios${NC}"
else
    echo -e "${RED}[!] Amass no disponible${NC}"
fi

# --- 3. theHarvester ---
echo -e "${BLUE}[*] Ejecutando theHarvester...${NC}"
if command -v theHarvester &>/dev/null; then
    # FIX: usar salida JSON (-f sin extensión; theHarvester añade .json/.xml según versión)
    theHarvester -d "$TARGET_DOMAIN" -b all \
        -f "${TEMP_DIR}/theharvester_out" 2>/dev/null

    # FIX: intentar extraer subdominios de JSON primero, luego XML
    TH_EXTRACTED="${TEMP_DIR}/theharvester.txt"
    touch "$TH_EXTRACTED"

    if [ -f "${TEMP_DIR}/theharvester_out.json" ]; then
        # Extraer campo "hosts" del JSON (compatible con python2/3)
        python3 -c "
import json, sys
try:
    data = json.load(open('${TEMP_DIR}/theharvester_out.json'))
    hosts = data.get('hosts', [])
    for h in hosts:
        print(h.split(':')[0])   # quitar puerto si lo hay
except Exception as e:
    sys.exit(0)
" 2>/dev/null | grep -E "\.${TARGET_DOMAIN}$" >> "$TH_EXTRACTED"

    elif [ -f "${TEMP_DIR}/theharvester_out.xml" ]; then
        # FIX: extraer de XML con grep más amplio (tag puede ser <host> o <hostname>)
        grep -oP '(?<=<host>)[^<]+|(?<=<hostname>)[^<]+' \
            "${TEMP_DIR}/theharvester_out.xml" 2>/dev/null \
            | grep -E "\.${TARGET_DOMAIN}$" >> "$TH_EXTRACTED"
    fi

    echo -e "${GREEN}[+] theHarvester completado: $(count_lines "$TH_EXTRACTED") subdominios${NC}"
else
    echo -e "${RED}[!] theHarvester no disponible${NC}"
fi

# --- 4. Subfinder ---
echo -e "${BLUE}[*] Ejecutando Subfinder...${NC}"
if command -v subfinder &>/dev/null; then
    subfinder -d "$TARGET_DOMAIN" \
              -o "${TEMP_DIR}/subfinder.txt" \
              -silent 2>/dev/null
    echo -e "${GREEN}[+] Subfinder completado: $(count_lines "${TEMP_DIR}/subfinder.txt") subdominios${NC}"
else
    echo -e "${RED}[!] Subfinder no disponible${NC}"
fi

# --- 5. DNSrecon ---
echo -e "${BLUE}[*] Ejecutando DNSRecon...${NC}"
if command -v dnsrecon &>/dev/null; then
    # FIX: dnsrecon -t brt requiere wordlist; usar std (enumeración estándar) o std+brt
    # Para bruteforce se necesita: -t brt -D /usr/share/dnsrecon/namelist.txt
    WORDLIST=""
    for wl in /usr/share/dnsrecon/namelist.txt \
               /usr/share/wordlists/dnsmap.txt \
               /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt; do
        if [ -f "$wl" ]; then
            WORDLIST="$wl"
            break
        fi
    done

    if [ -n "$WORDLIST" ]; then
        dnsrecon -d "$TARGET_DOMAIN" -t brt \
            -D "$WORDLIST" \
            --xml "${TEMP_DIR}/dnsrecon.xml" 2>/dev/null
    else
        # FIX: fallback a enumeración estándar si no hay wordlist
        echo -e "${YELLOW}[!] Wordlist no encontrada; usando enumeración estándar${NC}"
        dnsrecon -d "$TARGET_DOMAIN" -t std \
            --xml "${TEMP_DIR}/dnsrecon.xml" 2>/dev/null
    fi

    # FIX: dnsrecon escribe XML — extraer subdominios con grep sobre el XML
    if [ -f "${TEMP_DIR}/dnsrecon.xml" ]; then
        grep -oP '(?<=name=")[^"]+' "${TEMP_DIR}/dnsrecon.xml" 2>/dev/null \
            | grep -E "\.${TARGET_DOMAIN}$" \
            | sort -u > "${TEMP_DIR}/dnsrecon.txt"
    else
        touch "${TEMP_DIR}/dnsrecon.txt"
    fi

    echo -e "${GREEN}[+] DNSRecon completado: $(count_lines "${TEMP_DIR}/dnsrecon.txt") subdominios${NC}"
else
    echo -e "${RED}[!] DNSRecon no disponible${NC}"
fi

# =============================================================================
# CONSOLIDAR
# =============================================================================

echo -e "${BLUE}[*] Consolidando resultados...${NC}"

# FIX: recopilar en archivo temporal antes de filtrar
RAW_COMBINED="${TEMP_DIR}/combined_raw.txt"
> "$RAW_COMBINED"

for file in "${TEMP_DIR}"/*.txt; do
    [ -f "$file" ] && cat "$file" >> "$RAW_COMBINED"
done

# FIX: filtrar subdominios válidos, quitar espacios/puntos finales y deduplicar
grep -Ei "^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*\.${TARGET_DOMAIN}$" \
    "$RAW_COMBINED" 2>/dev/null \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/[[:space:]]//g; s/\.$//'\
    | sort -u > "$OUTPUT_FILE"

TOTAL=$(count_lines "$OUTPUT_FILE")

echo -e "${GREEN}[*]===========================================${NC}"
echo -e "${GREEN}[+] Enumeración completada${NC}"
echo -e "${GREEN}[+] Total de subdominios únicos: ${TOTAL}${NC}"
echo -e "${GREEN}[+] Resultados guardados en: ${OUTPUT_FILE}${NC}"
echo -e "${GREEN}[*]===========================================${NC}"

if [ "$TOTAL" -gt 0 ]; then
    echo -e "${BLUE}[*] Primeros 20 subdominios:${NC}"
    head -n 20 "$OUTPUT_FILE"
fi

# Limpiar temporales
rm -rf "$TEMP_DIR"

echo -e "${GREEN}[+] Proceso terminado${NC}"
