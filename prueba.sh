#!/bin/bash

# =============================================================================
# Script de Enumeración de Subdominios para Kali Linux
# Herramientas: sublist3r, amass, theHarvester, subfinder, dnsrecon
# =============================================================================

# Colores para salida
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Verificar si es root
if [[ $E -NE 0 ]]; then
    echo -e "${RED}[!] Este script debe ejecutarse como root${NC}"
    exit 1
fi

# Verificar argumentos
if [ -z "$1" ]; then
    echo "Uso: $0 <dominio> [output_file]"
    echo "Ejemplo: $0 example.com subdominios.txt"
    exit 1
fi

TARGET_DOMAIN=$1
OUTPUT_FILE=${2:-"subdominios_${TARGET_DOMAIN}.txt"}
TEMP_DIR="/tmp/subdomain_enum_$$"

echo -e "${BLUE}[*]===========================================${NC}"
echo -e "${BLUE}[*] Enumeración de Subdominios - Kali Linux${NC}"
echo -e "${BLUE}[*] Dominio objetivo: ${TARGET_DOMAIN}${NC}"
echo -e "${BLUE}[*]===========================================${NC}"

# Crear directorio temporal
mkdir -p "$TEMP_DIR"

# Función para instalar herramienta si no existe
install_tool() {
    local tool=$1
    local install_cmd=$2
    
    if ! command -v $tool &> /dev/null; then
        echo -e "${YELLOW}[!] $tool no encontrado. Instalando...${NC}"
        eval $install_cmd
    else
        echo -e "${GREEN}[+] $tool ya está instalado${NC}"
    fi
}

# Instalar dependencias necesarias
echo -e "${BLUE}[*] Verificando herramientas...${NC}"

# Instalar sublist3r
if ! command -v sublist3r &> /dev/null; then
    echo -e "${YELLOW}[!] Instalando sublist3r...${NC}"
    git clone https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r 2>/dev/null
    cd /opt/Sublist3r
    pip install -r requirements.txt 2>/dev/null
    ln -sf /opt/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
fi

# Instalar amass
if ! command -v amass &> /dev/null; then
    echo -e "${YELLOW}[!] Instalando amass...${NC}"
    go install -v github.com/owasp-amass/amass/v4/...@latest 2>/dev/null || \
    apt install -y amass 2>/dev/null
fi

# Instalar theHarvester
if ! command -v theHarvester &> /dev/null; then
    echo -e "${YELLOW}[!] Instalando theHarvester...${NC}"
    git clone https://github.com/laramies/theHarvester.git /opt/theHarvester 2>/dev/null
    cd /opt/theHarvester
    pip install -r requirements.txt 2>/dev/null
    ln -sf /opt/theHarvester/theHarvester.py /usr/local/bin/theHarvester
fi

# Instalar subfinder
if ! command -v subfinder &> /dev/null; then
    echo -e "${YELLOW}[!] Instalando subfinder...${NC}"
    go install -v github.com/projectdiscovery/subfinder/v2/...@latest 2>/dev/null || \
    apt install -y subfinder 2>/dev/null
fi

# Instalar dnsrecon
if ! command -v dnsrecon &> /dev/null; then
    echo -e "${YELLOW}[!] Instalando dnsrecon...${NC}"
    apt install -y dnsrecon 2>/dev/null
fi

echo -e "${GREEN}[+] Todas las herramientas verificadas${NC}"

# =============================================================================
# EJECUTAR HERRAMIENTAS DE ENUMERACIÓN
# =============================================================================

# 1. Sublist3r
echo -e "${BLUE}[*] Ejecutando Sublist3r...${NC}"
if command -v sublist3r &> /dev/null; then
    sublist3r -d "$TARGET_DOMAIN" -o "${TEMP_DIR}/sublist3r.txt" -t 20 2>/dev/null
    if [ -f "${TEMP_DIR}/sublist3r.txt" ]; then
        echo -e "${GREEN}[+] Sublist3r completado: $(wc -l < ${TEMP_DIR}/sublist3r.txt) subdominios${NC}"
    fi
else
    echo -e "${RED}[!] Sublist3r no disponible${NC}"
fi

# 2. Amass
echo -e "${BLUE}[*] Ejecutando Amass...${NC}"
if command -v amass &> /dev/null; then
    amass enum -passive -d "$TARGET_DOMAIN" -o "${TEMP_DIR}/amass.txt" 2>/dev/null
    if [ -f "${TEMP_DIR}/amass.txt" ]; then
        echo -e "${GREEN}[+] Amass completado: $(wc -l < ${TEMP_DIR}/amass.txt) subdominios${NC}"
    fi
else
    echo -e "${RED}[!] Amass no disponible${NC}"
fi

# 3. theHarvester
echo -e "${BLUE}[*] Ejecutando theHarvester...${NC}"
if command -v theHarvester &> /dev/null; then
    theHarvester -d "$TARGET_DOMAIN" -b all -f "${TEMP_DIR}/theharvester.xml" 2>/dev/null
    # Extraer subdominios del XML si existe
    if [ -f "${TEMP_DIR}/theharvester.xml" ]; then
        grep -oP '(?<=<host>)[^<]+' "${TEMP_DIR}/theharvester.xml" | grep -E "\.$TARGET_DOMAIN" > "${TEMP_DIR}/theharvester.txt" 2>/dev/null
        echo -e "${GREEN}[+] theHarvester completado: $(wc -l < ${TEMP_DIR}/theharvester.txt 2>/dev/null || echo 0) subdominios${NC}"
    fi
else
    echo -e "${RED}[!] theHarvester no disponible${NC}"
fi

# 4. Subfinder
echo -e "${BLUE}[*] Ejecutando Subfinder...${NC}"
if command -v subfinder &> /dev/null; then
    subfinder -d "$TARGET_DOMAIN" -o "${TEMP_DIR}/subfinder.txt" -silent 2>/dev/null
    if [ -f "${TEMP_DIR}/subfinder.txt" ]; then
        echo -e "${GREEN}[+] Subfinder completado: $(wc -l < ${TEMP_DIR}/subfinder.txt) subdominios${NC}"
    fi
else
    echo -e "${RED}[!] Subfinder no disponible${NC}"
fi

# 5. DNSrecon
echo -e "${BLUE}[*] Ejecutando DNSRecon...${NC}"
if command -v dnsrecon &> /dev/null; then
    dnsrecon -d "$TARGET_DOMAIN" -t brt -o "${TEMP_DIR}/dnsrecon.txt" 2>/dev/null
    # Extraer solo subdominios del output
    if [ -f "${TEMP_DIR}/dnsrecon.txt" ]; then
        grep -oE "^[a-zA-Z0-9.-]+\.$TARGET_DOMAIN" "${TEMP_DIR}/dnsrecon.txt" | sort -u > "${TEMP_DIR}/dnsrecon_clean.txt" 2>/dev/null
        mv "${TEMP_DIR}/dnsrecon_clean.txt" "${TEMP_DIR}/dnsrecon.txt" 2>/dev/null
        echo -e "${GREEN}[+] DNSRecon completado: $(wc -l < ${TEMP_DIR}/dnsrecon.txt 2>/dev/null || echo 0) subdominios${NC}"
    fi
else
    echo -e "${RED}[!] DNSRecon no disponible${NC}"
fi

# =============================================================================
# CONSOLIDAR Y ELIMINAR DUPLICADOS
# =============================================================================

echo -e "${BLUE}[*] Consolidando resultados...${NC}"

# Combinar todos los archivos y eliminar duplicados
> "$OUTPUT_FILE"

for file in "${TEMP_DIR}"/*.txt; do
    if [ -f "$file" ]; then
        cat "$file" >> "$OUTPUT_FILE"
    fi
done

# Filtrar solo subdominios válidos del dominio objetivo y eliminar duplicados
if [ -f "$OUTPUT_FILE" ]; then
    grep -E "^[a-zA-Z0-9.-]+\.$TARGET_DOMAIN$" "$OUTPUT_FILE" | \
        sed 's/\.$//' | \
        sort -u > "${TEMP_DIR}/final.txt"
    
    mv "${TEMP_DIR}/final.txt" "$OUTPUT_FILE"
fi

# Contar resultados finales
TOTAL=$(wc -l < "$OUTPUT_FILE" 2>/dev/null || echo 0)

echo -e "${GREEN}[*]===========================================${NC}"
echo -e "${GREEN}[+] Enumeración completada${NC}"
echo -e "${GREEN}[+] Total de subdominios únicos encontrados: ${TOTAL}${NC}"
echo -e "${GREEN}[+] Resultados guardados en: ${OUTPUT_FILE}${NC}"
echo -e "${GREEN}[*]===========================================${NC}"

# Mostrar los primeros 20 subdominios
if [ "$TOTAL" -gt 0 ]; then
    echo -e "${BLUE}[*] Primeros 20 subdominios:${NC}"
    head -n 20 "$OUTPUT_FILE"
fi

# Limpiar archivos temporales
rm -rf "$TEMP_DIR"

echo -e "${GREEN}[+] Proceso terminado${NC}"
