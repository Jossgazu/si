#!/usr/bin/env python3
"""
enum_subdominios.py — Práctica 2 UCSM
Ejecuta 5 herramientas de enumeración, consolida y guarda en .txt
Uso: python3 enum_subdominios.py <dominio> [-o salida.txt] [-t timeout]
Requisitos: sudo apt install sublist3r amass theharvester subfinder dnsrecon -y
"""
import argparse, datetime, os, re, subprocess, tempfile

R="\033[0m"; B="\033[94m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"; W="\033[1m"

def ok(m):  print(f"  {G}[+]{R} {m}")
def inf(m): print(f"  {B}[*]{R} {m}")
def err(m): print(f"  {Y}[!]{R} {m}")
def sec(t): print(f"\n{W}{C}{'─'*50}\n  {t}\n{'─'*50}{R}")

def disponible(cmd):
    return subprocess.run(["which", cmd], capture_output=True).returncode == 0

def extraer(texto, dominio):
    pat = re.compile(
        r'(?:^|[\s,|:\[\]])(\*?[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.'
        + re.escape(dominio) + r')\b', re.MULTILINE)
    return {m.group(1).lower().lstrip("*.") for m in pat.finditer(texto)}

def correr(cmd, timeout, nombre):
    if not disponible(cmd[0]):
        err(f"{nombre} no instalado — omitiendo"); return ""
    inf(f"Ejecutando: {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        err(f"{nombre} timeout ({timeout}s) — usando resultados parciales"); return ""
    except Exception as e:
        err(f"{nombre}: {e}"); return ""

def leer_si_existe(path):
    return open(path, errors="ignore").read() if os.path.exists(path) else ""

def herramienta(nombre, cmd, archivo_extra, dominio, timeout):
    sec(nombre)
    salida = correr(cmd, timeout, nombre)
    subs = extraer(salida + leer_si_existe(archivo_extra), dominio)
    ok(f"{nombre}: {G}{len(subs)}{R} subdominios encontrados")
    return subs

def guardar(resultados, dominio, salida):
    final = sorted(set().union(*resultados.values()))
    ahora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(salida, "w") as f:
        f.write(f"{'='*60}\n  REPORTE DE SUBDOMINIOS — {dominio}\n")
        f.write(f"  Fecha: {ahora} | Total único: {len(final)}\n{'='*60}\n\n")
        f.write("── POR HERRAMIENTA ──\n")
        for h, s in resultados.items():
            f.write(f"  {h:<15}: {len(s):>4}\n")
        f.write(f"\n{'─'*60}\n── SUBDOMINIOS (orden alfabético) ──\n\n")
        f.writelines(s + "\n" for s in final)
        f.write(f"\n{'='*60}\n")
    return final

def main():
    p = argparse.ArgumentParser(description="Enumerador de subdominios — 5 herramientas")
    p.add_argument("dominio")
    p.add_argument("-o", "--output", default=None)
    p.add_argument("-t", "--timeout", type=int, default=120)
    a = p.parse_args()

    dominio = a.dominio.strip().lower()
    salida  = a.output or f"{dominio.replace('.','_')}_subdominios.txt"
    print(f"\n{W}  Dominio: {C}{dominio}{R}  |  {W}Salida: {C}{salida}{R}\n")

    with tempfile.TemporaryDirectory() as tmp:
        f = lambda n: os.path.join(tmp, n)
        resultados = {
            "Sublist3r":    herramienta("Sublist3r",
                ["sublist3r","-d",dominio,"-o",f("sl.txt"),"-t","10","-n"],
                f("sl.txt"), dominio, a.timeout),
            "Amass":        herramienta("Amass",
                ["amass","enum","-d",dominio,"-o",f("am.txt"),"-passive"],
                f("am.txt"), dominio, a.timeout),
            "theHarvester": herramienta("theHarvester",
                ["theHarvester","-d",dominio,"-b","bing,google,yahoo,netcraft,virustotal,crtsh","-l","200","-f",f("th")],
                f("th.xml"), dominio, a.timeout),
            "Subfinder":    herramienta("Subfinder",
                ["subfinder","-d",dominio,"-o",f("sf.txt"),"-silent","-t","50"],
                f("sf.txt"), dominio, a.timeout),
            "DNSRecon":     herramienta("DNSRecon",
                ["dnsrecon","-d",dominio,"-t","std","-j",f("dr.json"),"--iw"],
                f("dr.json"), dominio, a.timeout),
        }

        sec("CONSOLIDACIÓN FINAL")
        final = guardar(resultados, dominio, salida)
        for h, s in resultados.items():
            print(f"  {C}{h:<15}{R} → {G}{len(s):>4}{R} subdominios")
        print(f"\n  Total único: {W}{G}{len(final)}{R}")
        print(f"\n{G}{W}  [✓] Guardado en: {salida}{R}\n")

if __name__ == "__main__":
    main()
