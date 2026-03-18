#!/usr/bin/env python3
import argparse, sys, os, shutil, requests, re, subprocess, dns.resolver, dns.zone, dns.query
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

B="\033[94m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"; BOLD="\033[1m"; X="\033[0m"
def info(m):    print(f"{B}[*]{X} {m}")
def success(m): print(f"{G}[+]{X} {m}")
def warn(m):    print(f"{Y}[!]{X} {m}")
def found(m):   print(f"{G}[FOUND]{X} {m}")

def run_cmd(cmd, t=90):
    try: return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t).stdout.strip()
    except: return ""

def parse(out, domain):
    subs = set()
    for line in out.splitlines():
        line = line.strip().lower()
        for p in ["[+]","[-]","[*]","[INF]","subdomain:","host:"]:
            if line.startswith(p): line = line[len(p):].strip()
        for proto in ["https://","http://"]: line = line.removeprefix(proto)
        line = line.split("/")[0]
        if domain in line and " " not in line and (line.endswith(f".{domain}") or line == domain):
            subs.add(line)
    return subs

def run_findomain(domain):
    if not shutil.which("findomain"): return warn("findomain no encontrado: apt install findomain") or set()
    info("Findomain..."); s = parse(run_cmd(f"findomain -t {domain} --quiet", 60), domain)
    success(f"Findomain: {len(s)}"); return s

def run_subfinder(domain):
    if not shutil.which("subfinder"): return warn("subfinder no encontrado: apt install subfinder") or set()
    info("SubFinder..."); s = parse(run_cmd(f"subfinder -d {domain} -silent"), domain)
    success(f"SubFinder: {len(s)}"); return s

def run_aquapone(domain):
    subs, hdr = set(), {"User-Agent": "SubEnum/2.0"}
    info("Aquapone (crt.sh · HackerTarget · BufferOver · RapidDNS · AlienVault · URLScan)...")
    def get(url):
        try: r = requests.get(url, timeout=15, headers=hdr); return r if r.status_code == 200 else None
        except: return None
    if r := get(f"https://crt.sh/?q=%.{domain}&output=json"):
        for e in r.json():
            for s in e.get("name_value","").split("\n"):
                s = s.strip().lower().lstrip("*.")
                if s.endswith(f".{domain}") or s == domain: subs.add(s)
    if r := get(f"https://api.hackertarget.com/hostsearch/?q={domain}"):
        if "error" not in r.text.lower():
            for line in r.text.splitlines():
                p = line.split(",")
                if p and domain in p[0]: subs.add(p[0].strip().lower())
    if r := get(f"https://dns.bufferover.run/dns?q=.{domain}"):
        for item in r.json().get("FDNS_A",[]) + r.json().get("RDNS",[]):
            for p in item.split(","):
                p = p.strip().lower()
                if p.endswith(f".{domain}"): subs.add(p)
    if r := get(f"https://rapiddns.io/subdomain/{domain}?full=1#result"):
        for s in re.findall(r'[\w\-\.]+\.' + re.escape(domain), r.text): subs.add(s.lower())
    if r := get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"):
        for e in r.json().get("passive_dns",[]):
            h = e.get("hostname","").lower()
            if h.endswith(f".{domain}") or h == domain: subs.add(h)
    if r := get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200"):
        for e in r.json().get("results",[]):
            h = e.get("page",{}).get("domain","").lower()
            if h.endswith(f".{domain}") or h == domain: subs.add(h)
    success(f"Aquapone: {len(subs)}"); return subs

TAKEOVER = [("Amazon S3","NoSuchBucket"),("GitHub Pages","There isn't a GitHub Pages site here"),
            ("Heroku","No such app"),("Fastly","Fastly error: unknown domain"),
            ("Ghost","Domain not configured"),("Zendesk","Help Center Closed"),
            ("Surge.sh","project not found"),("Webflow","The page you are looking for doesn't exist")]

def run_subover(domain, known=None):
    info("SubOver (takeover check)...")
    def check(sub):
        try:
            r = requests.get(f"http://{sub}", timeout=5, allow_redirects=True)
            for svc, sig in TAKEOVER:
                if sig.lower() in r.text.lower(): return sub, svc
        except: pass
        return None, None
    with ThreadPoolExecutor(max_workers=20) as ex:
        for sub, svc in ex.map(check, list(known or [])):
            if sub: warn(f"[TAKEOVER POSIBLE] {sub} → {svc}")
    return set()

def run_subbrute(domain, wordlist_path=None, threads=50):
    info("Subbrute (DNS brute force)...")
    default = ["www","mail","ftp","smtp","vpn","api","dev","staging","test","demo","beta","prod",
               "admin","portal","login","app","cdn","static","media","blog","shop","news","support",
               "docs","gitlab","jenkins","jira","cpanel","webmail","ns1","ns2","mx","exchange",
               "cloud","db","mysql","redis","git","ci","cd","docker","proxy","gateway","auth","sso",
               "v1","v2","v3","service","old","legacy","uat","qa","sandbox","internal","intranet"]
    if wordlist_path and os.path.exists(wordlist_path):
        with open(wordlist_path,"r",errors="ignore") as f:
            words = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    else: words = default
    def resolve(host):
        try:
            r = dns.resolver.Resolver(); r.timeout = r.lifetime = 3
            r.resolve(host,"A"); return host
        except: return None
    subs = set()
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for result in ex.map(resolve, [f"{w}.{domain}" for w in words]):
            if result: subs.add(result); found(result)
    success(f"Subbrute: {len(subs)}"); return subs

def try_axfr(domain):
    info("Zone Transfer (AXFR)..."); subs = set()
    try:
        for ns in [str(r.target).rstrip(".") for r in dns.resolver.resolve(domain,"NS")]:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=10))
                for name in zone.nodes:
                    s = f"{name}.{domain}".strip("@.").lower()
                    if s.endswith(f".{domain}"): subs.add(s)
                if subs: success(f"AXFR exitoso en {ns}: {len(subs)} registros")
            except: pass
    except Exception as e: warn(f"AXFR: {e}")
    if not subs: info("AXFR denegado (normal)")
    return subs

def main():
    ap = argparse.ArgumentParser(description="Subdomain Enumerator v2.0")
    ap.add_argument("-d","--domain",required=True); ap.add_argument("-o","--output",default=None)
    ap.add_argument("--wordlist",default=None); ap.add_argument("--tools",default=None)
    args = ap.parse_args()

    domain = args.domain
    tools  = [t.strip().lower() for t in args.tools.split(",")] if args.tools else \
             ["findomain","subfinder","aquapone","subover","subbrute","axfr"]

    print(f"\n{C}{BOLD}{'═'*55}\n  SUBDOMAIN ENUMERATOR v2.0 · {domain}\n{'═'*55}{X}\n")
    start, all_subs = datetime.now(), set()

    steps = [("findomain","FINDOMAIN",lambda: run_findomain(domain)),
             ("subfinder","SUBFINDER",lambda: run_subfinder(domain)),
             ("aquapone", "AQUAPONE", lambda: run_aquapone(domain)),
             ("subover",  "SUBOVER",  lambda: run_subover(domain, all_subs)),
             ("subbrute", "SUBBRUTE", lambda: run_subbrute(domain, args.wordlist)),
             ("axfr",     "AXFR",     lambda: try_axfr(domain))]

    for i,(key,label,fn) in enumerate(steps,1):
        if key in tools:
            print(f"{BOLD}[{i}/6] {label}{X}"); all_subs.update(fn()); print()

    # Quitar www. de cualquier subdominio y deduplicar
    cleaned = {s[4:] if s.startswith("www.") else s for s in all_subs}
    removed = len(all_subs) - len(cleaned)
    if removed: info(f"Deduplicación: {removed} entradas www.* eliminadas")
    all_subs = cleaned

    sorted_subs = sorted(all_subs)
    print(f"{G}{BOLD}{'─'*55}\n  Total: {len(sorted_subs)} subdominios únicos  |  {datetime.now()-start}\n{'─'*55}{X}")
    for s in sorted_subs: print(f"  {G}•{X} {s}")

    out = args.output or f"subdominios_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(out,"w") as f:
        f.write(f"# Target: {domain}\n# Date: {datetime.now()}\n# Total: {len(sorted_subs)}\n\n")
        f.writelines(f"{s}\n" for s in sorted_subs)
    print(f"\n{G}[✓]{X} Guardado en: {C}{out}{X}")

if __name__ == "__main__":
    main()
