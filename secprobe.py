#!/usr/bin/env python3
"""
SecProbe v1.0 - Web Security Evaluation Tool
Berbasis Standar OWASP A02 · A05 · A06

Author : Miftahus Surur
NIM    : B.2.4.22.0005
Prodi  : Teknik Informatika - Universitas Sultan Fatah Demak
"""

import argparse, socket, ssl, sys, time, datetime, requests, urllib.parse, warnings, threading
from colorama import init, Fore, Back, Style

init(autoreset=True)
warnings.filterwarnings("ignore")

VERSION = "1.0"
TIMEOUT = 10
LEBAR   = 70

SEVERITY_WEIGHT = {"CRITICAL":10,"HIGH":7,"MEDIUM":4,"LOW":1}
EXPLOIT_WEIGHT  = {"MUDAH":3,"SEDANG":2,"SULIT":1}

SCORE_CATEGORY = [
    (81,100,"AMAN",           "Konfigurasi keamanan sangat baik",         Fore.GREEN),
    (61, 80,"BAIK",           "Beberapa perbaikan minor disarankan",       Fore.CYAN),
    (41, 60,"PERLU PERHATIAN","Terdapat kerentanan yang perlu diperbaiki", Fore.YELLOW),
    (21, 40,"BERBAHAYA",      "Kerentanan serius ditemukan",               Fore.RED),
    (0,  20,"KRITIS",         "Website sangat rentan, tindakan segera!",   Fore.RED),
]

VULNERABLE_SERVERS = {
    "apache":["2.4.49","2.4.50","2.4.48","2.4.46","2.4.43","2.4.41","2.4.39","2.4.38","2.2.34","2.2.32"],
    "nginx": ["1.16.0","1.14.0","1.12.2","1.12.1","1.10.3","1.10.2","1.10.1","1.8.1","1.6.3"],
    "iis":   ["7.0","7.5","8.0","8.5"],
}

# ── SPINNER ─────────────────────────────────────────────────
class Spinner:
    def __init__(self, pesan=""):
        self.pesan=pesan; self._stop=False; self._t=None
    def _putar(self):
        frames=["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]; i=0
        while not self._stop:
            print(f"\r  {Fore.CYAN+Style.BRIGHT+frames[i%len(frames)]}  {Fore.WHITE}{self.pesan}{Style.RESET_ALL}   ",end="",flush=True)
            time.sleep(0.08); i+=1
    def mulai(self):
        self._stop=False; self._t=threading.Thread(target=self._putar,daemon=True); self._t.start()
    def stop(self,status="ok",msg=""):
        self._stop=True
        if self._t: self._t.join()
        ic=Fore.GREEN+"✔" if status=="ok" else Fore.RED+"✘"
        print(f"\r  {ic+Style.RESET_ALL}  {msg or self.pesan}{' '*20}")

# ── BOX HELPER ───────────────────────────────────────────────
def lb(s):
    for k in [Fore.RED,Fore.GREEN,Fore.YELLOW,Fore.CYAN,Fore.WHITE,Fore.BLUE,Fore.MAGENTA,
              Fore.BLACK,Back.WHITE,Back.RED,Style.BRIGHT,Style.RESET_ALL,Style.DIM,Style.NORMAL]:
        s=s.replace(k,"")
    return len(s)

def baris(t=""):
    pad=max(0,LEBAR-lb(t))
    print(Fore.BLUE+Style.BRIGHT+"║"+Style.RESET_ALL+t+" "*pad+Fore.BLUE+Style.BRIGHT+"║")

def bk(): baris()

def garis(tp="tengah"):
    C=Fore.BLUE+Style.BRIGHT
    g={"atas":("╔","═","╗"),"bawah":("╚","═","╝"),"tengah":("╠","═","╣"),"tipis":("╟","─","╢")}
    a,m,z=g.get(tp,("╠","═","╣"))
    print(C+a+m*LEBAR+z)

def warna_sev(sev):
    return {"CRITICAL":Fore.RED+Style.BRIGHT,"HIGH":Fore.RED+Style.BRIGHT,
            "MEDIUM":Fore.YELLOW+Style.BRIGHT,"LOW":Fore.CYAN+Style.BRIGHT}.get(sev,Fore.WHITE)

def badge(sev):
    w=warna_sev(sev)
    b={"CRITICAL":"▐ CRITICAL ▌","HIGH":"▐  HIGH   ▌","MEDIUM":"▐ MEDIUM  ▌","LOW":"▐  LOW    ▌"}.get(sev,sev)
    return w+b+Style.RESET_ALL

def bar_score(score,w=28):
    isi=int(score/100*w); ko=w-isi
    c=Fore.GREEN if score>=81 else Fore.CYAN if score>=61 else Fore.YELLOW if score>=41 else Fore.RED
    return c+Style.BRIGHT+"█"*isi+Style.DIM+"░"*ko+Style.RESET_ALL

def get_kat(score):
    for lo,hi,lb2,ket,wc in SCORE_CATEGORY:
        if lo<=score<=hi: return lb2,ket,wc
    return "KRITIS","Website sangat rentan!",Fore.RED

# ── BANNER ───────────────────────────────────────────────────
def banner(url):
    garis("atas"); bk()
    baris(Fore.CYAN+Style.BRIGHT+"  ███████╗███████╗ ██████╗██████╗ ██████╗  ██████╗ ██████╗ ███████╗")
    baris(Fore.CYAN+Style.BRIGHT+"  ██╔════╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝")
    baris(Fore.CYAN+Style.BRIGHT+"  ███████╗█████╗  ██║     ██████╔╝██████╔╝██║   ██║██████╔╝█████╗  ")
    baris(Fore.CYAN+Style.BRIGHT+"  ╚════██║██╔══╝  ██║     ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝  ")
    baris(Fore.CYAN+Style.BRIGHT+"  ███████║███████╗╚██████╗██║     ██║  ██║╚██████╔╝██████╔╝███████╗")
    baris(Fore.CYAN+Style.BRIGHT+"  ╚══════╝╚══════╝ ╚═════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝")
    bk()
    baris(Fore.WHITE+"  Web Security Evaluation Tool  "+Fore.BLUE+Style.BRIGHT+"│"+Style.RESET_ALL+
          Fore.GREEN+Style.BRIGHT+"  v"+VERSION+"  "+Fore.BLUE+Style.BRIGHT+"│"+Style.RESET_ALL+
          Fore.WHITE+"  OWASP A02 · A05 · A06")
    garis("tipis")
    baris(Fore.WHITE+Style.DIM+"  Author  : Miftahus Surur   │   NIM : B.2.4.22.0005")
    baris(Fore.WHITE+Style.DIM+"  Teknik Informatika  │  Universitas Sultan Fatah Demak")
    garis("tengah")
    baris(Fore.WHITE+"  "+Fore.BLUE+Style.BRIGHT+"◈  "+Style.RESET_ALL+Fore.WHITE+"Target  : "+Fore.YELLOW+Style.BRIGHT+url[:55])
    baris(Fore.WHITE+"  "+Fore.BLUE+Style.BRIGHT+"◈  "+Style.RESET_ALL+Fore.WHITE+"Tanggal : "+Fore.YELLOW+datetime.datetime.now().strftime("%A, %d %B %Y  %H:%M:%S"))
    garis("tengah"); bk()

def section(kode,nama,ikon):
    print(); garis("tipis")
    baris("  "+Fore.BLUE+Style.BRIGHT+"╔══[ "+Style.RESET_ALL+Fore.MAGENTA+Style.BRIGHT+ikon+" "+kode+Style.RESET_ALL+Fore.BLUE+Style.BRIGHT+" ]══╗"+Style.RESET_ALL+"  "+Fore.WHITE+Style.BRIGHT+nama)
    garis("tipis"); bk()

def show_temuan(t):
    w=warna_sev(t["severity"])
    baris("  "+badge(t["severity"])+"  "+Style.BRIGHT+t["nama"])
    baris("  "+Fore.WHITE+Style.DIM+"  ├─ "+Style.RESET_ALL+Fore.WHITE+"Skor Risiko  : "+w+Style.BRIGHT+str(t["skor"])+Style.RESET_ALL+"  "+Fore.WHITE+Style.DIM+"│"+Style.RESET_ALL+"  Exploitability : "+w+t["exploitability"])
    bks=[t["bukti"][i:i+46] for i in range(0,len(t["bukti"]),46)]
    baris("  "+Fore.WHITE+Style.DIM+"  ├─ "+Style.RESET_ALL+Fore.WHITE+"Bukti        : "+Style.DIM+bks[0])
    for c in bks[1:]: baris("  "+" "*20+Style.DIM+c)
    sks=[t["saran"][i:i+46] for i in range(0,len(t["saran"]),46)]
    baris("  "+Fore.WHITE+Style.DIM+"  └─ "+Style.RESET_ALL+Fore.GREEN+"Saran        : "+sks[0])
    for c in sks[1:]: baris("  "+" "*20+Fore.GREEN+c)
    bk()

def ok(pesan):  baris("  "+Fore.GREEN+Style.BRIGHT+"  ✔  "+Style.RESET_ALL+Fore.WHITE+pesan[:58])
def info(pesan): baris("  "+Fore.CYAN+Style.BRIGHT+"  »  "+Style.RESET_ALL+Style.DIM+pesan[:58])

# ── SCORING ──────────────────────────────────────────────────
def hs(sev,expl): return SEVERITY_WEIGHT[sev]*EXPLOIT_WEIGHT[expl]
def bt(nama,kat,sev,expl,bukti,saran):
    return dict(nama=nama,kategori=kat,severity=sev,exploitability=expl,skor=hs(sev,expl),bukti=bukti,saran=saran)

# ── VALIDASI ─────────────────────────────────────────────────
def validasi(url):
    if not url.startswith("http"): url="https://"+url
    parsed=urllib.parse.urlparse(url)
    if not parsed.scheme or not parsed.netloc: return False,"Format URL tidak valid",url
    host=parsed.netloc.split(":")[0]; port=443 if parsed.scheme=="https" else 80
    try:
        s=socket.create_connection((host,port),timeout=TIMEOUT); s.close()
    except socket.gaierror: return False,f"Domain tidak dikenali: {host}",url
    except socket.timeout:  return False,f"Koneksi timeout ke {host}",url
    except Exception as e:  return False,f"Koneksi gagal: {str(e)[:40]}",url
    return True,"Target dapat diakses",url

# ── A02 ──────────────────────────────────────────────────────
def scan_a02(url):
    hasil=[]; parsed=urllib.parse.urlparse(url)
    if parsed.scheme=="http":
        hasil.append(bt("HTTPS tidak digunakan pada website target","A02","HIGH","MUDAH",
            "Website menggunakan HTTP — data tidak terenkripsi",
            "Aktifkan HTTPS dengan sertifikat SSL/TLS valid dari CA terpercaya"))
    else:
        ok("Protokol HTTPS aktif"); host=parsed.netloc.split(":")[0]
        try:
            ctx=ssl.create_default_context()
            conn=ctx.wrap_socket(socket.create_connection((host,443),timeout=TIMEOUT),server_hostname=host)
            cert=conn.getpeercert(); conn.close()
            es=cert.get("notAfter","")
            if es:
                ed=datetime.datetime.strptime(es,"%b %d %H:%M:%S %Y %Z")
                sisa=(ed-datetime.datetime.utcnow()).days
                if sisa<0:
                    hasil.append(bt("Sertifikat SSL sudah kedaluwarsa","A02","HIGH","MUDAH",
                        f"Kedaluwarsa {abs(sisa)} hari lalu ({ed.strftime('%Y-%m-%d')})",
                        "Perbarui sertifikat SSL/TLS melalui CA terpercaya"))
                elif sisa<30:
                    hasil.append(bt("Sertifikat SSL akan segera kedaluwarsa","A02","MEDIUM","MUDAH",
                        f"Kedaluwarsa dalam {sisa} hari ({ed.strftime('%Y-%m-%d')})",
                        "Segera perbarui sertifikat SSL/TLS sebelum kedaluwarsa"))
                else: ok(f"Sertifikat SSL valid — exp: {ed.strftime('%Y-%m-%d')} ({sisa} hari)")
        except ssl.SSLCertVerificationError as e:
            hasil.append(bt("Sertifikat SSL tidak valid/tidak terpercaya","A02","HIGH","MUDAH",
                f"Verifikasi gagal: {str(e)[:52]}","Pastikan sertifikat diterbitkan CA terpercaya"))
        except Exception: pass
        try:
            ctx2=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx2.check_hostname=False; ctx2.verify_mode=ssl.CERT_NONE
            ctx2.minimum_version=ssl.TLSVersion.TLSv1; ctx2.maximum_version=ssl.TLSVersion.TLSv1_1
            conn2=ctx2.wrap_socket(socket.create_connection((host,443),timeout=TIMEOUT),server_hostname=host)
            ver=conn2.version(); conn2.close()
            if ver in ("TLSv1","TLSv1.1"):
                hasil.append(bt(f"Protokol TLS versi lama didukung ({ver})","A02","HIGH","SEDANG",
                    f"Server menerima koneksi {ver} yang sudah tidak aman",
                    "Nonaktifkan TLS 1.0 & 1.1 — gunakan minimal TLS 1.2 atau TLS 1.3"))
        except Exception: ok("TLS versi lama (1.0/1.1) tidak didukung")
    try:
        resp=requests.get(url,timeout=TIMEOUT,verify=False,allow_redirects=True)
        h={k.lower():v for k,v in resp.headers.items()}
        if "strict-transport-security" not in h:
            hasil.append(bt("Header HSTS tidak ditemukan","A02","MEDIUM","SEDANG",
                "Header Strict-Transport-Security tidak ada dalam respons HTTP",
                "Tambahkan: Strict-Transport-Security: max-age=31536000; includeSubDomains"))
        else: ok("Header HSTS ditemukan")
    except Exception: pass
    return hasil

# ── A05 ──────────────────────────────────────────────────────
def scan_a05(url):
    hasil=[]
    try:
        resp=requests.get(url,timeout=TIMEOUT,verify=False,allow_redirects=True)
        h={k.lower():v for k,v in resp.headers.items()}
        checks=[
            ("x-frame-options","Header X-Frame-Options tidak ditemukan","HIGH","MUDAH",
             "Header X-Frame-Options tidak ada dalam respons HTTP",
             "Tambahkan: X-Frame-Options: DENY atau SAMEORIGIN"),
            ("x-content-type-options","Header X-Content-Type-Options tidak ditemukan","MEDIUM","SEDANG",
             "Header X-Content-Type-Options tidak ada dalam respons HTTP",
             "Tambahkan: X-Content-Type-Options: nosniff"),
            ("content-security-policy","Header Content-Security-Policy tidak ditemukan","MEDIUM","SEDANG",
             "Header CSP tidak ada dalam respons HTTP",
             "Tambahkan header Content-Security-Policy sesuai kebijakan aplikasi"),
            ("x-permitted-cross-domain-policies","Header X-Permitted-Cross-Domain-Policies tidak ditemukan","LOW","SULIT",
             "Header X-Permitted-Cross-Domain-Policies tidak ada dalam respons HTTP",
             "Tambahkan: X-Permitted-Cross-Domain-Policies: none"),
            ("referrer-policy","Header Referrer-Policy tidak ditemukan","LOW","SULIT",
             "Header Referrer-Policy tidak ada dalam respons HTTP",
             "Tambahkan: Referrer-Policy: strict-origin-when-cross-origin"),
        ]
        for hdr,nama,sev,expl,bukti,saran in checks:
            if hdr not in h: hasil.append(bt(nama,"A05",sev,expl,bukti,saran))
            else: ok(f"{hdr} ditemukan")
        parsed=urllib.parse.urlparse(url); base=f"{parsed.scheme}://{parsed.netloc}/"
        try:
            r=requests.get(base,timeout=TIMEOUT,verify=False)
            if any(i in r.text.lower() for i in ["index of /","directory listing","parent directory","[dir]"]):
                hasil.append(bt("Directory Listing aktif pada server","A05","HIGH","MUDAH",
                    "Halaman root menampilkan isi direktori secara terbuka",
                    "Nonaktifkan: Apache → Options -Indexes | Nginx → autoindex off"))
            else: ok("Directory listing tidak aktif")
        except Exception: pass
    except Exception as e: info(f"Gagal A05: {str(e)[:52]}")
    return hasil

# ── A06 ──────────────────────────────────────────────────────
def scan_a06(url):
    hasil=[]
    try:
        resp=requests.get(url,timeout=TIMEOUT,verify=False,allow_redirects=True)
        h={k.lower():v for k,v in resp.headers.items()}
        server=h.get("server",""); xp=h.get("x-powered-by",""); asp=h.get("x-aspnet-version","") or h.get("x-aspnetmvc-version","")
        if server:
            hasil.append(bt("Informasi versi server terekspos melalui header","A06","MEDIUM","MUDAH",
                f"Header Server: {server}","Hapus atau sembunyikan versi dari header Server"))
            sl=server.lower()
            for sw,vs in VULNERABLE_SERVERS.items():
                if sw in sl:
                    for v in vs:
                        if v in server:
                            hasil.append(bt("Komponen server dengan kerentanan CVE terdeteksi","A06","HIGH","MUDAH",
                                f"{server} — versi ini memiliki kerentanan publik (CVE)",
                                f"Perbarui {sw.capitalize()} ke versi terbaru yang masih didukung resmi")); break
        else: ok("Header Server tidak mengekspos versi")
        if xp:
            hasil.append(bt("Header X-Powered-By mengekspos teknologi server","A06","LOW","MUDAH",
                f"X-Powered-By: {xp}","Hapus header X-Powered-By dari konfigurasi server"))
        else: ok("Header X-Powered-By tidak ditemukan")
        if asp:
            hasil.append(bt("Versi ASP.NET terekspos melalui header","A06","MEDIUM","MUDAH",
                f"Header ASP.NET: {asp}","Tambahkan enableVersionHeader='false' pada web.config"))
    except Exception as e: info(f"Gagal A06: {str(e)[:52]}")
    return hasil

# ── RINGKASAN ────────────────────────────────────────────────
def ringkasan(semua,url):
    tr=sum(t["skor"] for t in semua); ov=max(0,100-tr); lab,ket,wsc=get_kat(ov)
    high=sum(1 for t in semua if t["severity"]=="HIGH")
    med =sum(1 for t in semua if t["severity"]=="MEDIUM")
    low =sum(1 for t in semua if t["severity"]=="LOW")
    print(); garis("tengah")
    baris("  "+Style.BRIGHT+"◈  RINGKASAN HASIL EVALUASI KEAMANAN")
    garis("tipis"); bk()
    baris(Fore.WHITE+"  Target        : "+Fore.YELLOW+Style.BRIGHT+url[:52])
    baris(Fore.WHITE+"  Waktu Scan    : "+Fore.YELLOW+datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
    bk(); garis("tipis")
    baris("  Distribusi    :  "+Fore.RED+Style.BRIGHT+f"● HIGH {high}   "+Fore.YELLOW+Style.BRIGHT+f"● MEDIUM {med}   "+Fore.CYAN+Style.BRIGHT+f"● LOW {low}")
    baris(Fore.WHITE+"  Total Temuan  : "+Style.BRIGHT+f"{len(semua)} kerentanan teridentifikasi")
    baris(Fore.WHITE+"  Total Risiko  : "+Fore.RED+Style.BRIGHT+f"{tr} poin")
    bk(); garis("tipis")
    baris(Fore.WHITE+"  Overall Score : "+wsc+Style.BRIGHT+f"{ov}/100  "+bar_score(ov))
    baris(Fore.WHITE+"  Kategori      : "+wsc+Style.BRIGHT+f"[ {lab} ]")
    baris(Fore.WHITE+"  Keterangan    : "+wsc+ket)
    bk(); garis("tipis"); bk()
    if semua:
        baris(Style.BRIGHT+"  ◈  DETAIL TEMUAN & SARAN PERBAIKAN"); bk()
        for i,t in enumerate(semua,1):
            w=warna_sev(t["severity"])
            baris("  "+Fore.BLUE+Style.BRIGHT+"┌─["+Style.RESET_ALL+f" {i:02d} "+Fore.BLUE+Style.BRIGHT+"]"+Style.RESET_ALL+"─── "+w+Style.BRIGHT+t["nama"])
            baris("  "+Fore.BLUE+Style.BRIGHT+"│   "+Style.RESET_ALL+Fore.MAGENTA+Style.BRIGHT+t["kategori"]+Style.RESET_ALL+
                  "  "+Fore.BLUE+Style.DIM+"│"+Style.RESET_ALL+"  Severity : "+w+t["severity"]+
                  Style.RESET_ALL+"  "+Fore.BLUE+Style.DIM+"│"+Style.RESET_ALL+"  Skor : "+w+Style.BRIGHT+str(t["skor"]))
            bks=[t["bukti"][j:j+46] for j in range(0,len(t["bukti"]),46)]
            baris("  "+Fore.BLUE+Style.BRIGHT+"│   "+Style.RESET_ALL+Fore.WHITE+"Bukti  : "+Style.DIM+bks[0])
            for c in bks[1:]: baris("  "+Fore.BLUE+Style.BRIGHT+"│   "+" "*9+Style.DIM+c)
            sks=[t["saran"][j:j+46] for j in range(0,len(t["saran"]),46)]
            baris("  "+Fore.BLUE+Style.BRIGHT+"└─► "+Style.RESET_ALL+Fore.GREEN+"Saran  : "+sks[0])
            for c in sks[1:]: baris("      "+" "*9+Fore.GREEN+c)
            bk()
    garis("tipis")
    baris(Style.DIM+f"  SecProbe v{VERSION}  │  Scan selesai: {datetime.datetime.now().strftime('%H:%M:%S')}")
    bk(); garis("bawah")

# ── MAIN ─────────────────────────────────────────────────────
def main():
    parser=argparse.ArgumentParser(prog="secprobe",description="SecProbe v1.0 - Web Security Evaluation Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Contoh:\n  python secprobe.py --url https://example.com\n  python secprobe.py --url http://testphp.vulnweb.com")
    parser.add_argument("--url",required=True,metavar="<target_url>",help="URL website target")
    parser.add_argument("--version",action="version",version=f"SecProbe v{VERSION}")
    args=parser.parse_args(); url=args.url.strip(); print()

    sp=Spinner(f"Memvalidasi target: {url[:45]}"); sp.mulai(); time.sleep(0.4)
    valid,pesan,url=validasi(url)
    if not valid:
        sp.stop("err",f"Gagal: {pesan}")
        print(Fore.RED+Style.BRIGHT+f"\n  [✘] {pesan}\n"); sys.exit(1)
    sp.stop("ok",f"Target valid — {url[:50]}"); print()

    banner(url)

    for kode,nama,ikon,fn in [
        ("A02","CRYPTOGRAPHIC FAILURES",       "🔐",scan_a02),
        ("A05","SECURITY MISCONFIGURATION",     "⚙ ",scan_a05),
        ("A06","VULNERABLE AND OUTDATED COMPS","📦",scan_a06),
    ]:
        sp2=Spinner(f"Scanning {kode} — {nama}..."); sp2.mulai(); time.sleep(0.3)
        sp2.stop("ok",f"{kode} — {nama} selesai")
        section(kode,nama,ikon)
        hasil=fn(url)
        for t in hasil: show_temuan(t)
        if not hasil: baris(Fore.GREEN+Style.BRIGHT+"  ✔  Tidak ditemukan kerentanan pada modul "+kode)
        bk()
        if kode=="A02": t_a02=hasil
        elif kode=="A05": t_a05=hasil
        else: t_a06=hasil

    ringkasan(t_a02+t_a05+t_a06, url)

if __name__=="__main__":
    main()
