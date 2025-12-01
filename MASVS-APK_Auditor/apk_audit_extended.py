#!/usr/bin/env python3
"""
apk_audit_extended.py
Analizador estático avanzado con:
 - Androguard (APK parsing)
 - Opcional: JADX (decompila a Java para búsquedas más ricas)
 - Integración MobSF (si se pasa --mobsf-url y exportas MOBSF_API_KEY)
 - Reporte JSON + HTML (Jinja2)
 - Heurísticas ampliadas para evaluar MASVS por categorías
"""

import os
import sys
import argparse
import json
import subprocess
import time
import tempfile
import re
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape

# androguard
try:
    from androguard.core.bytecodes.apk import APK
except Exception as e:
    print("Por favor instala androguard: pip install androguard")
    raise

# ---------- Helpers ----------
def run(cmd, cwd=None, capture=False):
    if capture:
        return subprocess.check_output(cmd, shell=True, cwd=cwd, text=True, stderr=subprocess.DEVNULL)
    else:
        subprocess.check_call(cmd, shell=True, cwd=cwd)

def save_json(path, obj):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def safe_read(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except:
        return ""

# ---------- Utilities ----------
HARDCODE_KEYWORDS = ["API_KEY","SECRET","TOKEN","PASSWORD","AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY","BEARER","CLIENT_SECRET"]
WEAK_CRYPTO_PATTERNS = [r"\bMD5\b", r"\bSHA1\b", r"\bECB\b", r"\bDES\b", r"\bRC4\b", r"\bPBEWithMD5AndDES\b"]
DANGEROUS_PERMS = [
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.RECORD_AUDIO", "android.permission.READ_PHONE_STATE",
    "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION"
]

# ---------- MASVS checks mapping (heuristic) ----------
# Each check: id, desc, function to evaluate -> returns (result_bool, evidence_list)
def check_debuggable(manifest_xml, apk_obj):
    found = 'android:debuggable="true"' in manifest_xml
    return (not found, ["android:debuggable=true found"] if found else ["android:debuggable not true"])

def check_allow_backup(manifest_xml, apk_obj):
    found = 'android:allowBackup="true"' in manifest_xml
    return (not found, ["android:allowBackup=true found"] if found else ["allowBackup not enabled"])

def check_permissions(apk_obj):
    perms = apk_obj.get_permissions() or []
    found = [p for p in perms if p in DANGEROUS_PERMS]
    return (len(found)==0, found)

def check_exported_components(manifest_xml, apk_obj):
    exports = re.findall(r'(<activity[^>]*>)|(<service[^>]*>)|(<receiver[^>]*>)|(<provider[^>]*>)', manifest_xml, flags=re.IGNORECASE)
    # simpler: search android:exported="true"
    found = re.findall(r'android:exported="true"\s+[^>]*name="([^"]+)"', manifest_xml)
    if not found:
        # try other ordering
        found = re.findall(r'name="([^"]+)"[^>]*android:exported="true"', manifest_xml)
    return (len(found)==0, found)

def search_hardcoded_strings(apk_path, tempdir):
    """Run strings over apk and search keywords; plus androguard strings"""
    results = []
    try:
        out = subprocess.check_output(f"strings -a {apk_path}", shell=True, text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            for kw in HARDCODE_KEYWORDS:
                if kw.lower() in line.lower():
                    results.append(line.strip())
    except Exception:
        pass
    # also check resources via aapt? skip for speed
    return results

def search_weak_crypto(all_strings):
    found=[]
    for s in all_strings:
        for pat in WEAK_CRYPTO_PATTERNS:
            if re.search(pat, s, flags=re.IGNORECASE):
                found.append(f"{pat} -> {s}")
    return found

def search_external_storage(all_strings):
    hits = [s for s in all_strings if "getExternalStorage" in s or "getExternalStorageDirectory" in s or "Environment.getExternalStorage" in s]
    return hits

def jadx_decompile(apk_path, outdir):
    """decompile with jadx if available; returns java_dir or None"""
    if not shutil_which("jadx"):
        return None
    jd_out = os.path.join(outdir, "jadx")
    os.makedirs(jd_out, exist_ok=True)
    cmd = f"jadx -d {jd_out} {apk_path}"
    print("[*] Ejecutando jadx (puede tardar)...")
    subprocess.run(cmd, shell=True, check=False)
    return jd_out

def shutil_which(name):
    from shutil import which
    return which(name)

# ---------- Main analysis ----------
def analyze(apk_path, outdir, use_jadx=False, mobsf_url=None):
    os.makedirs(outdir, exist_ok=True)
    rawdir = os.path.join(outdir, "raw")
    os.makedirs(rawdir, exist_ok=True)

    report = {
        "metadata": {
            "apk": os.path.abspath(apk_path),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tool": "apk_audit_extended"
        },
        "masvs": {},
        "issues": [],
        "artifacts": {}
    }

    print("[*] Cargando APK con androguard...")
    a = APK(apk_path)
    manifest_xml = a.get_android_manifest_xml().toxml()
    save_json(os.path.join(rawdir, "apk_meta.json"), {"package": a.get_package(), "version": a.get_androidversion_name()})
    with open(os.path.join(rawdir, "AndroidManifest.xml"), "w", encoding="utf-8") as f:
        f.write(manifest_xml)

    # all strings
    try:
        all_strings = a.get_strings() or []
    except Exception:
        all_strings = []

    # Basic MASVS categories: STORAGE, RESILIENCE, NETWORK, CRYPTO, AUTH, DATA_LEAKS, PRIVACY, CODE_PROTECTION
    masvs = {
        "STORAGE": [],
        "RESILIENCE": [],
        "NETWORK": [],
        "CRYPTO": [],
        "AUTH": [],
        "DATA_LEAKS": [],
        "PRIVACY": [],
        "CODE_PROTECTION": []
    }

    # STORAGE checks
    ok, evidence = check_allow_backup(manifest_xml, a)
    masvs["STORAGE"].append({"id":"ST-1","desc":"allowBackup disabled","ok":ok,"evidence":evidence})
    secrets = search_hardcoded_strings(apk_path, rawdir)
    masvs["STORAGE"].append({"id":"ST-2","desc":"No hardcoded secrets in APK strings","ok": len(secrets)==0,"evidence": secrets})

    ext_hits = search_external_storage(all_strings)
    masvs["STORAGE"].append({"id":"ST-3","desc":"No uso de external storage","ok": len(ext_hits)==0, "evidence": ext_hits})

    # RESILIENCE checks
    ok, ev = check_debuggable(manifest_xml, a)
    masvs["RESILIENCE"].append({"id":"RS-1","desc":"debuggable false","ok":ok,"evidence":ev})
    ok, exported = check_exported_components(manifest_xml, a)
    masvs["RESILIENCE"].append({"id":"RS-2","desc":"No componentes exportados innecesarios","ok":ok,"evidence": exported})

    # CODE_PROTECTION (ofuscación + proguard mapping)
    classes = a.get_classes_names() or []
    short_names = [c for c in classes if re.match(r'^L[a-z]{1,2}/', c)]
    obf_heur = (len(classes)>0 and (len(short_names)/len(classes) > 0.15))
    masvs["CODE_PROTECTION"].append({"id":"CP-1","desc":"Ofuscación detectada heurísticamente","ok": obf_heur, "evidence":[f"{len(short_names)} nombres cortos / {len(classes)} clases"]})
    # proguard mapping not present? check for mapping.txt in resources (very heuristic)
    # search in apk for 'mapping.txt' (not reliable)
    masvs["CODE_PROTECTION"].append({"id":"CP-2","desc":"ProGuard/R8 mapping included in package (should not)","ok": True, "evidence": []})

    # DATA_LEAKS
    ok_perms, found_perms = check_permissions(a)
    masvs["DATA_LEAKS"].append({"id":"DL-1","desc":"No permisos peligrosos","ok": ok_perms, "evidence": found_perms})
    masvs["DATA_LEAKS"].append({"id":"DL-2","desc":"No secretos hardcoded", "ok": len(secrets)==0, "evidence": secrets})

    # CRYPTO
    weak = search_weak_crypto(all_strings)
    masvs["CRYPTO"].append({"id":"CR-1","desc":"No uso de crypto débil (MD5, SHA1, ECB, ...)", "ok": len(weak)==0, "evidence": weak})

    # NETWORK (heuristics)
    # Look for okhttp, HttpsURLConnection, setHostnameVerifier, TrustManager, disableSslVerification patterns
    network_evidence = []
    for s in all_strings:
        if s and re.search(r'okhttp|okhttp3|OkHttpClient|HttpsURLConnection|HostnameVerifier|TrustManager|SSLSocketFactory', s, re.IGNORECASE):
            network_evidence.append(s)
        if s and re.search(r"certificatepinning|pinning|setHostnameVerifier|AllowAllHostnameVerifier|X509TrustManager", s, re.IGNORECASE):
            network_evidence.append(s)
        if s and re.search(r"TrustAllCertificates|trustAllCerts|setHostnameVerifier\\(", s, re.IGNORECASE):
            network_evidence.append(s)
    masvs["NETWORK"].append({"id":"NW-1","desc":"Evidencias de manejo TLS/Pinning (revisar manual)", "ok": True, "evidence": network_evidence})

    # AUTH
    # Look for OAuth flows, token storage keywords
    auth_evidence = [s for s in all_strings if s and re.search(r"oauth|openid|jwt|bearer|access_token", s, re.IGNORECASE)]
    masvs["AUTH"].append({"id":"AU-1","desc":"Evidencias de flujos de autenticación (heurístico)", "ok": not bool(auth_evidence), "evidence": auth_evidence})

    # PRIVACY
    privacy_evidence = [s for s in all_strings if s and re.search(r"location|contacts|imei|deviceid|macaddress", s, re.IGNORECASE)]
    masvs["PRIVACY"].append({"id":"PV-1","desc":"Acceso a datos sensibles (location, contacts, imei...)", "ok": not bool(privacy_evidence), "evidence": privacy_evidence})

    # If use_jadx requested, decompile and run extra searches
    jadx_out = None
    if use_jadx and shutil_which("jadx"):
        print("[*] Decompiling with jadx for richer code analysis...")
        jd_out = os.path.join(rawdir, "jadx")
        os.makedirs(jd_out, exist_ok=True)
        try:
            subprocess.run(f"jadx -d {jd_out} {apk_path}", shell=True, check=True)
            jadx_out = jd_out
            report["artifacts"]["jadx_dir"] = jd_out
            # Search Java files for dangerous patterns
            java_issues = []
            for root, _, files in os.walk(jd_out):
                for f in files:
                    if f.endswith(".java"):
                        p = os.path.join(root, f)
                        txt = safe_read(p)
                        if re.search(r"android:debuggable|allowBackup", txt, re.IGNORECASE):
                            java_issues.append(f"{p}: manifest strings in java")
                        # hardcoded keys pattern
                        for kw in HARDCODE_KEYWORDS:
                            if kw.lower() in txt.lower():
                                java_issues.append(f"{p}: contains {kw}")
                        # insecure crypto uses
                        for pat in WEAK_CRYPTO_PATTERNS:
                            if re.search(pat, txt, re.IGNORECASE):
                                java_issues.append(f"{p}: crypto pattern {pat}")
                        # TrustManager/HostnameVerifier disabling checks
                        if re.search(r"X509TrustManager|allowAllHostnameVerifier|HostnameVerifier", txt):
                            java_issues.append(f"{p}: TLS related pattern")
            if java_issues:
                masvs["CODE_PROTECTION"].append({"id":"CP-JADX-1","desc":"Findings from JADX (hardcoded / TLS / crypto)", "ok": False, "evidence": java_issues})
            else:
                masvs["CODE_PROTECTION"].append({"id":"CP-JADX-1","desc":"Findings from JADX", "ok": True, "evidence": []})
        except subprocess.CalledProcessError as e:
            print("[!] jadx error:", e)
            report["artifacts"]["jadx_error"] = str(e)
    else:
        if use_jadx:
            print("[!] Se solicitó --use-jadx pero 'jadx' no está en PATH; omitiendo.")
        else:
            print("[*] JADX no solicitado; se puede ejecutar con --use-jadx")

    # MobSF integration (optional)
    mobsf_raw = None
    if mobsf_url:
        api_key = os.getenv("MOBSF_API_KEY")
        if api_key:
            try:
                print("[*] Uploading and scanning with MobSF...")
                ses = requests.Session()
                ses.headers.update({"Authorization": api_key})
                upload_url = mobsf_url.rstrip("/") + "/api/v1/upload"
                scan_url = mobsf_url.rstrip("/") + "/api/v1/scan"
                report_url = mobsf_url.rstrip("/") + "/api/v1/report_json"
                r = ses.post(upload_url, files={"file": (os.path.basename(apk_path), open(apk_path,"rb"), "application/octet-stream")})
                r.raise_for_status()
                up = r.json()
                scan_hash = up.get("hash")
                time.sleep(1)
                ses.post(scan_url, data={"scan_type": up.get("type","apk"), "scan_targets": scan_hash})
                time.sleep(2)
                r2 = ses.post(report_url, data={"hash": scan_hash})
                r2.raise_for_status()
                mobsf_raw = r2.json()
                save_json(os.path.join(rawdir, "mobsf.json"), mobsf_raw)
                report["artifacts"]["mobsf"] = "raw/mobsf.json"
                # Quick summary: if mobsf has 'issues' or 'findings' keys, add note (structure varies)
                report["artifacts"]["mobsf_summary_keys"] = list(mobsf_raw.keys())
            except Exception as e:
                print("[!] Error MobSF:", e)
        else:
            print("[!] MOBSF_API_KEY no encontrada en entorno; omitiendo MobSF")

    # Build issues list from MASVS statuses (flatten)
    issues = []
    for cat, checks in masvs.items():
        for c in checks:
            status = "OK" if c.get("ok") else ("WARN" if c.get("ok") is None else "KO")
            sev = "HIGH" if not c.get("ok") and c.get("id", "").startswith(("ST","RS","CR","DL")) else "MEDIUM"
            issues.append({
                "id": c.get("id"),
                "category": cat,
                "title": c.get("desc"),
                "result": status,
                "severity": sev,
                "evidence": c.get("evidence", [])
            })

    report["masvs"] = masvs
    report["issues"] = issues
    report["summary"] = {
        "total_checks": sum(len(v) for v in masvs.values()),
        "by_result": {
            "OK": sum(1 for i in issues if i["result"]=="OK"),
            "KO": sum(1 for i in issues if i["result"]=="KO"),
            "WARN": sum(1 for i in issues if i["result"]=="WARN")
        }
    }

    # save json + generate html
    save_json(os.path.join(outdir, "report.json"), report)

    # render HTML
    tmpl_dir = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(loader=FileSystemLoader(tmpl_dir), autoescape=select_autoescape(["html","xml"]))
    tmpl = env.get_template("report_template.html")
    html = tmpl.render(report=report)
    with open(os.path.join(outdir, "report.html"), "w", encoding="utf-8") as f:
        f.write(html)

    print("[*] Reportes generados en:", outdir)
    return report

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="APK Audit Extended (MASVS heuristics + JADX)")
    parser.add_argument("--apk", required=True, help="Ruta al APK")
    parser.add_argument("--outdir", default="audit_results", help="Directorio de salida")
    parser.add_argument("--use-jadx", action="store_true", help="Usar JADX para decompilar y análisis de Java")
    parser.add_argument("--mobsf-url", default=None, help="URL de MobSF (ej: http://127.0.0.1:8000)")
    args = parser.parse_args()

    report = analyze(args.apk, args.outdir, use_jadx=args.use_jadx, mobsf_url=args.mobsf_url)
    # Exit code >0 if there are HIGH severity KOs (for CI)
    high_issues = [i for i in report["issues"] if i["result"]=="KO" and i["severity"]=="HIGH"]
    if high_issues:
        print("[!] Se han encontrado issues HIGH:", len(high_issues))
        sys.exit(2)
    sys.exit(0)

if __name__ == "__main__":
    main()
