#!/usr/bin/env python3
"""
apk_audit_extended.py — FINAL-V3 (2025)
✔ Compatible con Androguard 4.x
✔ Python 3.13
✔ dx.get_strings() → StringAnalysis/bytes → str
✔ dx.get_classes() → ClassAnalysis/bytes → str
✔ MobSF fail-safe
✔ HTML template corrected
✔ summary.by_result added
"""

import os
import sys
import argparse
import json
import subprocess
import re
from datetime import datetime, UTC
from jinja2 import Environment, FileSystemLoader, select_autoescape
from lxml import etree

# ==========================================================
# ANDROGUARD IMPORT (MODERN API)
# ==========================================================

try:
    from androguard.misc import AnalyzeAPK
except Exception:
    print("ERROR: Androguard 4.x no instalado.")
    print("Ejecuta: pip install 'androguard==4.1.3'")
    sys.exit(1)

# ==========================================================
# SAFE STRING EXTRACTOR
# ==========================================================

def extract_string(s):
    """Extrae un string seguro desde StringAnalysis o bytes."""
    try:
        val = s.get_value()
    except:
        return ""

    if isinstance(val, bytes):
        try:
            return val.decode(errors="ignore")
        except:
            return ""
    try:
        return str(val)
    except:
        return ""

# ==========================================================
# SAFE CLASS NAME EXTRACTOR
# ==========================================================

def extract_class_name(cls):
    """Extrae nombre de clase desde ClassAnalysis o bytes."""
    try:
        name = cls.name
    except:
        return ""

    if isinstance(name, bytes):
        try:
            return name.decode(errors="ignore")
        except:
            return ""

    try:
        return str(name)
    except:
        return ""

# ==========================================================
# UTILS
# ==========================================================

def save_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def safe_read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except:
        return ""


def shutil_which(name):
    from shutil import which
    return which(name)

# ==========================================================
# SIGNATURE PATTERNS
# ==========================================================

HARDCODE_KEYWORDS = [
    "API_KEY", "SECRET", "TOKEN", "PASSWORD",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "BEARER", "CLIENT_SECRET"
]

WEAK_CRYPTO_PATTERNS = [
    r"\bMD5\b", r"\bSHA1\b", r"\bECB\b",
    r"\bDES\b", r"\bRC4\b", r"\bPBEWithMD5AndDES\b"
]

DANGEROUS_PERMS = [
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.CAMERA"
]

# ==========================================================
# SCANNERS
# ==========================================================

def search_hardcoded(apk_path):
    results = []
    try:
        out = subprocess.check_output(
            f"strings -a '{apk_path}'",
            shell=True,
            text=True,
            stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            for kw in HARDCODE_KEYWORDS:
                if kw.lower() in line.lower():
                    results.append(line.strip())
    except:
        pass
    return results


def search_weak_crypto(strings):
    found = []
    for s in strings:
        text = extract_string(s)
        for pat in WEAK_CRYPTO_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                found.append(f"{pat} → {text}")
    return found


def search_external_storage(strings):
    hits = []
    for s in strings:
        text = extract_string(s)
        if (
            "getExternalStorage" in text
            or "Environment.getExternalStorage" in text
        ):
            hits.append(text)
    return hits

# ==========================================================
# JADX
# ==========================================================

def jadx_decompile(apk_path, outdir):
    if not shutil_which("jadx"):
        return None
    jd_dir = os.path.join(outdir, "jadx")
    os.makedirs(jd_dir, exist_ok=True)
    subprocess.run(f"jadx -d '{jd_dir}' '{apk_path}'", shell=True)
    return jd_dir

# ==========================================================
# MAIN ANALYSIS
# ==========================================================

def analyze(apk_path, outdir, use_jadx=False, mobsf_url=None):

    os.makedirs(outdir, exist_ok=True)
    rawdir = os.path.join(outdir, "raw")
    os.makedirs(rawdir, exist_ok=True)

    report = {
        "metadata": {
            "apk": os.path.abspath(apk_path),
            "timestamp": datetime.now(UTC).isoformat(),
            "tool": "apk_audit_extended (FINAL-V3)"
        },
        "masvs": {},
        "issues": [],
        "artifacts": {}
    }

    print("[*] Analizando APK con Androguard...")

    a, d_list, dx = AnalyzeAPK(apk_path)

    # ==========================================================
    # Manifest
    # ==========================================================

    manifest_el = a.get_android_manifest_xml()
    try:
        manifest_xml = etree.tostring(manifest_el, encoding="unicode")
    except:
        manifest_xml = str(manifest_el)

    with open(os.path.join(rawdir, "AndroidManifest.xml"), "w", encoding="utf-8") as f:
        f.write(manifest_xml)

    # ==========================================================
    # Strings
    # ==========================================================

    try:
        all_strings = dx.get_strings()
    except:
        all_strings = []

    # ==========================================================
    # MASVS CHECKS
    # ==========================================================

    masvs = {
        "STORAGE": [], "RESILIENCE": [], "CRYPTO": [],
        "NETWORK": [], "AUTH": [], "PRIVACY": [],
        "DATA_LEAKS": [], "CODE_PROTECTION": []
    }

    # STORAGE — allowBackup
    allow_backup = 'android:allowBackup="true"' in manifest_xml
    masvs["STORAGE"].append({
        "id": "ST-1",
        "desc": "allowBackup disabled",
        "ok": not allow_backup,
        "evidence": ["allowBackup=true"] if allow_backup else []
    })

    # STORAGE — hardcoded secrets
    secrets = search_hardcoded(apk_path)
    masvs["STORAGE"].append({
        "id": "ST-2",
        "desc": "No hardcoded secrets",
        "ok": len(secrets) == 0,
        "evidence": secrets
    })

    # STORAGE — external storage
    ext_hits = search_external_storage(all_strings)
    masvs["STORAGE"].append({
        "id": "ST-3",
        "desc": "No external storage APIs",
        "ok": len(ext_hits) == 0,
        "evidence": ext_hits
    })

    # RESILIENCE — debuggable
    debuggable = 'android:debuggable="true"' in manifest_xml
    masvs["RESILIENCE"].append({
        "id": "RS-1",
        "desc": "debuggable false",
        "ok": not debuggable,
        "evidence": ["debuggable=true"] if debuggable else []
    })

    # RESILIENCE — exported components
    exported = re.findall(r'android:exported="true".*?name="([^"]+)"', manifest_xml)
    masvs["RESILIENCE"].append({
        "id": "RS-2",
        "desc": "No exported components",
        "ok": len(exported) == 0,
        "evidence": exported
    })

    # CRYPTO
    weak = search_weak_crypto(all_strings)
    masvs["CRYPTO"].append({
        "id": "CR-1",
        "desc": "No weak crypto",
        "ok": len(weak) == 0,
        "evidence": weak
    })

    # DATA LEAKS
    perms = a.get_permissions()
    bad = [p for p in perms if p in DANGEROUS_PERMS]
    masvs["DATA_LEAKS"].append({
        "id": "DL-1",
        "desc": "No dangerous perms",
        "ok": len(bad) == 0,
        "evidence": bad
    })

    # PRIVACY
    privacy_hits = []
    for s in all_strings:
        text = extract_string(s).lower()
        if any(x in text for x in ["imei","deviceid","location","contacts"]):
            privacy_hits.append(text)

    masvs["PRIVACY"].append({
        "id": "PV-1",
        "desc": "No sensitive identifiers",
        "ok": len(privacy_hits) == 0,
        "evidence": privacy_hits
    })

    # AUTH
    auth_hits = []
    for s in all_strings:
        text = extract_string(s).lower()
        if re.search(r"oauth|jwt|bearer|access_token", text):
            auth_hits.append(text)

    masvs["AUTH"].append({
        "id": "AU-1",
        "desc": "No plaintext auth tokens",
        "ok": len(auth_hits) == 0,
        "evidence": auth_hits
    })

    # CODE_PROTECTION — class analysis
    class_list = []
    try:
        for cls in dx.get_classes():
            cname = extract_class_name(cls)
            if cname:
                class_list.append(cname)
    except:
        class_list = []

    short = []
    for c in class_list:
        try:
            if re.match(r"^L[a-z]{1,2}/", c):
                short.append(c)
        except:
            continue

    obf = len(class_list) > 0 and len(short) / len(class_list) > 0.15

    masvs["CODE_PROTECTION"].append({
        "id": "CP-1",
        "desc": "Obfuscation heuristic",
        "ok": obf,
        "evidence": [f"{len(short)}/{len(class_list)} obfuscated"]
    })

    # NETWORK
    network_hits = []
    for s in all_strings:
        text = extract_string(s)
        if re.search(r"ssl|tls|hostnameverifier|trust|okhttp", text, re.I):
            network_hits.append(text)

    masvs["NETWORK"].append({
        "id": "NW-1",
        "desc": "Network/TLS indicators",
        "ok": True,
        "evidence": network_hits
    })

    # ==========================================================
    # JADX
    # ==========================================================

    if use_jadx:
        jd = jadx_decompile(apk_path, rawdir)
        if jd:
            java_hits = []
            for root, _, files in os.walk(jd):
                for f in files:
                    if not f.endswith(".java"):
                        continue
                    txt = safe_read(os.path.join(root, f))

                    for kw in HARDCODE_KEYWORDS:
                        if kw.lower() in txt.lower():
                            java_hits.append(f"{f} → {kw}")

                    for pat in WEAK_CRYPTO_PATTERNS:
                        if re.search(pat, txt, re.I):
                            java_hits.append(f"{f} → {pat}")

            masvs["CODE_PROTECTION"].append({
                "id": "CP-JADX",
                "desc": "JADX scan",
                "ok": len(java_hits) == 0,
                "evidence": java_hits
            })

    # ==========================================================
    # MOBSF (fail-safe)
    # ==========================================================

    if mobsf_url and os.getenv("MOBSF_API_KEY"):
        try:
            import requests
            print("[*] MobSF: analizando…")

            ses = requests.Session()
            ses.headers.update({"Authorization": os.getenv("MOBSF_API_KEY")})

            up = ses.post(
                mobsf_url.rstrip("/") + "/api/v1/upload",
                files={"file": (os.path.basename(apk_path), open(apk_path, "rb"))}
            ).json()

            if "hash" not in up:
                print("[!] MobSF devolvió error. Se omite MobSF.")
            else:
                scan_hash = up["hash"]

                ses.post(
                    mobsf_url.rstrip("/") + "/api/v1/scan",
                    data={"scan_type": up.get("type", "apk"), "scan_targets": scan_hash}
                )

                rep = ses.post(
                    mobsf_url.rstrip("/") + "/api/v1/report_json",
                    data={"hash": scan_hash}
                ).json()

                save_json(os.path.join(rawdir, "mobsf.json"), rep)
                report["artifacts"]["MobSF"] = "raw/mobsf.json"

        except Exception as e:
            print("[!] Error en MobSF:", e)

    # ==========================================================
    # BUILD ISSUES
    # ==========================================================

    report["masvs"] = masvs

    issues = []
    for cat, checks in masvs.items():
        for c in checks:
            issues.append({
                "id": c["id"],
                "category": cat,
                "title": c["desc"],
                "result": "OK" if c["ok"] else "KO",
                "severity": "HIGH" if not c["ok"] else "INFO",
                "evidence": c["evidence"]
            })

    # ==========================================================
    # SUMMARY + by_result
    # ==========================================================

    by_result = {
        "OK": sum(1 for i in issues if i["result"] == "OK"),
        "KO": sum(1 for i in issues if i["result"] == "KO"),
        "WARN": sum(1 for i in issues if i["severity"] == "INFO"),
    }

    report["summary"] = {
        "total": len(issues),
        "ok": by_result["OK"],
        "ko": by_result["KO"],
        "warn": by_result["WARN"],
        "by_result": by_result
    }

    save_json(os.path.join(outdir, "report.json"), report)

    # ==========================================================
    # RENDER HTML
    # ==========================================================

    tmpl_dir = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(loader=FileSystemLoader(tmpl_dir), autoescape=select_autoescape(["html"]))

    html = env.get_template("report_template.html").render(report=report)

    with open(os.path.join(outdir, "report.html"), "w", encoding="utf-8") as f:
        f.write(html)

    print("[✔] Auditoría completada →", outdir)
    return report

# ==========================================================
# CLI
# ==========================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", required=True)
    parser.add_argument("--outdir", default="audit_results")
    parser.add_argument("--use-jadx", action="store_true")
    parser.add_argument("--mobsf-url", default=None)
    args = parser.parse_args()

    analyze(args.apk, args.outdir, args.use_jadx, args.mobsf_url)


if __name__ == "__main__":
    main()
