#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Uso: $0 ruta/al/app.apk [output_dir]"
  exit 1
fi

APK="$1"
OUTDIR="${2:-audit_results}"
MOBSF_HOST="${MOBSF_HOST:-http://127.0.0.1:8000}"

mkdir -p "$OUTDIR"

echo "=== APK Audit Extended (MASVS heuristics + JADX + MobSF) ==="
echo "APK: $APK"
echo "Output: $OUTDIR"

# Checks
command -v python3 >/dev/null 2>&1 || { echo "python3 no encontrado."; exit 1; }
command -v apktool >/dev/null 2>&1 || { echo "apktool no encontrado. Instálalo."; exit 1; }

# Check jadx
if command -v jadx >/dev/null 2>&1; then
  echo "[*] jadx encontrado."
  USE_JADX=true
else
  echo "[!] jadx no encontrado. Para análisis de Java instala jadx y ponlo en PATH."
  USE_JADX=false
fi

# MobSF reachable?
MOBSF_AVAILABLE=false
if curl -sSf --max-time 3 "$MOBSF_HOST" >/dev/null 2>&1; then
  MOBSF_AVAILABLE=true
  echo "[*] MobSF responde en $MOBSF_HOST"
else
  echo "[!] MobSF no responde en $MOBSF_HOST (continuando sin MobSF)."
fi

# Run Python analyzer
PY="apk_audit_extended.py"
ARGS=(--apk "$APK" --outdir "$OUTDIR")
$USE_JADX && ARGS+=("--use-jadx")
$MOBSF_AVAILABLE && ARGS+=("--mobsf-url" "$MOBSF_HOST")

python3 "$PY" "${ARGS[@]}"

echo "=== Finalizado. Revisar $OUTDIR/report.json y $OUTDIR/report.html ==="
