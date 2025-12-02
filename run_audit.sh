#!/usr/bin/env bash
set -euo pipefail

echo "=== APK Audit Extended (MASVS + JADX + MobSF) ==="

# --------------------------------------------------
# 1. Activar entorno virtual
# --------------------------------------------------
if [ ! -f "venv/bin/activate" ]; then
    echo "[ERROR] No existe el entorno virtual (venv/)."
    echo "Ejecuta primero: ./setup_audit_env.sh"
    exit 1
fi

echo "[*] Activando entorno virtual..."
source venv/bin/activate

echo "[*] Python activo: $(which python3)"

# Verificar androguard
echo "[*] Verificando androguard..."
python3 - << 'EOF'
import androguard
EOF

echo "[+] androguard detectado en el entorno virtual."

# --------------------------------------------------
# 2. Argumentos
# --------------------------------------------------
if [ $# -lt 2 ]; then
  echo "Uso: $0 <ruta_apk> <output_dir>"
  exit 1
fi

APK="$1"
OUTDIR="$2"

echo "APK: $APK"
echo "Output: $OUTDIR"

# --------------------------------------------------
# 3. Verificar apktool / jadx
# --------------------------------------------------
command -v apktool >/dev/null || { echo "[ERROR] apktool no instalado."; exit 1; }

USE_JADX=false
if command -v jadx >/dev/null; then
    echo "[*] JADX encontrado."
    USE_JADX=true
else
    echo "[!] JADX no encontrado."
fi

# --------------------------------------------------
# 4. Detectar MobSF
# --------------------------------------------------
MOBSF_HOST="${MOBSF_HOST:-http://127.0.0.1:8000}"
MOBSF_AVAILABLE=false

if curl -sSf --max-time 2 "$MOBSF_HOST" >/dev/null 2>&1; then
    echo "[*] MobSF responde en $MOBSF_HOST"
    MOBSF_AVAILABLE=true
else
    echo "[!] MobSF no disponible."
fi

# --------------------------------------------------
# 5. Construcción de argumentos para Python
# --------------------------------------------------
ARGS=( --apk "$APK" --outdir "$OUTDIR" )

if [ "$USE_JADX" = true ]; then
    ARGS+=( --use-jadx )
fi

if [ "$MOBSF_AVAILABLE" = true ]; then
    ARGS+=( --mobsf-url "$MOBSF_HOST" )
fi

# --------------------------------------------------
# 6. EJECUCIÓN CON EL PYTHON DENTRO DEL VENV
# --------------------------------------------------
echo "[*] Ejecutando analizador con venv/python3..."
venv/bin/python3 apk_audit_extended.py "${ARGS[@]}"

echo "=== Auditoría completada. Resultados en $OUTDIR ==="
