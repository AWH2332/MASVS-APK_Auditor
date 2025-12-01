#!/usr/bin/env bash
set -e

echo "============================================================="
echo "   APK Security Audit – Instalador Automático (Kali Friendly)"
echo "============================================================="

OS="$(uname -s)"

# -----------------------------
#  1. Crear entorno virtual
# -----------------------------
echo ""
echo "🔧 Verificando entorno virtual Python..."

if [ ! -d "venv" ]; then
    echo "[+] Creando entorno virtual en ./venv"
    python3 -m venv venv
else
    echo "[+] Entorno virtual ya existe."
fi

# Activar entorno virtual
source venv/bin/activate

echo "[+] Entorno virtual activado: $(which python3)"

# -----------------------------
#  2. Instalar dependencias Python dentro del venv
# -----------------------------
echo ""
echo "🔧 Instalando dependencias Python (en entorno virtual)..."

pip install --upgrade pip >/dev/null
pip install androguard jinja2 requests python-magic >/dev/null

echo "[+] Dependencias Python instaladas."

# -----------------------------
# 3. Instalar apktool
# -----------------------------
install_apktool_linux() {
    echo "[+] Instalando apktool (Linux)..."
    sudo apt install apktool -y

}

install_apktool_macos() {
    echo "[+] Instalando apktool (macOS con brew)..."
    brew install apktool
}

echo ""
echo "🔎 Comprobando apktool..."
if ! command -v apktool &> /dev/null; then
    echo "[!] apktool no está instalado."
    if [[ "$OS" == "Linux" ]]; then
        install_apktool_linux
    elif [[ "$OS" == "Darwin" ]]; then
        install_apktool_macos
    fi
else
    echo "[+] apktool OK."
fi

# -----------------------------
# 4. Instalar jadx
# -----------------------------
install_jadx_linux() {
    echo "[+] Instalando jadx (Linux)..."
    sudo apt install jadx -y

}

install_jadx_macos() {
    echo "[+] Instalando jadx (macOS)..."
    brew install jadx
}

echo ""
echo "🔎 Comprobando jadx..."
if ! command -v jadx &> /dev/null; then
    echo "[!] jadx no está instalado."
    echo "¿Deseas instalar JADX automáticamente? (s/n)"
    read opt
    if [[ "$opt" == "s" ]]; then
        if [[ "$OS" == "Linux" ]]; then
            install_jadx_linux
        elif [[ "$OS" == "Darwin" ]]; then
            install_jadx_macos
        fi
    else
        echo "[!] Se omitió instalación de JADX."
    fi
else
    echo "[+] JADX OK."
fi

# -----------------------------
# 5. Docker / MobSF
# -----------------------------
echo ""
echo "🔎 Comprobando Docker..."

if ! command -v docker &> /dev/null; then
    echo "[!] Docker NO está instalado."
    echo "    Si quieres usar MobSF deberás instalar docker manualmente."
else
    echo "[+] Docker OK."
    echo ""

    echo "🔎 Comprobando MobSF..."
    if ! docker ps | grep -q mobsf; then
        echo "[!] MobSF no está corriendo."
        echo "¿Levantar MobSF con Docker ahora? (s/n)"
        read opt
        if [[ "$opt" == "s" ]]; then
            echo "[+] Iniciando MobSF..."
            docker run --rm -d -p 8000:8000 --name mobsf \
                opensecurity/mobile-security-framework-mobsf
            echo "[+] MobSF disponible en http://127.0.0.1:8000"
        fi
    else
        echo "[+] MobSF ya está en ejecución."
    fi
fi

# -----------------------------
# 6. Ajustar run_audit.sh para usar el venv
# -----------------------------
echo ""
echo "🔧 Ajustando run_audit.sh para usar el entorno virtual..."

if grep -q "source venv/bin/activate" run_audit.sh; then
    echo "[+] run_audit.sh ya está configurado."
else
    sed -i '1isource venv/bin/activate' run_audit.sh
    echo "[+] run_audit.sh modificado para activar venv automáticamente."
fi

echo ""
echo "============================================================="
echo " ✔ ENTORNO LISTO PARA USO"
echo "-------------------------------------------------------------"
echo " Ejecuta auditoría con:"
echo "     ./run_audit.sh myapp.apk results/"
echo ""
echo " Si usas MobSF, exporta tu API key:"
echo "     export MOBSF_API_KEY=\"TU_API_KEY\""
echo "============================================================="
