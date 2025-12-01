#!/usr/bin/env bash
set -e

echo "============================================================="
echo "   APK Security Audit – Instalador Automático de Dependencias"
echo "============================================================="

OS="$(uname -s)"

install_python_packages() {
    echo "[+] Instalando dependencias Python..."
    pip3 install --upgrade pip
    pip3 install androguard jinja2 requests python-magic > /dev/null
}

install_apktool_linux() {
    echo "[+] Instalando apktool (Linux)..."
    wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
    wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool.jar
    chmod +x apktool
    sudo mv apktool /usr/local/bin/
    sudo mv apktool.jar /usr/local/bin/
}

install_apktool_macos() {
    echo "[+] Instalando apktool (macOS con brew)..."
    brew install apktool
}

install_jadx_linux() {
    echo "[+] Instalando jadx (Linux)..."
    JADX_VERSION=$(curl -s https://api.github.com/repos/skylot/jadx/releases/latest | grep tag_name | cut -d '"' -f4)
    wget -q https://github.com/skylot/jadx/releases/download/${JADX_VERSION}/jadx-${JADX_VERSION}.zip
    unzip -q jadx-${JADX_VERSION}.zip
    sudo mv jadx-*/bin/jadx /usr/local/bin/
    sudo mv jadx-*/bin/jadx-gui /usr/local/bin/
}

install_jadx_macos() {
    echo "[+] Instalando jadx (macOS)..."
    brew install jadx
}

check_or_install_docker() {
    if ! command -v docker &> /dev/null; then
        echo "[!] Docker no está instalado."
        echo "    Si deseas usar MobSF, instala docker manualmente:"
        echo "    https://docs.docker.com/get-docker/"
    else
        echo "[+] Docker encontrado."
    fi
}

check_or_install_mobsf() {
    if ! docker ps | grep -q mobsf; then
        echo "[-] MobSF no está corriendo."
        echo "¿Quieres instalar/levantar MobSF automáticamente? (s/n)"
        read opt
        if [[ "$opt" == "s" ]]; then
            echo "[+] Levantando MobSF con Docker..."
            docker run --rm -d -p 8000:8000 --name mobsf \
                opensecurity/mobile-security-framework-mobsf
            echo "[+] MobSF iniciado en http://127.0.0.1:8000"
            echo "    Ve a Settings > API Key y exporta tu API key:"
            echo "    export MOBSF_API_KEY=\"TU_API_KEY\""
        else
            echo "[!] MobSF no será instalado (opcional)."
        fi
    else
        echo "[+] MobSF ya se está ejecutando."
    fi
}

echo ""
echo "🔎 Comprobando Python 3..."
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 no está instalado. Instálalo antes de continuar."
    exit 1
fi
echo "[+] Python3 OK."

echo ""
echo "🔎 Comprobando pip..."
if ! command -v pip3 &> /dev/null; then
    echo "[!] pip3 no está instalado. Instalando..."
    sudo apt install -y python3-pip || sudo brew install python3
else
    echo "[+] pip3 OK."
fi

install_python_packages

echo ""
echo "🔎 Comprobando apktool..."
if ! command -v apktool &> /dev/null; then
    echo "[!] apktool no está instalado."
    if [[ "$OS" == "Linux" ]]; then
        install_apktool_linux
    elif [[ "$OS" == "Darwin" ]]; then
        install_apktool_macos
    else
        echo "[!] Sistema operativo no detectado. Instala apktool manualmente."
        exit 1
    fi
else
    echo "[+] apktool OK."
fi

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
        echo "[+] JADX instalado."
    else
        echo "[!] Se omitió instalación de JADX (opcional)."
    fi
else
    echo "[+] JADX OK."
fi

echo ""
echo "🔎 Comprobando Docker..."
check_or_install_docker

echo ""
echo "🔎 Comprobando MobSF..."
check_or_install_mobsf

echo ""
echo "============================================================="
echo " ✔ Entorno listo para ejecutar:"
echo "      ./run_audit.sh <apk> <output_dir>"
echo "============================================================="
echo ""
echo "Si usarás MobSF, recuerda exportar tu API Key:"
echo "    export MOBSF_API_KEY=\"TU_API_KEY\""
echo ""
echo "¡Todo listo! 🚀"
