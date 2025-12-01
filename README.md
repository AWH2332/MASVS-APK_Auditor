APK Security Audit – README

Este proyecto proporciona una herramienta avanzada para el análisis estático de aplicaciones Android (.apk), alineada con OWASP MSTG y MASVS, incorporando:

  ✔ Descompilación con jadx (opcional)
  
  ✔ Análisis profundo con Androguard
  
  ✔ Detección de criptografía débil / storage inseguro
  
  ✔ Evaluación MASVS por categorías (STORAGE, RESILIENCE, CRYPTO, NETWORK…)
  
  ✔ Integración con MobSF (opcional)
  
  ✔ Generación de reportes: HTML + JSON (CI/CD friendly)
  
  ✔ Salida de error para pipelines en caso de vulnerabilidades HIGH
  

  Estructura del proyecto
  /
├── run_audit.sh                 # Wrapper principal
├── apk_audit_extended.py        # Analizador avanzado (Python)
├── templates/
│   └── report_template.html     # Plantilla Jinja2 para HTML
└── README.md                    # Este archivo

Características principales
  Funcionalidad	Descripción
    🔍 Análisis ESTÁTICO	Manifest, permisos, components exportados, crypto, storage, hardcoded secrets
    🧩 JADX	Búsqueda de patrones en código Java (si habilitado)
    📦 Androguard	Parsing avanzado de APK, strings, manifest, clases
    🛡 MASVS checks	STORAGE, RESILIENCE, CRYPTO, NETWORK, PRIVACY, AUTH, CODE_PROTECTION
    🔗 MobSF (opcional)	Upload + scan + obtención de JSON
    📊 Report HTML + JSON	Para analistas + CI/CD
    🧨 Exit codes	Code 0: OK — Code 2: HIGH issues encontradas

🔧 Requisitos del sistema
    ✔ Linux o macOS (recomendado)

Windows también funciona vía WSL2.

✔ Herramientas necesarias
Herramienta	  Necesaria	  Uso
Python 3.8+	  ✔	          Script principal
apktool	      ✔	          Descompilación a smali + manifest
jadx	        opcional (recomendado)	Decompilación a Java
docker	      opcional	   Para MobSF
MobSF	        opcional	Escaneo complementario


▶️ Uso
1. Usando el wrapper Bash
  chmod +x run_audit.sh

  ./run_audit.sh my_app.apk results_dir


Parámetros opcionales:

Detecta MobSF automáticamente si está en http://127.0.0.1:8000

Usa JADX si está instalado

Crea reporte HTML y JSON automáticamente

2. Uso directo del script Python
python3 apk_audit_extended.py \
  --apk my_app.apk \
  --outdir audit_output \
  --use-jadx \
  --mobsf-url http://127.0.0.1:8000

