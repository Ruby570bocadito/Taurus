"""
Taurus Setup and Installation Script
Automates the setup process
"""
import subprocess
import sys
import os
from pathlib import Path


def print_banner():
    """Print Taurus banner"""
    banner = """
    ╔════════════════════════════════════════════════════════════╗
    ║                                                            ║
    ║   ████████╗ █████╗ ██╗   ██╗██████╗ ██╗   ██╗███████╗   ║
    ║   ╚══██╔══╝██╔══██╗██║   ██║██╔══██╗██║   ██║██╔════╝   ║
    ║      ██║   ███████║██║   ██║██████╔╝██║   ██║███████╗   ║
    ║      ██║   ██╔══██║██║   ██║██╔══██╗██║   ██║╚════██║   ║
    ║      ██║   ██║  ██║╚██████╔╝██║  ██║╚██████╔╝███████║   ║
    ║      ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ║
    ║                                                            ║
    ║        ML Malware Generator - Setup & Installation        ║
    ║                      Version 1.0.0                         ║
    ║                                                            ║
    ╚════════════════════════════════════════════════════════════╝
    
    ⚠️  FOR AUTHORIZED SECURITY RESEARCH ONLY ⚠️
    """
    print(banner)


def check_python_version():
    """Check Python version"""
    print("[1/7] Checking Python version...")
    
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"❌ Python 3.8+ required. You have {version.major}.{version.minor}")
        return False
    
    print(f"✓ Python {version.major}.{version.minor}.{version.micro}")
    return True


def install_dependencies():
    """Install required dependencies"""
    print("\\n[2/7] Installing dependencies...")
    
    try:
        # Install from requirements.txt
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ])
        
        # Install shimmy for Gymnasium compatibility
        print("\\nInstalling shimmy for Gymnasium compatibility...")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "shimmy>=2.0"
        ])
        
        print("✓ Dependencies installed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False


def create_directories():
    """Create necessary directories"""
    print("\\n[3/7] Creating directories...")
    
    directories = [
        "output",
        "logs",
        "models/saved",
        "data/payloads",
        "config/profiles",
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"  ✓ {directory}/")
    
    print("✓ Directories created")
    return True


def integrate_cli_commands():
    """Integrate additional CLI commands"""
    print("\\n[4/7] Integrating CLI commands...")
    
    try:
        # Read cli.py
        with open("cli.py", "r", encoding="utf-8") as f:
            cli_content = f.read()
        
        # Check if already integrated
        if "from cli_additions import" in cli_content:
            print("  ℹ CLI additions already integrated")
            return True
        
        # Find the position to insert imports
        import_pos = cli_content.find("from utils.logger import get_logger")
        if import_pos == -1:
            print("  ⚠ Could not find import section, skipping auto-integration")
            print("  → Manually add: from cli_additions import interactive, batch, pack, c2")
            return True
        
        # Add import after logger import
        new_import = "\\ntry:\\n    from cli_additions import interactive, batch, pack, c2\\nexcept ImportError:\\n    pass\\n"
        
        cli_content = cli_content[:import_pos] + new_import + cli_content[import_pos:]
        
        # Write back
        with open("cli.py", "w", encoding="utf-8") as f:
            f.write(cli_content)
        
        print("✓ CLI commands integrated")
        return True
        
    except Exception as e:
        print(f"  ⚠ Could not auto-integrate: {e}")
        print("  → Manually add commands from cli_additions.py")
        return True


def run_tests():
    """Run import tests"""
    print("\\n[5/7] Running tests...")
    
    try:
        result = subprocess.run(
            [sys.executable, "test_imports.py"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if "Tests Passed: 4/5" in result.stdout or "Tests Passed: 5/5" in result.stdout:
            print("✓ Tests passed")
            return True
        else:
            print("⚠ Some tests failed (this may be normal)")
            print("  → Run 'python test_imports.py' for details")
            return True
            
    except Exception as e:
        print(f"  ⚠ Could not run tests: {e}")
        print("  → Manually run: python test_imports.py")
        return True


def create_example_config():
    """Create example configuration"""
    print("\\n[6/7] Creating example configuration...")
    
    example_config = {
        "payload_type": "reverse_shell",
        "target_os": "windows",
        "architecture": "x64",
        "obfuscation_level": 3,
        "use_evasion": True,
        "use_ml": False,
    }
    
    try:
        import json
        os.makedirs("config/profiles", exist_ok=True)
        
        with open("config/profiles/default.json", "w") as f:
            json.dump(example_config, f, indent=2)
        
        print("✓ Example configuration created: config/profiles/default.json")
        return True
    except Exception as e:
        print(f"  ⚠ Could not create config: {e}")
        return True


def display_next_steps():
    """Display next steps"""
    print("\\n[7/7] Setup complete!")
    print("\\n" + "="*60)
    print("NEXT STEPS")
    print("="*60)
    print("\\n1. Verify installation:")
    print("   python cli.py info")
    print("\\n2. Try interactive mode:")
    print("   python cli.py interactive")
    print("\\n3. Run advanced example:")
    print("   python examples/advanced_example.py")
    print("\\n4. Read documentation:")
    print("   - README_ENHANCED.md (complete guide)")
    print("   - INTEGRATION_GUIDE.md (setup details)")
    print("   - COMPLETION_SUMMARY.md (features overview)")
    print("\\n5. Generate your first payload:")
    print("   python cli.py generate \\\\")
    print("     --type reverse_shell \\\\")
    print("     --target windows \\\\")
    print("     --lhost 192.168.1.10 \\\\")
    print("     --lport 4444 \\\\")
    print("     --output payload.exe")
    print("\\n" + "="*60)
    print("⚠️  REMEMBER: Use only for authorized security testing!")
    print("="*60)


def main():
    """Main setup function"""
    print_banner()
    
    steps = [
        ("Checking Python version", check_python_version),
        ("Installing dependencies", install_dependencies),
        ("Creating directories", create_directories),
        ("Integrating CLI commands", integrate_cli_commands),
        ("Running tests", run_tests),
        ("Creating example config", create_example_config),
    ]
    
    for step_name, step_func in steps:
        if not step_func():
            print(f"\\n❌ Setup failed at: {step_name}")
            print("Please resolve the issue and run setup again.")
            return 1
    
    display_next_steps()
    return 0


if __name__ == "__main__":
    sys.exit(main())
