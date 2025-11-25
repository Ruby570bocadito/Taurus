"""
Comprehensive Test Suite for Taurus Advanced Features
Tests all 50+ new features across all modules
"""
import sys
import os
import time

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import get_logger

logger = get_logger()


class TestRunner:
    """Main test runner"""
    
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.skipped = 0
    
    def run_test(self, test_name: str, test_func):
        """Run a single test"""
        try:
            print(f"\n{'='*70}")
            print(f"🧪 Testing: {test_name}")
            print(f"{'='*70}")
            
            start = time.time()
            test_func()
            elapsed = time.time() - start
            
            print(f"✅ PASSED ({elapsed:.2f}s)")
            self.passed += 1
            return True
            
        except Exception as e:
            print(f"❌ FAILED: {e}")
            import traceback
            traceback.print_exc()
            self.failed += 1
            return False
    
    def print_summary(self):
        """Print test summary"""
        total = self.passed + self.failed + self.skipped
        print(f"\n{'='*70}")
        print(f"📊 TEST SUMMARY")
        print(f"{'='*70}")
        print(f"Total Tests: {total}")
        print(f"✅ Passed: {self.passed}")
        print(f"❌ Failed: {self.failed}")
        print(f"⏭️  Skipped: {self.skipped}")
        print(f"Success Rate: {(self.passed/total*100) if total > 0 else 0:.1f}%")
        print(f"{'='*70}\n")


def test_advanced_evasion():
    """Test advanced evasion techniques"""
    from evasion.advanced_evasion import (
        get_syscall_invoker,
        get_api_unhooker,
        HeavensGate,
        MemoryEvasion,
        PPIDSpoofing
    )
    
    print("Testing Syscall Invoker...")
    syscaller = get_syscall_invoker()
    assert syscaller is not None
    assert len(syscaller.syscall_numbers) > 0
    print(f"  ✓ {len(syscaller.syscall_numbers)} syscalls registered")
    
    print("Testing Syscall Stub Generation...")
    stub = syscaller.generate_syscall_stub(0x18)
    assert len(stub) > 0
    print(f"  ✓ Generated {len(stub)} byte stub")
    
    print("Testing API Unhooker...")
    unhooker = get_api_unhooker()
    assert unhooker is not None
    print("  ✓ API unhooker initialized")
    
    print("Testing Heaven's Gate...")
    is_wow64 = HeavensGate.is_wow64()
    print(f"  ✓ WoW64 detection: {is_wow64}")
    
    print("Testing Memory Evasion...")
    mem = MemoryEvasion.allocate_rwx_indirect(1024)
    if mem:
        print(f"  ✓ Allocated memory at 0x{mem:X}")
    
    print("✅ Advanced Evasion Tests Passed")


def test_anti_analysis():
    """Test anti-analysis suite"""
    from evasion.anti_analysis import (
        get_vm_detector,
        get_debugger_detector,
        get_sandbox_detector
    )
    
    print("Testing VM Detection...")
    vm_detector = get_vm_detector()
    checks = vm_detector.check_all()
    print(f"  ✓ Ran {len(checks)} VM detection checks")
    print(f"  ✓ Detected: {sum(1 for v in checks.values() if v)} indicators")
    
    print("Testing Debugger Detection...")
    debugger_detector = get_debugger_detector()
    is_debugged = debugger_detector.is_debugged()
    print(f"  ✓ Debugger detected: {is_debugged}")
    
    print("Testing Sandbox Detection...")
    sandbox_detector = get_sandbox_detector()
    is_sandbox = sandbox_detector.is_sandbox()
    print(f"  ✓ Sandbox detected: {is_sandbox}")
    
    print("✅ Anti-Analysis Tests Passed")


def test_advanced_injection():
    """Test advanced injection techniques"""
    from injection.injection_advanced import (
        get_reflective_dll_injection,
        get_process_doppelganging,
        get_atom_bombing
    )
    
    print("Testing Reflective DLL Injection...")
    reflective = get_reflective_dll_injection()
    code = reflective.generate_reflective_loader()
    assert len(code) > 0
    print(f"  ✓ Generated {len(code)} chars of loader code")
    
    print("Testing Process Doppelgänging...")
    doppel = get_process_doppelganging()
    code = doppel.generate_doppelganging_code()
    assert len(code) > 0
    print(f"  ✓ Generated doppelgänging template")
    
    print("Testing Atom Bombing...")
    atom = get_atom_bombing()
    code = atom.generate_atom_bombing_code()
    assert len(code) > 0
    print(f"  ✓ Generated atom bombing template")
    
    print("✅ Advanced Injection Tests Passed")


def test_persistence():
    """Test persistence mechanisms"""
    from persistence.persistence_manager import (
        get_persistence_manager,
        RegistryPersistence,
        ScheduledTaskPersistence,
        WMIPersistence
    )
    
    print("Testing Persistence Manager...")
    manager = get_persistence_manager()
    assert manager is not None
    print("  ✓ Persistence manager initialized")
    
    print("Testing Registry Persistence...")
    assert len(RegistryPersistence.REGISTRY_LOCATIONS) >= 10
    print(f"  ✓ {len(RegistryPersistence.REGISTRY_LOCATIONS)} registry locations")
    
    print("Testing Scheduled Task...")
    cmd = ScheduledTaskPersistence.generate_schtasks_command("test", "C:\\test.exe")
    assert "schtasks" in cmd
    print("  ✓ Generated schtasks command")
    
    print("Testing WMI Persistence...")
    script = WMIPersistence.generate_wmi_persistence_script()
    assert "WMI" in script
    print("  ✓ Generated WMI script")
    
    print("✅ Persistence Tests Passed")


def test_fileless_execution():
    """Test fileless execution techniques"""
    from generators.fileless_execution import (
        get_fileless_manager,
        PowerShellObfuscation,
        LOLBins
    )
    
    print("Testing Fileless Manager...")
    manager = get_fileless_manager()
    assert manager is not None
    print("  ✓ Fileless manager initialized")
    
    print("Testing PowerShell Obfuscation...")
    bypasses = PowerShellObfuscation.generate_amsi_bypass()
    assert len(bypasses) >= 3
    print(f"  ✓ {len(bypasses)} AMSI bypass methods")
    
    cradles = PowerShellObfuscation.generate_download_cradles()
    assert len(cradles) >= 8
    print(f"  ✓ {len(cradles)} download cradles")
    
    print("Testing LOLBins...")
    techniques = LOLBins.generate_all_lolbin_variants()
    assert len(techniques) >= 10
    print(f"  ✓ {len(techniques)} LOLBin techniques")
    
    print("✅ Fileless Execution Tests Passed")


def test_enhanced_c2():
    """Test enhanced C2 protocols"""
    from generators.c2_enhanced import get_enhanced_c2_manager
    
    print("Testing Enhanced C2 Manager...")
    c2 = get_enhanced_c2_manager()
    assert c2 is not None
    print("  ✓ C2 manager initialized")
    
    protocols = c2.get_all_protocols()
    assert len(protocols) >= 7
    print(f"  ✓ {len(protocols)} C2 protocols available")
    
    print("Testing Protocol Templates...")
    for protocol in ['doh', 'icmp', 'websocket', 'tor']:
        template = c2.generate_c2_template(protocol)
        assert len(template) > 0
        print(f"  ✓ {protocol.upper()} template generated")
    
    print("✅ Enhanced C2 Tests Passed")


def test_advanced_obfuscation():
    """Test advanced obfuscation engine"""
    from obfuscation.obfuscation_advanced import get_advanced_obfuscation_engine
    
    print("Testing Advanced Obfuscation Engine...")
    engine = get_advanced_obfuscation_engine()
    assert engine is not None
    print("  ✓ Obfuscation engine initialized")
    
    print("Testing Code Obfuscation...")
    test_code = "int x = 42; printf('test');"
    obfuscated = engine.obfuscate_code(test_code, level=5)
    assert len(obfuscated) > 0
    print(f"  ✓ Code obfuscated (level 5)")
    
    print("Testing String Encryption...")
    encrypted = engine.string_encrypt.encrypt_string_multilayer("secret")
    assert 'encrypted' in encrypted
    assert 'xor_key' in encrypted
    print("  ✓ Multi-layer string encryption")
    
    print("✅ Advanced Obfuscation Tests Passed")


def test_variant_generator():
    """Test variant generator"""
    from generators.variant_generator import get_variant_generator
    
    print("Testing Variant Generator...")
    generator = get_variant_generator()
    assert generator is not None
    print("  ✓ Variant generator initialized")
    
    print("Testing Variant Generation...")
    test_payload = b"TEST_PAYLOAD_DATA" * 10
    variants = generator.generate_variants(test_payload, count=10)
    assert len(variants) == 10
    print(f"  ✓ Generated {len(variants)} unique variants")
    
    # Check uniqueness
    hashes = [v[1] for v in variants]
    assert len(set(hashes)) == len(hashes)
    print("  ✓ All variants have unique hashes")
    
    print("✅ Variant Generator Tests Passed")


def test_integration():
    """Test integration of multiple features"""
    print("Testing Feature Integration...")
    
    # Test combining evasion + obfuscation
    from evasion.advanced_evasion import get_syscall_invoker
    from obfuscation.obfuscation_advanced import get_advanced_obfuscation_engine
    
    syscaller = get_syscall_invoker()
    obfuscator = get_advanced_obfuscation_engine()
    
    assert syscaller is not None
    assert obfuscator is not None
    print("  ✓ Multiple modules can be used together")
    
    # Test combining persistence + fileless
    from persistence.persistence_manager import get_persistence_manager
    from generators.fileless_execution import get_fileless_manager
    
    persistence = get_persistence_manager()
    fileless = get_fileless_manager()
    
    assert persistence is not None
    assert fileless is not None
    print("  ✓ Persistence + Fileless integration")
    
    print("✅ Integration Tests Passed")


def test_performance():
    """Test performance of key operations"""
    import time
    
    print("Testing Performance...")
    
    # Test VM detection speed
    from evasion.anti_analysis import get_vm_detector
    vm_detector = get_vm_detector()
    
    start = time.time()
    vm_detector.check_all()
    elapsed = time.time() - start
    print(f"  ✓ VM detection: {elapsed:.3f}s")
    assert elapsed < 5.0, "VM detection too slow"
    
    # Test variant generation speed
    from generators.variant_generator import get_variant_generator
    generator = get_variant_generator()
    
    start = time.time()
    variants = generator.generate_variants(b"TEST" * 100, count=10)
    elapsed = time.time() - start
    print(f"  ✓ 10 variants: {elapsed:.3f}s ({elapsed/10:.3f}s per variant)")
    assert elapsed < 10.0, "Variant generation too slow"
    
    print("✅ Performance Tests Passed")


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("🚀 TAURUS ADVANCED FEATURES - COMPREHENSIVE TEST SUITE")
    print("="*70)
    
    runner = TestRunner()
    
    # Run all test suites
    tests = [
        ("Advanced Evasion", test_advanced_evasion),
        ("Anti-Analysis", test_anti_analysis),
        ("Advanced Injection", test_advanced_injection),
        ("Persistence Mechanisms", test_persistence),
        ("Fileless Execution", test_fileless_execution),
        ("Enhanced C2", test_enhanced_c2),
        ("Advanced Obfuscation", test_advanced_obfuscation),
        ("Variant Generator", test_variant_generator),
        ("Integration", test_integration),
        ("Performance", test_performance),
    ]
    
    for test_name, test_func in tests:
        runner.run_test(test_name, test_func)
    
    # Print summary
    runner.print_summary()
    
    # Return exit code
    return 0 if runner.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
