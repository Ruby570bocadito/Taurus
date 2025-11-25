"""
Test script to verify all new modules import correctly
"""
import sys

def test_imports():
    """Test all module imports"""
    print("="*60)
    print("Taurus ML Malware Generator - Import Test")
    print("="*60)
    
    tests_passed = 0
    tests_failed = 0
    
    # Test 1: Evasion techniques
    print("\n[1/5] Testing evasion techniques module...")
    try:
        from evasion.evasion_techniques import (
            AMSIBypass,
            ETWPatch,
            SandboxDetection,
            AntiDebugging,
            ProcessInjection,
            EvasionOrchestrator,
            get_evasion_orchestrator,
        )
        print("  ✓ All evasion classes imported successfully")
        
        # Test instantiation
        orchestrator = get_evasion_orchestrator()
        print(f"  ✓ EvasionOrchestrator instantiated")
        print(f"    - AMSI bypass methods: {len(orchestrator.amsi_bypass.bypass_methods)}")
        print(f"    - ETW patch methods: {len(orchestrator.etw_patch.patch_methods)}")
        print(f"    - Sandbox detection methods: {len(orchestrator.sandbox_detection.detection_methods)}")
        print(f"    - Anti-debugging techniques: {len(orchestrator.anti_debugging.techniques)}")
        print(f"    - Process injection techniques: {len(orchestrator.process_injection.techniques)}")
        tests_passed += 1
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        tests_failed += 1
    
    # Test 2: Payload packer
    print("\n[2/5] Testing payload packer module...")
    try:
        from utils.payload_packer import PayloadPacker, get_packer
        print("  ✓ Payload packer imported successfully")
        
        packer = get_packer()
        print(f"  ✓ PayloadPacker instantiated")
        print(f"    - Compression methods: {', '.join(packer.compression_methods)}")
        print(f"    - Encryption methods: {', '.join(packer.encryption_methods)}")
        tests_passed += 1
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        tests_failed += 1
    
    # Test 3: C2 templates
    print("\n[3/5] Testing C2 templates module...")
    try:
        from generators.c2_templates import (
            HTTPBeacon,
            DNSTunnel,
            CustomProtocol,
            C2TemplateFactory,
            get_c2_factory,
        )
        print("  ✓ C2 templates imported successfully")
        
        factory = get_c2_factory()
        print(f"  ✓ C2TemplateFactory instantiated")
        tests_passed += 1
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        tests_failed += 1
    
    # Test 4: Enhanced obfuscator
    print("\n[4/5] Testing enhanced obfuscator...")
    try:
        from obfuscation.obfuscator import get_obfuscator, get_encoder
        obfuscator = get_obfuscator()
        print("  ✓ Obfuscator imported and instantiated")
        print(f"    - Total techniques: {len(obfuscator.obfuscation_techniques)}")
        print(f"    - New techniques: metamorphic_transform, instruction_substitution,")
        print(f"                      opaque_predicates, junk_code_generation")
        
        encoder = get_encoder()
        print(f"  ✓ Encoder instantiated")
        print(f"    - Encoding methods: {', '.join(encoder.encoders.keys())}")
        tests_passed += 1
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        tests_failed += 1
    
    # Test 5: Existing modules still work
    print("\n[5/5] Testing existing modules compatibility...")
    try:
        from generators.payload_factory import get_payload_factory
        from testing.detector import get_detector, get_functionality_tester
        from ml_engine import get_ml_engine
        
        print("  ✓ All existing modules still functional")
        tests_passed += 1
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        tests_failed += 1
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Tests Passed: {tests_passed}/5")
    print(f"Tests Failed: {tests_failed}/5")
    
    if tests_failed == 0:
        print("\n✓ All tests passed! Taurus is ready to use.")
        return 0
    else:
        print(f"\n✗ {tests_failed} test(s) failed. Check error messages above.")
        return 1


if __name__ == "__main__":
    sys.exit(test_imports())
