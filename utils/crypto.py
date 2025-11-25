"""
ML Malware Generator - Cryptographic Utilities
"""
import os
import hashlib
import base64
from typing import Tuple, Optional
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class CryptoUtils:
    """Cryptographic utilities for payload encryption and encoding"""
    
    @staticmethod
    def generate_key(key_size: int = 32) -> bytes:
        """Generate random encryption key"""
        return get_random_bytes(key_size)
    
    @staticmethod
    def aes_encrypt(data: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt data using AES-256-CBC
        Returns: (encrypted_data, iv)
        """
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        encrypted = cipher.encrypt(pad(data, AES.block_size))
        return encrypted, iv
    
    @staticmethod
    def aes_decrypt(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt data using AES-256-CBC"""
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return decrypted
    
    @staticmethod
    def xor_encrypt(data: bytes, key: bytes) -> bytes:
        """XOR encryption/decryption (symmetric)"""
        key_len = len(key)
        return bytes([data[i] ^ key[i % key_len] for i in range(len(data))])
    
    @staticmethod
    def rot_encode(data: bytes, shift: int = 13) -> bytes:
        """ROT encoding (simple Caesar cipher)"""
        return bytes([(b + shift) % 256 for b in data])
    
    @staticmethod
    def rot_decode(data: bytes, shift: int = 13) -> bytes:
        """ROT decoding"""
        return bytes([(b - shift) % 256 for b in data])
    
    @staticmethod
    def base64_encode(data: bytes) -> str:
        """Base64 encoding"""
        return base64.b64encode(data).decode('utf-8')
    
    @staticmethod
    def base64_decode(data: str) -> bytes:
        """Base64 decoding"""
        return base64.b64decode(data)
    
    @staticmethod
    def hex_encode(data: bytes) -> str:
        """Hexadecimal encoding"""
        return data.hex()
    
    @staticmethod
    def hex_decode(data: str) -> bytes:
        """Hexadecimal decoding"""
        return bytes.fromhex(data)
    
    @staticmethod
    def multi_layer_encrypt(
        data: bytes,
        key: bytes,
        layers: int = 3
    ) -> Tuple[bytes, list]:
        """
        Apply multiple layers of encryption
        Returns: (encrypted_data, encryption_metadata)
        """
        encrypted = data
        metadata = []
        
        for i in range(layers):
            # Alternate between different encryption methods
            if i % 3 == 0:
                # AES encryption
                encrypted, iv = CryptoUtils.aes_encrypt(encrypted, key)
                metadata.append({"method": "aes", "iv": iv.hex()})
            elif i % 3 == 1:
                # XOR encryption
                xor_key = hashlib.sha256(key + str(i).encode()).digest()[:16]
                encrypted = CryptoUtils.xor_encrypt(encrypted, xor_key)
                metadata.append({"method": "xor", "key_hash": hashlib.sha256(xor_key).hexdigest()[:16]})
            else:
                # ROT encoding
                shift = (i * 17) % 256
                encrypted = CryptoUtils.rot_encode(encrypted, shift)
                metadata.append({"method": "rot", "shift": shift})
        
        return encrypted, metadata
    
    @staticmethod
    def calculate_hash(data: bytes, algorithm: str = "sha256") -> str:
        """Calculate hash of data"""
        if algorithm == "md5":
            return hashlib.md5(data).hexdigest()
        elif algorithm == "sha1":
            return hashlib.sha1(data).hexdigest()
        elif algorithm == "sha256":
            return hashlib.sha256(data).hexdigest()
        elif algorithm == "sha512":
            return hashlib.sha512(data).hexdigest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    @staticmethod
    def generate_watermark(signature: str) -> bytes:
        """Generate watermark for payload identification"""
        # Create a unique watermark that's hard to detect but identifiable
        watermark_data = f"WM_{signature}_{os.urandom(8).hex()}"
        return hashlib.sha256(watermark_data.encode()).digest()[:16]
    
    @staticmethod
    def embed_watermark(payload: bytes, watermark: bytes, offset: Optional[int] = None) -> bytes:
        """Embed watermark into payload"""
        if offset is None:
            # Embed at a random position
            offset = len(payload) // 2
        
        # Insert watermark
        return payload[:offset] + watermark + payload[offset:]
    
    @staticmethod
    def extract_watermark(payload: bytes, offset: int, length: int = 16) -> bytes:
        """Extract watermark from payload"""
        return payload[offset:offset + length]
    
    @staticmethod
    def polymorphic_encode(data: bytes, seed: Optional[int] = None) -> Tuple[bytes, dict]:
        """
        Polymorphic encoding - generates different output each time
        Returns: (encoded_data, decoding_metadata)
        """
        if seed is None:
            seed = int.from_bytes(os.urandom(4), 'big')
        
        # Generate pseudo-random encoding scheme based on seed
        import random
        random.seed(seed)
        
        # Create random substitution table
        substitution = list(range(256))
        random.shuffle(substitution)
        
        # Apply substitution
        encoded = bytes([substitution[b] for b in data])
        
        # Create reverse substitution for decoding
        reverse_sub = [0] * 256
        for i, val in enumerate(substitution):
            reverse_sub[val] = i
        
        metadata = {
            "seed": seed,
            "method": "polymorphic_substitution",
            "reverse_table": reverse_sub,
        }
        
        return encoded, metadata


# Global crypto instance
crypto_utils = CryptoUtils()


def get_crypto() -> CryptoUtils:
    """Get global crypto utils instance"""
    return crypto_utils
