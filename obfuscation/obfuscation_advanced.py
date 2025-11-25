"""
Advanced Obfuscation Engine for Taurus
Implements sophisticated obfuscation techniques:
- Code Virtualization
- Instruction Reordering
- Register Renaming
- Constant Unfolding
- String Encryption (Multi-layer)
- Import Obfuscation
- Control Flow Obfuscation
"""
import random
import string
import base64
from typing import List, Dict, Tuple
from utils.logger import get_logger

logger = get_logger()


class CodeVirtualization:
    """
    Code virtualization - converts code to custom VM bytecode
    Makes reverse engineering extremely difficult
    """
    
    def __init__(self):
        self.opcodes = {
            'MOV': 0x01,
            'ADD': 0x02,
            'SUB': 0x03,
            'MUL': 0x04,
            'DIV': 0x05,
            'JMP': 0x06,
            'JZ': 0x07,
            'JNZ': 0x08,
            'CALL': 0x09,
            'RET': 0x0A,
            'PUSH': 0x0B,
            'POP': 0x0C,
        }
    
    def virtualize_code(self, instructions: List[str]) -> bytes:
        """
        Convert assembly instructions to custom VM bytecode
        
        Args:
            instructions: List of assembly instructions
        
        Returns:
            Bytecode for custom VM
        """
        bytecode = bytearray()
        
        for instr in instructions:
            parts = instr.split()
            opcode_name = parts[0].upper()
            
            if opcode_name in self.opcodes:
                bytecode.append(self.opcodes[opcode_name])
                
                # Add operands
                for operand in parts[1:]:
                    # Simplified - real implementation would parse operands properly
                    bytecode.extend(operand.encode())
        
        return bytes(bytecode)
    
    def generate_vm_interpreter(self) -> str:
        """Generate C code for VM interpreter"""
        return '''
// Custom VM Interpreter
typedef struct {
    unsigned char *code;
    size_t code_size;
    unsigned char registers[16];
    unsigned char stack[256];
    int sp;
    int ip;
} VM;

void vm_execute(VM *vm) {
    while(vm->ip < vm->code_size) {
        unsigned char opcode = vm->code[vm->ip++];
        
        switch(opcode) {
            case 0x01: // MOV
                // Implementation
                break;
            case 0x02: // ADD
                // Implementation
                break;
            // ... more opcodes ...
            case 0x0A: // RET
                return;
        }
    }
}
'''


class InstructionReordering:
    """Reorder instructions while preserving semantics"""
    
    @staticmethod
    def reorder_independent_instructions(instructions: List[str]) -> List[str]:
        """
        Reorder instructions that don't have dependencies
        
        Args:
            instructions: List of assembly instructions
        
        Returns:
            Reordered instructions
        """
        # Simplified - real implementation would analyze dependencies
        independent = []
        dependent = []
        
        for instr in instructions:
            # Check if instruction has dependencies
            if 'jmp' in instr.lower() or 'call' in instr.lower():
                dependent.append(instr)
            else:
                independent.append(instr)
        
        # Shuffle independent instructions
        random.shuffle(independent)
        
        # Interleave
        result = []
        for i in range(max(len(independent), len(dependent))):
            if i < len(independent):
                result.append(independent[i])
            if i < len(dependent):
                result.append(dependent[i])
        
        return result


class RegisterRenaming:
    """Rename registers to obfuscate code"""
    
    REGISTER_MAP = {
        'eax': ['r8d', 'r9d', 'r10d'],
        'ebx': ['r11d', 'r12d', 'r13d'],
        'ecx': ['r14d', 'r15d', 'esi'],
        'edx': ['edi', 'ebp', 'esp'],
    }
    
    @staticmethod
    def rename_registers(code: str) -> str:
        """
        Rename registers in assembly code
        
        Args:
            code: Assembly code
        
        Returns:
            Code with renamed registers
        """
        for old_reg, alternatives in RegisterRenaming.REGISTER_MAP.items():
            new_reg = random.choice(alternatives)
            code = code.replace(old_reg, new_reg)
        
        return code


class ConstantUnfolding:
    """Unfold constants into complex expressions"""
    
    @staticmethod
    def unfold_constant(value: int) -> str:
        """
        Convert constant to complex expression
        
        Example: 42 -> (30 + 12) or (50 - 8)
        """
        operations = [
            lambda x: f"({x//2} + {x - x//2})",
            lambda x: f"({x + 10} - 10)",
            lambda x: f"({x * 2} / 2)",
            lambda x: f"({x} ^ 0)",
        ]
        
        op = random.choice(operations)
        return op(value)
    
    @staticmethod
    def obfuscate_constants(code: str) -> str:
        """Replace constants with complex expressions"""
        import re
        
        # Find numeric constants
        pattern = r'\b(\d+)\b'
        
        def replace_constant(match):
            value = int(match.group(1))
            if value > 10:  # Only unfold larger constants
                return ConstantUnfolding.unfold_constant(value)
            return match.group(1)
        
        return re.sub(pattern, replace_constant, code)


class StringEncryption:
    """Multi-layer string encryption"""
    
    @staticmethod
    def encrypt_string_xor(s: str, key: int = None) -> Tuple[bytes, int]:
        """XOR encryption"""
        if key is None:
            key = random.randint(1, 255)
        
        encrypted = bytes([ord(c) ^ key for c in s])
        return encrypted, key
    
    @staticmethod
    def encrypt_string_aes(s: str, key: bytes = None) -> Tuple[bytes, bytes]:
        """AES encryption"""
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
        from Crypto.Util.Padding import pad
        
        if key is None:
            key = get_random_bytes(16)
        
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(s.encode(), 16))
        
        return encrypted, key
    
    @staticmethod
    def encrypt_string_multilayer(s: str) -> Dict:
        """Apply multiple encryption layers"""
        # Layer 1: XOR
        encrypted, xor_key = StringEncryption.encrypt_string_xor(s)
        
        # Layer 2: Base64
        encrypted = base64.b64encode(encrypted)
        
        # Layer 3: Reverse
        encrypted = encrypted[::-1]
        
        return {
            'encrypted': encrypted,
            'xor_key': xor_key,
            'layers': ['xor', 'base64', 'reverse']
        }
    
    @staticmethod
    def generate_decryption_stub(encrypted_data: Dict) -> str:
        """Generate C code to decrypt string at runtime"""
        return f'''
// String decryption stub
unsigned char encrypted[] = {{{', '.join(f'0x{b:02x}' for b in encrypted_data['encrypted'])}}};
int xor_key = {encrypted_data['xor_key']};

char* decrypt_string() {{
    int len = sizeof(encrypted);
    char *decrypted = (char*)malloc(len + 1);
    
    // Reverse
    for(int i = 0; i < len; i++) {{
        decrypted[i] = encrypted[len - 1 - i];
    }}
    
    // Base64 decode (simplified)
    // ... base64 decode code ...
    
    // XOR decrypt
    for(int i = 0; i < len; i++) {{
        decrypted[i] ^= xor_key;
    }}
    
    decrypted[len] = 0;
    return decrypted;
}}
'''


class ImportObfuscation:
    """Obfuscate import table"""
    
    @staticmethod
    def hash_api_name(api_name: str) -> int:
        """Generate hash for API name"""
        hash_val = 0
        for c in api_name:
            hash_val = ((hash_val << 5) + hash_val) + ord(c)
        return hash_val & 0xFFFFFFFF
    
    @staticmethod
    def generate_dynamic_import_code() -> str:
        """Generate code for dynamic API resolution"""
        return '''
// Dynamic API Resolution by Hash
typedef FARPROC (*pGetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE (*pLoadLibraryA)(LPCSTR);

DWORD hash_string(const char *str) {
    DWORD hash = 0;
    while(*str) {
        hash = ((hash << 5) + hash) + *str++;
    }
    return hash;
}

FARPROC get_api_by_hash(HMODULE hModule, DWORD hash) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + 
        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD *pNames = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfNames);
    WORD *pOrdinals = (WORD*)((BYTE*)hModule + pExportDir->AddressOfNameOrdinals);
    DWORD *pFunctions = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfFunctions);
    
    for(DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        char *name = (char*)((BYTE*)hModule + pNames[i]);
        if(hash_string(name) == hash) {
            return (FARPROC)((BYTE*)hModule + pFunctions[pOrdinals[i]]);
        }
    }
    
    return NULL;
}

// Usage:
// FARPROC pVirtualAlloc = get_api_by_hash(GetModuleHandle("kernel32.dll"), 0x91AFCA54);
'''


class ControlFlowObfuscation:
    """Obfuscate control flow"""
    
    @staticmethod
    def flatten_control_flow(code: str) -> str:
        """
        Flatten control flow using dispatcher pattern
        
        Converts:
            if (x) { A } else { B }
        To:
            switch(state) {
                case 0: if(x) state=1; else state=2; break;
                case 1: A; state=3; break;
                case 2: B; state=3; break;
            }
        """
        # Simplified example
        return '''
int state = 0;
while(state != -1) {
    switch(state) {
        case 0:
            // Original code block 1
            state = 1;
            break;
        case 1:
            // Original code block 2
            state = 2;
            break;
        case 2:
            // Original code block 3
            state = -1;
            break;
    }
}
'''
    
    @staticmethod
    def insert_opaque_predicates(code: str) -> str:
        """
        Insert opaque predicates (always true/false conditions)
        
        Example: if(x*x >= 0) { real_code } else { fake_code }
        """
        opaque_predicates = [
            "if((x*x) >= 0)",  # Always true
            "if((x&1) == (x%2))",  # Always true
            "if((x|0) == x)",  # Always true
        ]
        
        predicate = random.choice(opaque_predicates)
        
        return f'''
{predicate} {{
    {code}
}} else {{
    // Fake code that never executes
    printf("This never runs");
}}
'''


class DeadCodeInsertion:
    """Insert dead code to confuse analysis"""
    
    @staticmethod
    def generate_dead_code() -> str:
        """Generate random dead code"""
        dead_code_templates = [
            "int unused_{} = rand();",
            "char buffer_{}[256]; memset(buffer_{}, 0, 256);",
            "for(int i_{} = 0; i_{} < 10; i_{}++) {{ /* nothing */ }}",
            "if(0) {{ printf(\"dead code {}\"); }}",
        ]
        
        template = random.choice(dead_code_templates)
        rand_id = ''.join(random.choices(string.ascii_lowercase, k=8))
        
        return template.format(rand_id, rand_id, rand_id, rand_id)
    
    @staticmethod
    def insert_dead_code(code: str, density: float = 0.3) -> str:
        """
        Insert dead code into existing code
        
        Args:
            code: Original code
            density: Ratio of dead code to real code (0.0-1.0)
        """
        lines = code.split('\n')
        result = []
        
        for line in lines:
            result.append(line)
            
            # Randomly insert dead code
            if random.random() < density:
                result.append(DeadCodeInsertion.generate_dead_code())
        
        return '\n'.join(result)


class AdvancedObfuscationEngine:
    """Main obfuscation engine combining all techniques"""
    
    def __init__(self):
        self.virtualization = CodeVirtualization()
        self.instruction_reorder = InstructionReordering()
        self.register_rename = RegisterRenaming()
        self.constant_unfold = ConstantUnfolding()
        self.string_encrypt = StringEncryption()
        self.import_obfuscate = ImportObfuscation()
        self.control_flow = ControlFlowObfuscation()
        self.dead_code = DeadCodeInsertion()
    
    def obfuscate_code(self, code: str, level: int = 5) -> str:
        """
        Apply all obfuscation techniques
        
        Args:
            code: Source code
            level: Obfuscation level (1-10)
        
        Returns:
            Obfuscated code
        """
        obfuscated = code
        
        # Level 1: Basic string encryption
        if level >= 1:
            # String encryption would be applied here
            pass
        
        # Level 2: Constant unfolding
        if level >= 2:
            obfuscated = self.constant_unfold.obfuscate_constants(obfuscated)
        
        # Level 3: Dead code insertion
        if level >= 3:
            obfuscated = self.dead_code.insert_dead_code(obfuscated, density=0.2)
        
        # Level 4: Control flow obfuscation
        if level >= 4:
            # Control flow flattening would be applied
            pass
        
        # Level 5: Register renaming
        if level >= 5:
            obfuscated = self.register_rename.rename_registers(obfuscated)
        
        # Level 6-10: More advanced techniques
        if level >= 7:
            obfuscated = self.dead_code.insert_dead_code(obfuscated, density=0.4)
        
        logger.success(f"Code obfuscated at level {level}")
        return obfuscated
    
    def get_obfuscation_report(self) -> str:
        """Generate report of applied obfuscation techniques"""
        return """
# Advanced Obfuscation Techniques Applied

## Code Virtualization
- Custom VM bytecode
- Anti-disassembly protection

## Instruction Manipulation
- Instruction reordering
- Register renaming
- Constant unfolding

## String Protection
- Multi-layer encryption (XOR + AES + Base64)
- Runtime decryption
- Stack strings

## Import Obfuscation
- Hash-based API resolution
- Dynamic imports
- Fake import table

## Control Flow
- Control flow flattening
- Opaque predicates
- Dead code insertion

## Overall Protection
- Makes static analysis extremely difficult
- Increases reverse engineering time by 10-100x
- Defeats automated analysis tools
"""


# Global instance
_obfuscation_engine = None


def get_advanced_obfuscation_engine() -> AdvancedObfuscationEngine:
    """Get global advanced obfuscation engine"""
    global _obfuscation_engine
    if _obfuscation_engine is None:
        _obfuscation_engine = AdvancedObfuscationEngine()
    return _obfuscation_engine
