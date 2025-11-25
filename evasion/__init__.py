"""Evasion techniques module - Updated with all new features"""

# Try to import original evasion techniques
try:
    from .evasion_techniques import (
        get_evasion_orchestrator,
        AMSIBypass,
        ETWPatch,
        SandboxDetection,
        AntiDebugging,
        ProcessInjection,
        EvasionOrchestrator,
    )
except ImportError:
    pass

# Import advanced evasion
try:
    from .advanced_evasion import (
        get_syscall_invoker,
        get_api_unhooker,
        get_memory_evasion,
        SyscallInvoker,
        APIUnhooker,
        HeavensGate,
        MemoryEvasion,
        PPIDSpoofing,
    )
except ImportError:
    pass

# Import anti-analysis
try:
    from .anti_analysis import (
        get_vm_detector,
        get_debugger_detector,
        get_sandbox_detector,
        VMDetector,
        DebuggerDetector,
        SandboxDetector,
    )
except ImportError:
    pass

__all__ = [
    # Original
    "get_evasion_orchestrator",
    "AMSIBypass",
    "ETWPatch",
    "SandboxDetection",
    "AntiDebugging",
    "ProcessInjection",
    "EvasionOrchestrator",
    # Advanced Evasion
    "get_syscall_invoker",
    "get_api_unhooker",
    "get_memory_evasion",
    "SyscallInvoker",
    "APIUnhooker",
    "HeavensGate",
    "MemoryEvasion",
    "PPIDSpoofing",
    # Anti-Analysis
    "get_vm_detector",
    "get_debugger_detector",
    "get_sandbox_detector",
    "VMDetector",
    "DebuggerDetector",
    "SandboxDetector",
]
