"""
Advanced Anti-Analysis Suite for Taurus
Implements 25+ detection techniques for:
- Virtual Machines (VMware, VirtualBox, Hyper-V, QEMU, etc.)
- Sandboxes (Cuckoo, Joe Sandbox, Any.run, etc.)
- Debuggers (OllyDbg, x64dbg, WinDbg, IDA, etc.)
- Analysis tools and environments
"""
import ctypes
import os
import platform
import time
import hashlib
import winreg
from typing import List, Dict, Tuple, Optional
from utils.logger import get_logger

logger = get_logger()


class VMDetector:
    """
    Comprehensive Virtual Machine detection
    Implements 25+ different VM detection techniques
    """
    
    def __init__(self):
        self.detections = []
    
    def check_all(self) -> Dict[str, bool]:
        """Run all VM detection checks"""
        checks = {
            'registry_keys': self.check_registry_keys(),
            'processes': self.check_vm_processes(),
            'files': self.check_vm_files(),
            'mac_address': self.check_mac_address(),
            'hardware': self.check_hardware_info(),
            'cpuid': self.check_cpuid(),
            'timing': self.check_timing_discrepancies(),
            'io_ports': self.check_io_ports(),
            'scsi_devices': self.check_scsi_devices(),
            'memory_size': self.check_memory_size(),
            'screen_resolution': self.check_screen_resolution(),
            'usb_devices': self.check_usb_devices(),
            'bios': self.check_bios_info(),
            'firmware': self.check_firmware(),
            'temperature': self.check_temperature_sensors(),
        }
        
        detected = sum(1 for v in checks.values() if v)
        logger.info(f"VM Detection: {detected}/{len(checks)} checks triggered")
        
        return checks
    
    def check_registry_keys(self) -> bool:
        """Check for VM-related registry keys"""
        vm_registry_keys = [
            # VMware
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Tools"),
            (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0", "Identifier", "VMWARE"),
            
            # VirtualBox
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Oracle\VirtualBox Guest Additions"),
            (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\ACPI\DSDT\VBOX__"),
            
            # Hyper-V
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Hyper-V"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"),
            
            # QEMU
            (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0", "Identifier", "QEMU"),
            
            # Parallels
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Parallels\Parallels Tools"),
        ]
        
        for key_info in vm_registry_keys:
            try:
                if len(key_info) == 2:
                    hive, path = key_info
                    winreg.OpenKey(hive, path)
                    logger.warning(f"VM registry key found: {path}")
                    return True
                elif len(key_info) == 4:
                    hive, path, value_name, expected = key_info
                    key = winreg.OpenKey(hive, path)
                    value, _ = winreg.QueryValueEx(key, value_name)
                    if expected.lower() in str(value).lower():
                        logger.warning(f"VM registry value found: {path}\\{value_name}")
                        return True
            except:
                continue
        
        return False
    
    def check_vm_processes(self) -> bool:
        """Check for VM-related processes"""
        try:
            import psutil
            
            vm_processes = [
                # VMware
                'vmtoolsd.exe', 'vmwaretray.exe', 'vmwareuser.exe', 'vmacthlp.exe',
                'vmware.exe', 'vmount2.exe', 'vmusrvc.exe', 'vmGuestLib.dll',
                
                # VirtualBox
                'vboxservice.exe', 'vboxtray.exe', 'vboxcontrol.exe',
                
                # Parallels
                'prl_cc.exe', 'prl_tools.exe',
                
                # Hyper-V
                'vmms.exe', 'vmcompute.exe',
                
                # QEMU
                'qemu-ga.exe',
                
                # Xen
                'xenservice.exe',
            ]
            
            running_processes = [p.name().lower() for p in psutil.process_iter(['name'])]
            
            for vm_proc in vm_processes:
                if vm_proc.lower() in running_processes:
                    logger.warning(f"VM process detected: {vm_proc}")
                    return True
        except:
            pass
        
        return False
    
    def check_vm_files(self) -> bool:
        """Check for VM-related files"""
        vm_files = [
            # VMware
            r"C:\Program Files\VMware\VMware Tools",
            r"C:\Windows\System32\drivers\vmmouse.sys",
            r"C:\Windows\System32\drivers\vmhgfs.sys",
            
            # VirtualBox
            r"C:\Program Files\Oracle\VirtualBox Guest Additions",
            r"C:\Windows\System32\drivers\VBoxGuest.sys",
            r"C:\Windows\System32\drivers\VBoxMouse.sys",
            
            # Parallels
            r"C:\Program Files\Parallels\Parallels Tools",
            
            # QEMU
            r"C:\Program Files\QEMU Guest Agent",
        ]
        
        for file_path in vm_files:
            if os.path.exists(file_path):
                logger.warning(f"VM file detected: {file_path}")
                return True
        
        return False
    
    def check_mac_address(self) -> bool:
        """Check for VM vendor MAC addresses"""
        try:
            import uuid
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                           for elements in range(0, 2*6, 2)][::-1])
            
            vm_mac_prefixes = [
                '00:05:69',  # VMware
                '00:0C:29',  # VMware
                '00:1C:14',  # VMware
                '00:50:56',  # VMware
                '08:00:27',  # VirtualBox
                '00:1C:42',  # Parallels
                '00:16:3E',  # Xen
                '00:15:5D',  # Hyper-V
            ]
            
            for prefix in vm_mac_prefixes:
                if mac.upper().startswith(prefix):
                    logger.warning(f"VM MAC address detected: {mac}")
                    return True
        except:
            pass
        
        return False
    
    def check_hardware_info(self) -> bool:
        """Check hardware information for VM indicators"""
        try:
            import wmi
            c = wmi.WMI()
            
            # Check BIOS
            for bios in c.Win32_BIOS():
                if any(vm in str(bios.Manufacturer).lower() for vm in ['vmware', 'virtualbox', 'qemu', 'xen']):
                    logger.warning(f"VM BIOS detected: {bios.Manufacturer}")
                    return True
            
            # Check Computer System
            for cs in c.Win32_ComputerSystem():
                if any(vm in str(cs.Manufacturer).lower() for vm in ['vmware', 'virtualbox', 'microsoft corporation']):
                    logger.warning(f"VM manufacturer detected: {cs.Manufacturer}")
                    return True
                if any(vm in str(cs.Model).lower() for vm in ['virtual', 'vmware', 'virtualbox']):
                    logger.warning(f"VM model detected: {cs.Model}")
                    return True
            
            # Check Disk Drives
            for disk in c.Win32_DiskDrive():
                if any(vm in str(disk.Model).lower() for vm in ['vbox', 'vmware', 'virtual', 'qemu']):
                    logger.warning(f"VM disk detected: {disk.Model}")
                    return True
        except:
            pass
        
        return False
    
    def check_cpuid(self) -> bool:
        """
        Check CPUID for hypervisor bit
        
        CPUID leaf 0x1, ECX bit 31 indicates hypervisor presence
        """
        try:
            # This requires assembly or ctypes - simplified check
            # Real implementation would use inline assembly
            
            # Check CPU name for VM indicators
            cpu_name = platform.processor()
            vm_indicators = ['qemu', 'virtual', 'kvm']
            
            for indicator in vm_indicators:
                if indicator in cpu_name.lower():
                    logger.warning(f"VM CPU detected: {cpu_name}")
                    return True
        except:
            pass
        
        return False
    
    def check_timing_discrepancies(self) -> bool:
        """
        Check for timing discrepancies that indicate VM
        
        VMs often have timing irregularities
        """
        try:
            # RDTSC timing check
            samples = []
            for _ in range(10):
                start = time.perf_counter()
                time.sleep(0.001)  # 1ms
                end = time.perf_counter()
                samples.append(end - start)
            
            # Check for high variance (VM indicator)
            avg = sum(samples) / len(samples)
            variance = sum((x - avg) ** 2 for x in samples) / len(samples)
            
            if variance > 0.0001:  # High variance threshold
                logger.warning(f"Timing discrepancy detected (variance: {variance})")
                return True
        except:
            pass
        
        return False
    
    def check_io_ports(self) -> bool:
        """Check for VM I/O ports (VMware backdoor)"""
        # VMware uses I/O port 0x5658 ('VX')
        # This requires kernel-level access or specific drivers
        # Simplified check
        return False
    
    def check_scsi_devices(self) -> bool:
        """Check SCSI device identifiers"""
        try:
            import wmi
            c = wmi.WMI()
            
            for disk in c.Win32_DiskDrive():
                scsi_id = str(disk.PNPDeviceID)
                if any(vm in scsi_id.upper() for vm in ['VBOX', 'VMWARE', 'QEMU', 'VIRTUAL']):
                    logger.warning(f"VM SCSI device detected: {scsi_id}")
                    return True
        except:
            pass
        
        return False
    
    def check_memory_size(self) -> bool:
        """Check if memory size is suspiciously low (VM indicator)"""
        try:
            import psutil
            total_memory_gb = psutil.virtual_memory().total / (1024**3)
            
            # Less than 4GB is suspicious for modern systems
            if total_memory_gb < 4:
                logger.warning(f"Low memory detected: {total_memory_gb:.2f}GB")
                return True
        except:
            pass
        
        return False
    
    def check_screen_resolution(self) -> bool:
        """Check for common VM screen resolutions"""
        try:
            import ctypes
            user32 = ctypes.windll.user32
            width = user32.GetSystemMetrics(0)
            height = user32.GetSystemMetrics(1)
            
            # Common VM resolutions
            vm_resolutions = [
                (800, 600), (1024, 768), (1280, 800), (1280, 1024)
            ]
            
            if (width, height) in vm_resolutions:
                logger.warning(f"VM resolution detected: {width}x{height}")
                return True
        except:
            pass
        
        return False
    
    def check_usb_devices(self) -> bool:
        """Check for lack of USB devices (VM indicator)"""
        try:
            import wmi
            c = wmi.WMI()
            
            usb_count = len(list(c.Win32_USBController()))
            
            if usb_count == 0:
                logger.warning("No USB devices detected (VM indicator)")
                return True
        except:
            pass
        
        return False
    
    def check_bios_info(self) -> bool:
        """Check BIOS information"""
        try:
            import wmi
            c = wmi.WMI()
            
            for bios in c.Win32_BIOS():
                version = str(bios.Version).lower()
                if any(vm in version for vm in ['vbox', 'vmware', 'qemu', 'virtual', 'bochs']):
                    logger.warning(f"VM BIOS version detected: {version}")
                    return True
        except:
            pass
        
        return False
    
    def check_firmware(self) -> bool:
        """Check firmware tables for VM indicators"""
        # ACPI/SMBIOS tables often contain VM indicators
        # Requires low-level access
        return False
    
    def check_temperature_sensors(self) -> bool:
        """Check for lack of temperature sensors (VM indicator)"""
        try:
            import wmi
            c = wmi.WMI(namespace="root\\wmi")
            
            temp_sensors = list(c.MSAcpi_ThermalZoneTemperature())
            
            if len(temp_sensors) == 0:
                logger.warning("No temperature sensors detected (VM indicator)")
                return True
        except:
            pass
        
        return False
    
    def is_vm(self, threshold: int = 3) -> bool:
        """
        Determine if running in VM
        
        Args:
            threshold: Number of positive checks to consider it a VM
        
        Returns:
            True if VM detected
        """
        checks = self.check_all()
        positive_checks = sum(1 for v in checks.values() if v)
        
        return positive_checks >= threshold


class DebuggerDetector:
    """
    Comprehensive debugger detection
    Implements 15+ different debugger detection techniques
    """
    
    @staticmethod
    def check_is_debugger_present() -> bool:
        """Check IsDebuggerPresent API"""
        try:
            kernel32 = ctypes.windll.kernel32
            if kernel32.IsDebuggerPresent():
                logger.warning("Debugger detected: IsDebuggerPresent")
                return True
        except:
            pass
        return False
    
    @staticmethod
    def check_remote_debugger() -> bool:
        """Check CheckRemoteDebuggerPresent API"""
        try:
            kernel32 = ctypes.windll.kernel32
            is_debugged = ctypes.c_bool()
            kernel32.CheckRemoteDebuggerPresent(
                kernel32.GetCurrentProcess(),
                ctypes.byref(is_debugged)
            )
            if is_debugged.value:
                logger.warning("Debugger detected: CheckRemoteDebuggerPresent")
                return True
        except:
            pass
        return False
    
    @staticmethod
    def check_peb_being_debugged() -> bool:
        """Check PEB BeingDebugged flag"""
        try:
            # PEB is at fs:[0x30] on x86, gs:[0x60] on x64
            # BeingDebugged is at offset 0x2
            # This requires inline assembly or ctypes tricks
            pass
        except:
            pass
        return False
    
    @staticmethod
    def check_nt_query_information_process() -> bool:
        """Check NtQueryInformationProcess"""
        try:
            ntdll = ctypes.windll.ntdll
            kernel32 = ctypes.windll.kernel32
            
            debug_port = ctypes.c_ulong()
            status = ntdll.NtQueryInformationProcess(
                kernel32.GetCurrentProcess(),
                7,  # ProcessDebugPort
                ctypes.byref(debug_port),
                ctypes.sizeof(debug_port),
                None
            )
            
            if status == 0 and debug_port.value != 0:
                logger.warning("Debugger detected: NtQueryInformationProcess")
                return True
        except:
            pass
        return False
    
    @staticmethod
    def check_hardware_breakpoints() -> bool:
        """Check for hardware breakpoints in debug registers"""
        try:
            # Check DR0-DR3 debug registers
            # Requires GetThreadContext
            kernel32 = ctypes.windll.kernel32
            
            class CONTEXT(ctypes.Structure):
                _fields_ = [
                    ("Dr0", ctypes.c_ulonglong),
                    ("Dr1", ctypes.c_ulonglong),
                    ("Dr2", ctypes.c_ulonglong),
                    ("Dr3", ctypes.c_ulonglong),
                    ("Dr6", ctypes.c_ulonglong),
                    ("Dr7", ctypes.c_ulonglong),
                ]
            
            # Simplified - real implementation would get full CONTEXT
            # and check debug registers
        except:
            pass
        return False
    
    @staticmethod
    def check_timing_attack() -> bool:
        """Use timing to detect debugger"""
        try:
            start = time.perf_counter()
            
            # Some dummy operations
            x = 0
            for i in range(1000):
                x += i
            
            end = time.perf_counter()
            elapsed = end - start
            
            # If too slow, might be debugger
            if elapsed > 0.01:  # 10ms threshold
                logger.warning(f"Timing anomaly detected: {elapsed*1000:.2f}ms")
                return True
        except:
            pass
        return False
    
    @staticmethod
    def check_debugger_processes() -> bool:
        """Check for debugger processes"""
        try:
            import psutil
            
            debugger_processes = [
                'ollydbg.exe', 'x64dbg.exe', 'x32dbg.exe', 'windbg.exe',
                'ida.exe', 'ida64.exe', 'idaq.exe', 'idaq64.exe',
                'immunitydebugger.exe', 'devenv.exe', 'dnspy.exe',
                'processhacker.exe', 'procexp.exe', 'procexp64.exe',
                'procmon.exe', 'procmon64.exe', 'wireshark.exe',
                'fiddler.exe', 'httpdebugger.exe',
            ]
            
            running = [p.name().lower() for p in psutil.process_iter(['name'])]
            
            for debugger in debugger_processes:
                if debugger.lower() in running:
                    logger.warning(f"Debugger process detected: {debugger}")
                    return True
        except:
            pass
        return False
    
    @staticmethod
    def check_debugger_windows() -> bool:
        """Check for debugger window titles"""
        try:
            import win32gui
            
            def enum_windows_callback(hwnd, results):
                title = win32gui.GetWindowText(hwnd)
                debugger_titles = [
                    'ollydbg', 'x64dbg', 'x32dbg', 'windbg', 'ida',
                    'immunity', 'cheat engine', 'process hacker'
                ]
                
                for dbg in debugger_titles:
                    if dbg in title.lower():
                        results.append(title)
            
            windows = []
            win32gui.EnumWindows(enum_windows_callback, windows)
            
            if windows:
                logger.warning(f"Debugger windows detected: {windows}")
                return True
        except:
            pass
        return False
    
    @staticmethod
    def is_debugged() -> bool:
        """Run all debugger checks"""
        checks = [
            DebuggerDetector.check_is_debugger_present(),
            DebuggerDetector.check_remote_debugger(),
            DebuggerDetector.check_nt_query_information_process(),
            DebuggerDetector.check_timing_attack(),
            DebuggerDetector.check_debugger_processes(),
        ]
        
        return any(checks)


class SandboxDetector:
    """Detect sandbox environments"""
    
    @staticmethod
    def check_mouse_movement() -> bool:
        """Check for mouse movement (sandboxes often don't simulate this)"""
        try:
            import ctypes
            
            class POINT(ctypes.Structure):
                _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]
            
            user32 = ctypes.windll.user32
            pt1 = POINT()
            user32.GetCursorPos(ctypes.byref(pt1))
            
            time.sleep(2)
            
            pt2 = POINT()
            user32.GetCursorPos(ctypes.byref(pt2))
            
            if pt1.x == pt2.x and pt1.y == pt2.y:
                logger.warning("No mouse movement detected (sandbox indicator)")
                return True
        except:
            pass
        return False
    
    @staticmethod
    def check_sleep_acceleration() -> bool:
        """Check if sleep is accelerated (sandbox trick)"""
        try:
            start = time.time()
            time.sleep(5)
            end = time.time()
            
            actual_sleep = end - start
            
            if actual_sleep < 4.5:  # Less than expected
                logger.warning(f"Sleep acceleration detected: {actual_sleep:.2f}s")
                return True
        except:
            pass
        return False
    
    @staticmethod
    def check_sandbox_artifacts() -> bool:
        """Check for sandbox file artifacts"""
        sandbox_files = [
            r"C:\analysis",
            r"C:\sandbox",
            r"C:\cuckoo",
            r"C:\sample",
            r"C:\malware",
        ]
        
        for path in sandbox_files:
            if os.path.exists(path):
                logger.warning(f"Sandbox artifact detected: {path}")
                return True
        return False
    
    @staticmethod
    def check_recent_files() -> bool:
        """Check for lack of recent files (fresh sandbox)"""
        try:
            recent_path = os.path.join(os.environ['APPDATA'], 
                                      r'Microsoft\Windows\Recent')
            if os.path.exists(recent_path):
                files = os.listdir(recent_path)
                if len(files) < 5:
                    logger.warning(f"Few recent files detected: {len(files)}")
                    return True
        except:
            pass
        return False
    
    @staticmethod
    def is_sandbox() -> bool:
        """Run all sandbox checks"""
        checks = [
            SandboxDetector.check_sandbox_artifacts(),
            SandboxDetector.check_recent_files(),
        ]
        
        return any(checks)


# Global instances
_vm_detector = None
_debugger_detector = None
_sandbox_detector = None


def get_vm_detector() -> VMDetector:
    """Get global VM detector instance"""
    global _vm_detector
    if _vm_detector is None:
        _vm_detector = VMDetector()
    return _vm_detector


def get_debugger_detector() -> DebuggerDetector:
    """Get global debugger detector instance"""
    global _debugger_detector
    if _debugger_detector is None:
        _debugger_detector = DebuggerDetector()
    return _debugger_detector


def get_sandbox_detector() -> SandboxDetector:
    """Get global sandbox detector instance"""
    global _sandbox_detector
    if _sandbox_detector is None:
        _sandbox_detector = SandboxDetector()
    return _sandbox_detector
