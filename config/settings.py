"""
ML Malware Generator - Configuration Settings
"""
import os
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

# Base paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
OUTPUT_DIR = BASE_DIR / "output"
LOGS_DIR = BASE_DIR / "logs"

# Create directories if they don't exist
for directory in [DATA_DIR, MODELS_DIR, OUTPUT_DIR, LOGS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)


@dataclass
class MLConfig:
    """Machine Learning model configurations"""
    
    # GAN Configuration
    gan_latent_dim: int = 128
    gan_hidden_dim: int = 256
    gan_num_layers: int = 4
    gan_learning_rate: float = 0.0002
    gan_beta1: float = 0.5
    gan_beta2: float = 0.999
    
    # RL Configuration
    rl_algorithm: str = "PPO"  # PPO, DQN, A2C
    rl_learning_rate: float = 0.0003
    rl_gamma: float = 0.99
    rl_n_steps: int = 2048
    rl_batch_size: int = 64
    
    # Transformer Configuration
    transformer_model: str = "gpt2"  # Base model for shellcode generation
    transformer_max_length: int = 512
    transformer_num_layers: int = 6
    transformer_num_heads: int = 8
    transformer_learning_rate: float = 0.00005
    
    # Training Configuration
    epochs: int = 100
    batch_size: int = 32
    validation_split: float = 0.2
    early_stopping_patience: int = 10
    checkpoint_interval: int = 5
    
    # Device Configuration
    device: str = "cuda" if os.environ.get("CUDA_VISIBLE_DEVICES") else "cpu"
    mixed_precision: bool = True


@dataclass
class PayloadConfig:
    """Payload generation configurations"""
    
    # Supported payload types
    payload_types: list = None
    
    # Default payload settings
    default_lhost: str = "127.0.0.1"
    default_lport: int = 4444
    
    # Obfuscation settings
    obfuscation_level: int = 3  # 1-5, higher = more obfuscation
    enable_polymorphism: bool = True
    enable_encryption: bool = True
    
    # Encoding settings
    encoders: list = None
    encoding_iterations: int = 3
    
    # Evasion settings
    enable_av_evasion: bool = True
    enable_sandbox_evasion: bool = True
    enable_amsi_bypass: bool = True
    
    def __post_init__(self):
        if self.payload_types is None:
            self.payload_types = [
                "reverse_shell_tcp",
                "reverse_shell_http",
                "reverse_shell_https",
                "meterpreter",
                "backdoor",
                "keylogger",
            ]
        
        if self.encoders is None:
            self.encoders = [
                "base64",
                "xor",
                "rot13",
                "custom_ml",
            ]


@dataclass
class DetectionConfig:
    """Detection and evaluation configurations"""
    
    # VirusTotal API
    virustotal_api_key: Optional[str] = os.environ.get("VT_API_KEY")
    virustotal_enabled: bool = False
    virustotal_rate_limit: int = 4  # requests per minute
    
    # Local detection
    yara_rules_dir: Path = DATA_DIR / "yara_rules"
    enable_static_analysis: bool = True
    enable_dynamic_analysis: bool = False
    
    # Sandbox settings
    sandbox_type: str = "cuckoo"  # cuckoo, cape, local
    sandbox_timeout: int = 120  # seconds
    
    # Metrics thresholds
    max_detection_rate: float = 0.5  # 50% max detection acceptable
    min_functionality_score: float = 0.9  # 90% functionality required
    min_stealth_score: float = 0.7  # 70% stealth required


@dataclass
class SafetyConfig:
    """Safety and ethical controls"""
    
    # Watermarking
    enable_watermark: bool = True
    watermark_signature: str = "ML_RESEARCH_2024"
    
    # Kill switch
    enable_kill_switch: bool = True
    kill_switch_domain: str = "research-killswitch.local"
    
    # Logging
    mandatory_logging: bool = True
    log_all_generations: bool = True
    log_level: str = "INFO"
    
    # Environment checks
    allowed_environments: list = None
    require_vm_detection: bool = True
    
    # Ethical guidelines
    require_authorization: bool = True
    max_payloads_per_session: int = 100
    
    def __post_init__(self):
        if self.allowed_environments is None:
            self.allowed_environments = [
                "development",
                "testing",
                "research_lab",
            ]


@dataclass
class DataConfig:
    """Data collection and preprocessing configurations"""
    
    # Dataset paths
    malware_dataset_dir: Path = DATA_DIR / "malware_samples"
    shellcode_dataset_dir: Path = DATA_DIR / "shellcode_samples"
    benign_dataset_dir: Path = DATA_DIR / "benign_samples"
    
    # Data sources
    enable_malwarebazaar: bool = False
    enable_metasploit_samples: bool = True
    enable_exploit_db: bool = True
    
    # Preprocessing
    max_sample_size: int = 10 * 1024 * 1024  # 10MB
    min_sample_size: int = 1024  # 1KB
    supported_formats: list = None
    
    # Feature extraction
    extract_opcodes: bool = True
    extract_api_calls: bool = True
    extract_strings: bool = True
    extract_entropy: bool = True
    
    def __post_init__(self):
        if self.supported_formats is None:
            self.supported_formats = [
                ".exe",
                ".dll",
                ".bin",
                ".elf",
                ".apk",
            ]


# Global configuration instances
ml_config = MLConfig()
payload_config = PayloadConfig()
detection_config = DetectionConfig()
safety_config = SafetyConfig()
data_config = DataConfig()


def get_config(config_type: str):
    """Get configuration by type"""
    configs = {
        "ml": ml_config,
        "payload": payload_config,
        "detection": detection_config,
        "safety": safety_config,
        "data": data_config,
    }
    return configs.get(config_type)


def update_config(config_type: str, **kwargs):
    """Update configuration values"""
    config = get_config(config_type)
    if config:
        for key, value in kwargs.items():
            if hasattr(config, key):
                setattr(config, key, value)
    return config
