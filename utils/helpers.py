"""
Utility functions for Taurus ML Malware Generator
Helper functions for common operations
"""
import os
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

from utils.logger import get_logger

logger = get_logger()


class PayloadAnalyzer:
    """Analyze payloads for various characteristics"""
    
    @staticmethod
    def calculate_hash(data: bytes, algorithm: str = "sha256") -> str:
        """Calculate hash of data"""
        if algorithm == "md5":
            return hashlib.md5(data).hexdigest()
        elif algorithm == "sha1":
            return hashlib.sha1(data).hexdigest()
        elif algorithm == "sha256":
            return hashlib.sha256(data).hexdigest()
        elif algorithm == "sha512":
            return hashlib.sha512(data).hexdigest()
        else:
            raise ValueError(f"Unknown hash algorithm: {algorithm}")
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        import math
        
        # Count byte frequencies
        frequencies = {}
        for byte in data:
            frequencies[byte] = frequencies.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in frequencies.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def get_file_signature(data: bytes) -> str:
        """Identify file type from magic bytes"""
        signatures = {
            b'MZ': 'PE/EXE',
            b'\x7fELF': 'ELF',
            b'PK\x03\x04': 'ZIP',
            b'\x50\x4b\x03\x04': 'ZIP',
            b'\x1f\x8b': 'GZIP',
            b'BM': 'BMP',
            b'\x89PNG': 'PNG',
            b'\xff\xd8\xff': 'JPEG',
            b'GIF8': 'GIF',
        }
        
        for sig, file_type in signatures.items():
            if data.startswith(sig):
                return file_type
        
        return 'Unknown'
    
    @staticmethod
    def analyze_payload(data: bytes) -> Dict[str, Any]:
        """Comprehensive payload analysis"""
        analysis = {
            'size': len(data),
            'entropy': PayloadAnalyzer.calculate_entropy(data),
            'md5': PayloadAnalyzer.calculate_hash(data, 'md5'),
            'sha1': PayloadAnalyzer.calculate_hash(data, 'sha1'),
            'sha256': PayloadAnalyzer.calculate_hash(data, 'sha256'),
            'file_type': PayloadAnalyzer.get_file_signature(data),
            'timestamp': datetime.now().isoformat(),
        }
        
        # Check for suspicious characteristics
        analysis['suspicious'] = []
        
        if analysis['entropy'] > 7.5:
            analysis['suspicious'].append('High entropy (possibly encrypted/packed)')
        
        if analysis['entropy'] < 1.0:
            analysis['suspicious'].append('Very low entropy (possibly padded)')
        
        return analysis


class ConfigManager:
    """Manage configuration profiles"""
    
    def __init__(self, config_dir: str = "config/profiles"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
    
    def save_profile(self, name: str, config: Dict) -> None:
        """Save configuration profile"""
        profile_path = self.config_dir / f"{name}.json"
        
        with open(profile_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        logger.info(f"Saved profile: {name}")
    
    def load_profile(self, name: str) -> Dict:
        """Load configuration profile"""
        profile_path = self.config_dir / f"{name}.json"
        
        if not profile_path.exists():
            raise FileNotFoundError(f"Profile not found: {name}")
        
        with open(profile_path, 'r') as f:
            config = json.load(f)
        
        logger.info(f"Loaded profile: {name}")
        return config
    
    def list_profiles(self) -> List[str]:
        """List available profiles"""
        profiles = []
        for file in self.config_dir.glob("*.json"):
            profiles.append(file.stem)
        return profiles
    
    def delete_profile(self, name: str) -> None:
        """Delete configuration profile"""
        profile_path = self.config_dir / f"{name}.json"
        
        if profile_path.exists():
            profile_path.unlink()
            logger.info(f"Deleted profile: {name}")
        else:
            logger.warning(f"Profile not found: {name}")


class ReportGenerator:
    """Generate reports for payload generation"""
    
    @staticmethod
    def generate_html_report(
        payload_info: Dict,
        detection_results: Dict,
        functionality_results: Dict,
        output_path: str = "report.html"
    ) -> None:
        """Generate HTML report"""
        
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Taurus Payload Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .info-box {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 10px 0; }}
        .metric {{ display: inline-block; margin: 10px 20px 10px 0; }}
        .metric-label {{ font-weight: bold; color: #7f8c8d; }}
        .metric-value {{ color: #2c3e50; font-size: 1.2em; }}
        .success {{ color: #27ae60; }}
        .warning {{ color: #f39c12; }}
        .danger {{ color: #e74c3c; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #3498db; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Taurus Payload Generation Report</h1>
        <p><strong>Generated:</strong> {timestamp}</p>
        
        <h2>📦 Payload Information</h2>
        <div class="info-box">
            <div class="metric">
                <span class="metric-label">Size:</span>
                <span class="metric-value">{size} bytes</span>
            </div>
            <div class="metric">
                <span class="metric-label">Type:</span>
                <span class="metric-value">{payload_type}</span>
            </div>
            <div class="metric">
                <span class="metric-label">Target:</span>
                <span class="metric-value">{target}</span>
            </div>
            <div class="metric">
                <span class="metric-label">Entropy:</span>
                <span class="metric-value">{entropy:.2f}</span>
            </div>
        </div>
        
        <h2>🎭 Techniques Applied</h2>
        <table>
            <tr>
                <th>Category</th>
                <th>Techniques</th>
            </tr>
            {techniques_rows}
        </table>
        
        <h2>🔍 Detection Analysis</h2>
        <div class="info-box">
            <div class="metric">
                <span class="metric-label">Detection Rate:</span>
                <span class="metric-value {detection_class}">{detection_rate:.1%}</span>
            </div>
            <div class="metric">
                <span class="metric-label">Stealth Score:</span>
                <span class="metric-value {stealth_class}">{stealth_score:.1%}</span>
            </div>
        </div>
        
        <h2>✅ Functionality Tests</h2>
        <div class="info-box">
            <div class="metric">
                <span class="metric-label">Tests Passed:</span>
                <span class="metric-value success">{tests_passed}</span>
            </div>
            <div class="metric">
                <span class="metric-label">Tests Failed:</span>
                <span class="metric-value {tests_class}">{tests_failed}</span>
            </div>
        </div>
        
        <h2>📊 Hashes</h2>
        <table>
            <tr><th>Algorithm</th><th>Hash</th></tr>
            <tr><td>MD5</td><td><code>{md5}</code></td></tr>
            <tr><td>SHA1</td><td><code>{sha1}</code></td></tr>
            <tr><td>SHA256</td><td><code>{sha256}</code></td></tr>
        </table>
        
        <div class="footer">
            <p>⚠️ This report is for authorized security testing only</p>
            <p>Generated by Taurus ML Malware Generator v1.0.0</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Prepare data
        techniques_rows = ""
        if 'obfuscation' in payload_info:
            techniques = ', '.join(payload_info['obfuscation'].get('techniques_applied', []))
            techniques_rows += f"<tr><td>Obfuscation</td><td>{techniques}</td></tr>"
        
        if 'evasion' in payload_info:
            techniques = ', '.join(payload_info['evasion'].get('techniques_applied', []))
            techniques_rows += f"<tr><td>Evasion</td><td>{techniques}</td></tr>"
        
        detection_rate = detection_results.get('detection_score', 0)
        detection_class = 'success' if detection_rate < 0.3 else 'warning' if detection_rate < 0.7 else 'danger'
        
        stealth_score = 1.0 - detection_rate
        stealth_class = 'success' if stealth_score > 0.7 else 'warning' if stealth_score > 0.3 else 'danger'
        
        tests_failed = functionality_results.get('tests_failed', 0)
        tests_class = 'success' if tests_failed == 0 else 'danger'
        
        # Fill template
        html = html_template.format(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            size=payload_info.get('final_size', 0),
            payload_type=payload_info.get('type', 'Unknown'),
            target=payload_info.get('target_os', 'Unknown'),
            entropy=detection_results.get('local_analysis', {}).get('entropy', 0),
            techniques_rows=techniques_rows,
            detection_rate=detection_rate,
            detection_class=detection_class,
            stealth_score=stealth_score,
            stealth_class=stealth_class,
            tests_passed=functionality_results.get('tests_passed', 0),
            tests_failed=tests_failed,
            tests_class=tests_class,
            md5=detection_results.get('payload_hash', 'N/A'),
            sha1='N/A',
            sha256='N/A',
        )
        
        # Save report
        with open(output_path, 'w') as f:
            f.write(html)
        
        logger.success(f"HTML report generated: {output_path}")


class BatchProcessor:
    """Process multiple payloads in batch"""
    
    def __init__(self):
        self.results = []
    
    def process_batch(
        self,
        configs: List[Dict],
        output_dir: str = "batch_output"
    ) -> List[Dict]:
        """Process multiple payload configurations"""
        
        os.makedirs(output_dir, exist_ok=True)
        
        from generators.payload_factory import get_payload_factory
        from obfuscation.obfuscator import get_obfuscator
        
        factory = get_payload_factory()
        obfuscator = get_obfuscator()
        
        results = []
        
        for i, config in enumerate(configs, 1):
            logger.info(f"Processing payload {i}/{len(configs)}")
            
            try:
                # Generate payload
                payload, metadata = factory.generate_reverse_shell_tcp(
                    lhost=config.get('lhost', '127.0.0.1'),
                    lport=config.get('lport', 4444),
                    target_os=config.get('target_os', 'windows'),
                )
                
                # Obfuscate
                if config.get('obfuscate', True):
                    payload, obf_meta = obfuscator.obfuscate_payload(
                        payload,
                        level=config.get('obfuscation_level', 3)
                    )
                    metadata['obfuscation'] = obf_meta
                
                # Save
                output_file = f"{output_dir}/payload_{i}.bin"
                factory.save_payload(payload, output_file, metadata)
                
                results.append({
                    'index': i,
                    'config': config,
                    'output': output_file,
                    'size': len(payload),
                    'success': True,
                })
                
            except Exception as e:
                logger.error(f"Failed to process payload {i}: {e}")
                results.append({
                    'index': i,
                    'config': config,
                    'success': False,
                    'error': str(e),
                })
        
        # Save batch results
        with open(f"{output_dir}/batch_results.json", 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.success(f"Batch processing complete: {len(results)} payloads")
        
        return results


# Global instances
_analyzer = None
_config_manager = None
_report_generator = None
_batch_processor = None
_payload_factory = None
_obfuscator = None


def get_analyzer() -> PayloadAnalyzer:
    """Get global analyzer instance"""
    global _analyzer
    if _analyzer is None:
        _analyzer = PayloadAnalyzer()
    return _analyzer


def get_config_manager() -> ConfigManager:
    """Get global config manager instance"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


def get_report_generator() -> ReportGenerator:
    """Get global report generator instance"""
    global _report_generator
    if _report_generator is None:
        _report_generator = ReportGenerator()
    return _report_generator


def get_batch_processor() -> BatchProcessor:
    """Get global batch processor instance"""
    global _batch_processor
    if _batch_processor is None:
        _batch_processor = BatchProcessor()
    return _batch_processor


def get_payload_factory():
    """Get global payload factory instance"""
    global _payload_factory
    if _payload_factory is None:
        from generators.payload_factory import PayloadFactory
        _payload_factory = PayloadFactory()
    return _payload_factory


def get_obfuscator():
    """Get global obfuscator instance"""
    global _obfuscator
    if _obfuscator is None:
        from obfuscation.obfuscator import Obfuscator
        _obfuscator = Obfuscator()
    return _obfuscator
