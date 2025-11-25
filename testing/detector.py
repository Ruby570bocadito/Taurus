"""
ML Malware Generator - Detection and Evaluation System
Tests payloads against various detection methods
"""
import hashlib
import time
import requests
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import json

from config.settings import detection_config
from utils.logger import get_logger

logger = get_logger()


class PayloadDetector:
    """Detect and evaluate payloads"""
    
    def __init__(self):
        self.vt_api_key = detection_config.virustotal_api_key
        self.vt_enabled = detection_config.virustotal_enabled and self.vt_api_key is not None
    
    def analyze_payload(
        self,
        payload: bytes,
        use_virustotal: bool = False,
        use_local: bool = True,
    ) -> Dict:
        """
        Analyze payload with multiple detection methods
        
        Args:
            payload: Payload bytes to analyze
            use_virustotal: Use VirusTotal API
            use_local: Use local static analysis
        
        Returns:
            Analysis results dictionary
        """
        logger.info("Analyzing payload...")
        
        results = {
            "payload_hash": hashlib.sha256(payload).hexdigest(),
            "payload_size": len(payload),
            "timestamp": time.time(),
        }
        
        # Local static analysis
        if use_local:
            local_results = self._local_static_analysis(payload)
            results["local_analysis"] = local_results
        
        # VirusTotal analysis
        if use_virustotal and self.vt_enabled:
            vt_results = self._virustotal_analysis(payload)
            results["virustotal"] = vt_results
        elif use_virustotal and not self.vt_enabled:
            logger.warning("VirusTotal requested but not enabled/configured")
            results["virustotal"] = {"error": "Not configured"}
        
        # Calculate overall detection score
        results["detection_score"] = self._calculate_detection_score(results)
        
        logger.success(f"Analysis complete - Detection: {results['detection_score']:.1%}")
        return results
    
    def _local_static_analysis(self, payload: bytes) -> Dict:
        """Perform local static analysis"""
        logger.debug("Performing local static analysis...")
        
        analysis = {
            "entropy": self._calculate_entropy(payload),
            "suspicious_strings": self._find_suspicious_strings(payload),
            "file_type": self._detect_file_type(payload),
            "packed": self._detect_packing(payload),
        }
        
        # Simple heuristic detection
        detection_flags = []
        
        if analysis["entropy"] > 7.0:
            detection_flags.append("high_entropy")
        
        if len(analysis["suspicious_strings"]) > 5:
            detection_flags.append("suspicious_strings")
        
        if analysis["packed"]:
            detection_flags.append("packed")
        
        analysis["detection_flags"] = detection_flags
        analysis["detected"] = len(detection_flags) > 0
        
        return analysis
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        import math
        from collections import Counter
        
        # Count byte frequencies
        byte_counts = Counter(data)
        data_len = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _find_suspicious_strings(self, payload: bytes) -> List[str]:
        """Find suspicious strings in payload"""
        suspicious_keywords = [
            b"socket",
            b"connect",
            b"exec",
            b"shell",
            b"cmd",
            b"powershell",
            b"CreateProcess",
            b"VirtualAlloc",
            b"WriteProcessMemory",
            b"kernel32",
            b"ntdll",
        ]
        
        found = []
        for keyword in suspicious_keywords:
            if keyword in payload:
                found.append(keyword.decode('utf-8', errors='ignore'))
        
        return found
    
    def _detect_file_type(self, payload: bytes) -> str:
        """Detect file type from magic bytes"""
        if payload.startswith(b'MZ'):
            return "PE"
        elif payload.startswith(b'\x7fELF'):
            return "ELF"
        elif payload.startswith(b'PK'):
            return "ZIP/APK"
        else:
            return "Unknown"
    
    def _detect_packing(self, payload: bytes) -> bool:
        """Detect if payload is packed"""
        # High entropy often indicates packing/encryption
        entropy = self._calculate_entropy(payload)
        return entropy > 7.5
    
    def _virustotal_analysis(self, payload: bytes) -> Dict:
        """Analyze payload with VirusTotal API"""
        logger.debug("Analyzing with VirusTotal...")
        
        if not self.vt_api_key:
            return {"error": "No API key configured"}
        
        try:
            # Calculate file hash
            file_hash = hashlib.sha256(payload).hexdigest()
            
            # Check if file already exists in VT
            headers = {"x-apikey": self.vt_api_key}
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                # File already analyzed
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                
                total = sum(stats.values())
                malicious = stats.get("malicious", 0)
                
                return {
                    "hash": file_hash,
                    "detection_rate": malicious / total if total > 0 else 0.0,
                    "detections": malicious,
                    "total_engines": total,
                    "stats": stats,
                    "already_analyzed": True,
                }
            
            elif response.status_code == 404:
                # File not in VT, would need to upload
                # For safety, we don't auto-upload
                logger.warning("File not in VirusTotal database (upload required)")
                return {
                    "hash": file_hash,
                    "error": "File not found in VT (upload required)",
                    "already_analyzed": False,
                }
            
            else:
                logger.error(f"VirusTotal API error: {response.status_code}")
                return {"error": f"API error: {response.status_code}"}
        
        except Exception as e:
            logger.error(f"VirusTotal analysis failed: {e}")
            return {"error": str(e)}
    
    def _calculate_detection_score(self, results: Dict) -> float:
        """Calculate overall detection score (0.0 = not detected, 1.0 = fully detected)"""
        scores = []
        
        # Local analysis score
        if "local_analysis" in results:
            local = results["local_analysis"]
            if local.get("detected"):
                local_score = len(local.get("detection_flags", [])) / 3.0  # Normalize
                scores.append(min(local_score, 1.0))
        
        # VirusTotal score
        if "virustotal" in results and "detection_rate" in results["virustotal"]:
            scores.append(results["virustotal"]["detection_rate"])
        
        # Average of all scores
        return sum(scores) / len(scores) if scores else 0.0


class FunctionalityTester:
    """Test if payload maintains functionality"""
    
    def test_payload_functionality(
        self,
        payload: bytes,
        payload_type: str,
    ) -> Dict:
        """
        Test if payload is functional
        
        Args:
            payload: Payload to test
            payload_type: Type of payload (reverse_shell, meterpreter, etc.)
        
        Returns:
            Test results
        """
        logger.info(f"Testing {payload_type} functionality...")
        
        results = {
            "payload_type": payload_type,
            "tests_passed": 0,
            "tests_failed": 0,
            "functionality_score": 0.0,
        }
        
        # Basic structural tests
        if self._test_structure(payload, payload_type):
            results["tests_passed"] += 1
        else:
            results["tests_failed"] += 1
        
        # Size test
        if self._test_size(payload):
            results["tests_passed"] += 1
        else:
            results["tests_failed"] += 1
        
        # Integrity test
        if self._test_integrity(payload):
            results["tests_passed"] += 1
        else:
            results["tests_failed"] += 1
        
        # Calculate score
        total_tests = results["tests_passed"] + results["tests_failed"]
        results["functionality_score"] = results["tests_passed"] / total_tests if total_tests > 0 else 0.0
        
        logger.info(f"Functionality score: {results['functionality_score']:.1%}")
        return results
    
    def _test_structure(self, payload: bytes, payload_type: str) -> bool:
        """Test if payload has correct structure"""
        # Basic structure validation
        if len(payload) < 10:
            return False
        
        # Type-specific checks
        if payload_type in ["reverse_shell_tcp", "meterpreter"]:
            # Should have some code
            return len(payload) > 50
        
        return True
    
    def _test_size(self, payload: bytes) -> bool:
        """Test if payload size is reasonable"""
        # Not too small, not too large
        return 50 < len(payload) < 10 * 1024 * 1024  # 50 bytes to 10MB
    
    def _test_integrity(self, payload: bytes) -> bool:
        """Test payload integrity"""
        # Check if payload is not corrupted (basic check)
        return len(payload) > 0 and payload != b'\x00' * len(payload)


class MetricsCalculator:
    """Calculate performance metrics"""
    
    @staticmethod
    def calculate_metrics(
        detection_results: Dict,
        functionality_results: Dict,
        generation_time: float,
    ) -> Dict:
        """Calculate comprehensive metrics"""
        
        detection_rate = detection_results.get("detection_score", 1.0)
        functionality_score = functionality_results.get("functionality_score", 0.0)
        
        # Stealth score (inverse of detection)
        stealth_score = 1.0 - detection_rate
        
        # Overall score (weighted combination)
        overall_score = (
            stealth_score * 0.5 +  # 50% weight on stealth
            functionality_score * 0.4 +  # 40% weight on functionality
            (1.0 if generation_time < 10.0 else 0.5) * 0.1  # 10% weight on speed
        )
        
        metrics = {
            "detection_rate": detection_rate,
            "stealth_score": stealth_score,
            "functionality_score": functionality_score,
            "overall_score": overall_score,
            "generation_time": generation_time,
            "payload_size": detection_results.get("payload_size", 0),
        }
        
        # Success criteria
        metrics["success"] = (
            detection_rate < detection_config.max_detection_rate and
            functionality_score >= detection_config.min_functionality_score
        )
        
        return metrics


# Global instances
_detector = None
_functionality_tester = None


def get_detector() -> PayloadDetector:
    """Get global detector instance"""
    global _detector
    if _detector is None:
        _detector = PayloadDetector()
    return _detector


def get_functionality_tester() -> FunctionalityTester:
    """Get global functionality tester instance"""
    global _functionality_tester
    if _functionality_tester is None:
        _functionality_tester = FunctionalityTester()
    return _functionality_tester
