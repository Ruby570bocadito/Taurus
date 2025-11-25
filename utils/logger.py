"""
ML Malware Generator - Logging System
"""
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Optional
from loguru import logger

from config.settings import LOGS_DIR, safety_config


class MLLogger:
    """Custom logger for ML Malware Generator"""
    
    def __init__(self, name: str = "ml_malware_gen"):
        self.name = name
        self.setup_logger()
        
    def setup_logger(self):
        """Configure loguru logger"""
        # Remove default handler
        logger.remove()
        
        # Console handler with colors
        logger.add(
            sys.stderr,
            format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
            level=safety_config.log_level,
            colorize=True,
        )
        
        # File handler - general logs
        logger.add(
            LOGS_DIR / f"{self.name}.log",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function} - {message}",
            level="DEBUG",
            rotation="10 MB",
            retention="30 days",
            compression="zip",
        )
        
        # File handler - JSON structured logs
        logger.add(
            LOGS_DIR / f"{self.name}_structured.jsonl",
            format="{message}",
            level="INFO",
            rotation="10 MB",
            retention="30 days",
            serialize=True,
        )
        
        # File handler - payload generation audit (mandatory)
        if safety_config.log_all_generations:
            logger.add(
                LOGS_DIR / "payload_audit.jsonl",
                format="{message}",
                level="INFO",
                rotation="50 MB",
                retention="1 year",
                serialize=True,
                filter=lambda record: "payload_generation" in record["extra"],
            )
        
        # File handler - errors only
        logger.add(
            LOGS_DIR / "errors.log",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
            level="ERROR",
            rotation="5 MB",
            retention="90 days",
        )
    
    def log_payload_generation(
        self,
        payload_type: str,
        target_os: str,
        obfuscation_level: int,
        success: bool,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Log payload generation event (mandatory for audit)"""
        log_data = {
            "event": "payload_generation",
            "timestamp": datetime.utcnow().isoformat(),
            "payload_type": payload_type,
            "target_os": target_os,
            "obfuscation_level": obfuscation_level,
            "success": success,
            "metadata": metadata or {},
        }
        
        logger.bind(payload_generation=True).info(json.dumps(log_data))
    
    def log_training_epoch(
        self,
        model_type: str,
        epoch: int,
        loss: float,
        metrics: Dict[str, float],
    ):
        """Log training epoch metrics"""
        log_data = {
            "event": "training_epoch",
            "timestamp": datetime.utcnow().isoformat(),
            "model_type": model_type,
            "epoch": epoch,
            "loss": loss,
            "metrics": metrics,
        }
        
        logger.info(f"Training {model_type} - Epoch {epoch}: Loss={loss:.4f}, Metrics={metrics}")
        logger.bind(training=True).info(json.dumps(log_data))
    
    def log_detection_result(
        self,
        payload_hash: str,
        detection_rate: float,
        detected_by: list,
        total_engines: int,
    ):
        """Log detection analysis results"""
        log_data = {
            "event": "detection_analysis",
            "timestamp": datetime.utcnow().isoformat(),
            "payload_hash": payload_hash,
            "detection_rate": detection_rate,
            "detected_by": detected_by,
            "total_engines": total_engines,
        }
        
        logger.info(f"Detection: {detection_rate:.1%} ({len(detected_by)}/{total_engines} engines)")
        logger.bind(detection=True).info(json.dumps(log_data))
    
    def log_evasion_attempt(
        self,
        technique: str,
        success: bool,
        before_detection: float,
        after_detection: float,
    ):
        """Log evasion technique application"""
        log_data = {
            "event": "evasion_attempt",
            "timestamp": datetime.utcnow().isoformat(),
            "technique": technique,
            "success": success,
            "before_detection_rate": before_detection,
            "after_detection_rate": after_detection,
            "improvement": before_detection - after_detection,
        }
        
        improvement = before_detection - after_detection
        logger.info(f"Evasion '{technique}': {'✓' if success else '✗'} (Δ={improvement:+.1%})")
        logger.bind(evasion=True).info(json.dumps(log_data))
    
    def log_safety_violation(
        self,
        violation_type: str,
        details: str,
        severity: str = "HIGH",
    ):
        """Log safety control violations"""
        log_data = {
            "event": "safety_violation",
            "timestamp": datetime.utcnow().isoformat(),
            "violation_type": violation_type,
            "details": details,
            "severity": severity,
        }
        
        logger.error(f"SAFETY VIOLATION [{severity}]: {violation_type} - {details}")
        logger.bind(safety_violation=True).error(json.dumps(log_data))
    
    def info(self, message: str):
        """Log info message"""
        logger.info(message)
    
    def debug(self, message: str):
        """Log debug message"""
        logger.debug(message)
    
    def warning(self, message: str):
        """Log warning message"""
        logger.warning(message)
    
    def error(self, message: str, exception: Optional[Exception] = None):
        """Log error message"""
        if exception:
            logger.error(f"{message}: {str(exception)}")
            logger.exception(exception)
        else:
            logger.error(message)
    
    def success(self, message: str):
        """Log success message"""
        logger.success(message)


# Global logger instance
ml_logger = MLLogger()


def get_logger() -> MLLogger:
    """Get global logger instance"""
    return ml_logger
