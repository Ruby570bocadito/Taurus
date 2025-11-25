"""
Performance Monitor for Taurus
Tracks and optimizes system performance
"""
import time
import psutil
import os
from typing import Dict, List
from utils.logger import get_logger

logger = get_logger()


class PerformanceMonitor:
    """Monitor and optimize performance"""
    
    def __init__(self):
        self.metrics = []
        self.start_time = time.time()
    
    def track_operation(self, operation_name: str):
        """Decorator to track operation performance"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                start = time.time()
                start_memory = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
                
                result = func(*args, **kwargs)
                
                end = time.time()
                end_memory = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
                
                metric = {
                    'operation': operation_name,
                    'duration': end - start,
                    'memory_delta': end_memory - start_memory,
                    'timestamp': time.time()
                }
                
                self.metrics.append(metric)
                
                logger.info(f"{operation_name}: {metric['duration']:.3f}s, {metric['memory_delta']:.2f}MB")
                
                return result
            return wrapper
        return decorator
    
    def get_system_stats(self) -> Dict:
        """Get current system statistics"""
        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'process_memory': psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024,
        }
    
    def get_performance_report(self) -> str:
        """Generate performance report"""
        if not self.metrics:
            return "No metrics collected"
        
        total_time = sum(m['duration'] for m in self.metrics)
        avg_time = total_time / len(self.metrics)
        max_time = max(m['duration'] for m in self.metrics)
        
        total_memory = sum(m['memory_delta'] for m in self.metrics)
        
        report = f"""
# Performance Report

## Summary
- Total Operations: {len(self.metrics)}
- Total Time: {total_time:.2f}s
- Average Time: {avg_time:.3f}s
- Max Time: {max_time:.3f}s
- Total Memory Delta: {total_memory:.2f}MB

## System Stats
- CPU Usage: {psutil.cpu_percent()}%
- Memory Usage: {psutil.virtual_memory().percent}%
- Process Memory: {psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024:.2f}MB

## Top 5 Slowest Operations
"""
        
        sorted_metrics = sorted(self.metrics, key=lambda x: x['duration'], reverse=True)
        for i, metric in enumerate(sorted_metrics[:5], 1):
            report += f"\n{i}. {metric['operation']}: {metric['duration']:.3f}s"
        
        return report


# Global instance
_performance_monitor = None


def get_performance_monitor() -> PerformanceMonitor:
    """Get global performance monitor"""
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = PerformanceMonitor()
    return _performance_monitor
