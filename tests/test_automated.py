"""
Automated Testing and Continuous Integration for Taurus
Runs tests automatically after each improvement
Tracks performance metrics and regression
"""
import sys
import os
import time
import json
from datetime import datetime
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import get_logger

logger = get_logger()


class AutomatedTestRunner:
    """Automated test execution with metrics tracking"""
    
    def __init__(self):
        self.results_history = []
        self.metrics_file = "test_metrics.json"
        self.load_history()
    
    def load_history(self):
        """Load test history"""
        try:
            if os.path.exists(self.metrics_file):
                with open(self.metrics_file, 'r') as f:
                    self.results_history = json.load(f)
        except:
            self.results_history = []
    
    def save_history(self):
        """Save test history"""
        try:
            with open(self.metrics_file, 'w') as f:
                json.dump(self.results_history, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save history: {e}")
    
    def run_all_tests(self) -> Dict:
        """Run all test suites and collect metrics"""
        print("\n" + "="*70)
        print("🤖 AUTOMATED TEST SUITE - CONTINUOUS INTEGRATION")
        print("="*70)
        
        start_time = time.time()
        results = {
            'timestamp': datetime.now().isoformat(),
            'tests': {},
            'metrics': {},
            'status': 'running'
        }
        
        # Test categories
        test_suites = [
            ('Core Features', self.test_core_features),
            ('Advanced Evasion', self.test_advanced_evasion),
            ('Anti-Analysis', self.test_anti_analysis),
            ('Injection', self.test_injection),
            ('Persistence', self.test_persistence),
            ('Fileless', self.test_fileless),
            ('C2', self.test_c2),
            ('Obfuscation', self.test_obfuscation),
            ('Variants', self.test_variants),
            ('Cryptography', self.test_cryptography),
            ('Exploits', self.test_exploits),
            ('Performance', self.test_performance),
        ]
        
        total_passed = 0
        total_failed = 0
        
        for suite_name, test_func in test_suites:
            try:
                print(f"\n{'─'*70}")
                print(f"📦 {suite_name}")
                print(f"{'─'*70}")
                
                suite_start = time.time()
                passed, failed = test_func()
                suite_time = time.time() - suite_start
                
                results['tests'][suite_name] = {
                    'passed': passed,
                    'failed': failed,
                    'time': suite_time,
                    'status': 'pass' if failed == 0 else 'fail'
                }
                
                total_passed += passed
                total_failed += failed
                
                print(f"✅ {passed} passed, ❌ {failed} failed ({suite_time:.2f}s)")
                
            except Exception as e:
                print(f"❌ Suite failed: {e}")
                results['tests'][suite_name] = {'status': 'error', 'error': str(e)}
                total_failed += 1
        
        # Calculate metrics
        total_time = time.time() - start_time
        total_tests = total_passed + total_failed
        success_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0
        
        results['metrics'] = {
            'total_tests': total_tests,
            'passed': total_passed,
            'failed': total_failed,
            'success_rate': success_rate,
            'total_time': total_time,
            'avg_time_per_test': total_time / total_tests if total_tests > 0 else 0
        }
        
        results['status'] = 'success' if total_failed == 0 else 'failed'
        
        # Save results
        self.results_history.append(results)
        self.save_history()
        
        # Print summary
        self.print_summary(results)
        
        return results
    
    def test_core_features(self) -> Tuple[int, int]:
        """Test core features"""
        passed, failed = 0, 0
        
        try:
            from utils.helpers import get_analyzer, get_config_manager
            analyzer = get_analyzer()
            manager = get_config_manager()
            assert analyzer is not None
            assert manager is not None
            passed += 2
        except:
            failed += 2
        
        return passed, failed
    
    def test_advanced_evasion(self) -> Tuple[int, int]:
        """Test advanced evasion"""
        passed, failed = 0, 0
        
        try:
            from evasion.advanced_evasion import get_syscall_invoker, get_api_unhooker
            syscaller = get_syscall_invoker()
            unhooker = get_api_unhooker()
            assert syscaller is not None
            assert unhooker is not None
            passed += 2
        except:
            failed += 2
        
        return passed, failed
    
    def test_anti_analysis(self) -> Tuple[int, int]:
        """Test anti-analysis"""
        passed, failed = 0, 0
        
        try:
            from evasion.anti_analysis import get_vm_detector
            detector = get_vm_detector()
            checks = detector.check_all()
            assert len(checks) >= 10
            passed += 1
        except:
            failed += 1
        
        return passed, failed
    
    def test_injection(self) -> Tuple[int, int]:
        """Test injection techniques"""
        passed, failed = 0, 0
        
        try:
            from injection.injection_advanced import get_reflective_dll_injection
            reflective = get_reflective_dll_injection()
            code = reflective.generate_reflective_loader()
            assert len(code) > 0
            passed += 1
        except:
            failed += 1
        
        return passed, failed
    
    def test_persistence(self) -> Tuple[int, int]:
        """Test persistence"""
        passed, failed = 0, 0
        
        try:
            from persistence.persistence_manager import get_persistence_manager
            manager = get_persistence_manager()
            assert manager is not None
            passed += 1
        except:
            failed += 1
        
        return passed, failed
    
    def test_fileless(self) -> Tuple[int, int]:
        """Test fileless execution"""
        passed, failed = 0, 0
        
        try:
            from generators.fileless_execution import get_fileless_manager
            manager = get_fileless_manager()
            techniques = manager.get_all_techniques()
            assert len(techniques) >= 4
            passed += 1
        except:
            failed += 1
        
        return passed, failed
    
    def test_c2(self) -> Tuple[int, int]:
        """Test C2 protocols"""
        passed, failed = 0, 0
        
        try:
            from generators.c2_enhanced import get_enhanced_c2_manager
            c2 = get_enhanced_c2_manager()
            protocols = c2.get_all_protocols()
            assert len(protocols) >= 7
            passed += 1
        except:
            failed += 1
        
        return passed, failed
    
    def test_obfuscation(self) -> Tuple[int, int]:
        """Test obfuscation"""
        passed, failed = 0, 0
        
        try:
            from obfuscation.obfuscation_advanced import get_advanced_obfuscation_engine
            engine = get_advanced_obfuscation_engine()
            assert engine is not None
            passed += 1
        except:
            failed += 1
        
        return passed, failed
    
    def test_variants(self) -> Tuple[int, int]:
        """Test variant generation"""
        passed, failed = 0, 0
        
        try:
            from generators.variant_generator import get_variant_generator
            generator = get_variant_generator()
            variants = generator.generate_variants(b"TEST", count=5)
            assert len(variants) == 5
            passed += 1
        except:
            failed += 1
        
        return passed, failed
    
    def test_cryptography(self) -> Tuple[int, int]:
        """Test cryptography"""
        passed, failed = 0, 0
        
        try:
            from utils.crypto_enhanced import get_crypto_manager
            crypto = get_crypto_manager()
            encrypted, keys = crypto.encrypt_payload(b"TEST", method='aes')
            assert len(encrypted) > 0
            passed += 1
        except:
            failed += 1
        
        return passed, failed
    
    def test_exploits(self) -> Tuple[int, int]:
        """Test exploit templates"""
        passed, failed = 0, 0
        
        try:
            from exploits.exploit_templates import get_exploit_manager
            exploits = get_exploit_manager()
            macro = exploits.generate_exploit('macro', url='http://test.com')
            assert len(macro) > 0
            passed += 1
        except:
            failed += 1
        
        return passed, failed
    
    def test_performance(self) -> Tuple[int, int]:
        """Test performance metrics"""
        passed, failed = 0, 0
        
        try:
            # Test VM detection speed
            from evasion.anti_analysis import get_vm_detector
            detector = get_vm_detector()
            
            start = time.time()
            detector.check_all()
            elapsed = time.time() - start
            
            if elapsed < 5.0:
                passed += 1
            else:
                failed += 1
        except:
            failed += 1
        
        return passed, failed
    
    def print_summary(self, results: Dict):
        """Print test summary"""
        print("\n" + "="*70)
        print("📊 AUTOMATED TEST SUMMARY")
        print("="*70)
        
        metrics = results['metrics']
        print(f"Total Tests: {metrics['total_tests']}")
        print(f"✅ Passed: {metrics['passed']}")
        print(f"❌ Failed: {metrics['failed']}")
        print(f"Success Rate: {metrics['success_rate']:.1f}%")
        print(f"Total Time: {metrics['total_time']:.2f}s")
        print(f"Avg Time/Test: {metrics['avg_time_per_test']:.3f}s")
        
        # Trend analysis
        if len(self.results_history) > 1:
            prev = self.results_history[-2]['metrics']
            curr = metrics
            
            print(f"\n📈 TRENDS (vs previous run):")
            rate_change = curr['success_rate'] - prev['success_rate']
            time_change = curr['total_time'] - prev['total_time']
            
            print(f"Success Rate: {rate_change:+.1f}%")
            print(f"Time: {time_change:+.2f}s")
        
        print("="*70 + "\n")
    
    def generate_report(self) -> str:
        """Generate HTML test report"""
        if not self.results_history:
            return "No test results available"
        
        latest = self.results_history[-1]
        
        html = f'''
<!DOCTYPE html>
<html>
<head>
    <title>Taurus Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .pass {{ color: green; }}
        .fail {{ color: red; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
    </style>
</head>
<body>
    <h1>Taurus Automated Test Report</h1>
    <p>Generated: {latest['timestamp']}</p>
    
    <h2>Summary</h2>
    <table>
        <tr>
            <th>Metric</th>
            <th>Value</th>
        </tr>
        <tr>
            <td>Total Tests</td>
            <td>{latest['metrics']['total_tests']}</td>
        </tr>
        <tr>
            <td>Passed</td>
            <td class="pass">{latest['metrics']['passed']}</td>
        </tr>
        <tr>
            <td>Failed</td>
            <td class="fail">{latest['metrics']['failed']}</td>
        </tr>
        <tr>
            <td>Success Rate</td>
            <td>{latest['metrics']['success_rate']:.1f}%</td>
        </tr>
        <tr>
            <td>Total Time</td>
            <td>{latest['metrics']['total_time']:.2f}s</td>
        </tr>
    </table>
    
    <h2>Test Suites</h2>
    <table>
        <tr>
            <th>Suite</th>
            <th>Passed</th>
            <th>Failed</th>
            <th>Time</th>
            <th>Status</th>
        </tr>
'''
        
        for suite_name, suite_data in latest['tests'].items():
            if 'passed' in suite_data:
                status_class = 'pass' if suite_data['status'] == 'pass' else 'fail'
                html += f'''
        <tr>
            <td>{suite_name}</td>
            <td>{suite_data['passed']}</td>
            <td>{suite_data['failed']}</td>
            <td>{suite_data['time']:.2f}s</td>
            <td class="{status_class}">{suite_data['status'].upper()}</td>
        </tr>
'''
        
        html += '''
    </table>
</body>
</html>
'''
        
        return html


def main():
    """Run automated tests"""
    runner = AutomatedTestRunner()
    results = runner.run_all_tests()
    
    # Generate HTML report
    report = runner.generate_report()
    with open('test_report.html', 'w') as f:
        f.write(report)
    
    print(f"📄 HTML report saved to: test_report.html")
    
    # Return exit code
    return 0 if results['status'] == 'success' else 1


if __name__ == "__main__":
    sys.exit(main())
