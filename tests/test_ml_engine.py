"""
ML Engine Tests
Test advanced ML capabilities
"""
import sys
import os
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import get_logger

logger = get_logger()


def test_improved_gan():
    """Test improved GAN"""
    print("\n🧪 Testing Improved GAN...")
    
    from ml_engine.ml_advanced import ImprovedGAN
    
    gan = ImprovedGAN(input_dim=100, hidden_dim=256)
    
    # Test generator
    noise = np.random.randn(1, 100)
    generated = gan.generator_forward(noise)
    assert generated.shape == (1, 100)
    print(f"  ✓ Generator output shape: {generated.shape}")
    
    # Test discriminator
    score = gan.discriminator_forward(generated)
    assert 0 <= score <= 1
    print(f"  ✓ Discriminator score: {score:.4f}")
    
    # Test training step
    real_samples = np.random.randn(10, 100)
    g_loss, d_loss = gan.train_step(real_samples, batch_size=10)
    assert not np.isnan(g_loss) and not np.isnan(d_loss)
    print(f"  ✓ Training step: G_loss={g_loss:.4f}, D_loss={d_loss:.4f}")
    
    # Test variant generation
    variant = gan.generate_variant(seed=42)
    assert len(variant) == 100
    print(f"  ✓ Generated variant: {len(variant)} features")
    
    print("✅ GAN tests passed")


def test_reinforcement_learning():
    """Test RL agent"""
    print("\n🧪 Testing Reinforcement Learning Agent...")
    
    from ml_engine.ml_advanced import ReinforcementLearningAgent
    
    agent = ReinforcementLearningAgent(state_dim=50, action_dim=20)
    
    # Test action selection
    state = np.random.randn(50)
    action = agent.choose_action(state)
    assert 0 <= action < 20
    print(f"  ✓ Chosen action: {action}")
    
    # Test learning
    next_state = np.random.randn(50)
    agent.learn(state, action, 1.0, next_state, True)
    print(f"  ✓ Learning step completed")
    print(f"  ✓ Q-table size: {len(agent.q_table)}")
    
    # Test strategy generation
    strategy = agent.get_optimal_evasion_strategy(state)
    assert len(strategy) > 0
    print(f"  ✓ Generated strategy: {len(strategy)} steps")
    
    print("✅ RL tests passed")


def test_neural_obfuscator():
    """Test neural obfuscator"""
    print("\n🧪 Testing Neural Obfuscator...")
    
    from ml_engine.ml_advanced import NeuralObfuscator
    
    obfuscator = NeuralObfuscator(input_size=256)
    
    # Test obfuscation
    test_code = b"TEST_CODE_" * 30
    obfuscated = obfuscator.obfuscate_code(test_code)
    
    assert len(obfuscated) > 0
    print(f"  ✓ Obfuscated {len(test_code)} bytes to {len(obfuscated)} bytes")
    print(f"  ✓ Obfuscation applied successfully")
    
    print("✅ Neural obfuscator tests passed")


def test_ml_engine():
    """Test complete ML engine"""
    print("\n🧪 Testing ML Engine...")
    
    from ml_engine.ml_advanced import get_ml_engine
    
    engine = get_ml_engine()
    
    # Test payload optimization
    test_payload = b"PAYLOAD_DATA" * 10
    optimized, metadata = engine.generate_optimized_payload(test_payload)
    
    assert len(optimized) > 0
    assert 'ml_optimized' in metadata
    assert metadata['ml_optimized'] == True
    print(f"  ✓ Generated optimized payload: {len(optimized)} bytes")
    print(f"  ✓ Metadata: {list(metadata.keys())}")
    
    # Test training
    engine.train_on_detection_feedback(test_payload, False, 0.3)
    stats = engine.get_training_stats()
    
    assert stats['episodes'] > 0
    print(f"  ✓ Training episodes: {stats['episodes']}")
    print(f"  ✓ Average reward: {stats['avg_reward']:.4f}")
    
    print("✅ ML engine tests passed")


def test_evolutionary_optimizer():
    """Test evolutionary optimizer"""
    print("\n🧪 Testing Evolutionary Optimizer...")
    
    from ml_engine.evasion_optimizer import EvolutionaryOptimizer
    
    optimizer = EvolutionaryOptimizer(population_size=20)
    
    # Test fitness function
    def simple_fitness(individual):
        return 1.0 - individual['obfuscation_level'] / 10.0
    
    # Run optimization
    best = optimizer.optimize(simple_fitness, generations=5)
    
    assert 'obfuscation_level' in best
    assert 'compression' in best
    print(f"  ✓ Best obfuscation level: {best['obfuscation_level']}")
    print(f"  ✓ Best compression: {best['compression']}")
    print(f"  ✓ Generations: {optimizer.generations}")
    
    print("✅ Evolutionary optimizer tests passed")


def test_automated_evasion_optimizer():
    """Test automated evasion optimizer"""
    print("\n🧪 Testing Automated Evasion Optimizer...")
    
    from ml_engine.evasion_optimizer import get_evasion_optimizer
    
    optimizer = get_evasion_optimizer()
    
    # Test optimization
    test_payload = b"TEST" * 50
    optimal_config = optimizer.find_optimal_configuration(
        test_payload,
        generations=5
    )
    
    assert 'obfuscation_level' in optimal_config
    assert 'encryption' in optimal_config
    print(f"  ✓ Optimal obfuscation: {optimal_config['obfuscation_level']}")
    print(f"  ✓ Optimal encryption: {optimal_config['encryption']}")
    print(f"  ✓ Configurations tested: {len(optimizer.tested_configurations)}")
    
    # Test report generation
    report = optimizer.get_optimization_report()
    assert len(report) > 0
    print(f"  ✓ Generated optimization report")
    
    print("✅ Automated evasion optimizer tests passed")


def main():
    """Run all ML tests"""
    print("\n" + "="*70)
    print("🤖 TAURUS ML ENGINE - TEST SUITE")
    print("="*70)
    
    tests = [
        test_improved_gan,
        test_reinforcement_learning,
        test_neural_obfuscator,
        test_ml_engine,
        test_evolutionary_optimizer,
        test_automated_evasion_optimizer,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"❌ Test failed: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "="*70)
    print(f"📊 ML TEST SUMMARY")
    print("="*70)
    print(f"Total: {passed + failed}")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"Success Rate: {passed/(passed+failed)*100:.1f}%")
    print("="*70 + "\n")
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
