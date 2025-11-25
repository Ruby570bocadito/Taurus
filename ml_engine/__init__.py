"""
ML Engine Package for Taurus
Advanced machine learning capabilities
"""

try:
    from .ml_advanced import (
        get_ml_engine,
        ImprovedGAN,
        ReinforcementLearningAgent,
        NeuralObfuscator,
        AdvancedMLEngine,
    )
except ImportError:
    pass

try:
    from .evasion_optimizer import (
        get_evasion_optimizer,
        EvolutionaryOptimizer,
        AutomatedEvasionOptimizer,
    )
except ImportError:
    pass

__all__ = [
    'get_ml_engine',
    'ImprovedGAN',
    'ReinforcementLearningAgent',
    'NeuralObfuscator',
    'AdvancedMLEngine',
    'get_evasion_optimizer',
    'EvolutionaryOptimizer',
    'AutomatedEvasionOptimizer',
]
