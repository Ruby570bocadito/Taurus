"""
Automated AV Evasion Optimizer
Uses ML to automatically find optimal evasion combinations
"""
import numpy as np
from typing import List, Dict, Tuple
from utils.logger import get_logger

logger = get_logger()


class EvolutionaryOptimizer:
    """
    Evolutionary algorithm for evasion optimization
    Evolves payload configurations to minimize detection
    """
    
    def __init__(self, population_size: int = 50):
        self.population_size = population_size
        self.mutation_rate = 0.1
        self.crossover_rate = 0.7
        self.generations = 0
        self.best_fitness_history = []
    
    def _create_individual(self) -> Dict:
        """Create random individual (payload configuration)"""
        return {
            'obfuscation_level': np.random.randint(1, 11),
            'compression': np.random.choice(['zlib', 'lzma', 'custom']),
            'encryption': np.random.choice(['aes', 'chacha20', 'rsa', 'multi', None]),
            'evasion_techniques': np.random.choice([True, False], size=10).tolist(),
            'packing': np.random.choice([True, False]),
            'multi_stage': np.random.choice([True, False]),
        }
    
    def _fitness(self, individual: Dict, detection_score: float) -> float:
        """
        Calculate fitness (lower detection = higher fitness)
        
        Args:
            individual: Payload configuration
            detection_score: AV detection score (0-1)
        
        Returns:
            Fitness score
        """
        # Inverse of detection score
        base_fitness = 1.0 - detection_score
        
        # Penalize complexity (prefer simpler solutions)
        complexity_penalty = sum(individual['evasion_techniques']) * 0.01
        
        return base_fitness - complexity_penalty
    
    def _mutate(self, individual: Dict) -> Dict:
        """Mutate individual"""
        mutated = individual.copy()
        
        if np.random.random() < self.mutation_rate:
            mutated['obfuscation_level'] = np.random.randint(1, 11)
        
        if np.random.random() < self.mutation_rate:
            mutated['compression'] = np.random.choice(['zlib', 'lzma', 'custom'])
        
        if np.random.random() < self.mutation_rate:
            mutated['encryption'] = np.random.choice(['aes', 'chacha20', 'rsa', 'multi', None])
        
        # Mutate evasion techniques
        for i in range(len(mutated['evasion_techniques'])):
            if np.random.random() < self.mutation_rate:
                mutated['evasion_techniques'][i] = not mutated['evasion_techniques'][i]
        
        return mutated
    
    def _crossover(self, parent1: Dict, parent2: Dict) -> Tuple[Dict, Dict]:
        """Crossover two parents"""
        if np.random.random() > self.crossover_rate:
            return parent1.copy(), parent2.copy()
        
        child1 = parent1.copy()
        child2 = parent2.copy()
        
        # Swap some genes
        if np.random.random() < 0.5:
            child1['obfuscation_level'], child2['obfuscation_level'] = \
                child2['obfuscation_level'], child1['obfuscation_level']
        
        if np.random.random() < 0.5:
            child1['compression'], child2['compression'] = \
                child2['compression'], child1['compression']
        
        # Crossover evasion techniques
        crossover_point = np.random.randint(0, len(parent1['evasion_techniques']))
        child1['evasion_techniques'] = parent1['evasion_techniques'][:crossover_point] + \
                                       parent2['evasion_techniques'][crossover_point:]
        child2['evasion_techniques'] = parent2['evasion_techniques'][:crossover_point] + \
                                       parent1['evasion_techniques'][crossover_point:]
        
        return child1, child2
    
    def optimize(
        self,
        fitness_function,
        generations: int = 20
    ) -> Dict:
        """
        Run evolutionary optimization
        
        Args:
            fitness_function: Function that takes individual and returns fitness
            generations: Number of generations
        
        Returns:
            Best individual found
        """
        logger.info(f"Starting evolutionary optimization ({generations} generations)...")
        
        # Initialize population
        population = [self._create_individual() for _ in range(self.population_size)]
        
        for gen in range(generations):
            # Evaluate fitness
            fitness_scores = [fitness_function(ind) for ind in population]
            
            # Track best
            best_idx = np.argmax(fitness_scores)
            best_fitness = fitness_scores[best_idx]
            self.best_fitness_history.append(best_fitness)
            
            logger.info(f"Generation {gen+1}/{generations}: Best fitness = {best_fitness:.4f}")
            
            # Selection (tournament)
            selected = []
            for _ in range(self.population_size):
                tournament = np.random.choice(len(population), size=3, replace=False)
                winner = tournament[np.argmax([fitness_scores[i] for i in tournament])]
                selected.append(population[winner])
            
            # Crossover and mutation
            next_population = []
            for i in range(0, len(selected), 2):
                if i + 1 < len(selected):
                    child1, child2 = self._crossover(selected[i], selected[i+1])
                    next_population.append(self._mutate(child1))
                    next_population.append(self._mutate(child2))
                else:
                    next_population.append(self._mutate(selected[i]))
            
            population = next_population[:self.population_size]
            self.generations += 1
        
        # Return best individual
        final_fitness = [fitness_function(ind) for ind in population]
        best_idx = np.argmax(final_fitness)
        
        logger.success(f"Optimization complete. Best fitness: {final_fitness[best_idx]:.4f}")
        
        return population[best_idx]


class AutomatedEvasionOptimizer:
    """
    Automated system for finding optimal evasion configurations
    """
    
    def __init__(self):
        self.evolutionary = EvolutionaryOptimizer()
        self.tested_configurations = []
    
    def find_optimal_configuration(
        self,
        payload: bytes,
        test_function=None,
        generations: int = 20
    ) -> Dict:
        """
        Find optimal configuration for payload
        
        Args:
            payload: Payload to optimize
            test_function: Function to test detection (returns score 0-1)
            generations: Number of generations
        
        Returns:
            Optimal configuration
        """
        def fitness_func(individual: Dict) -> float:
            # Simulate testing (in real use, would actually test against AV)
            if test_function:
                detection_score = test_function(payload, individual)
            else:
                # Simulate detection score based on configuration
                detection_score = self._simulate_detection(individual)
            
            fitness = self.evolutionary._fitness(individual, detection_score)
            
            # Track tested configuration
            self.tested_configurations.append({
                'config': individual,
                'detection_score': detection_score,
                'fitness': fitness
            })
            
            return fitness
        
        optimal = self.evolutionary.optimize(fitness_func, generations)
        
        return optimal
    
    def _simulate_detection(self, config: Dict) -> float:
        """Simulate AV detection score"""
        # Higher obfuscation = lower detection
        base_score = 1.0 - (config['obfuscation_level'] / 10.0)
        
        # Encryption helps
        if config['encryption']:
            base_score *= 0.7
        
        # Packing helps
        if config['packing']:
            base_score *= 0.8
        
        # More evasion techniques = lower detection
        evasion_count = sum(config['evasion_techniques'])
        base_score *= (1.0 - evasion_count * 0.05)
        
        return max(0.0, min(1.0, base_score))
    
    def get_optimization_report(self) -> str:
        """Generate optimization report"""
        if not self.tested_configurations:
            return "No configurations tested yet"
        
        best = min(self.tested_configurations, key=lambda x: x['detection_score'])
        worst = max(self.tested_configurations, key=lambda x: x['detection_score'])
        avg_detection = np.mean([c['detection_score'] for c in self.tested_configurations])
        
        report = f"""
# Evasion Optimization Report

## Statistics
- Configurations Tested: {len(self.tested_configurations)}
- Generations: {self.evolutionary.generations}
- Best Detection Score: {best['detection_score']:.4f}
- Worst Detection Score: {worst['detection_score']:.4f}
- Average Detection Score: {avg_detection:.4f}

## Best Configuration
- Obfuscation Level: {best['config']['obfuscation_level']}
- Compression: {best['config']['compression']}
- Encryption: {best['config']['encryption']}
- Packing: {best['config']['packing']}
- Multi-Stage: {best['config']['multi_stage']}
- Evasion Techniques: {sum(best['config']['evasion_techniques'])}/10 enabled

## Improvement
- Detection Reduction: {(worst['detection_score'] - best['detection_score']) / worst['detection_score'] * 100:.1f}%
"""
        
        return report


# Global instance
_optimizer = None


def get_evasion_optimizer() -> AutomatedEvasionOptimizer:
    """Get global evasion optimizer"""
    global _optimizer
    if _optimizer is None:
        _optimizer = AutomatedEvasionOptimizer()
    return _optimizer
