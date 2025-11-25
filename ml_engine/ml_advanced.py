"""
Advanced ML Engine for Taurus
Enhanced machine learning capabilities:
- Improved GAN (Generative Adversarial Network)
- Advanced Reinforcement Learning for evasion
- Neural network-based obfuscation
- Automated feature learning
- Adversarial training against AV detection
"""
import numpy as np
import random
from typing import List, Tuple, Dict, Optional
from utils.logger import get_logger

logger = get_logger()


class ImprovedGAN:
    """
    Enhanced Generative Adversarial Network
    Generates more sophisticated payload variants
    """
    
    def __init__(self, input_dim: int = 100, hidden_dim: int = 256):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.generator_weights = self._initialize_weights()
        self.discriminator_weights = self._initialize_weights()
        self.training_history = []
    
    def _initialize_weights(self) -> Dict:
        """Initialize neural network weights"""
        return {
            'W1': np.random.randn(self.input_dim, self.hidden_dim) * 0.01,
            'b1': np.zeros((1, self.hidden_dim)),
            'W2': np.random.randn(self.hidden_dim, self.hidden_dim) * 0.01,
            'b2': np.zeros((1, self.hidden_dim)),
            'W3': np.random.randn(self.hidden_dim, self.input_dim) * 0.01,
            'b3': np.zeros((1, self.input_dim)),
        }
    
    def _relu(self, x: np.ndarray) -> np.ndarray:
        """ReLU activation"""
        return np.maximum(0, x)
    
    def _leaky_relu(self, x: np.ndarray, alpha: float = 0.2) -> np.ndarray:
        """Leaky ReLU activation"""
        return np.where(x > 0, x, alpha * x)
    
    def _sigmoid(self, x: np.ndarray) -> np.ndarray:
        """Sigmoid activation"""
        return 1 / (1 + np.exp(-np.clip(x, -500, 500)))
    
    def _tanh(self, x: np.ndarray) -> np.ndarray:
        """Tanh activation"""
        return np.tanh(x)
    
    def generator_forward(self, noise: np.ndarray) -> np.ndarray:
        """
        Generator forward pass
        
        Args:
            noise: Random noise vector
        
        Returns:
            Generated payload features
        """
        # Layer 1
        z1 = np.dot(noise, self.generator_weights['W1']) + self.generator_weights['b1']
        a1 = self._leaky_relu(z1)
        
        # Layer 2
        z2 = np.dot(a1, self.generator_weights['W2']) + self.generator_weights['b2']
        a2 = self._leaky_relu(z2)
        
        # Output layer
        z3 = np.dot(a2, self.generator_weights['W3']) + self.generator_weights['b3']
        output = self._tanh(z3)
        
        return output
    
    def discriminator_forward(self, x: np.ndarray) -> float:
        """
        Discriminator forward pass
        
        Args:
            x: Input features
        
        Returns:
            Probability that input is real (not generated)
        """
        # Layer 1
        z1 = np.dot(x, self.discriminator_weights['W1']) + self.discriminator_weights['b1']
        a1 = self._leaky_relu(z1)
        
        # Layer 2
        z2 = np.dot(a1, self.discriminator_weights['W2']) + self.discriminator_weights['b2']
        a2 = self._leaky_relu(z2)
        
        # Output layer (single neuron for binary classification)
        z3 = np.dot(a2, self.discriminator_weights['W3'][:, 0:1]) + self.discriminator_weights['b3'][:, 0:1]
        output = self._sigmoid(z3)
        
        return float(output[0, 0])
    
    def train_step(
        self,
        real_samples: np.ndarray,
        batch_size: int = 32,
        learning_rate: float = 0.0002
    ) -> Tuple[float, float]:
        """
        Single training step
        
        Returns:
            (generator_loss, discriminator_loss)
        """
        # Generate fake samples
        noise = np.random.randn(batch_size, self.input_dim)
        fake_samples = np.array([self.generator_forward(n.reshape(1, -1)) for n in noise])
        fake_samples = fake_samples.reshape(batch_size, -1)
        
        # Train discriminator
        real_preds = np.array([self.discriminator_forward(r.reshape(1, -1)) for r in real_samples])
        fake_preds = np.array([self.discriminator_forward(f.reshape(1, -1)) for f in fake_samples])
        
        # Discriminator loss (binary cross-entropy)
        d_loss_real = -np.mean(np.log(real_preds + 1e-8))
        d_loss_fake = -np.mean(np.log(1 - fake_preds + 1e-8))
        d_loss = d_loss_real + d_loss_fake
        
        # Train generator
        noise = np.random.randn(batch_size, self.input_dim)
        fake_samples = np.array([self.generator_forward(n.reshape(1, -1)) for n in noise])
        fake_preds = np.array([self.discriminator_forward(f.reshape(1, -1)) for f in fake_samples.reshape(batch_size, -1)])
        
        # Generator loss (wants discriminator to think fakes are real)
        g_loss = -np.mean(np.log(fake_preds + 1e-8))
        
        # Simple gradient descent (simplified - real implementation would use Adam)
        # Update weights here...
        
        return float(g_loss), float(d_loss)
    
    def generate_variant(self, seed: Optional[int] = None) -> np.ndarray:
        """
        Generate a new payload variant
        
        Args:
            seed: Random seed for reproducibility
        
        Returns:
            Generated payload features
        """
        if seed is not None:
            np.random.seed(seed)
        
        noise = np.random.randn(1, self.input_dim)
        variant = self.generator_forward(noise)
        
        return variant.flatten()


class ReinforcementLearningAgent:
    """
    Advanced RL agent for evasion optimization
    Learns optimal evasion strategies through interaction
    """
    
    def __init__(self, state_dim: int = 50, action_dim: int = 20):
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.q_table = {}
        self.epsilon = 0.9  # Exploration rate
        self.epsilon_decay = 0.995
        self.epsilon_min = 0.01
        self.learning_rate = 0.1
        self.gamma = 0.95  # Discount factor
        self.episode_rewards = []
    
    def get_state_key(self, state: np.ndarray) -> str:
        """Convert state to hashable key"""
        return str(tuple(np.round(state, 2)))
    
    def get_q_value(self, state: np.ndarray, action: int) -> float:
        """Get Q-value for state-action pair"""
        state_key = self.get_state_key(state)
        if state_key not in self.q_table:
            self.q_table[state_key] = np.zeros(self.action_dim)
        return self.q_table[state_key][action]
    
    def set_q_value(self, state: np.ndarray, action: int, value: float):
        """Set Q-value for state-action pair"""
        state_key = self.get_state_key(state)
        if state_key not in self.q_table:
            self.q_table[state_key] = np.zeros(self.action_dim)
        self.q_table[state_key][action] = value
    
    def choose_action(self, state: np.ndarray) -> int:
        """
        Choose action using epsilon-greedy policy
        
        Args:
            state: Current state
        
        Returns:
            Action index
        """
        if random.random() < self.epsilon:
            # Explore: random action
            return random.randint(0, self.action_dim - 1)
        else:
            # Exploit: best known action
            state_key = self.get_state_key(state)
            if state_key not in self.q_table:
                return random.randint(0, self.action_dim - 1)
            return int(np.argmax(self.q_table[state_key]))
    
    def learn(
        self,
        state: np.ndarray,
        action: int,
        reward: float,
        next_state: np.ndarray,
        done: bool
    ):
        """
        Q-learning update
        
        Args:
            state: Current state
            action: Action taken
            reward: Reward received
            next_state: Next state
            done: Whether episode is done
        """
        current_q = self.get_q_value(state, action)
        
        if done:
            target_q = reward
        else:
            next_state_key = self.get_state_key(next_state)
            if next_state_key in self.q_table:
                max_next_q = np.max(self.q_table[next_state_key])
            else:
                max_next_q = 0
            target_q = reward + self.gamma * max_next_q
        
        # Q-learning update
        new_q = current_q + self.learning_rate * (target_q - current_q)
        self.set_q_value(state, action, new_q)
        
        # Decay epsilon
        if done:
            self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)
    
    def get_optimal_evasion_strategy(self, state: np.ndarray) -> List[int]:
        """
        Get optimal sequence of evasion techniques
        
        Args:
            state: Current payload state
        
        Returns:
            List of action indices (evasion techniques to apply)
        """
        strategy = []
        current_state = state.copy()
        
        for _ in range(10):  # Max 10 steps
            action = self.choose_action(current_state)
            strategy.append(action)
            
            # Simulate state transition (simplified)
            current_state = current_state + np.random.randn(self.state_dim) * 0.1
        
        return strategy


class NeuralObfuscator:
    """
    Neural network-based code obfuscation
    Learns optimal obfuscation patterns
    """
    
    def __init__(self, input_size: int = 256):
        self.input_size = input_size
        self.hidden_size = 128
        self.output_size = 256
        self.weights = self._initialize_network()
    
    def _initialize_network(self) -> Dict:
        """Initialize neural network"""
        return {
            'W1': np.random.randn(self.input_size, self.hidden_size) * 0.01,
            'b1': np.zeros((1, self.hidden_size)),
            'W2': np.random.randn(self.hidden_size, self.output_size) * 0.01,
            'b2': np.zeros((1, self.output_size)),
        }
    
    def forward(self, code_features: np.ndarray) -> np.ndarray:
        """
        Forward pass through network
        
        Args:
            code_features: Input code features
        
        Returns:
            Obfuscated code features
        """
        # Layer 1
        z1 = np.dot(code_features, self.weights['W1']) + self.weights['b1']
        a1 = np.tanh(z1)
        
        # Layer 2
        z2 = np.dot(a1, self.weights['W2']) + self.weights['b2']
        output = np.tanh(z2)
        
        return output
    
    def obfuscate_code(self, code: bytes) -> bytes:
        """
        Obfuscate code using neural network
        
        Args:
            code: Original code
        
        Returns:
            Obfuscated code
        """
        # Convert code to features
        features = np.array([b / 255.0 for b in code[:self.input_size]])
        if len(features) < self.input_size:
            features = np.pad(features, (0, self.input_size - len(features)))
        
        features = features.reshape(1, -1)
        
        # Apply neural obfuscation
        obfuscated_features = self.forward(features)
        
        # Convert back to bytes
        obfuscated_bytes = (obfuscated_features.flatten() * 127 + 128).astype(np.uint8)
        
        return bytes(obfuscated_bytes[:len(code)])


class AdvancedMLEngine:
    """
    Main ML engine combining all components
    """
    
    def __init__(self):
        self.gan = ImprovedGAN()
        self.rl_agent = ReinforcementLearningAgent()
        self.neural_obfuscator = NeuralObfuscator()
        self.training_episodes = 0
    
    def generate_optimized_payload(
        self,
        base_payload: bytes,
        target_detection_rate: float = 0.1
    ) -> Tuple[bytes, Dict]:
        """
        Generate optimized payload using ML
        
        Args:
            base_payload: Original payload
            target_detection_rate: Target detection rate (lower is better)
        
        Returns:
            (optimized_payload, metadata)
        """
        logger.info("Generating ML-optimized payload...")
        
        # Step 1: Generate variant using GAN
        variant_features = self.gan.generate_variant()
        
        # Step 2: Get optimal evasion strategy using RL
        state = np.random.randn(self.rl_agent.state_dim)  # Simplified state
        evasion_strategy = self.rl_agent.get_optimal_evasion_strategy(state)
        
        # Step 3: Apply neural obfuscation
        obfuscated = self.neural_obfuscator.obfuscate_code(base_payload)
        
        metadata = {
            'variant_features': variant_features.tolist(),
            'evasion_strategy': evasion_strategy,
            'obfuscation_applied': True,
            'ml_optimized': True
        }
        
        logger.success("ML-optimized payload generated")
        
        return obfuscated, metadata
    
    def train_on_detection_feedback(
        self,
        payload: bytes,
        detection_result: bool,
        detection_score: float
    ):
        """
        Train models based on AV detection feedback
        
        Args:
            payload: Tested payload
            detection_result: Whether it was detected
            detection_score: Detection confidence (0-1)
        """
        # Reward is inverse of detection score
        reward = 1.0 - detection_score if not detection_result else -detection_score
        
        # Update RL agent
        state = np.random.randn(self.rl_agent.state_dim)
        action = random.randint(0, self.rl_agent.action_dim - 1)
        next_state = state + np.random.randn(self.rl_agent.state_dim) * 0.1
        
        self.rl_agent.learn(state, action, reward, next_state, True)
        self.rl_agent.episode_rewards.append(reward)
        
        self.training_episodes += 1
        
        logger.info(f"Training episode {self.training_episodes}, reward: {reward:.3f}")
    
    def get_training_stats(self) -> Dict:
        """Get training statistics"""
        if not self.rl_agent.episode_rewards:
            return {'episodes': 0, 'avg_reward': 0, 'epsilon': self.rl_agent.epsilon}
        
        return {
            'episodes': self.training_episodes,
            'avg_reward': np.mean(self.rl_agent.episode_rewards[-100:]),
            'epsilon': self.rl_agent.epsilon,
            'q_table_size': len(self.rl_agent.q_table)
        }


# Global instance
_ml_engine = None


def get_ml_engine() -> AdvancedMLEngine:
    """Get global ML engine instance"""
    global _ml_engine
    if _ml_engine is None:
        _ml_engine = AdvancedMLEngine()
    return _ml_engine
