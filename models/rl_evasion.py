"""
ML Malware Generator - Reinforcement Learning Evasion Agent
Uses RL to learn optimal evasion strategies
"""
import torch
import numpy as np
from typing import Dict, List, Tuple, Optional
from stable_baselines3 import PPO, DQN
from stable_baselines3.common.env_util import make_vec_env
from stable_baselines3.common.callbacks import BaseCallback
import gym
from gym import spaces

from config.settings import ml_config
from utils.logger import get_logger

logger = get_logger()


class EvasionEnvironment(gym.Env):
    """
    Custom Gym environment for learning evasion techniques
    
    State: Current payload features + detection results
    Action: Apply evasion technique (obfuscation, encoding, etc.)
    Reward: Based on detection rate reduction and functionality preservation
    """
    
    def __init__(
        self,
        payload_dim: int = 512,
        num_evasion_techniques: int = 10,
    ):
        super(EvasionEnvironment, self).__init__()
        
        self.payload_dim = payload_dim
        self.num_techniques = num_evasion_techniques
        
        # State space: payload features + detection results
        # [payload_features (512), detection_rate (1), functionality_score (1)]
        self.observation_space = spaces.Box(
            low=-1.0,
            high=1.0,
            shape=(payload_dim + 2,),
            dtype=np.float32,
        )
        
        # Action space: choose evasion technique
        # 0: XOR encoding
        # 1: ROT encoding
        # 2: Base64 encoding
        # 3: AES encryption
        # 4: Code obfuscation
        # 5: API hashing
        # 6: String encryption
        # 7: Polymorphic encoding
        # 8: Multi-layer encoding
        # 9: No action (keep current)
        self.action_space = spaces.Discrete(num_evasion_techniques)
        
        # Environment state
        self.current_payload = None
        self.current_detection_rate = 1.0  # Start with 100% detection
        self.current_functionality = 1.0  # Start with 100% functionality
        self.steps = 0
        self.max_steps = 20
        
        # Evasion technique names
        self.technique_names = [
            "xor_encoding",
            "rot_encoding",
            "base64_encoding",
            "aes_encryption",
            "code_obfuscation",
            "api_hashing",
            "string_encryption",
            "polymorphic_encoding",
            "multi_layer_encoding",
            "no_action",
        ]
    
    def reset(self) -> np.ndarray:
        """Reset environment to initial state"""
        # Initialize with random payload
        self.current_payload = np.random.randn(self.payload_dim).astype(np.float32)
        self.current_detection_rate = 1.0
        self.current_functionality = 1.0
        self.steps = 0
        
        return self._get_observation()
    
    def _get_observation(self) -> np.ndarray:
        """Get current observation (state)"""
        return np.concatenate([
            self.current_payload,
            [self.current_detection_rate],
            [self.current_functionality],
        ]).astype(np.float32)
    
    def step(self, action: int) -> Tuple[np.ndarray, float, bool, Dict]:
        """
        Execute action and return (observation, reward, done, info)
        """
        self.steps += 1
        
        # Apply evasion technique (simulated)
        technique = self.technique_names[action]
        
        # Simulate effect of technique on detection and functionality
        detection_reduction, functionality_impact = self._simulate_technique(action)
        
        # Update state
        old_detection = self.current_detection_rate
        self.current_detection_rate = max(0.0, self.current_detection_rate - detection_reduction)
        self.current_functionality = max(0.0, self.current_functionality - functionality_impact)
        
        # Modify payload (simulated transformation)
        self.current_payload = self._apply_transformation(self.current_payload, action)
        
        # Calculate reward
        reward = self._calculate_reward(
            old_detection,
            self.current_detection_rate,
            self.current_functionality,
        )
        
        # Check if done
        done = (
            self.steps >= self.max_steps or
            self.current_detection_rate < 0.1 or  # Successfully evaded
            self.current_functionality < 0.5  # Lost too much functionality
        )
        
        # Info
        info = {
            "technique": technique,
            "detection_rate": self.current_detection_rate,
            "functionality": self.current_functionality,
            "detection_reduction": detection_reduction,
        }
        
        return self._get_observation(), reward, done, info
    
    def _simulate_technique(self, action: int) -> Tuple[float, float]:
        """
        Simulate effect of evasion technique
        Returns: (detection_reduction, functionality_impact)
        """
        # Different techniques have different effectiveness and costs
        technique_effects = {
            0: (0.15, 0.02),  # XOR: good reduction, low impact
            1: (0.10, 0.01),  # ROT: moderate reduction, very low impact
            2: (0.08, 0.01),  # Base64: low reduction, very low impact
            3: (0.25, 0.05),  # AES: high reduction, moderate impact
            4: (0.30, 0.10),  # Code obfuscation: very high reduction, high impact
            5: (0.20, 0.08),  # API hashing: high reduction, moderate impact
            6: (0.18, 0.03),  # String encryption: good reduction, low impact
            7: (0.35, 0.12),  # Polymorphic: highest reduction, highest impact
            8: (0.28, 0.15),  # Multi-layer: very high reduction, very high impact
            9: (0.00, 0.00),  # No action: no change
        }
        
        base_reduction, base_impact = technique_effects.get(action, (0.0, 0.0))
        
        # Add some randomness
        reduction = base_reduction + np.random.normal(0, 0.05)
        impact = base_impact + np.random.normal(0, 0.02)
        
        return max(0.0, reduction), max(0.0, impact)
    
    def _apply_transformation(self, payload: np.ndarray, action: int) -> np.ndarray:
        """Apply transformation to payload based on action"""
        # Simple transformation simulation
        if action == 9:  # No action
            return payload
        
        # Apply random transformation
        noise = np.random.randn(*payload.shape) * 0.1
        transformed = payload + noise
        
        # Normalize
        transformed = np.clip(transformed, -1.0, 1.0)
        
        return transformed.astype(np.float32)
    
    def _calculate_reward(
        self,
        old_detection: float,
        new_detection: float,
        functionality: float,
    ) -> float:
        """
        Calculate reward for the action
        
        Reward components:
        1. Detection reduction (positive)
        2. Functionality preservation (positive)
        3. Penalty for losing functionality (negative)
        """
        # Detection reduction reward
        detection_improvement = old_detection - new_detection
        detection_reward = detection_improvement * 10.0
        
        # Functionality preservation reward
        functionality_reward = functionality * 2.0
        
        # Penalty for low functionality
        functionality_penalty = 0.0
        if functionality < 0.7:
            functionality_penalty = -5.0 * (0.7 - functionality)
        
        # Bonus for achieving low detection with high functionality
        bonus = 0.0
        if new_detection < 0.3 and functionality > 0.8:
            bonus = 10.0
        
        total_reward = detection_reward + functionality_reward + functionality_penalty + bonus
        
        return total_reward


class RLEvasionAgent:
    """Reinforcement Learning agent for learning evasion strategies"""
    
    def __init__(
        self,
        algorithm: str = "PPO",
        device: str = None,
    ):
        self.algorithm = algorithm
        self.device = device or ml_config.device
        
        # Create environment
        self.env = EvasionEnvironment()
        
        # Create RL agent
        if algorithm == "PPO":
            self.agent = PPO(
                "MlpPolicy",
                self.env,
                learning_rate=ml_config.rl_learning_rate,
                n_steps=ml_config.rl_n_steps,
                batch_size=ml_config.rl_batch_size,
                gamma=ml_config.rl_gamma,
                verbose=1,
                device=self.device,
            )
        elif algorithm == "DQN":
            self.agent = DQN(
                "MlpPolicy",
                self.env,
                learning_rate=ml_config.rl_learning_rate,
                batch_size=ml_config.rl_batch_size,
                gamma=ml_config.rl_gamma,
                verbose=1,
                device=self.device,
            )
        else:
            raise ValueError(f"Unsupported RL algorithm: {algorithm}")
        
        logger.info(f"Initialized RL Evasion Agent with {algorithm} on {self.device}")
    
    def train(self, total_timesteps: int = 100000):
        """Train the RL agent"""
        logger.info(f"Training RL agent for {total_timesteps} timesteps...")
        self.agent.learn(total_timesteps=total_timesteps)
        logger.success("RL training completed")
    
    def predict_best_technique(self, payload_state: np.ndarray) -> Tuple[int, str]:
        """
        Predict best evasion technique for given payload state
        Returns: (action_id, technique_name)
        """
        action, _ = self.agent.predict(payload_state, deterministic=True)
        technique = self.env.technique_names[action]
        return action, technique
    
    def evaluate(self, num_episodes: int = 10) -> Dict[str, float]:
        """Evaluate agent performance"""
        total_rewards = []
        final_detection_rates = []
        final_functionalities = []
        
        for _ in range(num_episodes):
            obs = self.env.reset()
            done = False
            episode_reward = 0
            
            while not done:
                action, _ = self.agent.predict(obs, deterministic=True)
                obs, reward, done, info = self.env.step(action)
                episode_reward += reward
            
            total_rewards.append(episode_reward)
            final_detection_rates.append(info['detection_rate'])
            final_functionalities.append(info['functionality'])
        
        metrics = {
            "avg_reward": np.mean(total_rewards),
            "avg_detection_rate": np.mean(final_detection_rates),
            "avg_functionality": np.mean(final_functionalities),
            "success_rate": np.mean([d < 0.3 for d in final_detection_rates]),
        }
        
        logger.info(f"Evaluation metrics: {metrics}")
        return metrics
    
    def save(self, path: str):
        """Save trained agent"""
        self.agent.save(path)
        logger.info(f"Saved RL agent to {path}")
    
    def load(self, path: str):
        """Load trained agent"""
        if self.algorithm == "PPO":
            self.agent = PPO.load(path, env=self.env, device=self.device)
        elif self.algorithm == "DQN":
            self.agent = DQN.load(path, env=self.env, device=self.device)
        logger.info(f"Loaded RL agent from {path}")
