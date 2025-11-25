"""
ML Malware Generator - Main ML Engine
Coordinates all ML models (GAN, RL, Transformer)
"""
import torch
import numpy as np
from typing import Dict, Optional, Tuple, List
from pathlib import Path

from models.gan_generator import MalwareGAN
from models.rl_evasion import RLEvasionAgent
from models.transformer_shellcode import ShellcodeTransformer
from config.settings import ml_config, MODELS_DIR
from utils.logger import get_logger

logger = get_logger()


class MLEngine:
    """Main ML engine coordinating all models"""
    
    def __init__(self, device: str = None):
        self.device = device or ml_config.device
        
        # Initialize models
        logger.info("Initializing ML Engine...")
        
        self.gan = MalwareGAN(device=self.device)
        self.rl_agent = RLEvasionAgent(
            algorithm=ml_config.rl_algorithm,
            device=self.device,
        )
        self.transformer = ShellcodeTransformer(device=self.device)
        
        logger.success("ML Engine initialized successfully")
    
    def generate_obfuscated_payload(
        self,
        base_payload: np.ndarray,
        obfuscation_level: int = 3,
        use_rl: bool = True,
    ) -> Tuple[np.ndarray, Dict]:
        """
        Generate obfuscated payload using GAN and optionally RL
        
        Args:
            base_payload: Original payload features
            obfuscation_level: Level of obfuscation (1-5)
            use_rl: Whether to use RL agent for optimization
        
        Returns:
            (obfuscated_payload, metadata)
        """
        logger.info(f"Generating obfuscated payload (level={obfuscation_level}, RL={use_rl})")
        
        metadata = {
            "obfuscation_level": obfuscation_level,
            "techniques_applied": [],
        }
        
        # Step 1: Use GAN to generate variations
        temperature = 0.5 + (obfuscation_level * 0.1)
        gan_output = self.gan.generate_payloads(
            num_samples=1,
            temperature=temperature,
        )[0]
        
        metadata["techniques_applied"].append("gan_obfuscation")
        
        # Step 2: Optionally use RL to optimize evasion
        if use_rl:
            # Create state from GAN output
            detection_rate = 0.8  # Simulated initial detection
            functionality = 1.0
            
            state = np.concatenate([
                gan_output,
                [detection_rate],
                [functionality],
            ]).astype(np.float32)
            
            # Get best evasion technique from RL agent
            action, technique = self.rl_agent.predict_best_technique(state)
            
            metadata["techniques_applied"].append(f"rl_{technique}")
            metadata["rl_action"] = int(action)
            metadata["rl_technique"] = technique
            
            logger.info(f"RL agent selected technique: {technique}")
        
        return gan_output, metadata
    
    def generate_shellcode(
        self,
        architecture: str = "x86",
        payload_type: str = "reverse_shell",
        polymorphic: bool = False,
        num_variants: int = 1,
    ) -> List[str]:
        """
        Generate shellcode using Transformer model
        
        Args:
            architecture: Target architecture (x86, x64)
            payload_type: Type of payload
            polymorphic: Generate polymorphic variants
            num_variants: Number of variants if polymorphic
        
        Returns:
            List of generated shellcode
        """
        logger.info(f"Generating {architecture} {payload_type} shellcode (polymorphic={polymorphic})")
        
        if polymorphic:
            # Generate base shellcode first
            base = self.transformer.generate_x86_shellcode(
                architecture=architecture,
                payload_type=payload_type,
                max_length=256,
            )
            
            # Generate polymorphic variants
            variants = self.transformer.generate_polymorphic_shellcode(
                base_shellcode=base,
                num_variants=num_variants,
                max_length=256,
            )
            
            logger.success(f"Generated {len(variants)} polymorphic shellcode variants")
            return variants
        else:
            # Generate single shellcode
            shellcode = self.transformer.generate_x86_shellcode(
                architecture=architecture,
                payload_type=payload_type,
                max_length=256,
            )
            
            logger.success("Generated shellcode")
            return [shellcode]
    
    def optimize_evasion(
        self,
        payload_features: np.ndarray,
        target_detection_rate: float = 0.3,
        max_iterations: int = 10,
    ) -> Tuple[np.ndarray, List[str]]:
        """
        Iteratively optimize payload for evasion using RL
        
        Args:
            payload_features: Current payload features
            target_detection_rate: Target detection rate to achieve
            max_iterations: Maximum optimization iterations
        
        Returns:
            (optimized_payload, techniques_applied)
        """
        logger.info(f"Optimizing evasion (target={target_detection_rate:.1%})")
        
        current_payload = payload_features
        current_detection = 1.0
        techniques_applied = []
        
        for iteration in range(max_iterations):
            if current_detection <= target_detection_rate:
                logger.success(f"Target detection rate achieved in {iteration} iterations")
                break
            
            # Create state
            state = np.concatenate([
                current_payload,
                [current_detection],
                [1.0],  # functionality
            ]).astype(np.float32)
            
            # Get best action from RL agent
            action, technique = self.rl_agent.predict_best_technique(state)
            techniques_applied.append(technique)
            
            # Simulate applying technique (in real scenario, would actually apply)
            # For now, just update detection rate based on technique effectiveness
            detection_reduction = {
                "xor_encoding": 0.15,
                "rot_encoding": 0.10,
                "base64_encoding": 0.08,
                "aes_encryption": 0.25,
                "code_obfuscation": 0.30,
                "api_hashing": 0.20,
                "string_encryption": 0.18,
                "polymorphic_encoding": 0.35,
                "multi_layer_encoding": 0.28,
                "no_action": 0.00,
            }.get(technique, 0.10)
            
            current_detection = max(0.0, current_detection - detection_reduction)
            
            logger.info(f"Iteration {iteration + 1}: Applied {technique}, detection={current_detection:.1%}")
        
        return current_payload, techniques_applied
    
    def train_all_models(
        self,
        gan_data: Optional[torch.Tensor] = None,
        rl_timesteps: int = 50000,
        transformer_data: Optional[List[str]] = None,
    ):
        """
        Train all ML models
        
        Args:
            gan_data: Training data for GAN
            rl_timesteps: Training timesteps for RL
            transformer_data: Training data for Transformer
        """
        logger.info("Starting training for all models...")
        
        # Train GAN
        if gan_data is not None:
            logger.info("Training GAN...")
            epochs = ml_config.epochs
            
            for epoch in range(epochs):
                d_loss, g_loss = self.gan.train_step(gan_data)
                
                if epoch % 10 == 0:
                    logger.info(f"GAN Epoch {epoch}/{epochs} - D_loss: {d_loss:.4f}, G_loss: {g_loss:.4f}")
            
            logger.success("GAN training completed")
        
        # Train RL agent
        logger.info("Training RL agent...")
        self.rl_agent.train(total_timesteps=rl_timesteps)
        
        # Fine-tune Transformer
        if transformer_data is not None:
            logger.info("Fine-tuning Transformer...")
            self.transformer.fine_tune(
                training_data=transformer_data,
                epochs=3,
            )
        
        logger.success("All models trained successfully")
    
    def save_all_models(self, checkpoint_name: str = "latest"):
        """Save all trained models"""
        checkpoint_dir = MODELS_DIR / "checkpoints" / checkpoint_name
        checkpoint_dir.mkdir(parents=True, exist_ok=True)
        
        # Save GAN
        self.gan.save_models(str(checkpoint_dir / "gan.pth"))
        
        # Save RL agent
        self.rl_agent.save(str(checkpoint_dir / "rl_agent"))
        
        # Save Transformer
        self.transformer.save_model(f"checkpoints/{checkpoint_name}/transformer")
        
        logger.success(f"All models saved to {checkpoint_dir}")
    
    def load_all_models(self, checkpoint_name: str = "latest"):
        """Load all trained models"""
        checkpoint_dir = MODELS_DIR / "checkpoints" / checkpoint_name
        
        # Load GAN
        self.gan.load_models(str(checkpoint_dir / "gan.pth"))
        
        # Load RL agent
        self.rl_agent.load(str(checkpoint_dir / "rl_agent.zip"))
        
        # Load Transformer
        self.transformer.load_model(f"checkpoints/{checkpoint_name}/transformer")
        
        logger.success(f"All models loaded from {checkpoint_dir}")
    
    def get_model_info(self) -> Dict:
        """Get information about loaded models"""
        return {
            "gan": {
                "latent_dim": self.gan.latent_dim,
                "hidden_dim": self.gan.hidden_dim,
                "output_dim": self.gan.output_dim,
                "device": self.gan.device,
            },
            "rl": {
                "algorithm": self.rl_agent.algorithm,
                "device": self.rl_agent.device,
                "num_techniques": self.rl_agent.env.num_techniques,
            },
            "transformer": {
                "model_name": self.transformer.model_name,
                "max_length": self.transformer.max_length,
                "device": self.transformer.device,
            },
        }


# Global ML engine instance
_ml_engine = None


def get_ml_engine() -> MLEngine:
    """Get global ML engine instance"""
    global _ml_engine
    if _ml_engine is None:
        _ml_engine = MLEngine()
    return _ml_engine
