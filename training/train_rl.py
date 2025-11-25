"""
ML Malware Generator - RL Training Pipeline
"""
from models.rl_evasion import RLEvasionAgent
from config.settings import ml_config
from utils.logger import get_logger
import time

logger = get_logger()


class RLTrainer:
    """Training pipeline for RL agent"""
    
    def __init__(
        self,
        algorithm: str = None,
        device: str = None,
    ):
        self.algorithm = algorithm or ml_config.rl_algorithm
        self.device = device or ml_config.device
        
        # Create agent
        self.agent = RLEvasionAgent(
            algorithm=self.algorithm,
            device=self.device,
        )
    
    def train(
        self,
        total_timesteps: int = 100000,
        eval_freq: int = 10000,
        save_freq: int = 25000,
    ):
        """
        Train RL agent
        
        Args:
            total_timesteps: Total training timesteps
            eval_freq: Evaluate every N timesteps
            save_freq: Save checkpoint every N timesteps
        """
        logger.info(f"Starting RL training: {total_timesteps} timesteps")
        logger.info(f"Algorithm: {self.algorithm}, Device: {self.device}")
        
        start_time = time.time()
        
        # Train agent
        self.agent.train(total_timesteps=total_timesteps)
        
        total_time = time.time() - start_time
        logger.success(f"RL training completed in {total_time:.2f}s")
        
        # Final evaluation
        logger.info("Performing final evaluation...")
        metrics = self.agent.evaluate(num_episodes=20)
        
        logger.info("=== Final Metrics ===")
        logger.info(f"Average Reward: {metrics['avg_reward']:.2f}")
        logger.info(f"Average Detection Rate: {metrics['avg_detection_rate']:.1%}")
        logger.info(f"Average Functionality: {metrics['avg_functionality']:.1%}")
        logger.info(f"Success Rate: {metrics['success_rate']:.1%}")
        
        # Save final model
        self.agent.save("rl_agent_final")
        
        return metrics
    
    def evaluate(self, num_episodes: int = 10):
        """Evaluate trained agent"""
        logger.info(f"Evaluating agent ({num_episodes} episodes)...")
        metrics = self.agent.evaluate(num_episodes=num_episodes)
        
        logger.info("=== Evaluation Results ===")
        logger.info(f"Average Reward: {metrics['avg_reward']:.2f}")
        logger.info(f"Average Detection Rate: {metrics['avg_detection_rate']:.1%}")
        logger.info(f"Average Functionality: {metrics['avg_functionality']:.1%}")
        logger.info(f"Success Rate: {metrics['success_rate']:.1%}")
        
        return metrics


def main():
    """Main training function"""
    logger.info("=== RL Training Pipeline ===")
    
    # Create trainer
    trainer = RLTrainer(algorithm="PPO")
    
    # Train
    metrics = trainer.train(
        total_timesteps=50000,
        eval_freq=10000,
    )
    
    logger.success("Training pipeline complete!")


if __name__ == "__main__":
    main()
