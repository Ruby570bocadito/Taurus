"""
Example: Train RL agent for evasion
"""
from models.rl_evasion import RLEvasionAgent
from utils.logger import get_logger

logger = get_logger()


def main():
    """Train RL agent example"""
    
    logger.info("=== Training RL Evasion Agent ===")
    
    # Create agent
    agent = RLEvasionAgent(algorithm="PPO")
    
    # Train
    logger.info("Starting training (this may take a while)...")
    agent.train(total_timesteps=50000)
    
    # Evaluate
    logger.info("\nEvaluating trained agent...")
    metrics = agent.evaluate(num_episodes=10)
    
    logger.info("\n=== Training Results ===")
    logger.info(f"Average Reward: {metrics['avg_reward']:.2f}")
    logger.info(f"Average Detection Rate: {metrics['avg_detection_rate']:.1%}")
    logger.info(f"Average Functionality: {metrics['avg_functionality']:.1%}")
    logger.info(f"Success Rate: {metrics['success_rate']:.1%}")
    
    # Save agent
    logger.info("\nSaving trained agent...")
    agent.save("trained_rl_agent")
    
    logger.success("Training complete!")


if __name__ == "__main__":
    main()
