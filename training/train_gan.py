"""
ML Malware Generator - GAN Training Pipeline
"""
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
from pathlib import Path
import time

from models.gan_generator import MalwareGAN
from data.collector import get_data_collector, get_data_preprocessor
from config.settings import ml_config, MODELS_DIR
from utils.logger import get_logger

logger = get_logger()


class GANTrainer:
    """Training pipeline for GAN model"""
    
    def __init__(
        self,
        gan: MalwareGAN = None,
        device: str = None,
    ):
        self.device = device or ml_config.device
        self.gan = gan or MalwareGAN(device=self.device)
        
        # Training metrics
        self.d_losses = []
        self.g_losses = []
        self.epochs_trained = 0
    
    def prepare_training_data(
        self,
        use_collected_data: bool = True,
    ) -> torch.Tensor:
        """Prepare training data for GAN"""
        logger.info("Preparing training data...")
        
        if use_collected_data:
            # Load collected data
            collector = get_data_collector()
            preprocessor = get_data_preprocessor()
            
            # Collect datasets
            collector.collect_all_datasets()
            
            # Load metasploit payloads
            metasploit_data = collector.load_dataset("metasploit_payloads")
            
            # Create synthetic training data from templates
            payload_samples = []
            for template in metasploit_data:
                # Generate synthetic payload bytes (simplified)
                synthetic = np.random.randint(0, 256, size=512, dtype=np.uint8).tobytes()
                payload_samples.append(synthetic)
            
            # Prepare for GAN training
            training_data = preprocessor.prepare_gan_training_data(
                payload_samples,
                feature_dim=512,
            )
        else:
            # Generate random training data for testing
            logger.warning("Using random training data (for testing only)")
            training_data = np.random.randn(1000, 512).astype(np.float32)
            training_data = np.clip(training_data, -1, 1)
        
        # Convert to PyTorch tensor
        training_tensor = torch.from_numpy(training_data).float()
        
        logger.success(f"Training data prepared: {training_tensor.shape}")
        return training_tensor
    
    def train(
        self,
        training_data: torch.Tensor = None,
        epochs: int = None,
        batch_size: int = None,
        save_interval: int = 10,
        checkpoint_name: str = "gan_training",
    ):
        """
        Train GAN model
        
        Args:
            training_data: Training data tensor
            epochs: Number of training epochs
            batch_size: Batch size
            save_interval: Save checkpoint every N epochs
            checkpoint_name: Name for checkpoints
        """
        epochs = epochs or ml_config.epochs
        batch_size = batch_size or ml_config.batch_size
        
        # Prepare data if not provided
        if training_data is None:
            training_data = self.prepare_training_data(use_collected_data=False)
        
        # Create DataLoader
        dataset = TensorDataset(training_data)
        dataloader = DataLoader(
            dataset,
            batch_size=batch_size,
            shuffle=True,
            drop_last=True,
        )
        
        logger.info(f"Starting GAN training: {epochs} epochs, batch size {batch_size}")
        logger.info(f"Training samples: {len(training_data)}, Batches per epoch: {len(dataloader)}")
        
        start_time = time.time()
        
        for epoch in range(epochs):
            epoch_d_loss = 0.0
            epoch_g_loss = 0.0
            num_batches = 0
            
            for batch_idx, (real_data,) in enumerate(dataloader):
                # Train step
                d_loss, g_loss = self.gan.train_step(real_data)
                
                epoch_d_loss += d_loss
                epoch_g_loss += g_loss
                num_batches += 1
            
            # Calculate average losses
            avg_d_loss = epoch_d_loss / num_batches
            avg_g_loss = epoch_g_loss / num_batches
            
            self.d_losses.append(avg_d_loss)
            self.g_losses.append(avg_g_loss)
            self.epochs_trained += 1
            
            # Log progress
            if epoch % 10 == 0 or epoch == epochs - 1:
                elapsed = time.time() - start_time
                logger.log_training_epoch(
                    model_type="GAN",
                    epoch=epoch + 1,
                    loss=avg_g_loss,
                    metrics={
                        "d_loss": avg_d_loss,
                        "g_loss": avg_g_loss,
                        "elapsed_time": elapsed,
                    }
                )
            
            # Save checkpoint
            if (epoch + 1) % save_interval == 0:
                self.save_checkpoint(checkpoint_name, epoch + 1)
        
        total_time = time.time() - start_time
        logger.success(f"GAN training completed in {total_time:.2f}s")
        
        # Save final model
        self.save_checkpoint(f"{checkpoint_name}_final", epochs)
    
    def save_checkpoint(self, name: str, epoch: int):
        """Save training checkpoint"""
        checkpoint_dir = MODELS_DIR / "checkpoints" / name
        checkpoint_dir.mkdir(parents=True, exist_ok=True)
        
        checkpoint_path = checkpoint_dir / f"epoch_{epoch}.pth"
        self.gan.save_models(str(checkpoint_path))
        
        # Save training metrics
        metrics_path = checkpoint_dir / f"metrics_epoch_{epoch}.json"
        import json
        with open(metrics_path, 'w') as f:
            json.dump({
                "epoch": epoch,
                "d_losses": self.d_losses,
                "g_losses": self.g_losses,
            }, f, indent=2)
        
        logger.info(f"Checkpoint saved: {checkpoint_path}")
    
    def load_checkpoint(self, checkpoint_path: str):
        """Load training checkpoint"""
        self.gan.load_models(checkpoint_path)
        logger.info(f"Loaded checkpoint: {checkpoint_path}")
    
    def generate_samples(self, num_samples: int = 10) -> np.ndarray:
        """Generate sample payloads using trained GAN"""
        logger.info(f"Generating {num_samples} samples...")
        samples = self.gan.generate_payloads(num_samples=num_samples)
        logger.success(f"Generated {len(samples)} samples")
        return samples


def main():
    """Main training function"""
    logger.info("=== GAN Training Pipeline ===")
    
    # Create trainer
    trainer = GANTrainer()
    
    # Train
    trainer.train(
        epochs=100,
        batch_size=32,
        save_interval=10,
    )
    
    # Generate samples
    samples = trainer.generate_samples(num_samples=5)
    logger.info(f"Sample shapes: {[s.shape for s in samples]}")
    
    logger.success("Training pipeline complete!")


if __name__ == "__main__":
    main()
