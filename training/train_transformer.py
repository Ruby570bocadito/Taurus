"""
ML Malware Generator - Transformer Training Pipeline
"""
from models.transformer_shellcode import ShellcodeTransformer
from data.collector import get_data_collector, get_data_preprocessor
from config.settings import ml_config
from utils.logger import get_logger
import time

logger = get_logger()


class TransformerTrainer:
    """Training pipeline for Transformer model"""
    
    def __init__(
        self,
        model_name: str = None,
        device: str = None,
    ):
        self.model_name = model_name or ml_config.transformer_model
        self.device = device or ml_config.device
        
        # Create transformer
        self.transformer = ShellcodeTransformer(
            model_name=self.model_name,
            device=self.device,
        )
    
    def prepare_training_data(self) -> list:
        """Prepare shellcode training data"""
        logger.info("Preparing shellcode training data...")
        
        # Load collected data
        collector = get_data_collector()
        preprocessor = get_data_preprocessor()
        
        # Collect shellcode samples
        collector.collect_all_datasets()
        shellcode_data = collector.load_dataset("shellcode_samples")
        
        # Extract shellcode strings
        shellcode_strings = []
        for sample in shellcode_data:
            if "description" in sample:
                # Create training example from description
                shellcode_strings.append(f"; {sample['description']}\n{sample.get('shellcode', '')}")
        
        # Add synthetic examples
        synthetic_examples = [
            "; x86 reverse shell\nsection .text\nglobal _start\n_start:\n  xor eax, eax\n  push eax",
            "; x64 execve /bin/sh\nsection .text\nglobal _start\n_start:\n  xor rax, rax\n  push rax",
            "; Windows MessageBox\nsection .text\nglobal _start\n_start:\n  xor ecx, ecx\n  push ecx",
        ]
        shellcode_strings.extend(synthetic_examples)
        
        # Preprocess
        preprocessed = preprocessor.prepare_transformer_training_data(shellcode_strings)
        
        logger.success(f"Prepared {len(preprocessed)} shellcode samples")
        return preprocessed
    
    def train(
        self,
        training_data: list = None,
        epochs: int = 3,
        learning_rate: float = None,
        batch_size: int = 8,
    ):
        """
        Fine-tune transformer on shellcode data
        
        Args:
            training_data: List of shellcode strings
            epochs: Number of training epochs
            learning_rate: Learning rate
            batch_size: Batch size
        """
        lr = learning_rate or ml_config.transformer_learning_rate
        
        # Prepare data if not provided
        if training_data is None:
            training_data = self.prepare_training_data()
        
        if not training_data:
            logger.warning("No training data available, skipping training")
            return
        
        logger.info(f"Starting Transformer fine-tuning: {epochs} epochs")
        logger.info(f"Training samples: {len(training_data)}, Batch size: {batch_size}")
        
        start_time = time.time()
        
        # Fine-tune
        self.transformer.fine_tune(
            training_data=training_data,
            epochs=epochs,
            learning_rate=lr,
            batch_size=batch_size,
        )
        
        total_time = time.time() - start_time
        logger.success(f"Transformer training completed in {total_time:.2f}s")
        
        # Save model
        self.transformer.save_model("transformer_finetuned")
    
    def generate_samples(self, num_samples: int = 5):
        """Generate shellcode samples"""
        logger.info(f"Generating {num_samples} shellcode samples...")
        
        samples = []
        for i in range(num_samples):
            shellcode = self.transformer.generate_x86_shellcode(
                architecture="x86",
                payload_type="reverse_shell",
                max_length=256,
            )
            samples.append(shellcode)
            logger.info(f"Sample {i+1}:\n{shellcode[:100]}...")
        
        return samples


def main():
    """Main training function"""
    logger.info("=== Transformer Training Pipeline ===")
    
    # Create trainer
    trainer = TransformerTrainer()
    
    # Train
    trainer.train(
        epochs=3,
        batch_size=4,
    )
    
    # Generate samples
    samples = trainer.generate_samples(num_samples=3)
    
    logger.success("Training pipeline complete!")


if __name__ == "__main__":
    main()
