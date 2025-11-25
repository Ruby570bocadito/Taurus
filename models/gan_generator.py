"""
ML Malware Generator - GAN Generator Model
Generates obfuscated code variations using Generative Adversarial Networks
"""
import torch
import torch.nn as nn
import torch.optim as optim
from typing import Tuple, Optional
import numpy as np

from config.settings import ml_config
from utils.logger import get_logger

logger = get_logger()


class Generator(nn.Module):
    """GAN Generator - generates obfuscated payload variations"""
    
    def __init__(
        self,
        latent_dim: int = 128,
        hidden_dim: int = 256,
        output_dim: int = 512,
        num_layers: int = 4,
    ):
        super(Generator, self).__init__()
        
        self.latent_dim = latent_dim
        self.hidden_dim = hidden_dim
        self.output_dim = output_dim
        
        # Build generator network
        layers = []
        
        # Input layer
        layers.append(nn.Linear(latent_dim, hidden_dim))
        layers.append(nn.LeakyReLU(0.2))
        layers.append(nn.BatchNorm1d(hidden_dim))
        
        # Hidden layers
        for _ in range(num_layers - 2):
            layers.append(nn.Linear(hidden_dim, hidden_dim))
            layers.append(nn.LeakyReLU(0.2))
            layers.append(nn.BatchNorm1d(hidden_dim))
            layers.append(nn.Dropout(0.3))
        
        # Output layer
        layers.append(nn.Linear(hidden_dim, output_dim))
        layers.append(nn.Tanh())  # Output in [-1, 1]
        
        self.model = nn.Sequential(*layers)
    
    def forward(self, z: torch.Tensor) -> torch.Tensor:
        """Generate payload from latent vector"""
        return self.model(z)
    
    def generate(self, num_samples: int = 1, device: str = "cpu") -> np.ndarray:
        """Generate payload samples"""
        self.eval()
        with torch.no_grad():
            z = torch.randn(num_samples, self.latent_dim).to(device)
            generated = self.forward(z)
            return generated.cpu().numpy()


class Discriminator(nn.Module):
    """GAN Discriminator - distinguishes real from generated payloads"""
    
    def __init__(
        self,
        input_dim: int = 512,
        hidden_dim: int = 256,
        num_layers: int = 4,
    ):
        super(Discriminator, self).__init__()
        
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        
        # Build discriminator network
        layers = []
        
        # Input layer
        layers.append(nn.Linear(input_dim, hidden_dim))
        layers.append(nn.LeakyReLU(0.2))
        layers.append(nn.Dropout(0.3))
        
        # Hidden layers
        for _ in range(num_layers - 2):
            layers.append(nn.Linear(hidden_dim, hidden_dim))
            layers.append(nn.LeakyReLU(0.2))
            layers.append(nn.Dropout(0.3))
        
        # Output layer (real/fake probability)
        layers.append(nn.Linear(hidden_dim, 1))
        layers.append(nn.Sigmoid())
        
        self.model = nn.Sequential(*layers)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Classify payload as real or fake"""
        return self.model(x)


class MalwareGAN:
    """Complete GAN system for malware generation"""
    
    def __init__(
        self,
        latent_dim: int = None,
        hidden_dim: int = None,
        output_dim: int = 512,
        device: str = None,
    ):
        self.latent_dim = latent_dim or ml_config.gan_latent_dim
        self.hidden_dim = hidden_dim or ml_config.gan_hidden_dim
        self.output_dim = output_dim
        self.device = device or ml_config.device
        
        # Initialize generator and discriminator
        self.generator = Generator(
            latent_dim=self.latent_dim,
            hidden_dim=self.hidden_dim,
            output_dim=self.output_dim,
            num_layers=ml_config.gan_num_layers,
        ).to(self.device)
        
        self.discriminator = Discriminator(
            input_dim=self.output_dim,
            hidden_dim=self.hidden_dim,
            num_layers=ml_config.gan_num_layers,
        ).to(self.device)
        
        # Optimizers
        self.g_optimizer = optim.Adam(
            self.generator.parameters(),
            lr=ml_config.gan_learning_rate,
            betas=(ml_config.gan_beta1, ml_config.gan_beta2),
        )
        
        self.d_optimizer = optim.Adam(
            self.discriminator.parameters(),
            lr=ml_config.gan_learning_rate,
            betas=(ml_config.gan_beta1, ml_config.gan_beta2),
        )
        
        # Loss function
        self.criterion = nn.BCELoss()
        
        logger.info(f"Initialized MalwareGAN on device: {self.device}")
    
    def train_step(
        self,
        real_data: torch.Tensor,
    ) -> Tuple[float, float]:
        """
        Single training step
        Returns: (discriminator_loss, generator_loss)
        """
        batch_size = real_data.size(0)
        real_data = real_data.to(self.device)
        
        # Labels
        real_labels = torch.ones(batch_size, 1).to(self.device)
        fake_labels = torch.zeros(batch_size, 1).to(self.device)
        
        # =================== Train Discriminator ===================
        self.d_optimizer.zero_grad()
        
        # Real data
        real_output = self.discriminator(real_data)
        d_loss_real = self.criterion(real_output, real_labels)
        
        # Fake data
        z = torch.randn(batch_size, self.latent_dim).to(self.device)
        fake_data = self.generator(z)
        fake_output = self.discriminator(fake_data.detach())
        d_loss_fake = self.criterion(fake_output, fake_labels)
        
        # Total discriminator loss
        d_loss = d_loss_real + d_loss_fake
        d_loss.backward()
        self.d_optimizer.step()
        
        # =================== Train Generator ===================
        self.g_optimizer.zero_grad()
        
        # Generate fake data and try to fool discriminator
        z = torch.randn(batch_size, self.latent_dim).to(self.device)
        fake_data = self.generator(z)
        fake_output = self.discriminator(fake_data)
        
        # Generator wants discriminator to think fake data is real
        g_loss = self.criterion(fake_output, real_labels)
        g_loss.backward()
        self.g_optimizer.step()
        
        return d_loss.item(), g_loss.item()
    
    def generate_payloads(
        self,
        num_samples: int = 1,
        temperature: float = 1.0,
    ) -> np.ndarray:
        """
        Generate payload samples
        temperature: controls randomness (higher = more random)
        """
        self.generator.eval()
        with torch.no_grad():
            z = torch.randn(num_samples, self.latent_dim).to(self.device) * temperature
            generated = self.generator(z)
            return generated.cpu().numpy()
    
    def save_models(self, path: str):
        """Save generator and discriminator"""
        torch.save({
            'generator_state_dict': self.generator.state_dict(),
            'discriminator_state_dict': self.discriminator.state_dict(),
            'g_optimizer_state_dict': self.g_optimizer.state_dict(),
            'd_optimizer_state_dict': self.d_optimizer.state_dict(),
        }, path)
        logger.info(f"Saved GAN models to {path}")
    
    def load_models(self, path: str):
        """Load generator and discriminator"""
        checkpoint = torch.load(path, map_location=self.device)
        self.generator.load_state_dict(checkpoint['generator_state_dict'])
        self.discriminator.load_state_dict(checkpoint['discriminator_state_dict'])
        self.g_optimizer.load_state_dict(checkpoint['g_optimizer_state_dict'])
        self.d_optimizer.load_state_dict(checkpoint['d_optimizer_state_dict'])
        logger.info(f"Loaded GAN models from {path}")
