"""
Simple Image Encryption Tool using Pixel Manipulation
Supports encryption and decryption using various pixel manipulation techniques
"""

from PIL import Image
import numpy as np
import os
import argparse
from typing import Tuple


class ImageEncryptionTool:
    """
    A class to encrypt and decrypt images using pixel manipulation techniques.
    """
    
    def __init__(self, key: int = 42):
        """
        Initialize the encryption tool with a key.
        
        Args:
            key: Integer key for encryption/decryption (default: 42)
        """
        self.key = key
    
    def encrypt_xor(self, image_path: str, output_path: str) -> None:
        """
        Encrypt an image using XOR operation with the key.
        
        Args:
            image_path: Path to the input image
            output_path: Path to save the encrypted image
        """
        try:
            # Load image and convert to RGB if necessary
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Convert image to numpy array
            img_array = np.array(img, dtype=np.uint8)
            
            # Apply XOR encryption to each pixel
            encrypted_array = img_array ^ (self.key % 256)
            
            # Convert back to image and save
            encrypted_img = Image.fromarray(encrypted_array)
            encrypted_img.save(output_path)
            print(f"✓ Image encrypted using XOR and saved to: {output_path}")
        
        except FileNotFoundError:
            print(f"✗ Error: Image file not found at {image_path}")
        except Exception as e:
            print(f"✗ Encryption failed: {str(e)}")
    
    def decrypt_xor(self, image_path: str, output_path: str) -> None:
        """
        Decrypt an XOR-encrypted image using the same key.
        
        Args:
            image_path: Path to the encrypted image
            output_path: Path to save the decrypted image
        """
        # XOR decryption is the same as encryption
        self.encrypt_xor(image_path, output_path)
        print(f"✓ Image decrypted using XOR and saved to: {output_path}")
    
    def encrypt_shift(self, image_path: str, output_path: str, shift: int = None) -> None:
        """
        Encrypt an image by shifting pixel values.
        
        Args:
            image_path: Path to the input image
            output_path: Path to save the encrypted image
            shift: Shift amount (uses key if not provided)
        """
        if shift is None:
            shift = self.key % 256
        
        try:
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            img_array = np.array(img, dtype=np.uint16)  # Use uint16 to handle overflow
            
            # Apply shift to pixel values
            encrypted_array = (img_array + shift) % 256
            encrypted_array = encrypted_array.astype(np.uint8)
            
            encrypted_img = Image.fromarray(encrypted_array)
            encrypted_img.save(output_path)
            print(f"✓ Image encrypted using SHIFT (shift={shift}) and saved to: {output_path}")
        
        except FileNotFoundError:
            print(f"✗ Error: Image file not found at {image_path}")
        except Exception as e:
            print(f"✗ Encryption failed: {str(e)}")
    
    def decrypt_shift(self, image_path: str, output_path: str, shift: int = None) -> None:
        """
        Decrypt a shift-encrypted image.
        
        Args:
            image_path: Path to the encrypted image
            output_path: Path to save the decrypted image
            shift: Shift amount used during encryption
        """
        if shift is None:
            shift = self.key % 256
        
        try:
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            img_array = np.array(img, dtype=np.uint16)
            
            # Reverse the shift
            decrypted_array = (img_array - shift) % 256
            decrypted_array = decrypted_array.astype(np.uint8)
            
            decrypted_img = Image.fromarray(decrypted_array)
            decrypted_img.save(output_path)
            print(f"✓ Image decrypted using SHIFT (shift={shift}) and saved to: {output_path}")
        
        except FileNotFoundError:
            print(f"✗ Error: Image file not found at {image_path}")
        except Exception as e:
            print(f"✗ Decryption failed: {str(e)}")
    
    def encrypt_swap(self, image_path: str, output_path: str) -> None:
        """
        Encrypt an image by swapping pixel channels and shuffling rows.
        
        Args:
            image_path: Path to the input image
            output_path: Path to save the encrypted image
        """
        try:
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            img_array = np.array(img, dtype=np.uint8)
            height, width, channels = img_array.shape
            
            # Swap color channels (R, G, B) -> (B, G, R)
            encrypted_array = img_array[:, :, ::-1].copy()
            
            # Shuffle rows based on key
            row_indices = np.arange(height)
            np.random.seed(self.key)
            np.random.shuffle(row_indices)
            encrypted_array = encrypted_array[row_indices]
            
            encrypted_img = Image.fromarray(encrypted_array)
            encrypted_img.save(output_path)
            print(f"✓ Image encrypted using SWAP and saved to: {output_path}")
        
        except FileNotFoundError:
            print(f"✗ Error: Image file not found at {image_path}")
        except Exception as e:
            print(f"✗ Encryption failed: {str(e)}")
    
    def decrypt_swap(self, image_path: str, output_path: str) -> None:
        """
        Decrypt a swap-encrypted image.
        
        Args:
            image_path: Path to the encrypted image
            output_path: Path to save the decrypted image
        """
        try:
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            img_array = np.array(img, dtype=np.uint8)
            height, width, channels = img_array.shape
            
            # Reverse the row shuffle
            row_indices = np.arange(height)
            np.random.seed(self.key)
            np.random.shuffle(row_indices)
            reverse_indices = np.argsort(row_indices)
            decrypted_array = img_array[reverse_indices]
            
            # Reverse the channel swap
            decrypted_array = decrypted_array[:, :, ::-1].copy()
            
            decrypted_img = Image.fromarray(decrypted_array)
            decrypted_img.save(output_path)
            print(f"✓ Image decrypted using SWAP and saved to: {output_path}")
        
        except FileNotFoundError:
            print(f"✗ Error: Image file not found at {image_path}")
        except Exception as e:
            print(f"✗ Decryption failed: {str(e)}")
    
    def encrypt_multiply(self, image_path: str, output_path: str, multiplier: int = None) -> None:
        """
        Encrypt an image by multiplying pixel values.
        
        Args:
            image_path: Path to the input image
            output_path: Path to save the encrypted image
            multiplier: Multiplier value (uses key if not provided)
        """
        if multiplier is None:
            multiplier = (self.key % 10) + 2  # Ensure multiplier is between 2 and 11
        
        try:
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            img_array = np.array(img, dtype=np.uint16)
            
            # Multiply pixel values and clip to valid range
            encrypted_array = (img_array * multiplier) % 256
            encrypted_array = encrypted_array.astype(np.uint8)
            
            encrypted_img = Image.fromarray(encrypted_array)
            encrypted_img.save(output_path)
            print(f"✓ Image encrypted using MULTIPLY (multiplier={multiplier}) and saved to: {output_path}")
        
        except FileNotFoundError:
            print(f"✗ Error: Image file not found at {image_path}")
        except Exception as e:
            print(f"✗ Encryption failed: {str(e)}")
    
    def get_image_info(self, image_path: str) -> None:
        """
        Display information about an image.
        
        Args:
            image_path: Path to the image
        """
        try:
            img = Image.open(image_path)
            print(f"\n--- Image Information ---")
            print(f"Filename: {os.path.basename(image_path)}")
            print(f"Size: {img.size[0]} x {img.size[1]} pixels")
            print(f"Mode: {img.mode}")
            print(f"Format: {img.format}")
            print(f"File size: {os.path.getsize(image_path) / 1024:.2f} KB\n")
        
        except FileNotFoundError:
            print(f"✗ Error: Image file not found at {image_path}")
        except Exception as e:
            print(f"✗ Failed to get image info: {str(e)}")


def main():
    """Main function to handle command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Simple Image Encryption Tool using Pixel Manipulation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt with XOR
  python image_encryption_tool.py encrypt -i input.jpg -o encrypted.jpg -m xor -k 42
  
  # Decrypt with XOR
  python image_encryption_tool.py decrypt -i encrypted.jpg -o decrypted.jpg -m xor -k 42
  
  # Encrypt with SHIFT
  python image_encryption_tool.py encrypt -i input.jpg -o encrypted.jpg -m shift -k 100
  
  # Encrypt with SWAP
  python image_encryption_tool.py encrypt -i input.jpg -o encrypted.jpg -m swap -k 42
  
  # View image info
  python image_encryption_tool.py info -i input.jpg
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt an image')
    encrypt_parser.add_argument('-i', '--input', required=True, help='Input image path')
    encrypt_parser.add_argument('-o', '--output', required=True, help='Output image path')
    encrypt_parser.add_argument('-m', '--method', choices=['xor', 'shift', 'swap', 'multiply'],
                                default='xor', help='Encryption method (default: xor)')
    encrypt_parser.add_argument('-k', '--key', type=int, default=42, help='Encryption key (default: 42)')
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt an image')
    decrypt_parser.add_argument('-i', '--input', required=True, help='Input image path')
    decrypt_parser.add_argument('-o', '--output', required=True, help='Output image path')
    decrypt_parser.add_argument('-m', '--method', choices=['xor', 'shift', 'swap', 'multiply'],
                                default='xor', help='Decryption method (default: xor)')
    decrypt_parser.add_argument('-k', '--key', type=int, default=42, help='Decryption key (default: 42)')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Display image information')
    info_parser.add_argument('-i', '--input', required=True, help='Input image path')
    info_parser.add_argument('-k', '--key', type=int, default=42, help='Encryption key (default: 42)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize encryption tool
    tool = ImageEncryptionTool(key=args.key)
    
    if args.command == 'encrypt':
        print(f"\nEncrypting image with {args.method.upper()} method...")
        if args.method == 'xor':
            tool.encrypt_xor(args.input, args.output)
        elif args.method == 'shift':
            tool.encrypt_shift(args.input, args.output)
        elif args.method == 'swap':
            tool.encrypt_swap(args.input, args.output)
        elif args.method == 'multiply':
            tool.encrypt_multiply(args.input, args.output)
    
    elif args.command == 'decrypt':
        print(f"\nDecrypting image with {args.method.upper()} method...")
        if args.method == 'xor':
            tool.decrypt_xor(args.input, args.output)
        elif args.method == 'shift':
            tool.decrypt_shift(args.input, args.output)
        elif args.method == 'swap':
            tool.decrypt_swap(args.input, args.output)
        elif args.method == 'multiply':
            print("✗ Note: Multiply method may result in lossy decryption due to modulo operation")
    
    elif args.command == 'info':
        tool.get_image_info(args.input)


if __name__ == '__main__':
    main()
