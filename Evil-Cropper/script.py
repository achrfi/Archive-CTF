import sys
from PIL import Image
import os

def encrypt_data(data):
    key = bytes([0x41, 0x42, 0x43])
    encrypted = bytearray()
    for i, byte in enumerate(data):
        encrypted.append(byte ^ key[i % len(key)])
    return bytes(encrypted)

def decrypt_data(data):
    return encrypt_data(data)

def crop_image():
    try:
        img = Image.open('original.jpg')
        img = img.convert('RGB')
        width, height = img.size
        
        half_width = width // 2
        left_half = img.crop((0, 0, half_width, height))
        left_half.save('cropped.jpg', 'JPEG', quality=100, subsampling=0)
        
        right_half = img.crop((half_width, 0, width, height))
        right_half.save('temp_right.jpg', 'JPEG', quality=100, subsampling=0)
        
        with open('temp_right.jpg', 'rb') as f:
            right_data = f.read()
        encrypted_data = encrypt_data(right_data)
        with open('encrypted_half.bin', 'wb') as f:
            f.write(encrypted_data)
        
        os.remove('temp_right.jpg')
        print("Image cropped successfully!")

    except Exception as e:
        print(f"Error during cropping: {str(e)}")

def restore_image():
    try:
        left_half = Image.open('cropped.jpg')
        half_width, height = left_half.size
        with open('encrypted_half.bin', 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = decrypt_data(encrypted_data)
        with open('temp_right.jpg', 'wb') as f:
            f.write(decrypted_data)

        right_half = Image.open('temp_right.jpg')
        restored_img = Image.new('RGB', (half_width * 2, height))
        restored_img.paste(left_half, (0, 0))
        restored_img.paste(right_half, (half_width, 0))
        
        restored_img.save('restored.jpg', 'JPEG', quality=100, subsampling=0)
        os.remove('temp_right.jpg')
        print("Image restored successfully!")
        
    except Exception as e:
        print(f"Error during restoration: {str(e)}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 script.py [CROP|RESTORE]")
        return
    
    command = sys.argv[1].upper()
    
    if command == "CROP":
        if not os.path.exists('original.jpg'):
            print("Error: original.jpg not found!")
            return
        crop_image()
    
    elif command == "RESTORE":
        if not os.path.exists('cropped.jpg') or not os.path.exists('encrypted_half.bin'):
            print("Error: Required files (cropped.jpg and/or encrypted_half.bin) not found!")
            return
        restore_image()
    
    else:
        print("Invalid command. Use CROP or RESTORE")

if __name__ == "__main__":
    main()