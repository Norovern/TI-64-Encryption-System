# TI-64 Alloy Encryption System
# Ver. 1.3 Beta - Public Release Beta
# Apache 2.0 License

# Check for required modules
try:
    import os
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, padding
    import base64
    import stepic
    from PIL import Image
except ImportError as e:
    missing_module = str(e).split("'")[1]
    print(f"Error: The required module '{missing_module}' is not installed.")
    print("Please install all required modules with the following commands in your main Python powershell:")
    print("  pip install cryptography")
    print("  pip install stegano")
    print("  pip install pillow")
    exit(1)

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
import base64
import stepic
from PIL import Image

# AES encryption function
def aes_encrypt(text, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_text = padder.update(text.encode()) + padder.finalize()
    encrypted_text = encryptor.update(padded_text) + encryptor.finalize()

    return base64.b64encode(salt + iv + encrypted_text).decode()

# AES decryption function
def aes_decrypt(encrypted_text, password):
    encrypted_data = base64.b64decode(encrypted_text.encode())

    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    encrypted_message = encrypted_data[32:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_text = decryptor.update(encrypted_message) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    text = unpadder.update(padded_text) + unpadder.finalize()

    return text.decode()

# Embed text in image with error handling for file save issues
def embed_text_in_image(image_path, text, output_path):
    if not os.path.isfile(image_path):
        print(f"Error: File '{image_path}' does not exist.")
        return

    img = Image.open(image_path)
    if img.format != 'PNG':
        img = img.convert('RGB')
    
    encoded_img = stepic.encode(img, text.encode())
    encoded_img.save(output_path)

# Extract text from image with error handling
def extract_text_from_image(image_path):
    if not os.path.isfile(image_path):
        print(f"Error: The file '{image_path}' does not exist.")
        return None

    img = Image.open(image_path)
    try:
        extracted_data = stepic.decode(img)
        if isinstance(extracted_data, bytes):  # Check if the data is bytes
            return extracted_data.decode()
        else:
            return extracted_data
    except Exception as e:
        print("Failed to extract text from image:", e)
        return None

def get_downloads_folder():
    """Returns the user's Downloads folder path."""
    return os.path.join(os.path.expanduser("~"), "Downloads")

def encrypt_archive():
    while True:
        print("\nEncryption - Page 1")
        filename = input("Enter image file name: ").strip().strip('"')
        image_path = os.path.join(get_downloads_folder(), f"{filename}.png")

        # Check if the image file exists
        if not os.path.isfile(image_path):
            print(f"Error: File '{image_path}' does not exist.")
            continue
        
        # Convert image to PNG if it's not already
        img = Image.open(image_path)
        if img.format != 'PNG':
            png_image_path = os.path.join(get_downloads_folder(), f"{filename}.png")
            img.convert('RGB').save(png_image_path, format='PNG')
            print(f"Image converted to PNG and saved as '{png_image_path}'")
            image_path = png_image_path  # Update the path to the new PNG file
        else:
            image_path = os.path.join(get_downloads_folder(), filename)

        password = input("Enter encryption key: ")

        # Ask if the user wants to load text from a file
        load_from_file = input("Would you like to type or load text from a file? (L/T): ").strip().lower()
        text = ""

        if load_from_file == 'L':
            text_filename = input("Enter the file name: ").strip().strip('"')
            text_file_path = os.path.join(get_downloads_folder(), f"{text_filename}.txt")

            # Check if the text file exists
            if not os.path.isfile(text_file_path):
                print(f"Error: File '{text_file_path}' does not exist.")
                continue
            
            # Read the contents of the text file
            with open(text_file_path, 'r') as text_file:
                text = text_file.read()
        else:
            text = input("Enter text to encrypt: ")

        encrypted_text = aes_encrypt(text, password)

        print("\nEncryption - Page 2")
        output_filename = input("Enter a file name for the encrypted archive: ").strip().strip('"')
        output_path = os.path.join(get_downloads_folder(), f"{output_filename}.png")

        embed_text_in_image(image_path, encrypted_text, output_path)
        print(f"Archive successfully saved at {output_path}")
        break  # Exit loop after successful encryption

def decrypt_archive():
    while True:
        print("\nDecryption - Page 1")
        filename = input("Enter archive file name (with file type): ").strip().strip('"')
        image_path = os.path.join(get_downloads_folder(), filename)

        # Check if the image file exists
        if not os.path.isfile(image_path):
            print(f"Error: The file '{image_path}' does not exist. Please try again.")
            continue

        password = input("Enter decryption key: ")

        encrypted_text = extract_text_from_image(image_path)
        if encrypted_text is None:
            print("Extraction failed. Check the file and try again.")
            continue  # Continue to prompt for the file again

        try:
            decrypted_text = aes_decrypt(encrypted_text, password)
        except Exception as e:
            print("Decryption failed:", e)
            continue  # Continue to prompt for the file again

        choice = input("Would you like to export the decrypted text or display it? (E/D): ").strip().lower()
        
        if choice == 'e':
            output_filename = input("Enter the name for the file: ").strip().strip('"')
            output_path = os.path.join(get_downloads_folder(), f"{output_filename}.txt")
            with open(output_path, 'w') as file:
                file.write(decrypted_text)
            print(f"Decrypted text saved to {output_path}")
        elif choice == 'd':
            print("")
            print(decrypted_text)        
            print("")
        else:
            print("Invalid. Select 'E' to export or 'D' to display.")
        break  # Exit loop after successful decryption

def return_to_menu():
    input("\nPress Enter for Menu.")

cyan = "\033[36m"
reset = "\033[0m"

def main():
    print("   *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *")
    ascii_art = r"""
      _____   ___            __     _  _          _      _   _                     _____                                         _     _                     ____                  _                        
     |_   _| |_ _|          / /_   | || |        / \    | | | |   ___    _   _    | ____|  _ __     ___   _ __   _   _   _ __   | |_  (_)   ___    _ __     / ___|   _   _   ___  | |_    ___   _ __ ___    
       | |    | |   _____  | '_ \  | || |_      / _ \   | | | |  / _ \  | | | |   |  _|   | '_ \   / __| | '__| | | | | | '_ \  | __| | |  / _ \  | '_ \    \___ \  | | | | / __| | __|  / _ \ | '_ ` _ \   
       | |    | |  |_____| | (_) | |__   _|    / ___ \  | | | | | (_) | | |_| |   | |___  | | | | | (__  | |    | |_| | | |_) | | |_  | | | (_) | | | | |    ___) | | |_| | \__ \ | |_  |  __/ | | | | | |  
       |_|   |___|          \___/     |_|     /_/   \_\ |_| |_|  \___/   \__, |   |_____| |_| |_|  \___| |_|     \__, | | .__/   \__| |_|  \___/  |_| |_|   |____/   \__, | |___/  \__|  \___| |_| |_| |_|  
                                                                         |___/                                   |___/  |_|                                          |___/                                  
    """
    print(cyan + ascii_art + reset)
    print("   *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *     *")
    print("\033[36m                                                                                Ver. 1.3 Beta - Public Release Beta\033[0m")
    print("")

    try:
        while True:
            print("")
            print("\n                                                                                             Main Menu:")
            print("")                    
            print("")
            print("                                                                                          1. Encrypt Archive")
            print("                                                                                          2. Decrypt Archive")
            print("                                                                                          3. How to Use this Program")
            print("                                                                                          4. Licensing & ToS")
            print("                                                                                          5. Changelog")
            print("                                                                                          6. Exit Program")

            choice = input("                                                                                     Enter page: ").strip()
            if choice == '1':
                encrypt_archive()
                return_to_menu()
            elif choice == '2':
                decrypt_archive()
                return_to_menu()
            elif choice == '3':
                print("")
                print("")
                print("This software is specifically designed to act as a method for long-term storage for long pieces of text, theoretically up to 64 gigabytes due to the AES encryption method, barring the base image's pixel count.")
                print("The program is called 'Alloy' due to the layered double-encryption of steganography and AES-256. It is designed to appear inconspicuous and remain incredibly secure.")
                print("To use this software, you operate it as if you were using Powershell or Command Prompt.")
                print("To encrypt, insert an image to use as a base for the steganography, a custom encryption key to use as a password, and the text or text file you wish to encrypt.")
                print("To decrypt, it is much the same process. Insert the archive file image, and then the encryption key.")
                print("This software was created originally with the sole purpose of password management. However, it likely has much more potential than simply managing logins.")
                print("")
                print("")
                return_to_menu()
            elif choice == '4':
                print("")
                print("")
                print("Licensed under Apache License 2.0")
                print("Redistribution and changes are allowed with proper credit to the creator.")
                print("See below for more information.")
                print("https://www.apache.org/licenses/LICENSE-2.0.html")
                print("")
                print("Created by Norovern Robert Elijah")
                print("https://twitter.com/norovern_bro")
                return_to_menu()
            elif choice == '5':
                print("")
                print("")
                print("Version 1.0 Alpha;")
                print("  -Encryptor & decryptor loop working")
                print("  -Added ability to export decrypted text into .txt file")
                print("")
                print("Version 1.1 Alpha;")
                print("  -Refined a better user interface for ease of use")
                print("")
                print("Version 1.2 Beta;")
                print("  -Added ability to import txt file for input")
                print("  -Tweaked user interface slightly")
                print("  -Closed-door testing introduced")
                print("  -Added failsafes to prevent looping back to menu due to misinput")
                print("  -Added failsafe to ensure required addon modules are installed")
                print("  -Added check to allow user to pause and read certain pages before going back to menu.")
                print("")
                print("Version 1.3 Beta;")
                print("  -Made Beta available for the public to test")
                print("")
                return_to_menu()
            elif choice == '6':
                print("")
                print("")
                print("")
                print("Shutting Down...")
                print("")
                print("")
                print("")
                break
            else:
                print("Invalid input.")
                return_to_menu()
    except Exception as e:
        print("If you're seeing this, shit's fucked.:", str(e))
        print("Just close the program and save yourself the processing power.")

if __name__ == "__main__":
    main()
