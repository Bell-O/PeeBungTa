import os
import subprocess
import sys
import getpass
import pyfiglet
import platform
from colorama import Fore, Style, init
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from argon2.low_level import hash_secret_raw, Type
from cryptography.exceptions import InvalidTag

init(autoreset=True)

def install_and_import(package, module_name=None):
    try:
        module_name = module_name or package
        __import__(module_name)
    except ImportError:
        print(f"Installing missing package: {package}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"Package {package} installed successfully.")
        __import__(module_name)

install_and_import("pyfiglet")
install_and_import("colorama")
install_and_import("cryptography")
install_and_import("argon2-cffi", module_name="argon2")

def derive_key(password: str, salt: bytes, key_size: int = 32) -> bytes:
    if key_size not in [16, 24, 32]:
        raise ValueError("Invalid key size. AES supports 16, 24, or 32 bytes.")
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=2,
        memory_cost=2**16,
        parallelism=2,
        hash_len=key_size,
        type=Type.ID,
    )

def encrypt_file(file_path: str, password: str):
    try:
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = derive_key(password, salt, key_size=32)

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        encrypted_path = file_path + '.hee'
        with open(encrypted_path, 'wb') as f:
            f.write(salt + nonce + encryptor.tag + ciphertext)

        print(Fore.GREEN + f"[+] File '{file_path}' has been encrypted as '{encrypted_path}'")
    except Exception as e:
        print(Fore.RED + f"[!] Error during encryption: {e}")

def decrypt_file(file_path: str, password: str):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        salt = data[:16]
        nonce = data[16:28]
        tag = data[28:44]
        ciphertext = data[44:]
        key = derive_key(password, salt, key_size=32)

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        original_file_path = file_path.replace('.hee', '')
        with open(original_file_path, 'wb') as f:
            f.write(plaintext)

        print(Fore.GREEN + f"[+] File '{file_path}' has been decrypted as '{original_file_path}'")
    except InvalidTag:
        print(Fore.RED + "[!] Authentication failed: Invalid password or corrupted file.")
    except Exception as e:
        print(Fore.RED + f"[!] Error during decryption: {e}")

def hide_file_in_file(container_file, secret_file, password):
    try:
        encrypt_file(secret_file, password)
        encrypted_file = secret_file + '.hee'

        with open(container_file, 'ab') as container, open(encrypted_file, 'rb') as encrypted:
            original_name = os.path.basename(secret_file).encode() + b'\n'
            container.write(b'FILE_HIDDEN_START')
            container.write(original_name)
            container.write(encrypted.read())
            container.write(b'FILE_HIDDEN_END')

        os.remove(encrypted_file)
        print(Fore.GREEN + f"[+] File '{encrypted_file}' has been hidden inside '{container_file}'")
    except Exception as e:
        print(Fore.RED + f"[!] Error hiding file: {e}")

def extract_file_from_file(container_file, password=None, raw_extraction=False):
    try:
        with open(container_file, 'rb') as f:
            data = f.read()

        start_marker = data.find(b'FILE_HIDDEN_START')
        end_marker = data.find(b'FILE_HIDDEN_END')

        if start_marker == -1 or end_marker == -1:
            print(Fore.RED + "[!] No hidden file found in the container.")
            return

        hidden_data = data[start_marker + len(b'FILE_HIDDEN_START'):end_marker]
        split_index = hidden_data.find(b'\n')
        if split_index == -1:
            print(Fore.RED + "[!] Malformed hidden data.")
            return

        original_name = hidden_data[:split_index].decode()
        encrypted_data = hidden_data[split_index + 1:]

        if raw_extraction:
            raw_file = f"raw_{original_name}.hee"
            with open(raw_file, 'wb') as raw:
                raw.write(encrypted_data)
            print(Fore.GREEN + f"[+] Encrypted file extracted as '{raw_file}'")
        else:
            temp_file = 'temp_hidden.hee'

            with open(temp_file, 'wb') as temp:
                temp.write(encrypted_data)

            decrypt_file(temp_file, password)
            os.rename('temp_hidden', original_name)
            os.remove(temp_file)

    except Exception as e:
        print(Fore.RED + f"[!] Error extracting file: {e}")

def remove_hidden_file(container_file):
    try:
        with open(container_file, 'rb') as f:
            data = f.read()

        start_marker = data.find(b'FILE_HIDDEN_START')
        end_marker = data.find(b'FILE_HIDDEN_END')

        if start_marker == -1 or end_marker == -1:
            print(Fore.RED + "[!] No hidden file found in the container.")
            return

        cleaned_data = data[:start_marker] + data[end_marker + len(b'FILE_HIDDEN_END'):]

        with open(container_file, 'wb') as f:
            f.write(cleaned_data)

        print(Fore.GREEN + f"[+] Hidden file removed from '{container_file}'")
    except Exception as e:
        print(Fore.RED + f"[!] Error removing hidden file: {e}")

def list_files():
    current_dir = os.getcwd()
    files = [f for f in os.listdir(current_dir) if os.path.isfile(os.path.join(current_dir, f))]
    
    if not files:
        print(Fore.RED + "[!] No files found in the current directory.")
        return None

    print(Fore.CYAN + "\nAvailable files:")
    for idx, file in enumerate(files):
        print(Fore.CYAN + f"  {idx + 1}. {file}")
    return files

def display_figlet():
    fig = pyfiglet.Figlet(font="slant")
    print(Fore.RED + fig.renderText("FileHider"))
    print(Fore.YELLOW + "Secure File Hiding by Bell (github.com/Bell-O)")

def select_file(files, action):
    try:
        file_index = int(input(Fore.YELLOW + f"\n[?] Select a file number to {action}: ")) - 1
        if 0 <= file_index < len(files):
            print(Fore.GREEN + f"[+] Selected file to {action}: {files[file_index]}")
            return files[file_index]
        else:
            print(Fore.RED + "[!] Invalid file number. Please try again.")
            return None
    except ValueError:
        print(Fore.RED + "[!] Please enter a valid number.")
        return None

def display_title():
    title = pyfiglet.figlet_format("PeeBungTa", font="slant")
    title_text = Fore.RED + title + Fore.YELLOW + "Secure File Hiding by Bell (github.com/Bell-O)\n"
    
    ghost_art = (
        Fore.CYAN + """
         .-"      "-.
        /            \\
       |,  .-.  .-.  ,|
       | )(_o/  \o_)( |
       |/     /\     \|
       (_     ^^     _)
        \__|IIIIII|__/
         | \IIIIII/ |
         \          /
          `--------`
        """
    )

    print(ghost_art)
    print(title_text)
    
def clear():
    if platform.system() == "Windows":
        subprocess.Popen("cls", shell=True).communicate()
    else:  # Linux and Mac
        print("\033c", end="")

def get_password():
    while True:
        password = getpass.getpass("Enter a password: ")
        confirm_password = getpass.getpass("Confirm password: ")
        if password == confirm_password:
            return password
        else:
            print(Fore.RED + "[!] Passwords do not match. Please try again.")

def hide_file_menu():
    files = list_files()
    if files:
        container_file = select_file(files, "hide in")
        secret_file = select_file(files, "hide")
        if container_file and secret_file:
            password = get_password()
            hide_file_in_file(container_file, secret_file, password)

def extract_file_menu():
    files = list_files()
    if files:
        container_file = select_file(files, "extract from")
        if container_file:
            password = getpass.getpass("Enter the password to extract the file: ")
            extract_file_from_file(container_file, password)

def extract_raw_file_menu():
    files = list_files()
    if files:
        container_file = select_file(files, "extract from")
        if container_file:
            extract_file_from_file(container_file, raw_extraction=True)

def remove_hidden_file_menu():
    files = list_files()
    if files:
        container_file = select_file(files, "remove hidden file from")
        if container_file:
            remove_hidden_file(container_file)

def main():
    clear()
    display_title()
    
    while True:
        print(Fore.MAGENTA + "\nMenu:")
        print(Fore.CYAN + "  1. Hide a file in another file")
        print(Fore.CYAN + "  2. Extract a hidden file")
        print(Fore.CYAN + "  3. Extract a hidden file (raw)")
        print(Fore.CYAN + "  4. Remove a hidden file")
        print(Fore.CYAN + "  5. Exit")
        choice = input(Fore.YELLOW + "\nSelect an option: ").strip()

        if choice == '1':
            hide_file_menu()
        elif choice == '2':
            extract_file_menu()
        elif choice == '3':
            extract_raw_file_menu()
        elif choice == '4':
            remove_hidden_file_menu()
        elif choice == '5':
            print(Fore.GREEN + "\n[+] Thank you for using FileHider!")
            break
        else:
            print(Fore.RED + "\n[!] Invalid option. Please try again.")

if __name__ == "__main__":
    main()