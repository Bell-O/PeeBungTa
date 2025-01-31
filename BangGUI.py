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
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter import ttk

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

        messagebox.showinfo("Success", f"File '{file_path}' has been encrypted as '{encrypted_path}'")
    except Exception as e:
        messagebox.showerror("Error", f"Error during encryption: {e}")

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

        messagebox.showinfo("Success", f"File '{file_path}' has been decrypted as '{original_file_path}'")
    except InvalidTag:
        messagebox.showerror("Error", "Authentication failed: Invalid password or corrupted file.")
    except Exception as e:
        messagebox.showerror("Error", f"Error during decryption: {e}")

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
        messagebox.showinfo("Success", f"File '{encrypted_file}' has been hidden inside '{container_file}'")
    except Exception as e:
        messagebox.showerror("Error", f"Error hiding file: {e}")

def extract_file_from_file(container_file, password=None, raw_extraction=False):
    try:
        with open(container_file, 'rb') as f:
            data = f.read()

        start_marker = data.find(b'FILE_HIDDEN_START')
        end_marker = data.find(b'FILE_HIDDEN_END')

        if start_marker == -1 or end_marker == -1:
            messagebox.showerror("Error", "No hidden file found in the container.")
            return

        hidden_data = data[start_marker + len(b'FILE_HIDDEN_START'):end_marker]
        split_index = hidden_data.find(b'\n')
        if split_index == -1:
            messagebox.showerror("Error", "Malformed hidden data.")
            return

        original_name = hidden_data[:split_index].decode()
        encrypted_data = hidden_data[split_index + 1:]

        if raw_extraction:
            raw_file = f"raw_{original_name}.hee"
            with open(raw_file, 'wb') as raw:
                raw.write(encrypted_data)
            messagebox.showinfo("Success", f"Encrypted file extracted as '{raw_file}'")
        else:
            temp_file = 'temp_hidden.hee'

            with open(temp_file, 'wb') as temp:
                temp.write(encrypted_data)

            decrypt_file(temp_file, password)
            os.rename('temp_hidden', original_name)
            os.remove(temp_file)

    except Exception as e:
        messagebox.showerror("Error", f"Error extracting file: {e}")

def remove_hidden_file(container_file):
    try:
        with open(container_file, 'rb') as f:
            data = f.read()

        start_marker = data.find(b'FILE_HIDDEN_START')
        end_marker = data.find(b'FILE_HIDDEN_END')

        if start_marker == -1 or end_marker == -1:
            messagebox.showerror("Error", "No hidden file found in the container.")
            return

        cleaned_data = data[:start_marker] + data[end_marker + len(b'FILE_HIDDEN_END'):]

        with open(container_file, 'wb') as f:
            f.write(cleaned_data)

        messagebox.showinfo("Success", f"Hidden file removed from '{container_file}'")
    except Exception as e:
        messagebox.showerror("Error", f"Error removing hidden file: {e}")

def list_files():
    current_dir = os.getcwd()
    files = [f for f in os.listdir(current_dir) if os.path.isfile(os.path.join(current_dir, f))]
    
    if not files:
        messagebox.showerror("Error", "No files found in the current directory.")
        return None

    return files

def display_figlet():
    fig = pyfiglet.Figlet(font="slant")
    return fig.renderText("PeeBangTa")

def get_password():
    password = simpledialog.askstring("Password", "Enter a password:", show='*')
    confirm_password = simpledialog.askstring("Password", "Confirm password:", show='*')
    if password == confirm_password:
        return password
    else:
        messagebox.showerror("Error", "Passwords do not match. Please try again.")
        return None

def hide_file_menu():
    container_file = filedialog.askopenfilename(title="Select Container File")
    secret_file = filedialog.askopenfilename(title="Select Secret File")
    if container_file and secret_file:
        password = get_password()
        if password:
            hide_file_in_file(container_file, secret_file, password)

def extract_file_menu():
    container_file = filedialog.askopenfilename(title="Select Container File")
    if container_file:
        password = simpledialog.askstring("Password", "Enter the password to extract the file:", show='*')
        if password:
            extract_file_from_file(container_file, password)

def extract_raw_file_menu():
    container_file = filedialog.askopenfilename(title="Select Container File")
    if container_file:
        extract_file_from_file(container_file, raw_extraction=True)

def remove_hidden_file_menu():
    container_file = filedialog.askopenfilename(title="Select Container File")
    if container_file:
        remove_hidden_file(container_file)

ghost_art = r"""
         .-"      "-.
        /            \
       |,  .-.  .-.  ,|
       | )(_o/  \o_)( |
       |/     /\     \|
       (_     ^^     _)
        \__|IIIIII|__/
         | \IIIIII/ |
         \          /
          `--------`
"""

def main():
    root = tk.Tk()
    root.title("PeeBangTa - Secure File Hider")
    root.geometry("800x700")  
    root.configure(bg="white")

    PRIMARY_COLOR = "#5162FF"
    SECONDARY_COLOR = "#6D7AFF"
    TEXT_COLOR = "#0C0D2A"
    BG_COLOR = "#FFFFFF"

    style = ttk.Style()
    style.theme_use("clam")
    
    style.configure("TButton",
                    font=("Helvetica", 11, "bold"),
                    borderwidth=0,
                    relief="flat",
                    foreground=BG_COLOR,
                    background=PRIMARY_COLOR,
                    padding=12)
    
    style.map("TButton",
              background=[("active", SECONDARY_COLOR), ("disabled", "#E0E0E0")],
              foreground=[("disabled", "#A0A0A0")])
    
    style.configure("TLabel", background=BG_COLOR, foreground=TEXT_COLOR)
    style.configure("TFrame", background=BG_COLOR)
    style.configure("Monospace.TLabel", font=("Courier New", 8))

    header_frame = ttk.Frame(root, style="TFrame")
    header_frame.pack(pady=10, fill=tk.X)

    ghost_label = ttk.Label(header_frame, 
                           text=ghost_art,
                           style="Monospace.TLabel",
                           justify=tk.CENTER)
    ghost_label.pack(pady=10)

    title_label = ttk.Label(header_frame,
                           text="PeeBangTa",
                           font=("Helvetica", 24, "bold"),
                           style="TLabel")
    title_label.pack()

    subtitle_label = ttk.Label(header_frame,
                              text="Secure File Hiding Solution",
                              font=("Helvetica", 12),
                              style="TLabel")
    subtitle_label.pack(pady=5)

    main_frame = ttk.Frame(root, style="TFrame")
    main_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)

    buttons = [
        ("Hide a file in another file", hide_file_menu),
        ("Extract a hidden file", extract_file_menu),
        ("Extract a hidden file (raw)", extract_raw_file_menu),
        ("Remove a hidden file", remove_hidden_file_menu),
        ("Exit", root.quit)
    ]

    for text, command in buttons:
        btn = ttk.Button(main_frame,
                        text=text,
                        command=command,
                        style="TButton")
        btn.pack(fill=tk.X, pady=8)

    footer_frame = ttk.Frame(root, style="TFrame")
    footer_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10)
    
    credit_label = ttk.Label(footer_frame,
                            text="Based on Secure File Hiding by Bell (github.com/Bell-O)",
                            font=("Helvetica", 8),
                            style="TLabel")
    credit_label.pack()

    def on_enter(e):
        e.widget["background"] = SECONDARY_COLOR

    def on_leave(e):
        e.widget["background"] = PRIMARY_COLOR

    for child in main_frame.winfo_children():
        if isinstance(child, ttk.Button):
            child.bind("<Enter>", on_enter)
            child.bind("<Leave>", on_leave)

    root.mainloop()

if __name__ == "__main__":
    main()
