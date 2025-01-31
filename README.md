# PeeBangTa - Secure File Hider

PeeBangTa is a powerful file-hiding tool designed to securely **encrypt, hide, extract, and remove files** within other files. It provides both **a command-line interface (CLI)** and **a graphical user interface (GUI)** to ensure ease of use and flexibility.

This tool is ideal for users who need to **secure sensitive information** or **embed confidential files within other files** to prevent unauthorized access.

## 🚀 Features

### 🔒 **File Encryption & Decryption**
- Uses **AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)** for strong encryption.
- Protects sensitive files with a **password-based key derivation function (Argon2).**
- Prevents unauthorized decryption and detects data tampering.

### 📂 **File Hiding Mechanism**
- Allows **hiding a file inside another file** (e.g., images, videos, or any other container files).
- Maintains the integrity of the host file so it remains usable.
- Uses a **marker-based system** to embed and extract hidden data.

### 🔍 **File Extraction & Recovery**
- Extracts and restores **hidden encrypted files** from the container file.
- Supports **raw extraction mode**, allowing users to retrieve encrypted files separately.
- Password-protected decryption ensures **only authorized users** can recover hidden files.

### ❌ **Hidden File Removal**
- Removes hidden files from a container without affecting the original content.
- Leaves no traces of the previously hidden data.

### 🖥️ **Graphical User Interface (GUI)**
- User-friendly interface built with **Tkinter**.
- Provides a seamless experience for non-technical users.
- Includes **buttons for hiding, extracting, and removing files** in just a few clicks.

### 💻 **Command-Line Interface (CLI)**
- Lightweight and efficient **terminal-based operation**.
- Supports quick batch operations and scripting.

---

## 🛠️ Installation

Before running the tool, ensure you have **Python 3.6+** installed.

### Install Required Dependencies
```bash
pip install -r requirements.txt
```

Alternatively, if dependencies are missing, the script will attempt to install them automatically.

---

## 📜 Usage

### **CLI Version (`Bang.py`)**
Run the script from the terminal:
```bash
python Bang.py
```

#### **Available Options**
1. **Hide a file in another file** – Securely store a file within another file.
2. **Extract a hidden file** – Retrieve a file from a container file (requires a password).
3. **Extract a hidden file (raw mode)** – Extract an encrypted file without decryption.
4. **Remove a hidden file** – Permanently erase a hidden file from the container.
5. **Exit** – Close the program.

### **GUI Version (`BangGUI.py`)**
To launch the graphical interface:
```bash
python BangGUI.py
```

#### **Graphical Interface Features**
- **Select a container file** to hide another file inside.
- **Enter a password** to securely encrypt and embed the file.
- **Extract files** with password authentication.
- **Remove hidden files** with a simple button click.

---

## 🔐 Security Notes
- Encryption uses **AES-256-GCM**, one of the strongest symmetric encryption algorithms.
- Passwords are hashed using **Argon2**, a highly secure key derivation function.
- Encrypted data is appended to the container file in a **marker-based format** (`FILE_HIDDEN_START` and `FILE_HIDDEN_END`).
- If the wrong password is used, the decryption will fail and prevent unauthorized access.

---

## 🖥️ Example Usage

### **Hiding a File (CLI)**
```bash
python Bang.py
```
- Select an **existing file** as the container.
- Choose the **file to hide** inside it.
- Enter a **secure password** for encryption.
- The file is now **hidden inside the container**.

### **Extracting a Hidden File**
```bash
python Bang.py
```
- Select the **container file**.
- Enter the **correct password**.
- The **original file** is restored.

---

## 💡 Why Use PeeBangTa?
✅ **Easy to Use** – Works with both CLI and GUI.  
✅ **Strong Security** – AES-256 encryption with password protection.  
✅ **Stealthy** – Files remain hidden within another file.  
✅ **No Special Tools Needed** – Can be used on any system with Python installed.  

---

## 📜 License
This project is licensed under the Bell Software License (BSL). See the LICENSE file for details.

---

## 👨‍💻 Author
Created by **Bell (github.com/Bell-O)**.  

If you like this project, give it a ⭐ on GitHub!
