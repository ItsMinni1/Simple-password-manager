# Password Manager (Naive Solution)
A lightweight, secure, and local-first Command Line Interface (CLI) application to safely store, manage, and retrieve your credentials. This utility ensures your passwords remain entirely on your machine, eliminating reliance on third-party cloud hosting.

# Features
Secure Local Storage: Stores your credentials inside flat JSON files locally on your device.

Fernet Symmetric Encryption: Utilizes the cryptography library's Fernet implementation (AES-128 in CBC mode with HMAC-SHA256) to encrypt and decrypt stored passwords.

One-Way Master Password Hashing: Secures application access by storing a cryptographic SHA-256 hash of your master credentials.

Automatic Clipboard Copying: Automatically copies retrieved passwords directly to your clipboard using pyperclip for quick usage.

Hidden Password Inputs: Leverages getpass to ensure sensitive inputs are hidden in the terminal while typing.

Witty Interface: Features responsive, character-rich terminal messaging to guide you along the way.

# Prerequisites & Dependencies
To run this application, you must have Python 3.x installed. The project also relies on two external libraries for cryptographic actions and clipboard integration.

Install the required modules via pip:

Bash
pip install cryptography pyperclip

# Data Structure & Architecture
The application automatically provisions three local files in its root directory upon setup:

userData.json: Holds your registered username and the SHA-256 hashed master password used to authenticate your login sessions.

encryptionKey.key: Holds your unique generated Fernet key. Keep this file secure! If this key is lost, your saved passwords cannot be decrypted.

passwords.json: Holds the array of your saved entries, linking the website name to its strongly encrypted ciphertext string.

# How to Use
1. Initialization & Registration
Run the script using your terminal:

Bash
python main.py
(Replace main.py with whatever you named your script file).

On your very first run, select Option 1 to register your master account with a unique username and password. The system only allows one master profile registry to secure the vault locally.

2. Standard Workflow
Once registered, select Option 2 to login. Successful authentication unlocks the core credentials menu:

Plaintext
1. Add Password        -> Input a website and its password to encrypt and save it.
2. Get Password        -> Retrieve an absolute plain text value and auto-copy it to your clipboard.
3. View saved websites -> Display a clean roster of every domain currently configured in your vault.
4. Quit                -> Safely jump back out to the main landing view.

# Important Security Disclaimers
[!WARNING]
Educational & Local Use Context: This project serves as an excellent demonstration of basic symmetric encryption and local state persistence. However, note the following constraints for production environments:

Key & Vault Proximity: Storing the encryptionKey.key right alongside passwords.json in the exact same workspace means that anyone with physical or remote access to your project folder can decrypt your vault. For true security, the key file should ideally be moved to an isolated, secure directory or environment variable.

SHA-256 for Passwords: Plain SHA-256 functions incredibly fast, making it susceptible to modern GPU brute-force attacks. For enterprise-grade master key derivation, memory-hard algorithms like Argon2id or PBKDF2 are recommended.

# Screenshots

<img width="590" height="144" alt="image" src="https://github.com/user-attachments/assets/b125e644-d0a0-42ee-b49e-8717048aa9df" />

<img width="590" height="153" alt="image" src="https://github.com/user-attachments/assets/1301e4c1-7f8a-43e5-b343-c2e783e0065c" />

<img width="590" height="381" alt="image" src="https://github.com/user-attachments/assets/e0800b5a-98b5-40cb-9c77-b4e480ba9b52" />

<img width="522" height="204" alt="image" src="https://github.com/user-attachments/assets/0fa24cf1-c15d-4d09-b748-4873df299d84" />

