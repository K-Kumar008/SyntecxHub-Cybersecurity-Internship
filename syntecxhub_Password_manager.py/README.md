# syntecxhub_Password_manager.py
This project is a local password manager developed using Python 3 on Kali Linux.  It allows users to securely store, retrieve, delete, and search credentials while ensuring that  all sensitive information is encrypted before being saved to disk. 
# 🔐 Secure Password Manager (Python)

## 1️⃣ Overview

The Secure Password Manager is a command-line based application written in **Python** that allows users to securely store and manage passwords for multiple websites and applications. All credentials are encrypted using a master password, ensuring that sensitive data is never stored in plain text.

This project is intended for **educational, learning, and personal use**, demonstrating real-world cryptography concepts such as secure key derivation, encryption, and encrypted local storage.

---

## 2️⃣ How It Works (Extended Description)

When the application is run for the first time, the user is prompted to create a **master password**. This password is never stored directly. Instead, the following secure process is used:

- A **random cryptographic salt** is generated.
- The master password is combined with the salt using **PBKDF2-HMAC-SHA256**, a secure key derivation function.
- The derived encryption key is used to encrypt the password vault using **Fernet symmetric encryption (AES-based)**.

All credentials are stored in an encrypted vault file (`vault.enc`). Each time the program is run, the correct master password must be entered to decrypt and access the vault. If the password is incorrect, the vault remains inaccessible.

---

## 3️⃣ Features

- 🔑 Master password authentication
- 🔐 Strong AES-based encryption using Fernet
- 🧂 Secure key derivation using PBKDF2 with salt
- ➕ Add new website or application credentials
- 🔍 Retrieve stored usernames and passwords
- ❌ Delete saved credentials
- 🔎 Search entries by website/app name
- 📋 Display stored entries in a table format
- 💾 Encrypted local storage (no internet or cloud access)

---

## 🛠️ Technologies Used

- Python 3
- `cryptography` library
- PBKDF2-HMAC-SHA256
- Fernet symmetric encryption
- JSON for structured data storage

---

## 📦 Install Required Dependency

Make sure Python 3 is installed, then install the required library:

```bash
pip install cryptography

```bash
git clone https://github.com/your-username/password-manager.git
cd password-manager

Run the application:

python password_manager.py

