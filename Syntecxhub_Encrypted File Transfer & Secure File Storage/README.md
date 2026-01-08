# 🔒 Secure File Transfer Project

## 📝 Overview
This project implements a **secure file transfer system** using Python.  
It allows clients to **upload files to a server over a secure TLS channel**, ensuring:

- 🔐 **Encryption:** AES-256-CBC encryption for file content  
- 🛡 **Integrity:** HMAC-SHA256 checks for each chunk  
- 🌐 **Secure channel:** TLS/SSL communication using self-signed certificate  
- 💾 **Encrypted storage:** Files stored encrypted on server disk  

Works with **any file type**, including text files, images, PDFs, and binaries.

---

## 🚀 Features

- 📤 Encrypted file upload  
- 📦 Chunked file transfer for large files  
- 🔒 HMAC verification to ensure data integrity  
- 🌐 TLS-secured communication  
- 💾 Encrypted storage on server  
- 👥 Handles multiple clients sequentially  
- 🖼 Tested with text files and PNG images  

---

## ⚙️ Prerequisites

- Python 3.13+  
- [PyCryptodome](https://pypi.org/project/pycryptodome/) library  

Install PyCryptodome:
```bash
pip install pycryptodome


