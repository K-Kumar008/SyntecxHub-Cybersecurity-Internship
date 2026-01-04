# Syntecxhub_Encrypted_Chat_Application
The Encrypted Chat Application is a client–server-based chat system that ensures secure communication  between multiple clients using AES (Advanced Encryption Standard) encryption. The application uses TCP  socket programming to establish reliable communication and encrypts all messages before transmission to  protect confidentiality.
# 🔐 Secure Chat Application

A **multi-client encrypted chat application** written in Python using **sockets** and **AES encryption (CBC mode)**. This project demonstrates **end-to-end encryption** with a **pre-shared key**, allowing multiple clients to connect to a server and communicate securely.  

This project is intended for **learning purposes** and to understand concepts like **network programming**, **encryption**, and **threading** in Python.

---

## Table of Contents

- [Features](#features)  
- [Requirements](#requirements)  
- [Installation](#installation)  
- [How It Works](#how-it-works)  
  - [Server](#server)  
  - [Client](#client)  
- [Setup and Usage](#setup-and-usage)  
- [Configuration](#configuration)  
- [Security Notes](#security-notes)  
- [Future Improvements](#future-improvements)  
- [Example Output](#example-output)  
- [Folder Structure](#folder-structure)  
- [License](#license)  

---

## Features

- **End-to-End Encryption**: Uses AES-CBC mode with SHA256-derived keys.  
- **Random IV per Message**: Ensures that repeated messages are encrypted differently.  
- **Multi-Client Support**: Messages from one client are broadcast to all other clients.  
- **Message Logging**: All messages are logged on the server for auditing purposes.  
- **Cross-Platform**: Works on Windows, Linux, and macOS with Python 3.x.  
- **Threaded Architecture**: Handles multiple clients simultaneously using Python threads.  

---

## Requirements

- Python 3.8 or higher  
- [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/) for cryptography  

Install dependencies using pip:


## Installation



- Install dependencies:
- pip install -r requirements.txt



```bash
pip install pycryptodome
