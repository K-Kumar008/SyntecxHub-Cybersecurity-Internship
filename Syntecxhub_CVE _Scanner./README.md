# Vulnerability / CVE Scanner

![GitHub last commit](https://img.shields.io/github/last-commit/yourusername/yourrepo) ![GitHub license](https://img.shields.io/github/license/yourusername/yourrepo)

---

## Project Overview

The **Vulnerability / CVE Scanner** is a lightweight cybersecurity tool that scans target hosts to detect running services and checks them against known vulnerabilities (CVEs) using the **NVD (National Vulnerability Database) API**.  

This tool is intended for **educational purposes and authorized security testing only**. It helps in learning vulnerability assessment, responsible disclosure, and CVSS-based risk classification.

---

## Features

- DNS resolution of target IP or domain  
- Service and version detection using **Nmap**  
- Banner grabbing and parsing service information  
- Automated CVE lookup via NVD API  
- Severity classification: LOW, MEDIUM, HIGH, CRITICAL  
- Generates a structured, tabulated vulnerability report  

---

## Installation

1. Clone the repository:

```bash
'''pip3 install -r requirements.txt
'''sudo apt install nmap

git clone https://github.com/K-Kumar008/yourrepo.git
cd yourrepo

#Get a free API key from the NVD Developer API
NVD_API_KEY = "PUT_YOUR_API_KEY_HERE"  

