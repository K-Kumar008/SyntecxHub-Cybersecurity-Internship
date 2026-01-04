# Tcp_PortScanning.py
This project is a TCP Port Scanner developed in Python that scans a target host to identify  the status of TCP ports. It uses socket programming for network communication and  multithreading to improve scanning speed. The scanner reports whether ports are OPEN,  CLOSED, FILTERED, or TIMEOUT, and logs results for future reference.
# TCP Port Scanner

A simple multi-threaded TCP port scanner written in Python.

## Features
- Fast scanning using threads
- Detects OPEN, CLOSED, and FILTERED ports
- Logs results to a file
- Uses only Python standard libraries

## Requirements
- Python 3.x

## Usage

Run the script:
```bash
python port_scanner.py
