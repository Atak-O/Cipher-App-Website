# CipherLab Web Edition

CipherLab is a Flask-based cryptography toolkit for encrypting, decrypting, and analyzing classical ciphers through a modern cybersecurity-themed web interface.

## Features

- Caesar Cipher
- Vigenere Cipher
- Atbash Cipher
- ROT13
- Morse Code
- Base64
- Binary / ASCII Converter
- XOR Cipher
- Rail Fence Cipher
- Affine Cipher
- CipherLab AI Assistant with heuristic cipher detection
- Copy to clipboard
- TXT result download
- Character counters
- Session-based operation history
- Toast notifications and loading indicators

## Project Structure

```text
project/
├── app.py
├── cipher_methods.py
├── ai_assistant.py
├── requirements.txt
├── templates/
│   └── index.html
├── static/
│   ├── style.css
│   └── script.js
└── assets/
```

## Setup

```bash
python3 -m pip install -r requirements.txt
```

## Run

```bash
python3 app.py
```



For production, set a strong `SECRET_KEY` environment variable before running the app.


