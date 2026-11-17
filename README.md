# Digital Signature Generation & Verification App

Mini Project for **Cyber Security Lab (7CS4-22)**, B.Tech VII Semester, SKIT Jaipur (Session 2026-27)

**Student:** [Your Name] | **Roll No:** [Roll No] | **Project Code:** [CSL-xxx]

A desktop application (Python + Tkinter) to **sign documents with RSA/ECDSA, verify signatures, and detect any modification of the signed file**.

## Features

- Key pair generation: **RSA-PSS (2048-bit)**, **ECDSA (P-256)** and **Ed25519**, saved as PEM files
- Optional **password protection** for the private key
- Sign any file (PDF, Word, text, image...) using SHA-256 and save a `.sig` file
- Verify a file with its signature and public key: shows **VALID** or **INVALID**
- **Tamper demo**: change one character and see verification fail
- **History log** of every operation (`signature_log.json`)

## How it works

1. **Sign:** the file is hashed with SHA-256 and the hash is signed with the sender's **private key**.
2. **Verify:** the receiver hashes the received file and checks the signature with the sender's **public key**.
3. If the file or signature was changed, verification fails.

This gives **integrity**, **authentication** and **non-repudiation**.

## Requirements

- Python 3.8 or later
- `cryptography` library (Tkinter comes with Python)

```
pip install -r requirements.txt
```

## Run

```
python digital_signature_app.py
```

## Usage

1. **Generate Keys** tab: choose the algorithm, click *Generate Key Pair*.
2. **Sign** tab: select the file and the private key, click *Sign File* (creates `file.sig`).
3. **Verify** tab: select the file, the `.sig` file and the public key, click *Verify Signature*.
4. Edit the file by even one character and verify again to see **INVALID**.

## Screenshots

Add your screenshots to a `screenshots/` folder and link them here:

```
![Key generation](screenshots/01_keygen.png)
![Sign](screenshots/02_sign.png)
![Valid](screenshots/03_valid.png)
![Invalid](screenshots/04_invalid.png)
![Tamper demo](screenshots/05_tamper_demo.png)
![History](screenshots/06_history.png)
```

## Security notes

- **Never share or upload your private key.** This repository ignores `*_private.pem` files on purpose.
- All testing was done on my own computer with dummy files.

## Limitations and future scope

- No certificate authority (X.509) and no trusted timestamp
- No user login
- Future: certificates, timestamping, hardware token support, web version

## Tech stack

Python 3, Tkinter, `cryptography` library
