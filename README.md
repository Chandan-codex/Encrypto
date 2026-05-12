# ENCRYPTO 🛡️
### Professional Hybrid Encryption Suite (ECC + AES-256)

**ENCRYPTO** is a high-performance security application that bridges a low-level C++ cryptographic engine with a modern React web interface. It implements the **ECIES (Elliptic Curve Integrated Encryption Scheme)** using NIST P-256 and AES-256-CBC to provide military-grade security with ultra-compact payloads.

---

## ✨ Features
- **🚀 High Performance**: Core logic implemented in C++ for maximum speed.
- **🔐 Hybrid Cryptography**: Uses ECC for secure key exchange and AES-256 for data encryption.
- **📦 Ultimate Compression**: Optimized payload serialization resulting in ~114 character strings.
- **🌈 Emoji Support**: Native support for UTF-8 and emojis via Base64-safe transport layers.
- **🎨 Premium UI**: Sleek, glassmorphism-based dark mode interface built with React & Vite.
- **🔑 Google Auth**: Integrated Firebase authentication for secure user access.

---

## 🏗️ Architecture
The project follows a **Split Hosting** architecture:
1. **Frontend**: React (Vite) + Tailwind/CSS — Optimized for **Vercel**.
2. **Bridge Server**: Node.js (Express) — Acts as the communication layer between the Web and C++.
3. **Engine**: C++11 (OpenSSL 3.0) — The cryptographic core.

---

## 🛠️ Technical Stack
| Layer | Technology |
| :--- | :--- |
| **Frontend** | React, Vite, Lucide Icons, Firebase |
| **API Bridge** | Node.js, Express, Axios |
| **Security Engine** | C++11, OpenSSL 3.0 |
| **Cryptography** | ECC P-256, AES-256-CBC, SHA-256 |

---

## 🚀 Deployment (Professional Setup)

### 1. Backend (Render / Railway)
The backend requires a Linux environment with OpenSSL. You can use the following Docker-based approach:
- Install `libssl-dev` and `build-essential`.
- Compile the engine: `g++ main.cpp HybridEncryptor.cpp -o Encrypto -lssl -lcrypto`
- Start the bridge: `node api/index.js`

### 2. Frontend (Vercel)
- Connect repository.
- Set Root Directory to `web/`.
- Set API environment variable to point to your deployed backend.

---

## 💻 Local Development
1. **Compile Engine**: `mingw32-make` (Windows) or `make` (Linux).
2. **Start API**: `cd api && npm install && node index.js`
3. **Start Web**: `cd web && npm install && npm run dev`

---

## 🔒 Security Disclaimer
This project implements standard cryptographic primitives. However, security is a holistic property. Always ensure your Private Keys (`.pem`) are kept secure and never committed to version control.
