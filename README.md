# FolderGuardian 🔒

FolderGuardian is a Windows desktop tool (C# WPF) for protecting sensitive folders through **AES-256 encryption (keys secured with DPAPI)** and **real-time monitoring**.  
It lets you encrypt or decrypt a folder on demand, while keeping a security log of suspicious file activity such as unexpected modifications, deletions, or creation of `.exe` files.

---

## ✨ Features
- **AES-256 encryption** with keys protected by **DPAPI** (user-specific).
- On-demand **Encrypt / Decrypt** buttons for quick folder protection.
- **Real-time monitoring** of the chosen folder:
  - Detects modifications and deletions.
  - Logs suspicious activity (e.g., unexpected `.exe` creation).
- Security log (`SecurityLog.txt`) saved in the protected folder.
- Simple, minimal WPF UI.

---

## 🔑 Key Management
- Encryption keys are stored securely via DPAPI at:
C:\Users<YourName>\AppData\Roaming\FolderGuardian\protected.key
- Currently, DPAPI is used automatically.  
- **Optional future extension:** support for **password-based encryption** if you prefer user-provided secrets.

---

## 🛠️ Possible Extensions
These are not implemented but straightforward to add:
- **Recursive encryption** (encrypt subfolders as well).
- **Filename scrambling** (obfuscate file names during encryption).
- **Password-based encryption** instead of DPAPI.

---

## 🚀 Usage
1. Clone the repository.
2. Build the project (`FolderGuardian.sln`).
3. Run the WPF application.
4. Choose a sensitive folder path in `MainWindow.xaml.cs` (default: `D:\SensitiveFolder`).
5. Use the UI buttons to:
 - **Encrypt Folder**
 - **Decrypt Folder**
 - **Start Monitoring**
6. Check `SecurityLog.txt` inside the folder for logged events.

---

## ⚠️ Disclaimer
This project is for **educational and personal use only**.  
FolderGuardian uses strong encryption (AES-256 + DPAPI).
However, the monitoring component runs in user mode, not kernel level, so it can be bypassed by a determined attacker.
Treat this as a personal or educational tool, not a full enterprise-grade endpoint protection system.
