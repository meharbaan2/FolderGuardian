# FolderGuardian 🔒

FolderGuardian is a Windows desktop tool (C# WPF) for protecting sensitive folders through **AES-256 encryption (keys secured with DPAPI)** and **real-time monitoring**.  
It lets you encrypt or decrypt a folder on demand, while keeping a security log of suspicious file activity such as unexpected modifications, deletions, renames, or creation of executable/script-like files.

---

## ✨ Features
- **AES-256 encryption** with keys protected by **DPAPI** (user-specific).
- On-demand **Encrypt / Decrypt** buttons for quick folder protection.
- **Recursive encryption and decryption** across nested subfolders.
- **Filename obfuscation** for newly encrypted files.
- **Folder-name obfuscation** for nested folders, including deep folder-only chains.
- **Legacy compatibility** for older `.enc` files created by previous versions of FolderGuardian.
- **Integrity validation** for the current encryption format to detect tampering before decryption.
- **Real-time monitoring** of the chosen folder:
  - Detects modifications, deletions, creations, and renames.
  - Logs suspicious activity such as newly created `.exe`, `.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, or `.scr` files.
- Security log (`SecurityLog.txt`) saved in the protected folder.
- WPF desktop UI with folder picker, progress, and rolling ETA during encrypt/decrypt operations.

---

## 🔑 Key Management
- Legacy encrypted files use the original DPAPI-protected key at:
  - `%APPDATA%\FolderGuardian\protected.key`
- Current-format encryptions use:
  - `%APPDATA%\FolderGuardian\protected.v2.key`
- DPAPI ties these keys to the current Windows user profile.
- If either key file is lost, files encrypted with that format may become unrecoverable.
- Currently, DPAPI is used automatically.  
- **Optional future extension:** support for **password-based encryption** if you prefer user-provided secrets.

---

## 🛠️ Current Behavior
- Encryption now works recursively, so deeply nested folders are included.
- Newly encrypted files are written under obfuscated random `.enc` names.
- The original filename is stored inside the encrypted payload so decryption can restore it.
- Obfuscated folders store their original names in protected metadata so they can also be restored during decryption.
- Older `.enc` files still fall back to the earlier decryption path for compatibility.

---

## 🚀 Usage
1. Clone the repository.
2. Build the project (`FolderGuardian.sln`).
3. Run the WPF application.
4. Choose the folder you want to protect using the UI folder picker.
5. Use the UI buttons to:
   - **Encrypt**
   - **Decrypt**
   - **Start Watchtower**
6. Watch the progress panel for operation status and estimated time remaining.
7. Check `SecurityLog.txt` inside the folder for logged events.

---

## ⚠️ Notes
- New-format encrypted files are designed for recovery on the same Windows account unless the required DPAPI-protected key files are preserved.
- The monitoring component runs in user mode, not kernel level, so it can be bypassed by a determined attacker.
- FolderGuardian is best treated as a strong personal/privacy tool, not a full enterprise-grade endpoint protection system.

---

## 🧪 Suggested Next Improvements
These are not implemented yet, but would be good next steps:
- **Preview / dry-run mode** before encrypting or decrypting.
- **Password-based encryption** instead of DPAPI.
- **Key export / backup guidance** inside the UI.
- **Automated tests** for encryption compatibility and recovery scenarios.

---

## ⚠️ Disclaimer
This project is for **educational and personal use only**.  
FolderGuardian uses strong encryption (AES-256 + DPAPI), but safe usage still depends on protecting the correct Windows profile and preserving the required key files.
