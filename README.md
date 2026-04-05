# FolderGuardian

FolderGuardian is a C# WPF desktop tool for protecting sensitive folders on Windows.

It can:

- Encrypt files in a folder with AES-256.
- Decrypt both new and older `.enc` files created by previous versions of the app.
- Store encryption material with DPAPI so keys stay tied to the current Windows user profile.
- Monitor a folder in real time and log suspicious file activity to `SecurityLog.txt`.

## Current Status

This project now uses a single WPF app layout instead of the older split console/WPF structure.

New encryptions use a stronger format than the original version:

- A fresh IV is generated per file.
- A per-file derived key flow is used.
- Integrity validation is included, so tampered encrypted files are detected during decryption.

Older encrypted files are still supported.

- Legacy `.enc` files created by the earlier version can still be decrypted.
- The old DPAPI key file is preserved at `%APPDATA%\FolderGuardian\protected.key`.
- New encryptions use `%APPDATA%\FolderGuardian\protected.v2.key`.

## Tech Stack

- .NET 8
- WPF
- AES-256
- Windows DPAPI
- `FileSystemWatcher`

## Project Structure

```text
FolderGuardian/
  Core/
    EncryptionHelper.cs
    FolderEncryptor.cs
    FolderMonitor.cs
    FolderOperationSummary.cs
    HashingWriteStream.cs
    LimitedReadStream.cs
  App.xaml
  App.xaml.cs
  MainWindow.xaml
  MainWindow.xaml.cs
  FolderGuardian.csproj
  FolderGuardian.sln
```

## Features

### 1. Folder Encryption

- Encrypts files recursively inside the selected folder.
- Obfuscates subfolder names recursively, including deep folder-only chains before the actual files.
- Writes encrypted output under an obfuscated random `.enc` filename.
- Stores the original filename inside the encrypted payload so decryption can restore it later.
- Stores original subfolder names in protected metadata so they can be restored during decryption.
- Removes the original plaintext file after successful encryption.

### 2. Folder Decryption

- Decrypts recursive `.enc` files inside the selected folder.
- Supports both the current format and the older legacy format.
- Restores the original filename for files encrypted by the current format.
- Restores obfuscated subfolder names recursively after file recovery finishes.
- Removes the encrypted file after successful decryption.

### 3. Real-Time Monitoring

- Watches the selected folder and subfolders.
- Logs create, modify, delete, and rename activity.
- Highlights newly created executable or script-like files.
- Writes entries into `SecurityLog.txt` in the monitored folder.

### 4. Desktop UI

- Folder picker instead of a hardcoded path.
- Encrypt, decrypt, and monitor controls.
- Live activity log.
- Status summary and key storage information.
- Progress feedback with a rolling ETA estimate during encrypt/decrypt operations.

## Build and Run

Requirements:

- Windows
- .NET 8 SDK

Build:

```powershell
dotnet build .\FolderGuardian.sln
```

Run:

```powershell
dotnet run --project .\FolderGuardian.csproj
```

## Important Notes

- DPAPI ties the key material to the Windows user profile that created it.
- If `%APPDATA%\FolderGuardian\protected.key` is lost, older legacy encrypted files may become unrecoverable.
- If `%APPDATA%\FolderGuardian\protected.v2.key` is lost, files encrypted by the current format may become unrecoverable.
- This app is designed for local protection and recovery on the same Windows account, not for secure key sharing between machines.

## Suggested Next Improvements

- Add automated tests for encrypt/decrypt and legacy compatibility.
- Add explicit progress reporting and cancellation for very large folders.
- Add export/backup guidance for key files.
- Add configurable monitoring rules and exclusions.
