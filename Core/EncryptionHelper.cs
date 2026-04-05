using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace FolderGuardian.Core;

internal static class EncryptionHelper
{
    internal const string FolderMetadataFileName = ".fgname";
    private const int KeySize = 32;
    private const int IvSize = 16;
    private const int SaltSize = 16;
    private const int TagSize = 32;
    private const int BaseHeaderSize = 37;
    private const int NameLengthSize = 4;
    private const int MaxStoredFileNameBytes = 1024;
    private const byte ModernFormatVersion1 = 1;
    private const byte ModernFormatVersion2 = 2;
    private const int Pbkdf2Iterations = 150_000;
    private static readonly byte[] FileMagic = Encoding.ASCII.GetBytes("FGD1");
    private static readonly string AppDataDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "FolderGuardian");
    private static readonly string LegacyKeyFilePath = Path.Combine(AppDataDirectory, "protected.key");
    private static readonly string ModernKeyFilePath = Path.Combine(AppDataDirectory, "protected.v2.key");

    public static string KeyLocationDescription => $"{ModernKeyFilePath} (legacy: {LegacyKeyFilePath})";

    public static bool IsFolderMetadataFile(string path)
    {
        return Path.GetFileName(path).Equals(FolderMetadataFileName, StringComparison.OrdinalIgnoreCase);
    }

    public static async Task EncryptFileAsync(string inputFile, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(inputFile))
        {
            throw new FileNotFoundException("The file to encrypt was not found.", inputFile);
        }

        if (inputFile.EndsWith(".enc", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The selected file is already encrypted.");
        }

        byte[] masterKey = GetOrCreateModernMasterKey();
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] iv = RandomNumberGenerator.GetBytes(IvSize);
        byte[] keyMaterial = Rfc2898DeriveBytes.Pbkdf2(masterKey, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeySize * 2);
        byte[] encryptionKey = keyMaterial[..KeySize];
        byte[] authenticationKey = keyMaterial[KeySize..];
        byte[] originalNameBytes = Encoding.UTF8.GetBytes(Path.GetFileName(inputFile));

        if (originalNameBytes.Length == 0 || originalNameBytes.Length > MaxStoredFileNameBytes)
        {
            throw new InvalidOperationException("The source file name could not be stored safely for decryption.");
        }

        string encryptedFile = GetObfuscatedEncryptedPath(inputFile);
        string tempEncryptedFile = encryptedFile + ".tmp";

        try
        {
            byte[] header = CreateHeaderV2(salt, iv, originalNameBytes);

            {
                await using FileStream inputStream = new(inputFile, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
                await using FileStream outputStream = new(tempEncryptedFile, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true);
                using HMACSHA256 hmac = new(authenticationKey);
                using Aes aes = CreateAes(encryptionKey, iv);

                hmac.TransformBlock(header, 0, header.Length, null, 0);
                await outputStream.WriteAsync(header, cancellationToken);

                await using (HashingWriteStream hashingStream = new(outputStream, hmac))
                await using (CryptoStream cryptoStream = new(hashingStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    await inputStream.CopyToAsync(cryptoStream, 81920, cancellationToken);
                    cryptoStream.FlushFinalBlock();
                }

                hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                await outputStream.WriteAsync(hmac.Hash!, cancellationToken);
                await outputStream.FlushAsync(cancellationToken);
            }

            File.Move(tempEncryptedFile, encryptedFile, overwrite: true);
            File.Delete(inputFile);
        }
        catch
        {
            SafeDelete(tempEncryptedFile);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
            CryptographicOperations.ZeroMemory(keyMaterial);
        }
    }

    public static async Task DecryptFileAsync(string inputFile, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(inputFile))
        {
            throw new FileNotFoundException("The file to decrypt was not found.", inputFile);
        }

        if (!inputFile.EndsWith(".enc", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Only .enc files can be decrypted.");
        }

        ModernEnvelope? envelope = await TryReadModernEnvelopeAsync(inputFile, cancellationToken);
        if (envelope is null)
        {
            await DecryptLegacyFileAsync(inputFile, cancellationToken);
            return;
        }

        byte[] masterKey = LoadModernMasterKey();
        byte[] keyMaterial = Rfc2898DeriveBytes.Pbkdf2(masterKey, envelope.Salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeySize * 2);
        byte[] encryptionKey = keyMaterial[..KeySize];
        byte[] authenticationKey = keyMaterial[KeySize..];
        byte[] computedTag = await ComputeAuthenticationTagAsync(inputFile, authenticationKey, envelope.FileLength - TagSize, cancellationToken);

        if (!CryptographicOperations.FixedTimeEquals(envelope.ExpectedTag, computedTag))
        {
            throw new CryptographicException("The encrypted file failed integrity validation.");
        }

        string outputFile = GetModernDecryptedOutputPath(inputFile, envelope);
        string tempOutputFile = outputFile + ".tmp";
        long cipherTextLength = envelope.FileLength - envelope.HeaderLength - TagSize;

        try
        {
            {
                await using FileStream inputStream = new(inputFile, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
                inputStream.Position = envelope.HeaderLength;

                using Aes aes = CreateAes(encryptionKey, envelope.Iv);
                await using FileStream outputStream = new(tempOutputFile, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true);
                await using LimitedReadStream limitedReadStream = new(inputStream, cipherTextLength);
                await using CryptoStream cryptoStream = new(limitedReadStream, aes.CreateDecryptor(), CryptoStreamMode.Read);

                await cryptoStream.CopyToAsync(outputStream, 81920, cancellationToken);
                await outputStream.FlushAsync(cancellationToken);
            }

            File.Move(tempOutputFile, outputFile, overwrite: true);
            File.Delete(inputFile);
        }
        catch
        {
            SafeDelete(tempOutputFile);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
            CryptographicOperations.ZeroMemory(keyMaterial);
            CryptographicOperations.ZeroMemory(computedTag);
        }
    }

    public static bool HasFolderMetadata(string directoryPath)
    {
        return File.Exists(Path.Combine(directoryPath, FolderMetadataFileName));
    }

    public static string ObfuscateDirectoryName(string directoryPath)
    {
        if (!Directory.Exists(directoryPath))
        {
            throw new DirectoryNotFoundException($"The directory '{directoryPath}' was not found.");
        }

        if (HasFolderMetadata(directoryPath))
        {
            return directoryPath;
        }

        string originalName = Path.GetFileName(directoryPath);
        if (string.IsNullOrWhiteSpace(originalName))
        {
            throw new InvalidOperationException("The directory name could not be read.");
        }

        byte[] nameBytes = Encoding.UTF8.GetBytes(originalName);
        byte[] protectedName = ProtectedData.Protect(nameBytes, null, DataProtectionScope.CurrentUser);
        string metadataPath = Path.Combine(directoryPath, FolderMetadataFileName);
        File.WriteAllBytes(metadataPath, protectedName);
        File.SetAttributes(metadataPath, FileAttributes.Hidden | FileAttributes.NotContentIndexed);

        string parentDirectory = Path.GetDirectoryName(directoryPath)
            ?? throw new InvalidOperationException("The directory does not have a valid parent path.");
        string obfuscatedDirectoryPath = GetUniqueDirectoryPath(parentDirectory, "dir_");
        Directory.Move(directoryPath, obfuscatedDirectoryPath);
        return obfuscatedDirectoryPath;
    }

    public static string RestoreDirectoryName(string directoryPath)
    {
        if (!Directory.Exists(directoryPath))
        {
            throw new DirectoryNotFoundException($"The directory '{directoryPath}' was not found.");
        }

        string metadataPath = Path.Combine(directoryPath, FolderMetadataFileName);
        if (!File.Exists(metadataPath))
        {
            return directoryPath;
        }

        byte[] protectedName = File.ReadAllBytes(metadataPath);
        byte[] originalNameBytes = ProtectedData.Unprotect(protectedName, null, DataProtectionScope.CurrentUser);
        string originalName = Path.GetFileName(Encoding.UTF8.GetString(originalNameBytes));

        if (string.IsNullOrWhiteSpace(originalName))
        {
            throw new CryptographicException("The stored folder name is not valid.");
        }

        string parentDirectory = Path.GetDirectoryName(directoryPath)
            ?? throw new InvalidOperationException("The directory does not have a valid parent path.");
        string restoredDirectoryPath = GetAvailableDirectoryPath(Path.Combine(parentDirectory, originalName));

        try
        {
            Directory.Move(directoryPath, restoredDirectoryPath);
            string restoredMetadataPath = Path.Combine(restoredDirectoryPath, FolderMetadataFileName);
            if (File.Exists(restoredMetadataPath))
            {
                File.Delete(restoredMetadataPath);
            }

            return restoredDirectoryPath;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(originalNameBytes);
        }
    }

    private static async Task<ModernEnvelope?> TryReadModernEnvelopeAsync(string inputFile, CancellationToken cancellationToken)
    {
        await using FileStream probeStream = new(inputFile, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
        long fileLength = probeStream.Length;

        if (fileLength < BaseHeaderSize + TagSize)
        {
            return null;
        }

        byte[] baseHeader = new byte[BaseHeaderSize];
        await ReadExactlyAsync(probeStream, baseHeader, cancellationToken);

        if (!HasModernMagic(baseHeader))
        {
            return null;
        }

        byte version = baseHeader[4];
        byte[] salt = baseHeader[5..(5 + SaltSize)];
        byte[] iv = baseHeader[(5 + SaltSize)..BaseHeaderSize];
        string? originalFileName = null;
        int headerLength = BaseHeaderSize;

        if (version == ModernFormatVersion2)
        {
            byte[] nameLengthBytes = new byte[NameLengthSize];
            await ReadExactlyAsync(probeStream, nameLengthBytes, cancellationToken);
            int nameByteLength = BinaryPrimitives.ReadInt32LittleEndian(nameLengthBytes);

            if (nameByteLength <= 0 || nameByteLength > MaxStoredFileNameBytes)
            {
                throw new CryptographicException("The encrypted file contains an invalid stored name.");
            }

            if (fileLength < BaseHeaderSize + NameLengthSize + nameByteLength + TagSize)
            {
                throw new CryptographicException("The encrypted file header is incomplete.");
            }

            byte[] nameBytes = new byte[nameByteLength];
            await ReadExactlyAsync(probeStream, nameBytes, cancellationToken);
            originalFileName = Encoding.UTF8.GetString(nameBytes);
            headerLength += NameLengthSize + nameByteLength;
        }
        else if (version != ModernFormatVersion1)
        {
            return null;
        }

        probeStream.Position = fileLength - TagSize;
        byte[] expectedTag = new byte[TagSize];
        await ReadExactlyAsync(probeStream, expectedTag, cancellationToken);

        return new ModernEnvelope(version, salt, iv, expectedTag, headerLength, fileLength, originalFileName);
    }

    private static async Task DecryptLegacyFileAsync(string inputFile, CancellationToken cancellationToken)
    {
        (byte[] legacyKey, byte[] legacyIv) = LoadLegacyKeyMaterial();
        string outputFile = GetLegacyDecryptedOutputPath(inputFile);
        string tempOutputFile = outputFile + ".tmp";

        try
        {
            {
                using Aes aes = CreateAes(legacyKey, legacyIv);
                await using FileStream inputStream = new(inputFile, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
                await using FileStream outputStream = new(tempOutputFile, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true);
                await using CryptoStream cryptoStream = new(inputStream, aes.CreateDecryptor(), CryptoStreamMode.Read);

                await cryptoStream.CopyToAsync(outputStream, 81920, cancellationToken);
                await outputStream.FlushAsync(cancellationToken);
            }

            File.Move(tempOutputFile, outputFile, overwrite: true);
            File.Delete(inputFile);
        }
        catch
        {
            SafeDelete(tempOutputFile);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(legacyKey);
            CryptographicOperations.ZeroMemory(legacyIv);
        }
    }

    private static byte[] GetOrCreateModernMasterKey()
    {
        Directory.CreateDirectory(AppDataDirectory);

        if (File.Exists(ModernKeyFilePath))
        {
            return ProtectedData.Unprotect(File.ReadAllBytes(ModernKeyFilePath), null, DataProtectionScope.CurrentUser);
        }

        byte[] masterKey = RandomNumberGenerator.GetBytes(KeySize);
        byte[] protectedKey = ProtectedData.Protect(masterKey, null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(ModernKeyFilePath, protectedKey);
        return masterKey;
    }

    private static byte[] LoadModernMasterKey()
    {
        if (!File.Exists(ModernKeyFilePath))
        {
            throw new FileNotFoundException("The current encryption key was not found for this Windows user profile.", ModernKeyFilePath);
        }

        return ProtectedData.Unprotect(File.ReadAllBytes(ModernKeyFilePath), null, DataProtectionScope.CurrentUser);
    }

    private static (byte[] Key, byte[] Iv) LoadLegacyKeyMaterial()
    {
        if (!File.Exists(LegacyKeyFilePath))
        {
            throw new FileNotFoundException("The legacy protected key was not found. Existing encrypted files cannot be restored without it.", LegacyKeyFilePath);
        }

        byte[] protectedData = File.ReadAllBytes(LegacyKeyFilePath);
        byte[] combined = ProtectedData.Unprotect(protectedData, null, DataProtectionScope.CurrentUser);

        if (combined.Length < KeySize + IvSize)
        {
            throw new CryptographicException("The legacy protected key file is not valid.");
        }

        byte[] key = combined[..KeySize];
        byte[] iv = combined[KeySize..(KeySize + IvSize)];
        CryptographicOperations.ZeroMemory(combined);
        return (key, iv);
    }

    private static Aes CreateAes(byte[] key, byte[] iv)
    {
        Aes aes = Aes.Create();
        aes.KeySize = KeySize * 8;
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key;
        aes.IV = iv;
        return aes;
    }

    private static byte[] CreateHeaderV2(byte[] salt, byte[] iv, byte[] originalNameBytes)
    {
        byte[] header = new byte[BaseHeaderSize + NameLengthSize + originalNameBytes.Length];
        Buffer.BlockCopy(FileMagic, 0, header, 0, FileMagic.Length);
        header[4] = ModernFormatVersion2;
        Buffer.BlockCopy(salt, 0, header, 5, salt.Length);
        Buffer.BlockCopy(iv, 0, header, 5 + salt.Length, iv.Length);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(BaseHeaderSize, NameLengthSize), originalNameBytes.Length);
        Buffer.BlockCopy(originalNameBytes, 0, header, BaseHeaderSize + NameLengthSize, originalNameBytes.Length);
        return header;
    }

    private static bool HasModernMagic(byte[] header)
    {
        return header.Length >= BaseHeaderSize
            && header[..FileMagic.Length].SequenceEqual(FileMagic);
    }

    private static async Task<byte[]> ComputeAuthenticationTagAsync(string inputFile, byte[] authenticationKey, long authenticatedLength, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[81920];
        using HMACSHA256 hmac = new(authenticationKey);
        await using FileStream inputStream = new(inputFile, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);

        long remaining = authenticatedLength;

        while (remaining > 0)
        {
            int bytesToRead = (int)Math.Min(buffer.Length, remaining);
            int read = await inputStream.ReadAsync(buffer.AsMemory(0, bytesToRead), cancellationToken);

            if (read == 0)
            {
                throw new EndOfStreamException("The encrypted file ended unexpectedly during integrity validation.");
            }

            hmac.TransformBlock(buffer, 0, read, null, 0);
            remaining -= read;
        }

        hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return hmac.Hash!;
    }

    private static async Task ReadExactlyAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        int totalRead = 0;

        while (totalRead < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(totalRead), cancellationToken);

            if (read == 0)
            {
                throw new EndOfStreamException("The encrypted file ended unexpectedly.");
            }

            totalRead += read;
        }
    }

    private static string GetModernDecryptedOutputPath(string encryptedFile, ModernEnvelope envelope)
    {
        if (envelope.Version == ModernFormatVersion2 && !string.IsNullOrWhiteSpace(envelope.OriginalFileName))
        {
            string directory = Path.GetDirectoryName(encryptedFile) ?? string.Empty;
            string safeName = Path.GetFileName(envelope.OriginalFileName);

            if (string.IsNullOrWhiteSpace(safeName))
            {
                throw new CryptographicException("The stored output file name is not valid.");
            }

            return Path.Combine(directory, safeName);
        }

        return GetLegacyDecryptedOutputPath(encryptedFile);
    }

    private static string GetLegacyDecryptedOutputPath(string encryptedFile)
    {
        string directory = Path.GetDirectoryName(encryptedFile) ?? string.Empty;
        string fileName = Path.GetFileName(encryptedFile);
        return Path.Combine(directory, fileName[..^4]);
    }

    private static string GetObfuscatedEncryptedPath(string inputFile)
    {
        string directory = Path.GetDirectoryName(inputFile) ?? string.Empty;
        string encryptedPath;

        do
        {
            string randomName = Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();
            encryptedPath = Path.Combine(directory, $"{randomName}.enc");
        }
        while (File.Exists(encryptedPath));

        return encryptedPath;
    }

    private static string GetUniqueDirectoryPath(string parentDirectory, string prefix)
    {
        string directoryPath;

        do
        {
            string randomName = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
            directoryPath = Path.Combine(parentDirectory, $"{prefix}{randomName}");
        }
        while (Directory.Exists(directoryPath));

        return directoryPath;
    }

    private static string GetAvailableDirectoryPath(string preferredPath)
    {
        if (!Directory.Exists(preferredPath))
        {
            return preferredPath;
        }

        string parentDirectory = Path.GetDirectoryName(preferredPath) ?? string.Empty;
        string fileName = Path.GetFileName(preferredPath);
        int suffix = 1;
        string candidatePath;

        do
        {
            candidatePath = Path.Combine(parentDirectory, $"{fileName} ({suffix})");
            suffix++;
        }
        while (Directory.Exists(candidatePath));

        return candidatePath;
    }

    private static void SafeDelete(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private sealed record ModernEnvelope(
        byte Version,
        byte[] Salt,
        byte[] Iv,
        byte[] ExpectedTag,
        int HeaderLength,
        long FileLength,
        string? OriginalFileName);
}
