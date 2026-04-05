using System.Diagnostics;
using System.IO;
using System.Linq;

namespace FolderGuardian.Core;

internal static class FolderEncryptor
{
    public static async Task<FolderOperationSummary> EncryptFolderAsync(
        string folderPath,
        Action<string>? logger = null,
        Action<FolderOperationProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return await ProcessFolderAsync(folderPath, logger, progress, encryptMode: true, cancellationToken);
    }

    public static async Task<FolderOperationSummary> DecryptFolderAsync(
        string folderPath,
        Action<string>? logger = null,
        Action<FolderOperationProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return await ProcessFolderAsync(folderPath, logger, progress, encryptMode: false, cancellationToken);
    }

    private static async Task<FolderOperationSummary> ProcessFolderAsync(
        string folderPath,
        Action<string>? logger,
        Action<FolderOperationProgress>? progress,
        bool encryptMode,
        CancellationToken cancellationToken)
    {
        if (!Directory.Exists(folderPath))
        {
            throw new DirectoryNotFoundException($"The folder '{folderPath}' was not found.");
        }

        List<string> fileWorkItems = encryptMode
            ? Directory.EnumerateFiles(folderPath, "*", SearchOption.AllDirectories)
                .Where(ShouldEncryptFile)
                .ToList()
            : Directory.EnumerateFiles(folderPath, "*.enc", SearchOption.AllDirectories).ToList();

        List<string> directoryWorkItems = encryptMode
            ? Directory.EnumerateDirectories(folderPath, "*", SearchOption.AllDirectories)
                .OrderByDescending(GetDepth)
                .ToList()
            : Directory.EnumerateDirectories(folderPath, "*", SearchOption.AllDirectories)
                .Where(EncryptionHelper.HasFolderMetadata)
                .OrderByDescending(GetDepth)
                .ToList();

        int totalCount = fileWorkItems.Count + directoryWorkItems.Count;
        int processed = 0;
        int skipped = 0;
        int failed = 0;
        Stopwatch stopwatch = Stopwatch.StartNew();

        foreach (string filePath in fileWorkItems)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                if (encryptMode)
                {
                    await EncryptionHelper.EncryptFileAsync(filePath, cancellationToken);
                    logger?.Invoke($"Encrypted file: {filePath}");
                    ReportProgress(progress, stopwatch, ++processed, totalCount, failed, "Encrypting files", filePath);
                }
                else
                {
                    await EncryptionHelper.DecryptFileAsync(filePath, cancellationToken);
                    logger?.Invoke($"Decrypted file: {filePath}");
                    ReportProgress(progress, stopwatch, ++processed, totalCount, failed, "Decrypting files", filePath);
                }
            }
            catch (Exception ex)
            {
                failed++;
                processed++;
                logger?.Invoke($"Failed on {filePath}: {ex.Message}");
                ReportProgress(progress, stopwatch, processed, totalCount, failed, encryptMode ? "Encrypting files" : "Decrypting files", filePath);
            }
        }

        foreach (string directoryPath in directoryWorkItems)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                if (encryptMode)
                {
                    string obfuscatedPath = EncryptionHelper.ObfuscateDirectoryName(directoryPath);
                    logger?.Invoke($"Obfuscated folder: {directoryPath} -> {obfuscatedPath}");
                    ReportProgress(progress, stopwatch, ++processed, totalCount, failed, "Obfuscating folders", directoryPath);
                }
                else
                {
                    string restoredPath = EncryptionHelper.RestoreDirectoryName(directoryPath);
                    logger?.Invoke($"Restored folder: {directoryPath} -> {restoredPath}");
                    ReportProgress(progress, stopwatch, ++processed, totalCount, failed, "Restoring folders", directoryPath);
                }
            }
            catch (Exception ex)
            {
                failed++;
                processed++;
                logger?.Invoke($"Failed on {directoryPath}: {ex.Message}");
                ReportProgress(progress, stopwatch, processed, totalCount, failed, encryptMode ? "Obfuscating folders" : "Restoring folders", directoryPath);
            }
        }

        if (totalCount == 0)
        {
            progress?.Invoke(new FolderOperationProgress(
                encryptMode ? "Nothing to encrypt" : "Nothing to decrypt",
                null,
                0,
                0,
                0,
                null));
        }

        stopwatch.Stop();
        return new FolderOperationSummary(processed - failed, skipped, failed, totalCount, stopwatch.Elapsed);
    }

    private static bool ShouldEncryptFile(string filePath)
    {
        string fileName = Path.GetFileName(filePath);
        return !filePath.EndsWith(".enc", StringComparison.OrdinalIgnoreCase)
               && !fileName.Equals("SecurityLog.txt", StringComparison.OrdinalIgnoreCase)
               && !EncryptionHelper.IsFolderMetadataFile(filePath);
    }

    private static int GetDepth(string path)
    {
        return path.Count(character => character == Path.DirectorySeparatorChar || character == Path.AltDirectorySeparatorChar);
    }

    private static void ReportProgress(
        Action<FolderOperationProgress>? progress,
        Stopwatch stopwatch,
        int completedCount,
        int totalCount,
        int failedCount,
        string phase,
        string currentItem)
    {
        if (progress is null)
        {
            return;
        }

        TimeSpan? eta = null;
        if (completedCount > 0 && totalCount > completedCount)
        {
            double secondsPerItem = stopwatch.Elapsed.TotalSeconds / completedCount;
            eta = TimeSpan.FromSeconds(secondsPerItem * (totalCount - completedCount));
        }

        progress(new FolderOperationProgress(
            phase,
            currentItem,
            completedCount,
            totalCount,
            failedCount,
            eta));
    }
}
