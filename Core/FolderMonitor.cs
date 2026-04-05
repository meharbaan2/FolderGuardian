using System.IO;
using System.Linq;

namespace FolderGuardian.Core;

internal sealed class FolderMonitor : IDisposable
{
    private static readonly HashSet<string> SuspiciousExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe",
        ".ps1",
        ".bat",
        ".cmd",
        ".vbs",
        ".js",
        ".scr"
    };

    private readonly FileSystemWatcher _watcher;
    private readonly Action<string>? _logger;
    private readonly object _eventLock = new();
    private readonly object _logFileLock = new();
    private readonly Dictionary<string, DateTime> _lastEventTimes = new(StringComparer.OrdinalIgnoreCase);
    private bool _disposed;

    public FolderMonitor(string folderPath, Action<string>? logger = null)
    {
        FolderPath = folderPath;
        _logger = logger;
        LogFilePath = Path.Combine(FolderPath, "SecurityLog.txt");

        Directory.CreateDirectory(FolderPath);

        _watcher = new FileSystemWatcher(FolderPath)
        {
            IncludeSubdirectories = true,
            EnableRaisingEvents = false,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
            InternalBufferSize = 32 * 1024
        };

        _watcher.Changed += OnChanged;
        _watcher.Created += OnCreated;
        _watcher.Deleted += OnDeleted;
        _watcher.Renamed += OnRenamed;
        _watcher.Error += OnError;
    }

    public string FolderPath { get; }

    public string LogFilePath { get; }

    public bool IsRunning => _watcher.EnableRaisingEvents;

    public void Start()
    {
        ThrowIfDisposed();
        _watcher.EnableRaisingEvents = true;
        WriteLogLine("Monitoring enabled.");
    }

    public void Stop()
    {
        if (_disposed)
        {
            return;
        }

        _watcher.EnableRaisingEvents = false;
        WriteLogLine("Monitoring paused.");
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _watcher.EnableRaisingEvents = false;
        _watcher.Changed -= OnChanged;
        _watcher.Created -= OnCreated;
        _watcher.Deleted -= OnDeleted;
        _watcher.Renamed -= OnRenamed;
        _watcher.Error -= OnError;
        _watcher.Dispose();
        _disposed = true;
    }

    private void OnChanged(object? sender, FileSystemEventArgs e)
    {
        LogSuspiciousActivity(e.FullPath, "Modified");
    }

    private void OnCreated(object? sender, FileSystemEventArgs e)
    {
        string extension = Path.GetExtension(e.FullPath);
        string action = SuspiciousExtensions.Contains(extension)
            ? "New executable or script created"
            : "Created";

        LogSuspiciousActivity(e.FullPath, action);
    }

    private void OnDeleted(object? sender, FileSystemEventArgs e)
    {
        LogSuspiciousActivity(e.FullPath, "Deleted");
    }

    private void OnRenamed(object? sender, RenamedEventArgs e)
    {
        LogSuspiciousActivity(e.FullPath, $"Renamed from {e.OldFullPath}");
    }

    private void OnError(object? sender, ErrorEventArgs e)
    {
        WriteLogLine($"Monitor warning: {e.GetException().Message}. Some file events may have been missed.");
    }

    private void LogSuspiciousActivity(string filePath, string action)
    {
        string fileName = Path.GetFileName(filePath);

        if (string.IsNullOrWhiteSpace(fileName))
        {
            return;
        }

        if (fileName.Equals("SecurityLog.txt", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals(EncryptionHelper.FolderMetadataFileName, StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".enc", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase)
            || fileName.StartsWith("~$", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        DateTime now = DateTime.UtcNow;
        string dedupeKey = $"{action}|{filePath}";

        lock (_eventLock)
        {
            if (_lastEventTimes.TryGetValue(dedupeKey, out DateTime lastSeen)
                && (now - lastSeen).TotalMilliseconds < 800)
            {
                return;
            }

            _lastEventTimes[dedupeKey] = now;

            if (_lastEventTimes.Count > 500)
            {
                DateTime expiry = now.AddMinutes(-5);
                foreach (string key in _lastEventTimes.Where(entry => entry.Value < expiry).Select(entry => entry.Key).ToList())
                {
                    _lastEventTimes.Remove(key);
                }
            }
        }

        WriteLogLine($"{action}: {filePath}");
    }

    private void WriteLogLine(string message)
    {
        string line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}  {message}";
        _logger?.Invoke(line);
        Console.WriteLine($"[LOG] {line}");

        try
        {
            lock (_logFileLock)
            {
                File.AppendAllText(LogFilePath, line + Environment.NewLine);
            }
        }
        catch
        {
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
