using System.IO;

namespace FolderGuardian.Core
{
    class FolderMonitor
    {
        private FileSystemWatcher watcher;
        private string folderPath;
        private readonly object _lock = new();
        // Tracks the last time we logged an event for a given path to avoid duplicates
        private readonly Dictionary<string, DateTime> _lastEventTimes = new();
        private readonly Action<string>? _logger; // optional logger callback

        public FolderMonitor(string path, Action<string>? logger = null)
        {
            folderPath = path;
            _logger = logger;

            if (!Directory.Exists(folderPath))
                Directory.CreateDirectory(folderPath);

            watcher = new FileSystemWatcher(folderPath)
            {
                IncludeSubdirectories = true,
                EnableRaisingEvents = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime
            };

            watcher.Changed += OnChanged;
            watcher.Deleted += OnChanged;
            watcher.Created += OnCreated;
            watcher.Renamed += OnRenamed;
        }

        private void OnChanged(object sender, FileSystemEventArgs e)
        {
            LogSuspiciousActivity(e.FullPath, e.ChangeType.ToString());
        }

        private void OnCreated(object sender, FileSystemEventArgs e)
        {
            // If a new exe appears, log it. Other created files will still be logged by Changed if needed.
            if (Path.GetExtension(e.FullPath).Equals(".exe", StringComparison.OrdinalIgnoreCase))
            {
                LogSuspiciousActivity(e.FullPath, "New EXE Created");
            }
        }

        private void OnRenamed(object sender, RenamedEventArgs e)
        {
            LogSuspiciousActivity(e.FullPath, $"Renamed from {e.OldFullPath}");
        }

        private void LogSuspiciousActivity(string filePath, string action)
        {
            // --- 1) Basic filename checks ---
            string fileName = Path.GetFileName(filePath); // <-- declare fileName here

            // Ignore changes to the log file itself to avoid infinite feedback loops
            if (fileName.Equals("SecurityLog.txt", StringComparison.OrdinalIgnoreCase))
                return;

            // Ignore encrypted files if you don't want them logged
            if (fileName.EndsWith(".enc", StringComparison.OrdinalIgnoreCase))
                return;

            // Optionally ignore temp/lock files from editors (add more rules as needed)
            if (fileName.StartsWith("~$") || fileName.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase))
                return;

            // --- 2) Debounce duplicate events for the same path ---
            DateTime now = DateTime.UtcNow;
            lock (_lock)
            {
                if (_lastEventTimes.TryGetValue(filePath, out DateTime last))
                {
                    // If the last logged event for this file was less than 800ms ago, ignore this one
                    if ((now - last).TotalMilliseconds < 800)
                        return;
                }
                _lastEventTimes[filePath] = now;
            }

            // --- 3) Send to UI if logger is available ---
            string line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}: {action} on {filePath}";
            _logger?.Invoke(line);

            // Always log to console too (optional)
            Console.WriteLine($"[LOG] {line}");

            // --- 4) Append to log file ---
            string logFile = Path.Combine(folderPath, "SecurityLog.txt");
            try
            {
                File.AppendAllText(logFile, line + Environment.NewLine);
            }
            catch
            {
                // Swallow file lock/permission errors
            }
        }
    }
}
