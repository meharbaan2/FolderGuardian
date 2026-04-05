using FolderGuardian.Core;
using System.Diagnostics;
using System.IO;
using System.Windows;
using Forms = System.Windows.Forms;

namespace FolderGuardian;

public partial class MainWindow : Window
{
    private FolderMonitor? _monitor;
    private bool _isBusy;
    private int _visibleLogCount;

    public MainWindow()
    {
        InitializeComponent();

        string defaultFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            "FolderGuardian");

        FolderPathBox.Text = defaultFolder;
        KeyPathText.Text = EncryptionHelper.KeyLocationDescription;
        UpdateFolderDetails();
    }

    private async void EncryptBtn_Click(object sender, RoutedEventArgs e)
    {
        await RunFolderActionAsync(
            "Encrypting folder...",
            (folderPath, progress, cancellationToken) => FolderEncryptor.EncryptFolderAsync(folderPath, AppendLog, progress, cancellationToken));
    }

    private async void DecryptBtn_Click(object sender, RoutedEventArgs e)
    {
        await RunFolderActionAsync(
            "Decrypting folder...",
            (folderPath, progress, cancellationToken) => FolderEncryptor.DecryptFolderAsync(folderPath, AppendLog, progress, cancellationToken));
    }

    private void MonitorBtn_Click(object sender, RoutedEventArgs e)
    {
        string? folderPath = GetValidatedFolderPath(createIfMissing: true);
        if (folderPath is null)
        {
            return;
        }

        if (_monitor is not null && !string.Equals(_monitor.FolderPath, folderPath, StringComparison.OrdinalIgnoreCase))
        {
            _monitor.Dispose();
            _monitor = null;
        }

        if (_monitor is null)
        {
            _monitor = new FolderMonitor(folderPath, AppendLog);
        }

        if (_monitor.IsRunning)
        {
            _monitor.Stop();
            MonitorBtn.Content = "Start Watchtower";
            MonitorStateText.Text = "Stopped";
        }
        else
        {
            _monitor.Start();
            MonitorBtn.Content = "Stop Watchtower";
            MonitorStateText.Text = "Active";
        }

        UpdateFolderDetails();
    }

    private void BrowseBtn_Click(object sender, RoutedEventArgs e)
    {
        using Forms.FolderBrowserDialog dialog = new()
        {
            Description = "Select the folder you want FolderGuardian to protect.",
            UseDescriptionForTitle = true,
            InitialDirectory = Directory.Exists(FolderPathBox.Text)
                ? FolderPathBox.Text
                : Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            ShowNewFolderButton = true
        };

        if (dialog.ShowDialog() == Forms.DialogResult.OK)
        {
            FolderPathBox.Text = dialog.SelectedPath;
            UpdateFolderDetails();
        }
    }

    private void OpenLogBtn_Click(object sender, RoutedEventArgs e)
    {
        string? folderPath = GetValidatedFolderPath(createIfMissing: true);
        if (folderPath is null)
        {
            return;
        }

        string logFile = Path.Combine(folderPath, "SecurityLog.txt");
        if (!File.Exists(logFile))
        {
            File.WriteAllText(logFile, "FolderGuardian security log" + Environment.NewLine);
        }

        Process.Start(new ProcessStartInfo
        {
            FileName = logFile,
            UseShellExecute = true
        });
    }

    private void ClearLog_Click(object sender, RoutedEventArgs e)
    {
        LogBox.Clear();
        _visibleLogCount = 0;
        ActivityCountText.Text = "0";
    }

    private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
    {
        _monitor?.Dispose();
    }

    public void AppendLog(string message)
    {
        Dispatcher.Invoke(() =>
        {
            LogBox.AppendText($"{message}{Environment.NewLine}");
            LogBox.ScrollToEnd();
            _visibleLogCount++;
            ActivityCountText.Text = _visibleLogCount.ToString();
        });
    }

    private async Task RunFolderActionAsync(
        string busyMessage,
        Func<string, Action<FolderOperationProgress>, CancellationToken, Task<FolderOperationSummary>> operation)
    {
        if (_isBusy)
        {
            AppendLog("Another operation is already in progress.");
            return;
        }

        string? folderPath = GetValidatedFolderPath(createIfMissing: false);
        if (folderPath is null)
        {
            return;
        }

        SetBusyState(true, busyMessage);
        ProgressText.Text = "Scanning work items...";
        EtaText.Text = "ETA --";
        CurrentItemText.Text = "Preparing operation.";
        OperationProgressBar.Maximum = 1;
        OperationProgressBar.Value = 0;

        try
        {
            FolderOperationSummary summary = await Task.Run(
                () => operation(folderPath, UpdateOperationProgress, CancellationToken.None));

            OperationProgressBar.Maximum = Math.Max(summary.TotalCount, 1);
            OperationProgressBar.Value = Math.Max(summary.TotalCount, 1);
            ProgressText.Text = $"{summary.ProcessedCount} of {summary.TotalCount} work items completed";
            EtaText.Text = "ETA complete";
            CurrentItemText.Text = "Operation finished.";
            RunSummaryText.Text = $"{summary.ProcessedCount} processed, {summary.SkippedCount} skipped, {summary.FailedCount} failed in {FormatDuration(summary.Duration)}.";
            AppendLog($"Completed. {RunSummaryText.Text}");
        }
        catch (Exception ex)
        {
            RunSummaryText.Text = "The operation did not complete.";
            ProgressText.Text = "Operation stopped";
            EtaText.Text = "ETA --";
            CurrentItemText.Text = ex.Message;
            AppendLog($"Operation failed: {ex.Message}");
        }
        finally
        {
            SetBusyState(false, "Ready");
            UpdateFolderDetails();
        }
    }

    private string? GetValidatedFolderPath(bool createIfMissing)
    {
        string folderPath = FolderPathBox.Text.Trim();

        if (string.IsNullOrWhiteSpace(folderPath))
        {
            System.Windows.MessageBox.Show(this, "Pick a folder first.", "Folder Required", MessageBoxButton.OK, MessageBoxImage.Information);
            return null;
        }

        if (!Directory.Exists(folderPath))
        {
            if (!createIfMissing)
            {
                System.Windows.MessageBox.Show(this, "That folder does not exist.", "Folder Not Found", MessageBoxButton.OK, MessageBoxImage.Warning);
                return null;
            }

            Directory.CreateDirectory(folderPath);
        }

        FolderPathBox.Text = folderPath;
        UpdateFolderDetails();
        return folderPath;
    }

    private void SetBusyState(bool isBusy, string statusMessage)
    {
        _isBusy = isBusy;
        EncryptBtn.IsEnabled = !isBusy;
        DecryptBtn.IsEnabled = !isBusy;
        MonitorBtn.IsEnabled = !isBusy;
        BrowseBtn.IsEnabled = !isBusy;
        OperationProgressBar.IsIndeterminate = false;
        StatusText.Text = statusMessage;
    }

    private void UpdateFolderDetails()
    {
        string folderPath = FolderPathBox.Text.Trim();
        SelectedFolderText.Text = string.IsNullOrWhiteSpace(folderPath) ? "No folder selected" : folderPath;
        KeyPathText.Text = EncryptionHelper.KeyLocationDescription;

        if (_monitor is null)
        {
            MonitorStateText.Text = "Stopped";
            return;
        }

        MonitorStateText.Text = _monitor.IsRunning ? "Active" : "Stopped";
    }

    private void UpdateOperationProgress(FolderOperationProgress progress)
    {
        Dispatcher.Invoke(() =>
        {
            OperationProgressBar.IsIndeterminate = false;
            OperationProgressBar.Maximum = Math.Max(progress.TotalCount, 1);
            OperationProgressBar.Value = Math.Min(progress.CompletedCount, OperationProgressBar.Maximum);
            ProgressText.Text = progress.TotalCount == 0
                ? progress.Phase
                : $"{progress.CompletedCount} / {progress.TotalCount} complete";

            EtaText.Text = progress.EstimatedRemaining is TimeSpan remaining
                ? $"ETA {FormatDuration(remaining)}"
                : "ETA calculating...";

            CurrentItemText.Text = string.IsNullOrWhiteSpace(progress.CurrentItem)
                ? progress.Phase
                : $"{progress.Phase}: {progress.CurrentItem}";
        });
    }

    private static string FormatDuration(TimeSpan duration)
    {
        if (duration.TotalHours >= 1)
        {
            return duration.ToString(@"h\:mm\:ss");
        }

        if (duration.TotalMinutes >= 1)
        {
            return duration.ToString(@"m\:ss");
        }

        return $"{Math.Max(1, (int)Math.Round(duration.TotalSeconds))}s";
    }
}
