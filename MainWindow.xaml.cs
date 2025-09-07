using FolderGuardian.Core;
using System;
using System.Windows;

namespace FolderGuardian
{
    public partial class MainWindow : Window
    {
        private string folderPath = @"D:\SensitiveFolder"; // change this to your test folder
        private FolderMonitor? monitor;

        public MainWindow()
        {
            InitializeComponent();
        }

        private void EncryptBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                FolderEncryptor.EncryptFolder(folderPath);
                AppendLog("Manual encryption complete.");
            }
            catch (Exception ex)
            {
                AppendLog("Error during encryption: " + ex.Message);
            }
        }

        private void DecryptBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                FolderEncryptor.DecryptFolder(folderPath);
                AppendLog("Manual decryption complete.");
            }
            catch (Exception ex)
            {
                AppendLog("Error during decryption: " + ex.Message);
            }
        }

        private void MonitorBtn_Click(object sender, RoutedEventArgs e)
        {
            if (monitor == null)
            {
                monitor = new FolderMonitor(folderPath, AppendLog);
                AppendLog("Monitoring started...");
                MonitorBtn.Content = "Monitoring Active";
                MonitorBtn.IsEnabled = false;
            }
            else
            {
                AppendLog("Monitoring already active.");
            }
        }

        private void ClearLog_Click(object sender, RoutedEventArgs e)
        {
            LogBox.Clear();
        }

        // This runs on UI thread via Dispatcher
        public void AppendLog(string message)
        {
            Dispatcher.Invoke(() =>
            {
                LogBox.AppendText($"{message}{Environment.NewLine}");
                LogBox.ScrollToEnd();
            });
        }
    }
}