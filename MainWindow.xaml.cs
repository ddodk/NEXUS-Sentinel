using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using NEXUS.Sentinel.Data;
using NEXUS.Sentinel.Services;
using NexusSentinel.Engine;

namespace NEXUS.Sentinel;

public partial class MainWindow : Window
{
    private async Task AnalyzeSelectedFileAsync(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return;

        try
        {
            var result = await ScanOrchestrator.AnalyzeFileAsync(
                path,
                _eventStore);

            if (result.File.Hash.Sha256.Length > 0)
            {
                _lastSha256 = result.File.Hash.Sha256;
                Sha256Text.Text = result.File.Hash.Sha256;
                CopyHashButton.IsEnabled = true;
            }
            else
            {
                Sha256Text.Text = "Хеш не получен";
                CopyHashButton.IsEnabled = false;
            }

            string summary = result.Error ??
                $"Размер: {FormatFileSize(result.File.Hash.SizeBytes)} • " +
                $"Вердикт: {result.Verdict} • " +
                $"Исход: {result.Outcome}";

            switch (result.Outcome)
            {
                case ScanOutcome.Clean:
                    ScanResultText.Text = summary;
                    ScanResultText.Foreground = Brushes.LightGreen;
                    ScannerStatusText.Text = "Завершён";
                    ScannerStatusText.Foreground = Brushes.LightGreen;
                    break;
                case ScanOutcome.Suspicious:
                    ScanResultText.Text = summary;
                    ScanResultText.Foreground = Brushes.Orange;
                    ScannerStatusText.Text = "Подозрительно";
                    ScannerStatusText.Foreground = Brushes.Orange;
                    break;
                case ScanOutcome.Malicious:
                    ScanResultText.Text = summary;
                    ScanResultText.Foreground = Brushes.Red;
                    ScannerStatusText.Text = "Вредоносно";
                    ScannerStatusText.Foreground = Brushes.Red;
                    break;
                case ScanOutcome.Error:
                    ScanResultText.Text = summary;
                    ScanResultText.Foreground = Brushes.Orange;
                    ScannerStatusText.Text = "Ошибка";
                    ScannerStatusText.Foreground = Brushes.Orange;
                    break;
            }

            if (result.Outcome == ScanOutcome.Error)
            {
                _eventStore.Add("FileScanUiError", summary);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Sha256Text.Text = "Хеш не получен";
            ScanResultText.Text = $"Ошибка: {ex.Message}";
            ScanResultText.Foreground = Brushes.Orange;
            ScannerStatusText.Text = "Ошибка";
            ScannerStatusText.Foreground = Brushes.Orange;
            _eventStore.Add("FileScanUiUnexpectedError", ex.Message);
        }
    }
}
