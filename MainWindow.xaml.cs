using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using System.Windows.Threading;
using NEXUS.Sentinel.Data;
using NEXUS.Sentinel.Diagnostics;
using NexusSentinel.Engine;
using NEXUS.Sentinel.Services;

namespace NEXUS.Sentinel;

public partial class MainWindow : Window
{
    private readonly DispatcherTimer _timer;
    private readonly Dictionary<int, TimeSpan> _previousCpu = new();
    private readonly Dictionary<int, string> _knownProcesses = new();
    private readonly EventStore _eventStore = new();
    private readonly ScanOrchestrator _scanOrchestrator;
    private readonly CancellationTokenSource _shutdownCancellation = new();

    private readonly DataSourceStatus _processStatus = new()
    {
        Name = "Windows Process Monitor"
    };

    private long _lastSampleTimestamp;
    private bool _isRefreshing;
    private bool _hasLoggedMonitorError;
    private bool _isScanning;
    private string? _lastSha256;

    public MainWindow()
    {
        InitializeComponent();

        _scanOrchestrator = new ScanOrchestrator(
            (type, message) => _eventStore.Add(type, message));

        ProcessGrid.ItemsSource = new List<ProcessRow>();

        _timer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(3)
        };

        _timer.Tick += (_, _) => RefreshProcesses();

        Loaded += (_, _) =>
        {
            _eventStore.Add(
                "MonitorStarted",
                "NEXUS Sentinel начал мониторинг процессов.");

            RefreshProcesses();
            _timer.Start();
        };

        Closed += (_, _) =>
        {
            _shutdownCancellation.Cancel();
            _timer.Stop();

            _eventStore.Add(
                "MonitorStopped",
                "Мониторинг процессов остановлен.");
        };
    }

    private void FilterBox_TextChanged(
        object sender,
        TextChangedEventArgs e)
    {
        if (!_isRefreshing)
            RefreshProcesses();
    }

    private void RefreshButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        RefreshProcesses();
    }

    private void ClearFilterButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        FilterBox.Text = string.Empty;
        RefreshProcesses();
    }

    private void OpenEventLogButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        var window = new EventLogWindow(_eventStore)
        {
            Owner = this
        };

        window.ShowDialog();
    }

    private void ProcessesNavButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        ProcessGrid.ScrollIntoView(ProcessGrid.Items.Count > 0
            ? ProcessGrid.Items[0]
            : null);

        ProcessGrid.Focus();
    }

    private void ScannerNavButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        ScannerCard.BringIntoView();
        ScanFileButton.Focus();
    }

    private void ProcessGrid_SelectionChanged(
        object sender,
        SelectionChangedEventArgs e)
    {
        if (ProcessGrid.SelectedItem is ProcessRow row)
        {
            StatusTextUpdate(
                $"Выбран процесс: {row.ProcessName} • PID {row.Id}");
        }
    }

    private void ProcessGrid_MouseDoubleClick(
        object sender,
        MouseButtonEventArgs e)
    {
        if (ProcessGrid.SelectedItem is not ProcessRow row)
            return;

        var window = new ProcessDetailsWindow(row)
        {
            Owner = this
        };

        window.ShowDialog();
    }

    private async void ScanFileButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (_isScanning)
            return;

        var dialog = new OpenFileDialog
        {
            Title = "Выберите файл для вычисления SHA-256",
            CheckFileExists = true,
            CheckPathExists = true,
            Multiselect = false,
            Filter = "Все файлы (*.*)|*.*"
        };

        if (dialog.ShowDialog(this) != true)
            return;

        string path = dialog.FileName;

        _isScanning = true;
        _lastSha256 = null;

        CopyHashButton.IsEnabled = false;
        ScanFileButton.IsEnabled = false;
        ScannerStatusText.Text = "Сканирование";
        ScannerStatusText.Foreground = Brushes.LightBlue;

        ScanFilePathText.Text = path;
        Sha256Text.Text = "Вычисление...";
        ScanResultText.Text = "Чтение файла и вычисление SHA-256...";
        ScanResultText.Foreground = Brushes.LightBlue;

        try
        {
            ScanResult result = await _scanOrchestrator.ScanAsync(
                path,
                _shutdownCancellation.Token);

            if (!IsLoaded)
                return;

            if (!string.IsNullOrEmpty(result.File.Hash.Sha256))
            {
                _lastSha256 = result.File.Hash.Sha256;
                Sha256Text.Text = result.File.Hash.Sha256;
                CopyHashButton.IsEnabled = true;
            }
            else
            {
                Sha256Text.Text = "Хеш не получен";
            }

            if (result.Outcome == ScanOutcome.Error)
            {
                ScanResultText.Text = $"Ошибка: {result.Error}";
                ScanResultText.Foreground = Brushes.Orange;
                ScannerStatusText.Text = "Ошибка";
                ScannerStatusText.Foreground = Brushes.Orange;
            }
            else
            {
                string peStatus = result.Pe?.FormatStatus switch
                {
                    PeFormatStatus.PeValid => "PE: структура разобрана",
                    PeFormatStatus.PeCorrupted => "PE: повреждён",
                    _ => "PE: не обнаружен"
                };
                string fileDetails = result.File.Hash.Sha256.Length == 0
                    ? string.Empty
                    : $" • Размер: {FormatFileSize(result.File.Hash.SizeBytes)}" +
                      $" • Время: {DateTime.Now:HH:mm:ss}";

                ScanResultText.Text = result.Heuristics.Count == 0
                    ? $"{result.Verdict} • Риск: {result.RiskScore}/100" +
                      $"{fileDetails} • {peStatus}. Поддерживаемые индикаторы " +
                      "не обнаружены; безопасность файла не подтверждена."
                    : $"{result.Verdict} • Риск: {result.RiskScore}/100" +
                      $"{fileDetails} • {peStatus}. Проверка не заменяет " +
                      "антивирусный анализ.";

                ScannerStatusText.Text = "Завершён";
                ScannerStatusText.Foreground = result.Verdict switch
                {
                    Verdict.Malicious => Brushes.OrangeRed,
                    Verdict.Suspicious => Brushes.Orange,
                    _ => Brushes.LightGreen
                };
                ScanResultText.Foreground = ScannerStatusText.Foreground;

                _eventStore.Add(
                    "FileScanCompleted",
                    $"Сканирование завершено: {result.Outcome}, " +
                    $"риск {result.RiskScore}.");
            }
        }
        catch (OperationCanceledException)
        {
            if (!IsLoaded)
                return;

            Sha256Text.Text = "Сканирование отменено";
            ScanResultText.Text = "Сканирование отменено.";
            ScanResultText.Foreground = Brushes.Orange;
            ScannerStatusText.Text = "Отменено";
            ScannerStatusText.Foreground = Brushes.Orange;
        }
        catch (OutOfMemoryException)
        {
            throw;
        }
        catch (Exception ex)
        {
            if (!IsLoaded)
                return;

            Sha256Text.Text = "Хеш не получен";
            ScanResultText.Text = $"Ошибка: {ex.Message}";
            ScanResultText.Foreground = Brushes.Orange;
            ScannerStatusText.Text = "Ошибка";
            ScannerStatusText.Foreground = Brushes.Orange;
            _eventStore.Add(
                "FileScanUiError",
                "Не удалось отобразить результат сканирования.");
        }
        finally
        {
            _isScanning = false;
            if (IsLoaded)
                ScanFileButton.IsEnabled = true;
        }
    }

    private void CopyHashButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_lastSha256))
            return;

        try
        {
            Clipboard.SetText(_lastSha256);

            ScanResultText.Text =
                "SHA-256 скопирован в буфер обмена.";
            ScanResultText.Foreground = Brushes.LightGreen;
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                this,
                $"Не удалось скопировать хеш: {ex.Message}",
                "NEXUS Sentinel",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    private async void RefreshProcesses()
    {
        if (_isRefreshing)
            return;

        _isRefreshing = true;

        try
        {
            long now = Stopwatch.GetTimestamp();
            double elapsedSeconds = _lastSampleTimestamp == 0
                ? 0
                : Stopwatch.GetElapsedTime(
                    _lastSampleTimestamp,
                    now).TotalSeconds;
            _lastSampleTimestamp = now;

            ProcessSnapshot snapshot = await Task.Run(
                () => CaptureProcessSnapshot(
                    new Dictionary<int, TimeSpan>(_previousCpu),
                    elapsedSeconds,
                    _shutdownCancellation.Token),
                _shutdownCancellation.Token);

            if (!IsLoaded)
                return;

            var nextCpuSamples = snapshot.CpuSamples;
            var rows = snapshot.Rows;
            var currentProcesses = snapshot.ProcessNames;

            foreach (var item in currentProcesses)
            {
                if (!_knownProcesses.TryGetValue(
                        item.Key,
                        out string? previousName))
                {
                    _eventStore.Add(
                        "ProcessObserved",
                        $"Обнаружен процесс: {item.Value}",
                        item.Key);
                }
                else if (previousName != item.Value)
                {
                    _eventStore.Add(
                        "ProcessChanged",
                        $"Для PID {item.Key} изменилось имя процесса.",
                        item.Key);
                }
            }

            foreach (var item in _knownProcesses)
            {
                if (!currentProcesses.ContainsKey(item.Key))
                {
                    _eventStore.Add(
                        "ProcessNoLongerVisible",
                        $"Процесс больше не обнаружен: {item.Value}",
                        item.Key);
                }
            }

            _knownProcesses.Clear();

            foreach (var item in currentProcesses)
                _knownProcesses[item.Key] = item.Value;

            _previousCpu.Clear();

            foreach (var sample in nextCpuSamples)
                _previousCpu[sample.Key] = sample.Value;

            string query = FilterBox.Text.Trim();
            var visibleRows = rows
                .Where(row =>
                    query.Length == 0
                    || row.ProcessName.Contains(
                        query,
                        StringComparison.OrdinalIgnoreCase)
                    || row.Id.ToString().Contains(query)
                    || row.PathText.Contains(
                        query,
                        StringComparison.OrdinalIgnoreCase))
                .OrderBy(row => row.ProcessName)
                .ToList();

            ProcessGrid.ItemsSource = visibleRows;

            _processStatus.MarkAvailable(DataCompleteness.Partial);

            StatusTextUpdate(
                $"Процессов: {rows.Count} • " +
                $"Показано: {visibleRows.Count} • " +
                $"Обновлено: {DateTime.Now:HH:mm:ss}");

            ProcessCountText.Text = rows.Count.ToString();
            LastUpdateText.Text = DateTime.Now.ToString("HH:mm:ss");

            _hasLoggedMonitorError = false;
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            _processStatus.MarkError(ex.Message);

            if (!_hasLoggedMonitorError)
            {
                _eventStore.Add(
                    "MonitorError",
                    $"Ошибка мониторинга: {ex.Message}");

                _hasLoggedMonitorError = true;
            }

            StatusTextUpdate($"Ошибка мониторинга: {ex.Message}");
            LastUpdateText.Text = "Ошибка";
        }
        finally
        {
            _isRefreshing = false;
        }
    }

    private static ProcessSnapshot CaptureProcessSnapshot(
        IReadOnlyDictionary<int, TimeSpan> previousCpu,
        double elapsedSeconds,
        CancellationToken cancellationToken)
    {
        var cpuSamples = new Dictionary<int, TimeSpan>();
        var rows = new List<ProcessRow>();
        var processNames = new Dictionary<int, string>();

        foreach (Process process in Process.GetProcesses())
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (process)
            {
                try
                {
                    int id = process.Id;
                    string name = process.ProcessName;
                    long memoryBytes = 0;
                    bool hasMemory = false;
                    TimeSpan cpuTime = TimeSpan.Zero;
                    bool hasCpuTime = false;
                    string path = "Недоступен";

                    try
                    {
                        memoryBytes = process.WorkingSet64;
                        hasMemory = true;
                    }
                    catch (OutOfMemoryException)
                    {
                        throw;
                    }
                    catch
                    {
                    }

                    try
                    {
                        cpuTime = process.TotalProcessorTime;
                        hasCpuTime = true;
                    }
                    catch (OutOfMemoryException)
                    {
                        throw;
                    }
                    catch
                    {
                    }

                    try
                    {
                        string? filePath = process.MainModule?.FileName;

                        if (!string.IsNullOrWhiteSpace(filePath))
                            path = filePath;
                    }
                    catch (OutOfMemoryException)
                    {
                        throw;
                    }
                    catch
                    {
                    }

                    processNames[id] = name;

                    string cpuText = "Сбор данных";

                    if (hasCpuTime)
                    {
                        if (previousCpu.TryGetValue(
                                id,
                                out TimeSpan previousCpuTime)
                            && elapsedSeconds >= 0.5)
                        {
                            double cpuPercent =
                                (cpuTime - previousCpuTime).TotalMilliseconds
                                / (elapsedSeconds * 1000.0)
                                / Environment.ProcessorCount
                                * 100.0;

                            cpuText = $"{Math.Clamp(cpuPercent, 0.0, 100.0):F1} %";
                        }

                        cpuSamples[id] = cpuTime;
                    }
                    else
                    {
                        cpuText = "Недоступен";
                    }

                    rows.Add(new ProcessRow
                    {
                        ProcessName = name,
                        Id = id,
                        CpuText = cpuText,
                        MemoryText = hasMemory
                            ? $"{memoryBytes / 1024.0 / 1024.0:F1} MB"
                            : "Недоступен",
                        PathText = path
                    });
                }
                catch
                {
                    // Процесс мог завершиться во время чтения.
                }
            }
        }

        return new ProcessSnapshot(rows, processNames, cpuSamples);
    }

    private void StatusTextUpdate(string message)
    {
        // Строка статуса выводится в заголовке окна.
        Title = $"NEXUS Sentinel — {message}";
    }

    private static string FormatFileSize(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double size = bytes;
        int unit = 0;

        while (size >= 1024 && unit < units.Length - 1)
        {
            size /= 1024;
            unit++;
        }

        return $"{size:F2} {units[unit]}";
    }

    private sealed record ProcessSnapshot(
        List<ProcessRow> Rows,
        Dictionary<int, string> ProcessNames,
        Dictionary<int, TimeSpan> CpuSamples);
}

public sealed class ProcessRow
{
    public string ProcessName { get; set; } = "";
    public int Id { get; set; }
    public string CpuText { get; set; } = "";
    public string MemoryText { get; set; } = "";
    public string PathText { get; set; } = "";
}
