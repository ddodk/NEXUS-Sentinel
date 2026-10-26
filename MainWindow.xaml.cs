
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using Microsoft.Win32;
using NEXUS.Sentinel.Data;
using NEXUS.Sentinel.Diagnostics;
using NEXUS.Sentinel.Services;

namespace NEXUS.Sentinel;

public partial class MainWindow : Window
{
    private readonly DispatcherTimer _timer;
    private readonly Dictionary<int, TimeSpan> _previousCpu = new();
    private readonly Dictionary<int, string> _knownProcesses = new();
    private readonly EventStore _eventStore = new();

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

        ProcessGrid.ItemsSource = new List<ProcessRow>();
        ProcessGrid.MouseDoubleClick += ProcessGrid_MouseDoubleClick;

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
        FilterBox.Text = "";
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
        ScanFilePathText.Text = path;
        Sha256Text.Text = "Вычисление...";
        ScanResultText.Text = "Чтение файла и вычисление SHA-256...";
        ScanResultText.Foreground =
            System.Windows.Media.Brushes.LightBlue;

        try
        {
            var result = await FileHashService.CalculateSha256Async(path);

            if (result.Success)
            {
                _lastSha256 = result.Sha256;
                Sha256Text.Text = result.Sha256;
                CopyHashButton.IsEnabled = true;

                string sizeText = FormatFileSize(result.FileSizeBytes);

                ScanResultText.Text =
                    $"Успешно • Размер: {sizeText} • " +
                    $"Время: {result.CheckedAt:HH:mm:ss}";

                ScanResultText.Foreground =
                    System.Windows.Media.Brushes.LightGreen;

                _eventStore.Add(
                    "FileHashCalculated",
                    $"Вычислен SHA-256 для файла: {Path.GetFileName(path)}");
            }
            else
            {
                Sha256Text.Text = "Хеш не получен";
                ScanResultText.Text =
                    result.Error ?? result.Status;

                ScanResultText.Foreground =
                    System.Windows.Media.Brushes.Orange;
            }
        }
        catch (Exception ex)
        {
            Sha256Text.Text = "Хеш не получен";
            ScanResultText.Text = $"Ошибка: {ex.Message}";
            ScanResultText.Foreground =
                System.Windows.Media.Brushes.Orange;
        }
        finally
        {
            _isScanning = false;
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
            ScanResultText.Text = "SHA-256 скопирован в буфер обмена.";
            ScanResultText.Foreground =
                System.Windows.Media.Brushes.LightGreen;
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

    private void RefreshProcesses()
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

            var nextCpuSamples = new Dictionary<int, TimeSpan>();
            var rows = new List<ProcessRow>();
            var currentProcesses = new Dictionary<int, string>();

            foreach (Process process in Process.GetProcesses())
            {
                using (process)
                {
                    try
                    {
                        int id = process.Id;
                        string name = process.ProcessName;

                        long memoryBytes = 0;
                        TimeSpan cpuTime = TimeSpan.Zero;
                        bool hasCpuTime = false;
                        string path = "Недоступен";

                        try
                        {
                            memoryBytes = process.WorkingSet64;
                        }
                        catch
                        {
                            // Доступ к памяти может быть ограничен.
                        }

                        try
                        {
                            cpuTime = process.TotalProcessorTime;
                            hasCpuTime = true;
                        }
                        catch
                        {
                            // Доступ к CPU может быть ограничен.
                        }

                        try
                        {
                            string? filePath = process.MainModule?.FileName;

                            if (!string.IsNullOrWhiteSpace(filePath))
                                path = filePath;
                        }
                        catch
                        {
                            // Путь может быть недоступен.
                        }

                        currentProcesses[id] = name;

                        string cpuText = "Сбор данных";

                        if (hasCpuTime)
                        {
                            if (_previousCpu.TryGetValue(
                                    id,
                                    out TimeSpan previousCpu)
                                && elapsedSeconds >= 0.5)
                            {
                                double cpuPercent =
                                    (cpuTime - previousCpu).TotalMilliseconds
                                    / (elapsedSeconds * 1000.0)
                                    / Environment.ProcessorCount
                                    * 100.0;

                                cpuPercent = Math.Clamp(
                                    cpuPercent, 0.0, 100.0);

                                cpuText = $"{cpuPercent:F1} %";
                            }

                            nextCpuSamples[id] = cpuTime;
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
                            MemoryText =
                                $"{memoryBytes / 1024.0 / 1024.0:F1} MB",
                            PathText = path
                        });
                    }
                    catch
                    {
                        // Процесс мог завершиться во время чтения.
                    }
                }
            }

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

            StatusText.Text =
                $"Процессов: {rows.Count} • " +
                $"Показано: {visibleRows.Count} • " +
                $"Обновлено: {DateTime.Now:HH:mm:ss}";

            _hasLoggedMonitorError = false;
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

            StatusText.Text = $"Ошибка мониторинга: {ex.Message}";
        }
        finally
        {
            _isRefreshing = false;
        }
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
}

public sealed class ProcessRow
{
    public string ProcessName { get; set; } = "";
    public int Id { get; set; }
    public string CpuText { get; set; } = "";
    public string MemoryText { get; set; } = "";
    public string PathText { get; set; } = "";
}
