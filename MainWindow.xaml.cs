
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;

namespace NEXUS.Sentinel;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<ProcessRow> _processes = new();
    private readonly Dictionary<int, TimeSpan> _previousCpu = new();
    private readonly ICollectionView _processView;
    private readonly DispatcherTimer _timer;

    private long _lastSampleTimestamp;

    public MainWindow()
    {
        InitializeComponent();

        _processView = CollectionViewSource.GetDefaultView(_processes);
        _processView.Filter = MatchesFilter;
        ProcessGrid.ItemsSource = _processView;

        _timer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(3)
        };

        _timer.Tick += (_, _) => RefreshProcesses();

        Loaded += (_, _) =>
        {
            RefreshProcesses();
            _timer.Start();
        };

        Closed += (_, _) => _timer.Stop();
    }

    private bool MatchesFilter(object item)
    {
        if (item is not ProcessRow process)
            return false;

        string query = FilterBox?.Text?.Trim() ?? "";

        if (query.Length == 0)
            return true;

        return process.ProcessName.Contains(
                   query, StringComparison.OrdinalIgnoreCase)
               || process.Id.ToString().Contains(query)
               || process.PathText.Contains(
                   query, StringComparison.OrdinalIgnoreCase);
    }

    private void FilterBox_TextChanged(
        object sender,
        System.Windows.Controls.TextChangedEventArgs e)
    {
        _processView?.Refresh();
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
        _processView.Refresh();
    }

    private void RefreshProcesses()
    {
        try
        {
            long now = Stopwatch.GetTimestamp();

            double elapsedSeconds = _lastSampleTimestamp == 0
                ? 0
                : Stopwatch.GetElapsedTime(
                    _lastSampleTimestamp, now).TotalSeconds;

            _lastSampleTimestamp = now;

            var nextCpuSamples = new Dictionary<int, TimeSpan>();
            var rows = new List<ProcessRow>();

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
                            // Процесс мог завершиться или закрыть доступ.
                        }

                        try
                        {
                            cpuTime = process.TotalProcessorTime;
                            hasCpuTime = true;
                        }
                        catch
                        {
                            // CPU может быть недоступен.
                        }

                        try
                        {
                            string? filePath = process.MainModule?.FileName;

                            if (!string.IsNullOrWhiteSpace(filePath))
                                path = filePath;
                        }
                        catch
                        {
                            // Windows может ограничивать доступ к пути.
                        }

                        string cpuText = "Сбор данных";

                        if (hasCpuTime)
                        {
                            if (_previousCpu.TryGetValue(
                                    id, out TimeSpan previousCpu)
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
                        // Пропускаем процесс, который завершился
                        // во время чтения данных.
                    }
                }
            }

            _previousCpu.Clear();

            foreach (var sample in nextCpuSamples)
                _previousCpu[sample.Key] = sample.Value;

            var orderedRows = rows
                .OrderBy(row => row.ProcessName)
                .ToList();

            _processes.Clear();

            foreach (ProcessRow row in orderedRows)
                _processes.Add(row);

            _processView.Refresh();

            StatusText.Text =
                $"Процессов: {rows.Count}  •  Обновлено: {DateTime.Now:HH:mm:ss}";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Ошибка мониторинга: {ex.Message}";
        }
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
