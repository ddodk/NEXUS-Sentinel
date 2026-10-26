
using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using NEXUS.Sentinel.Data;
using Microsoft.Win32;

namespace NEXUS.Sentinel;

public partial class EventLogWindow : Window
{
    private readonly EventStore _eventStore;

    public EventLogWindow(EventStore eventStore)
    {
        InitializeComponent();

        _eventStore = eventStore;

        LoadEvents();
    }

    private void LoadEvents()
    {
        try
        {
            string query = SearchBox.Text.Trim();

            var events = _eventStore.GetRecentEvents(2000)
                .Where(item =>
                    query.Length == 0
                    || item.Type.Contains(
                        query,
                        StringComparison.OrdinalIgnoreCase)
                    || item.Message.Contains(
                        query,
                        StringComparison.OrdinalIgnoreCase)
                    || item.ProcessId?.ToString().Contains(query) == true)
                .Select(item => new EventLogRow
                {
                    TimestampText = item.TimestampUtc.ToString(
                        "yyyy-MM-dd HH:mm:ss"),
                    Type = item.Type,
                    ProcessIdText = item.ProcessId?.ToString() ?? "—",
                    Message = item.Message
                })
                .ToList();

            EventsGrid.ItemsSource = events;
            CountText.Text = $"Записей: {events.Count}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Не удалось загрузить журнал:\n{ex.Message}",
                "NEXUS Sentinel",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    private void SearchBox_TextChanged(
        object sender,
        TextChangedEventArgs e)
    {
        if (IsLoaded)
            LoadEvents();
    }

    private void RefreshButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        LoadEvents();
    }

    private void ExportButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        try
        {
            var dialog = new SaveFileDialog
            {
                Title = "Экспорт журнала событий",
                Filter = "JSON (*.json)|*.json",
                FileName = $"NEXUS-Sentinel-events-{DateTime.Now:yyyyMMdd-HHmmss}.json",
                DefaultExt = ".json",
                AddExtension = true
            };

            if (dialog.ShowDialog(this) != true)
                return;

            var events = _eventStore.GetRecentEvents(2000);

            string json = JsonSerializer.Serialize(
                events,
                new JsonSerializerOptions
                {
                    WriteIndented = true
                });

            File.WriteAllText(dialog.FileName, json);

            MessageBox.Show(
                $"Журнал экспортирован:\n{dialog.FileName}",
                "NEXUS Sentinel",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Ошибка экспорта:\n{ex.Message}",
                "NEXUS Sentinel",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }
}

public sealed class EventLogRow
{
    public string TimestampText { get; set; } = "";
    public string Type { get; set; } = "";
    public string ProcessIdText { get; set; } = "";
    public string Message { get; set; } = "";
}
