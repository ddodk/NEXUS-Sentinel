
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace NEXUS.Sentinel.Data;

public sealed class SentinelEvent
{
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    public string Type { get; set; } = "";
    public string Message { get; set; } = "";
    public int? ProcessId { get; set; }
}

public sealed class EventStore
{
    private readonly object _sync = new();
    private readonly string _filePath;
    private readonly int _maxEvents;
    private readonly List<SentinelEvent> _events = new();

    public EventStore(int maxEvents = 2000)
    {
        _maxEvents = Math.Clamp(maxEvents, 100, 20000);

        string directory = Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData),
            "NEXUS", "Sentinel");

        _filePath = Path.Combine(directory, "events.json");

        Load();
    }

    public IReadOnlyList<SentinelEvent> GetRecentEvents(int count = 100)
    {
        lock (_sync)
        {
            return _events
                .TakeLast(Math.Clamp(count, 1, _maxEvents))
                .Reverse()
                .ToList();
        }
    }

    public void Add(
        string type,
        string message,
        int? processId = null)
    {
        lock (_sync)
        {
            _events.Add(new SentinelEvent
            {
                TimestampUtc = DateTime.UtcNow,
                Type = type,
                Message = message,
                ProcessId = processId
            });

            if (_events.Count > _maxEvents)
            {
                _events.RemoveRange(
                    0, _events.Count - _maxEvents);
            }

            Save();
        }
    }

    private void Load()
    {
        lock (_sync)
        {
            try
            {
                if (!File.Exists(_filePath))
                    return;

                string json = File.ReadAllText(_filePath);

                var loaded =
                    JsonSerializer.Deserialize<List<SentinelEvent>>(json);

                if (loaded is not null)
                {
                    _events.AddRange(
                        loaded.TakeLast(_maxEvents));
                }
            }
            catch
            {
                // Повреждённый журнал не должен останавливать приложение.
            }
        }
    }

    private void Save()
    {
        try
        {
            string? directory = Path.GetDirectoryName(_filePath);

            if (directory is null)
                return;

            Directory.CreateDirectory(directory);

            string json = JsonSerializer.Serialize(
                _events,
                new JsonSerializerOptions { WriteIndented = true });

            string temporaryPath = _filePath + ".tmp";

            File.WriteAllText(temporaryPath, json);
            File.Move(temporaryPath, _filePath, true);
        }
        catch
        {
            // Ошибку сохранения позже выведем в диагностику.
        }
    }
}
