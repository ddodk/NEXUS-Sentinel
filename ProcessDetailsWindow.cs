
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace NEXUS.Sentinel;

public sealed class ProcessDetailsWindow : Window
{
    private readonly ProcessRow _row;

    public ProcessDetailsWindow(ProcessRow row)
    {
        _row = row;

        Title = $"NEXUS Sentinel — {_row.ProcessName}";
        Width = 720;
        Height = 620;
        MinWidth = 520;
        MinHeight = 420;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = Brush("#080B12");
        Foreground = Brush("#F2F5FF");

        var root = new DockPanel
        {
            Margin = new Thickness(22)
        };

        var footer = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 14, 0, 0)
        };

        var closeButton = new Button
        {
            Content = "Закрыть",
            Padding = new Thickness(20, 9, 20, 9),
            Background = Brush("#776BFF"),
            Foreground = Brushes.White,
            BorderThickness = new Thickness(0)
        };

        closeButton.Click += (_, _) => Close();
        footer.Children.Add(closeButton);

        DockPanel.SetDock(footer, Dock.Bottom);
        root.Children.Add(footer);

        var scroll = new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto
        };

        var content = new StackPanel();

        content.Children.Add(new TextBlock
        {
            Text = "КАРТОЧКА ПРОЦЕССА",
            FontSize = 23,
            FontWeight = FontWeights.Bold,
            Margin = new Thickness(0, 0, 0, 6)
        });

        content.Children.Add(new TextBlock
        {
            Text = "Сведения, доступные текущему пользователю Windows",
            FontSize = 12,
            Foreground = Brush("#96A3BB"),
            Margin = new Thickness(0, 0, 0, 18)
        });

        AddSection(content, "Основные сведения");
        AddField(content, "Имя процесса", _row.ProcessName);
        AddField(content, "PID", _row.Id.ToString());
        AddField(content, "Память", _row.MemoryText);
        AddField(content, "Загрузка CPU", _row.CpuText);
        AddField(content, "Путь к файлу", _row.PathText);

        AddSection(content, "Сведения о файле");

        string? path = _row.PathText;

        if (string.IsNullOrWhiteSpace(path)
            || path == "Недоступен"
            || !File.Exists(path))
        {
            AddField(
                content,
                "Файл",
                "Путь недоступен или файл уже не существует.");

            AddField(
                content,
                "Время запуска",
                "Недоступно");

            AddField(
                content,
                "Версия и издатель",
                "Недоступны");

            AddField(
                content,
                "Сертификат",
                "Не удалось проверить: файл недоступен.");
        }
        else
        {
            ReadFileDetails(content, path);
        }

        content.Children.Add(new TextBlock
        {
            Text =
                "Важно: сведения о сертификате сами по себе " +
                "не подтверждают подлинность файла. Эта карточка " +
                "не выполняет полноценную проверку Authenticode " +
                "и не определяет, является ли процесс вредоносным.",
            TextWrapping = TextWrapping.Wrap,
            Foreground = Brush("#E9C878"),
            Background = Brush("#202033"),
            Padding = new Thickness(12),
            Margin = new Thickness(0, 16, 0, 8)
        });

        scroll.Content = content;
        root.Children.Add(scroll);
        Content = root;
    }

    private static void ReadFileDetails(
        Panel content,
        string path)
    {
        try
        {
            var version = FileVersionInfo.GetVersionInfo(path);

            AddField(
                content,
                "Описание",
                EmptyAsUnavailable(version.FileDescription));

            AddField(
                content,
                "Версия файла",
                EmptyAsUnavailable(version.FileVersion));

            AddField(
                content,
                "Компания",
                EmptyAsUnavailable(version.CompanyName));

            AddField(
                content,
                "Размер файла",
                $"{new FileInfo(path).Length / 1024.0:F1} KB");
        }
        catch (Exception ex)
        {
            AddField(
                content,
                "Метаданные файла",
                $"Недоступны: {ex.Message}");
        }

        try
        {
            using Process process = Process.GetProcessById(
                GetCurrentPidForLookup(content, path));

            DateTime startTime = process.StartTime;

            AddField(
                content,
                "Время запуска",
                startTime.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"));
        }
        catch
        {
            AddField(
                content,
                "Время запуска",
                "Недоступно: Windows ограничила доступ или процесс завершился.");
        }

        try
        {
            using X509Certificate certificate =
                X509Certificate.CreateFromSignedFile(path);

            AddField(
                content,
                "Субъект сертификата",
                certificate.Subject);

            AddField(
                content,
                "Издатель сертификата",
                certificate.Issuer);

            using var certificate2 = new X509Certificate2(certificate);

            AddField(
                content,
                "Срок действия сертификата",
                $"{certificate2.NotBefore.ToLocalTime():yyyy-MM-dd} — " +
                $"{certificate2.NotAfter.ToLocalTime():yyyy-MM-dd}");

            AddField(
                content,
                "Статус проверки подписи",
                "Криптографическая проверка не выполнялась.");
        }
        catch
        {
            AddField(
                content,
                "Сведения о сертификате",
                "Сертификат не найден или его не удалось прочитать. " +
                "Это не доказывает, что файл вредоносный.");
        }
    }

    private int GetCurrentPidForLookup(Panel content, string path)
    {
        return _row.Id;
    }

    private static string EmptyAsUnavailable(string? value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? "Нет данных"
            : value;
    }

    private static void AddSection(Panel panel, string title)
    {
        panel.Children.Add(new TextBlock
        {
            Text = title,
            FontSize = 15,
            FontWeight = FontWeights.SemiBold,
            Foreground = Brush("#A9A0FF"),
            Margin = new Thickness(0, 12, 0, 8)
        });
    }

    private static void AddField(
        Panel panel,
        string label,
        string value)
    {
        var card = new Border
        {
            Background = Brush("#151C2D"),
            BorderBrush = Brush("#28344B"),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(7),
            Padding = new Thickness(11),
            Margin = new Thickness(0, 0, 0, 7)
        };

        var stack = new StackPanel();

        stack.Children.Add(new TextBlock
        {
            Text = label,
            FontSize = 11,
            Foreground = Brush("#96A3BB")
        });

        stack.Children.Add(new TextBlock
        {
            Text = value,
            FontSize = 13,
            Margin = new Thickness(0, 4, 0, 0),
            TextWrapping = TextWrapping.Wrap,
            IsTextSelectionEnabled = true
        });

        card.Child = stack;
        panel.Children.Add(card);
    }

    private static SolidColorBrush Brush(string color)
    {
        return new SolidColorBrush(
            (Color)ColorConverter.ConvertFromString(color));
    }
}
