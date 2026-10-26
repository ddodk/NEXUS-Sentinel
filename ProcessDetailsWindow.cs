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
        Background = CreateBrush("#080B12");
        Foreground = CreateBrush("#F2F5FF");

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
            Background = CreateBrush("#776BFF"),
            Foreground = Brushes.White,
            BorderThickness = new Thickness(0)
        };

        closeButton.Click += (_, _) => Close();

        footer.Children.Add(closeButton);

        DockPanel.SetDock(footer, Dock.Bottom);
        root.Children.Add(footer);

        var scroll = new ScrollViewer
        {
            VerticalScrollBarVisibility =
                ScrollBarVisibility.Auto
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
            Foreground = CreateBrush("#96A3BB"),
            Margin = new Thickness(0, 0, 0, 18),
            TextWrapping = TextWrapping.Wrap
        });

        AddSection(content, "Основные сведения");

        AddField(content, "Имя процесса", _row.ProcessName);
        AddField(content, "PID", _row.Id.ToString());
        AddField(content, "Память", _row.MemoryText);
        AddField(content, "Загрузка CPU", _row.CpuText);
        AddField(content, "Путь к файлу", _row.PathText);

        AddSection(content, "Сведения о файле");

        string path = _row.PathText;

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
                "Сведения о сертификате",
                "Файл недоступен для проверки.");
        }
        else
        {
            ReadFileDetails(content, path);
        }

        content.Children.Add(new TextBlock
        {
            Text =
                "Важно: наличие сертификата само по себе не " +
                "подтверждает безопасность файла. Полноценная " +
                "проверка цифровой подписи Authenticode здесь " +
                "не выполняется. Отсутствие сертификата не " +
                "доказывает, что файл вредоносный.",
            TextWrapping = TextWrapping.Wrap,
            Foreground = CreateBrush("#E9C878"),
            Background = CreateBrush("#202033"),
            Padding = new Thickness(12),
            Margin = new Thickness(0, 16, 0, 8)
        });

        scroll.Content = content;
        root.Children.Add(scroll);

        Content = root;
    }

    private void ReadFileDetails(
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

            var fileInfo = new FileInfo(path);

            AddField(
                content,
                "Размер файла",
                $"{fileInfo.Length / 1024.0:F1} KB");
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
            using Process process =
                Process.GetProcessById(_row.Id);

            DateTime startTime = process.StartTime;

            AddField(
                content,
                "Время запуска",
                startTime.ToString("yyyy-MM-dd HH:mm:ss"));
        }
        catch
        {
            AddField(
                content,
                "Время запуска",
                "Недоступно: доступ ограничен или процесс завершился.");
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

            using var certificate2 =
                new X509Certificate2(certificate);

            AddField(
                content,
                "Срок действия сертификата",
                $"{certificate2.NotBefore:yyyy-MM-dd} — " +
                $"{certificate2.NotAfter:yyyy-MM-dd}");

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
                "Сертификат не найден или его не удалось прочитать.");
        }
    }

    private static string EmptyAsUnavailable(string? value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? "Нет данных"
            : value;
    }

    private static void AddSection(
        Panel panel,
        string title)
    {
        panel.Children.Add(new TextBlock
        {
            Text = title,
            FontSize = 15,
            FontWeight = FontWeights.SemiBold,
            Foreground = CreateBrush("#A9A0FF"),
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
            Background = CreateBrush("#151C2D"),
            BorderBrush = CreateBrush("#28344B"),
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
            Foreground = CreateBrush("#96A3BB"),
            TextWrapping = TextWrapping.Wrap
        });

        stack.Children.Add(new TextBox
        {
            Text = value,
            FontSize = 13,
            Margin = new Thickness(0, 4, 0, 0),
            TextWrapping = TextWrapping.Wrap,
            IsReadOnly = true,
            BorderThickness = new Thickness(0),
            Background = Brushes.Transparent,
            Foreground = CreateBrush("#F2F5FF"),
            Padding = new Thickness(0),
            IsReadOnlyCaretVisible = false
        });

        card.Child = stack;
        panel.Children.Add(card);
    }

    private static SolidColorBrush CreateBrush(string color)
    {
        return new SolidColorBrush(
            (Color)ColorConverter.ConvertFromString(color));
    }
}

