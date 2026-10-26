
using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
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
        Height = 700;
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

        AddSection(content, "Метаданные файла");

        string path = _row.PathText;

        bool fileAvailable =
            !string.IsNullOrWhiteSpace(path)
            && path != "Недоступен"
            && File.Exists(path);

        if (fileAvailable)
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
                    "Метаданные",
                    $"Недоступны: {ex.Message}");
            }

            try
            {
                using Process process =
                    Process.GetProcessById(_row.Id);

                AddField(
                    content,
                    "Время запуска",
                    process.StartTime.ToString("yyyy-MM-dd HH:mm:ss"));
            }
            catch
            {
                AddField(
                    content,
                    "Время запуска",
                    "Недоступно: доступ ограничен или процесс завершился.");
            }
        }
        else
        {
            AddField(
                content,
                "Файл",
                "Путь недоступен или файл уже не существует.");
        }

        var signaturePanel = new StackPanel();

        AddSection(signaturePanel, "Проверка Authenticode");

        AddField(
            signaturePanel,
            "Статус",
            fileAvailable
                ? "Проверка выполняется..."
                : "Невозможно проверить: файл недоступен.");

        content.Children.Add(signaturePanel);

        content.Children.Add(new TextBlock
        {
            Text =
                "Действительная подпись не гарантирует безопасность " +
                "программы. Отсутствие подписи само по себе не " +
                "означает, что файл вредоносный. Для проверки " +
                "используется системный механизм Windows; проверка " +
                "может зависеть от доступности сертификатов и " +
                "инфраструктуры доверия.",
            TextWrapping = TextWrapping.Wrap,
            Foreground = CreateBrush("#E9C878"),
            Background = CreateBrush("#202033"),
            Padding = new Thickness(12),
            Margin = new Thickness(0, 16, 0, 8)
        });

        scroll.Content = content;
        root.Children.Add(scroll);

        Content = root;

        if (fileAvailable)
            _ = LoadSignatureAsync(signaturePanel, path);
    }

    private async Task LoadSignatureAsync(
        Panel panel,
        string path)
    {
        AuthenticodeResult result;

        try
        {
            result = await Task.Run(
                () => AuthenticodeVerifier.Verify(path));
        }
        catch (Exception ex)
        {
            result = new AuthenticodeResult
            {
                Status = "CheckFailed",
                Error = ex.Message
            };
        }

        if (!IsLoaded)
            return;

        panel.Children.Clear();

        AddSection(panel, "Проверка Authenticode");
            
string statusText = result.Status switch
{
    "Valid" =>
        "Действительная подпись",

    "NotSigned" =>
        "Подпись отсутствует",

    "HashMismatch" =>
        "Хеш файла не соответствует подписи",

    "NotTrusted" =>
        "Подписант не считается доверенным",

    "UnknownError" =>
        "Не удалось определить статус подписи",

    "CheckFailed" =>
        "Проверка не завершена",

    _ =>
        $"Статус Windows: {result.Status}"
};


        AddField(panel, "Результат", statusText);

        if (!string.IsNullOrWhiteSpace(result.StatusMessage))
        {
            AddField(
                panel,
                "Сообщение Windows",
                result.StatusMessage);
        }

        if (!string.IsNullOrWhiteSpace(result.Signer))
        {
            AddField(
                panel,
                "Подписант",
                result.Signer);
        }

        if (!string.IsNullOrWhiteSpace(result.Issuer))
        {
            AddField(
                panel,
                "Издатель сертификата",
                result.Issuer);
        }

        if (!string.IsNullOrWhiteSpace(result.NotBefore)
            && DateTimeOffset.TryParse(
                result.NotBefore,
                out DateTimeOffset notBefore))
        {
            AddField(
                panel,
                "Сертификат действителен с",
                notBefore.ToLocalTime().ToString("yyyy-MM-dd"));
        }

        if (!string.IsNullOrWhiteSpace(result.NotAfter)
            && DateTimeOffset.TryParse(
                result.NotAfter,
                out DateTimeOffset notAfter))
        {
            AddField(
                panel,
                "Сертификат действителен до",
                notAfter.ToLocalTime().ToString("yyyy-MM-dd"));
        }

        if (!string.IsNullOrWhiteSpace(result.Error))
        {
            AddField(
                panel,
                "Ошибка",
                result.Error);
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
            Padding = new Thickness(0)
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
