
using System;
using System.Diagnostics;
using System.IO;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using NEXUS.Sentinel.Services;

namespace NEXUS.Sentinel;

public sealed class ProcessDetailsWindow : Window
{
    private readonly ProcessRow _row;
    private readonly CancellationTokenSource _windowCancellation = new();

    private readonly TextBlock _sha256Text = new()
    {
        Text = "Нажмите «Вычислить SHA-256»",
        TextWrapping = TextWrapping.Wrap,
        FontSize = 12
    };

    private readonly TextBlock _sha256Status = new()
    {
        Text = "Файл ещё не проверен",
        TextWrapping = TextWrapping.Wrap,
        FontSize = 11
    };

    private Button? _sha256Button;
    private Button? _copyHashButton;

    public ProcessDetailsWindow(ProcessRow row)
    {
        _row = row;
        Closed += (_, _) =>
        {
            _windowCancellation.Cancel();
            _windowCancellation.Dispose();
        };

        Title = $"NEXUS Sentinel — {_row.ProcessName}";
        Width = 720;
        Height = 760;
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

        string path = _row.PathText;

        bool fileAvailable =
            !string.IsNullOrWhiteSpace(path)
            && path != "Недоступен"
            && File.Exists(path);

        var metadataPanel = new StackPanel();
        AddSection(metadataPanel, "Метаданные файла");
        content.Children.Add(metadataPanel);

        if (fileAvailable)
            AddField(metadataPanel, "Статус", "Загрузка метаданных...");
        else
            AddField(
                metadataPanel,
                "Файл",
                "Путь недоступен или файл уже не существует.");

        // SHA-256
        var hashPanel = new StackPanel();

        AddSection(hashPanel, "Целостность файла · SHA-256");

        _sha256Text.Foreground = CreateBrush("#F2F5FF");
        _sha256Text.Margin = new Thickness(0, 4, 0, 8);

        _sha256Status.Foreground = CreateBrush("#96A3BB");
        _sha256Status.Margin = new Thickness(0, 0, 0, 8);

        hashPanel.Children.Add(_sha256Text);
        hashPanel.Children.Add(_sha256Status);

        _sha256Button = new Button
        {
            Content = "Вычислить SHA-256",
            Padding = new Thickness(12, 8, 12, 8),
            HorizontalAlignment = HorizontalAlignment.Left,
            Background = CreateBrush("#776BFF"),
            Foreground = Brushes.White,
            BorderThickness = new Thickness(0),
            IsEnabled = fileAvailable
        };

        _sha256Button.Click += async (_, _) =>
        {
            if (!fileAvailable || _sha256Button == null)
                return;

            _sha256Button.IsEnabled = false;
            _sha256Text.Text = "Вычисление...";
            _sha256Status.Text = "Чтение файла и расчёт хеша.";
            
            if (_copyHashButton != null)
            {
                hashPanel.Children.Remove(_copyHashButton);
                _copyHashButton = null;
            }

            try
            {
                var result =
                    await FileHashService.CalculateSha256Async(
                        path,
                        _windowCancellation.Token);

                if (!IsLoaded)
                    return;

                if (result.Success)
                {
                    _sha256Text.Text = result.Sha256;

                    _sha256Status.Text =
                        $"Успешно · {result.FileSizeBytes:N0} байт · " +
                        result.CheckedAt.ToString("HH:mm:ss");

                    _copyHashButton = new Button
                    {
                        Content = "Копировать SHA-256",
                        Padding = new Thickness(12, 7, 12, 7),
                        Margin = new Thickness(0, 8, 0, 0),
                        HorizontalAlignment = HorizontalAlignment.Left
                    };

                    _copyHashButton.Click += (_, _) =>
                    {
                        try
                        {
                            Clipboard.SetText(result.Sha256);
                            _sha256Status.Text =
                                "Хеш скопирован в буфер обмена.";
                        }
                        catch (Exception ex)
                        {
                            _sha256Status.Text =
                                $"Ошибка копирования: {ex.Message}";
                        }
                    };

                    hashPanel.Children.Add(_copyHashButton);
                }
                else
                {
                    _sha256Text.Text = "Проверка не выполнена";
                    _sha256Status.Text =
                        result.Error ?? result.Status;
                }
            }
            catch (OutOfMemoryException)
            {
                throw;
            }
            catch (Exception ex)
            {
                if (!IsLoaded)
                    return;

                _sha256Text.Text = "Ошибка";
                _sha256Status.Text = ex.Message;
            }
            finally
            {
                if (IsLoaded && _sha256Button != null)
                    _sha256Button.IsEnabled = true;
            }
        };

        hashPanel.Children.Add(_sha256Button);
        content.Children.Add(hashPanel);

        // Authenticode
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
                "означает, что файл вредоносный. SHA-256 позволяет " +
                "сравнивать содержимое файлов, но не определяет " +
                "безопасность файла. Проверка Authenticode использует " +
                "системный механизм Windows.",
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
        {
            Loaded += (_, _) =>
            {
                _ = LoadFileMetadataAsync(
                    metadataPanel,
                    path,
                    _row.Id,
                    _windowCancellation.Token);
                _ = LoadSignatureAsync(signaturePanel, path);
            };
        }
    }

    private async Task LoadFileMetadataAsync(
        Panel panel,
        string path,
        int processId,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<(string Label, string Value)> fields;

        try
        {
            fields = await Task.Run(
                () => ReadFileMetadata(path, processId, cancellationToken),
                cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        catch (OutOfMemoryException)
        {
            throw;
        }
        catch
        {
            if (!IsLoaded)
                return;

            fields = new[] { ("Метаданные", "Недоступны.") };
        }

        if (!IsLoaded)
            return;

        panel.Children.Clear();
        AddSection(panel, "Метаданные файла");

        foreach (var field in fields)
            AddField(panel, field.Label, field.Value);
    }

    private static IReadOnlyList<(string Label, string Value)> ReadFileMetadata(
        string path,
        int processId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var fields = new List<(string Label, string Value)>();

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            FileVersionInfo version = FileVersionInfo.GetVersionInfo(path);
            fields.Add(("Описание", EmptyAsUnavailable(version.FileDescription)));
            fields.Add(("Версия файла", EmptyAsUnavailable(version.FileVersion)));
            fields.Add(("Компания", EmptyAsUnavailable(version.CompanyName)));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (OutOfMemoryException)
        {
            throw;
        }
        catch
        {
            fields.Add(("Метаданные", "Недоступны."));
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            fields.Add((
                "Размер файла",
                $"{new FileInfo(path).Length / 1024.0:F1} KB"));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (OutOfMemoryException)
        {
            throw;
        }
        catch
        {
            fields.Add(("Размер файла", "Недоступен."));
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using Process process = Process.GetProcessById(processId);
            fields.Add((
                "Время запуска",
                process.StartTime.ToString("yyyy-MM-dd HH:mm:ss")));
        }
        catch (OutOfMemoryException)
        {
            throw;
        }
        catch
        {
            fields.Add((
                "Время запуска",
                "Недоступно: доступ ограничен или процесс завершился."));
        }

        return fields;
    }

    private async Task LoadSignatureAsync(
        Panel panel,
        string path)
    {
        AuthenticodeResult result;

        try
        {
            result = await AuthenticodeVerifier.VerifyAsync(
                path,
                _windowCancellation.Token);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        catch (OutOfMemoryException)
        {
            throw;
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
