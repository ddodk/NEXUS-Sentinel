
using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace NEXUS.Sentinel;

public sealed class AuthenticodeResult
{
    public string Status { get; init; } = "UnknownError";
    public string StatusMessage { get; init; } = "";
    public string Signer { get; init; } = "";
    public string Issuer { get; init; } = "";
    public string NotBefore { get; init; } = "";
    public string NotAfter { get; init; } = "";
    public bool SignerCertificateExpired { get; init; }
    public string Error { get; init; } = "";

    public bool IsValid =>
        string.Equals(
            Status,
            "Valid",
            StringComparison.OrdinalIgnoreCase);
}

public static class AuthenticodeVerifier
{
    public static AuthenticodeResult Verify(string filePath)
    {
        return VerifyAsync(filePath).GetAwaiter().GetResult();
    }

    public static async Task<AuthenticodeResult> VerifyAsync(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(filePath))
        {
            return Failure("Путь к файлу не указан.");
        }

        if (!File.Exists(filePath))
            return Failure("Файл не найден или недоступен.");

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            var startInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            startInfo.ArgumentList.Add("-NoProfile");
            startInfo.ArgumentList.Add("-NonInteractive");
            startInfo.ArgumentList.Add("-Command");

            startInfo.ArgumentList.Add(
                "$ErrorActionPreference = 'Stop'; " +
                "$s = Get-AuthenticodeSignature " +
                "-LiteralPath $env:NEXUS_SENTINEL_FILE; " +
                "$c = $s.SignerCertificate; " +
                "[pscustomobject]@{ " +
                "Status = [string]$s.Status; " +
                "StatusMessage = [string]$s.StatusMessage; " +
                "Signer = if ($c) { $c.Subject } else { '' }; " +
                "Issuer = if ($c) { $c.Issuer } else { '' }; " +
                "NotBefore = if ($c) { $c.NotBefore.ToString('o') } else { '' }; " +
                "NotAfter = if ($c) { $c.NotAfter.ToString('o') } else { '' } " +
                "} | ConvertTo-Json -Compress");

            startInfo.Environment["NEXUS_SENTINEL_FILE"] = filePath;

            using var process = new Process
            {
                StartInfo = startInfo
            };

            if (!process.Start())
                return Failure("Не удалось запустить PowerShell.");

            using var timeout = CancellationTokenSource
                .CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));

            Task<string> outputTask = process.StandardOutput.ReadToEndAsync();
            Task<string> errorTask = process.StandardError.ReadToEndAsync();

            try
            {
                await process.WaitForExitAsync(timeout.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                TryKill(process);
                _ = ObservePipeCompletionAsync(outputTask);
                _ = ObservePipeCompletionAsync(errorTask);

                if (cancellationToken.IsCancellationRequested)
                    throw;

                return Failure(
                    "Проверка превысила лимит времени в 10 секунд.");
            }

            string output = await outputTask.ConfigureAwait(false);
            string error = await errorTask.ConfigureAwait(false);

            if (process.ExitCode != 0)
            {
                return Failure(
                    string.IsNullOrWhiteSpace(error)
                        ? $"PowerShell завершился с кодом {process.ExitCode}."
                        : error.Trim());
            }

            return ParseResult(output);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (OutOfMemoryException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return Failure(ex.Message);
        }
    }

    internal static AuthenticodeResult ParseResult(string output)
    {
        using JsonDocument document = JsonDocument.Parse(output);
        JsonElement root = document.RootElement;

        string status = ReadString(root, "Status");
        string notAfter = ReadString(root, "NotAfter");
        bool certificateExpired =
            string.Equals(status, "NotTrusted", StringComparison.OrdinalIgnoreCase) &&
            DateTimeOffset.TryParse(
                notAfter,
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out DateTimeOffset certificateExpiry) &&
            certificateExpiry < DateTimeOffset.UtcNow;

        return new AuthenticodeResult
        {
            Status = status,
            StatusMessage = ReadString(root, "StatusMessage"),
            Signer = ReadString(root, "Signer"),
            Issuer = ReadString(root, "Issuer"),
            NotBefore = ReadString(root, "NotBefore"),
            NotAfter = notAfter,
            SignerCertificateExpired = certificateExpired
        };
    }

    private static async Task ObservePipeCompletionAsync(Task<string> task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch
        {
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
        }
        catch
        {
        }
    }

    private static string ReadString(
        JsonElement root,
        string property)
    {
        if (!root.TryGetProperty(
                property,
                out JsonElement value))
        {
            return "";
        }

        return value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? ""
            : value.ToString();
    }

    private static AuthenticodeResult Failure(string message)
    {
        return new AuthenticodeResult
        {
            Status = "CheckFailed",
            StatusMessage = "Проверка не завершена.",
            Error = message
        };
    }
}
