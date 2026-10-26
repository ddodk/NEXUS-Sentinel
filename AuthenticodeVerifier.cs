
using System;
using System.Diagnostics;
using System.Text.Json;

namespace NEXUS.Sentinel;

public sealed class AuthenticodeResult
{
    public string Status { get; init; } = "UnknownError";
    public string StatusMessage { get; init; } = "";
    public string Signer { get; init; } = "";
    public string Issuer { get; init; } = "";
    public string NotBefore { get; init; } = "";
    public string NotAfter { get; init; } = "";
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
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return Failure("Путь к файлу не указан.");
        }

        try
        {
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

            if (!process.WaitForExit(10000))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch
                {
                }

                return Failure(
                    "Проверка превысила лимит времени в 10 секунд.");
            }

            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();

            if (process.ExitCode != 0)
            {
                return Failure(
                    string.IsNullOrWhiteSpace(error)
                        ? $"PowerShell завершился с кодом {process.ExitCode}."
                        : error.Trim());
            }

            using JsonDocument document =
                JsonDocument.Parse(output);

            JsonElement root = document.RootElement;

            return new AuthenticodeResult
            {
                Status = ReadString(root, "Status"),
                StatusMessage = ReadString(root, "StatusMessage"),
                Signer = ReadString(root, "Signer"),
                Issuer = ReadString(root, "Issuer"),
                NotBefore = ReadString(root, "NotBefore"),
                NotAfter = ReadString(root, "NotAfter")
            };
        }
        catch (Exception ex)
        {
            return Failure(ex.Message);
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
