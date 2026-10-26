using System.Security.Cryptography;
using NEXUS.Sentinel.Models;

namespace NEXUS.Sentinel.Services;

public static class FileHashService
{
    public static async Task<FileScanResult> CalculateSha256Async(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return Failure(filePath, "Путь к файлу не указан.");
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            await using var stream = new FileStream(
                filePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 81920,
                options: FileOptions.Asynchronous |
                         FileOptions.SequentialScan);

            long fileSize = stream.Length;

            using var sha256 = SHA256.Create();

            byte[] hash = await sha256.ComputeHashAsync(
                stream,
                cancellationToken);

            string hashText = Convert.ToHexString(hash);

            return new FileScanResult
            {
                FilePath = filePath,
                Sha256 = hashText,
                FileSizeBytes = fileSize,
                CheckedAt = DateTime.Now,
                Success = true,
                Status = "Хеш вычислен успешно"
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            return Failure(
                filePath,
                "Нет разрешения на чтение файла.");
        }
        catch (FileNotFoundException)
        {
            return Failure(
                filePath,
                "Файл не найден или был удалён.");
        }
        catch (DirectoryNotFoundException)
        {
            return Failure(
                filePath,
                "Каталог файла не найден.");
        }
        catch (IOException ex)
        {
            return Failure(
                filePath,
                $"Ошибка чтения файла: {ex.Message}");
        }
        catch (Exception ex)
        {
            return Failure(
                filePath,
                $"Не удалось вычислить SHA-256: {ex.Message}");
        }
    }

    private static FileScanResult Failure(
        string? filePath,
        string error)
    {
        return new FileScanResult
        {
            FilePath = filePath ?? string.Empty,
            CheckedAt = DateTime.Now,
            Success = false,
            Status = "Проверка не выполнена",
            Error = error
        };
    }
}
