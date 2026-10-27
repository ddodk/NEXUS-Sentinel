
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using NEXUS.Sentinel.Models;

namespace NEXUS.Sentinel.Services;

public static class FileHashService
{
    public static async Task<FileScanResult> CalculateSha256Async(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return Failure(filePath, "Путь к файлу не указан.");

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

            using var sha256 = IncrementalHash.CreateHash(
                HashAlgorithmName.SHA256);
            using var sha512 = IncrementalHash.CreateHash(
                HashAlgorithmName.SHA512);
            byte[] buffer = new byte[81920];

            while (true)
            {
                int bytesRead = await stream.ReadAsync(
                    buffer.AsMemory(), cancellationToken);

                if (bytesRead == 0)
                    break;

                sha256.AppendData(buffer, 0, bytesRead);
                sha512.AppendData(buffer, 0, bytesRead);
            }

            return new FileScanResult
            {
                FilePath = filePath,
                Sha256 = Convert.ToHexString(sha256.GetHashAndReset()),
                Sha512 = Convert.ToHexString(sha512.GetHashAndReset()),
                FileSizeBytes = fileSize,
                LastWriteUtc = File.GetLastWriteTimeUtc(filePath),
                CheckedAt = DateTime.Now,
                Success = true,
                Status = "Хеш вычислен успешно"
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (OutOfMemoryException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            return Failure(filePath, "Нет разрешения на чтение файла.");
        }
        catch (FileNotFoundException)
        {
            return Failure(filePath, "Файл не найден или был удалён.");
        }
        catch (DirectoryNotFoundException)
        {
            return Failure(filePath, "Каталог файла не найден.");
        }
        catch (IOException ex)
        {
            return Failure(filePath, $"Ошибка чтения файла: {ex.Message}");
        }
        catch (Exception ex)
        {
            return Failure(
                filePath,
                $"Не удалось вычислить SHA-256: {ex.Message}");
        }
    }

    private static FileScanResult Failure(
        string? filePath, string error)
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
