using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NEXUS.Sentinel.Models;
using NEXUS.Sentinel.Services;

namespace NexusSentinel.Engine;

public sealed class ScanOrchestrator
{
    private const string PeCorruptedRuleId = "PE_CORRUPTED";

    private readonly Func<string, CancellationToken, Task<FileScanResult>> _hashFile;
    private readonly Func<string, CancellationToken, PeAnalysisResult> _parsePe;
    private readonly Func<PeAnalysisResult, IReadOnlyList<HeuristicFinding>> _analyzePe;
    private readonly Action<string, string>? _logEvent;

    public ScanOrchestrator(
        Action<string, string>? logEvent = null,
        Func<string, CancellationToken, Task<FileScanResult>>? hashFile = null,
        Func<string, PeAnalysisResult>? parsePe = null,
        Func<PeAnalysisResult, IReadOnlyList<HeuristicFinding>>? analyzePe = null,
        Func<string, CancellationToken, PeAnalysisResult>? parsePeWithCancellation = null)
    {
        _logEvent = logEvent;
        _hashFile = hashFile ?? FileHashService.CalculateSha256Async;
        _parsePe = parsePeWithCancellation ??
            (parsePe is null
                ? PeParser.Parse
                : (path, _) => parsePe(path));
        _analyzePe = analyzePe ?? (_ => Array.Empty<HeuristicFinding>());
    }

    public async Task<ScanResult> ScanAsync(
        string? path,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(path))
            return Failure(path, "Путь к файлу не указан.");

        string fullPath;

        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception ex) when (
            ex is ArgumentException ||
            ex is NotSupportedException ||
            ex is PathTooLongException)
        {
            return Failure(path, $"Некорректный путь к файлу: {ex.Message}");
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            await using var analysisGuard = new FileStream(
                fullPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 4096,
                options: FileOptions.Asynchronous |
                         FileOptions.SequentialScan);

            FileScanResult hash = await _hashFile(
                fullPath, cancellationToken);

            if (!hash.Success)
            {
                return Failure(
                    fullPath,
                    hash.Error ?? hash.Status,
                    hash);
            }

                    cancellationToken.ThrowIfCancellationRequested();

            var identity = new FileIdentity(
                fullPath,
                new HashResult(
                    hash.Sha256,
                    hash.Sha512,
                    hash.FileSizeBytes,
                    hash.LastWriteUtc),
                DateTime.UtcNow);

            if (!FileMatchesHash(fullPath, hash))
            {
                return Failure(
                    fullPath,
                    "Файл изменился после вычисления хеша.",
                    hash,
                    identity: identity);
            }

            PeAnalysisResult pe = await Task.Run(
                () => _parsePe(fullPath, cancellationToken),
                cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();

            if (pe.FormatStatus == PeFormatStatus.ParseError)
            {
                return Failure(
                    fullPath,
                    pe.ParseError ?? "Не удалось разобрать файл.",
                    identity: identity,
                    pe: pe);
            }

            if (!FileMatchesHash(fullPath, hash))
            {
                    return Failure(
                        fullPath,
                        "Файл изменился во время анализа.",
                        hash,
                        identity,
                        pe);
            }

            IReadOnlyList<HeuristicFinding> analyzedFindings =
                pe.FormatStatus == PeFormatStatus.NotPe
                    ? Array.Empty<HeuristicFinding>()
                    : _analyzePe(pe);

            var findings = analyzedFindings
                .Where(finding => !string.Equals(
                    finding.RuleId,
                    PeCorruptedRuleId,
                    StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (pe.FormatStatus == PeFormatStatus.PeCorrupted)
            {
                findings.Add(new HeuristicFinding(
                    PeCorruptedRuleId,
                    "Структура PE повреждена или некорректна.",
                    25,
                    pe.ParseError ?? "Обнаружена некорректная структура PE."));
            }

            int riskScore = (int)Math.Min(
                100L,
                findings.Sum(finding => (long)Math.Max(0, finding.Weight)));

            Verdict verdict = riskScore >= 75
                ? Verdict.Malicious
                : findings.Count == 0 || riskScore >= 25
                    ? Verdict.Suspicious
                    : Verdict.Clean;

            return new ScanResult(
                identity,
                ToOutcome(verdict),
                verdict,
                riskScore,
                findings,
                pe,
                null,
                null,
                null);
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
            return Failure(
                fullPath,
                $"Непредвиденная ошибка сканирования: {ex.Message}");
        }
    }

    private ScanResult Failure(
        string? path,
        string message,
        FileScanResult? hash = null,
        FileIdentity? identity = null,
        PeAnalysisResult? pe = null)
    {
        TryLogError();

        identity ??= new FileIdentity(
            path ?? string.Empty,
            new HashResult(
                hash?.Sha256 ?? string.Empty,
                hash?.Sha512 ?? string.Empty,
                hash?.FileSizeBytes ?? 0,
                hash?.LastWriteUtc ?? DateTime.MinValue),
            DateTime.UtcNow);

        return new ScanResult(
            identity,
            ScanOutcome.Error,
            Verdict.Suspicious,
            0,
            Array.Empty<HeuristicFinding>(),
            pe,
            null,
            null,
            message);
    }

    private void TryLogError()
    {
        try
        {
            _logEvent?.Invoke(
                "FileScanError",
                "Ошибка сканирования файла.");
        }
        catch
        {
            // A logging failure must not turn a failed scan into a success.
        }
    }

    private static bool FileMatchesHash(
        string path,
        FileScanResult hash)
    {
        try
        {
            var file = new FileInfo(path);
            file.Refresh();

            return file.Exists
                && file.Length == hash.FileSizeBytes
                && file.LastWriteTimeUtc == hash.LastWriteUtc;
        }
        catch (Exception ex) when (
            ex is IOException ||
            ex is UnauthorizedAccessException ||
            ex is ArgumentException ||
            ex is NotSupportedException)
        {
            return false;
        }
    }

    private static ScanOutcome ToOutcome(Verdict verdict)
    {
        return verdict switch
        {
            Verdict.Malicious => ScanOutcome.Malicious,
            Verdict.Suspicious => ScanOutcome.Suspicious,
            _ => ScanOutcome.Clean
        };
    }
}