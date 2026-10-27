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
    private readonly Func<string, PeAnalysisResult> _parsePe;
    private readonly Func<PeAnalysisResult, IReadOnlyList<HeuristicFinding>> _analyzePe;
    private readonly Action<string, string>? _logEvent;

    public ScanOrchestrator(
        Action<string, string>? logEvent = null,
        Func<string, CancellationToken, Task<FileScanResult>>? hashFile = null,
        Func<string, PeAnalysisResult>? parsePe = null,
        Func<PeAnalysisResult, IReadOnlyList<HeuristicFinding>>? analyzePe = null)
    {
        _logEvent = logEvent;
        _hashFile = hashFile ?? FileHashService.CalculateSha256Async;
        _parsePe = parsePe ?? PeParser.Parse;
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

            PeAnalysisResult pe = _parsePe(fullPath);
            cancellationToken.ThrowIfCancellationRequested();

            if (pe.FormatStatus == PeFormatStatus.ParseError)
            {
                return Failure(
                    fullPath,
                    pe.ParseError ?? "Не удалось разобрать файл.",
                    identity: identity,
                    pe: pe);
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

            int riskScore = Math.Clamp(
                findings.Sum(finding => Math.Max(0, finding.Weight)), 0, 100);

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
        TryLogError(message);

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

    private void TryLogError(string message)
    {
        try
        {
            _logEvent?.Invoke("FileScanError", message);
        }
        catch
        {
            // A logging failure must not turn a failed scan into a success.
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