using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NEXUS.Sentinel.Data;
using NEXUS.Sentinel.Models;
using NEXUS.Sentinel.Services;

namespace NexusSentinel.Engine;

public static class FileScanPipeline
{
    public static async Task<ScanResult> AnalyzeFileAsync(
        string filePath,
        EventStore? eventStore = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            string path = filePath ?? string.Empty;
            var emptyFile = new FileIdentity(
                path,
                new HashResult(string.Empty, string.Empty, 0, DateTime.UtcNow),
                DateTime.UtcNow);

            return CreateErrorResult(
                emptyFile,
                "File path is empty.",
                Array.Empty<HeuristicFinding>(),
                eventStore,
                "File path is empty.");
        }

        var heuristics = new List<HeuristicFinding>();
        var verdict = Verdict.Clean;
        int riskScore = 0;
        PeAnalysisResult? pe = null;

        try
        {
            pe = PeParser.Parse(filePath);

            if (pe.FormatStatus == PeFormatStatus.ParseError)
            {
                var errorText = pe.ParseError ?? "PE parse error.";
                Log(eventStore, "FileScanParseError",
                    $"PE parse failed for {filePath}: {errorText}");

                return CreateErrorResult(
                    new FileIdentity(
                        filePath,
                        new HashResult(string.Empty, string.Empty, 0, DateTime.UtcNow),
                        DateTime.UtcNow),
                    errorText,
                    heuristics,
                    eventStore,
                    errorText);
            }

            if (pe.FormatStatus == PeFormatStatus.PeCorrupted)
            {
                var finding = new HeuristicFinding(
                    "PE_CORRUPTED",
                    pe.ParseError ?? "PE structure is corrupted.",
                    25,
                    "PE structure failed validation.");

                verdict = ApplyHeuristic(verdict, heuristics, finding);
                riskScore += finding.Weight;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (OutOfMemoryException ex)
        {
            Log(eventStore, "FileScanOutOfMemory",
                $"Out-of-memory while scanning {filePath}: {ex.Message}");

            return CreateErrorResult(
                new FileIdentity(
                    filePath,
                    new HashResult(string.Empty, string.Empty, 0, DateTime.UtcNow),
                    DateTime.UtcNow),
                ex.Message,
                heuristics,
                eventStore,
                ex.Message);
        }
        catch (Exception ex)
        {
            Log(eventStore, "FileScanUnexpectedError",
                $"Unexpected scan error for {filePath}: {ex.Message}");

            return CreateErrorResult(
                new FileIdentity(
                    filePath,
                    new HashResult(string.Empty, string.Empty, 0, DateTime.UtcNow),
                    DateTime.UtcNow),
                ex.Message,
                heuristics,
                eventStore,
                ex.Message);
        }

        FileScanResult hashResult;

        try
        {
            hashResult = await FileHashService.CalculateSha256Async(
                filePath,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (OutOfMemoryException ex)
        {
            Log(eventStore, "FileScanOutOfMemory",
                $"Out-of-memory while hashing {filePath}: {ex.Message}");

            return CreateErrorResult(
                new FileIdentity(
                    filePath,
                    new HashResult(string.Empty, string.Empty, 0, DateTime.UtcNow),
                    DateTime.UtcNow),
                ex.Message,
                heuristics,
                eventStore,
                ex.Message);
        }
        catch (Exception ex)
        {
            Log(eventStore, "FileScanHashError",
                $"Hash failure for {filePath}: {ex.Message}");

            return CreateErrorResult(
                new FileIdentity(
                    filePath,
                    new HashResult(string.Empty, string.Empty, 0, DateTime.UtcNow),
                    DateTime.UtcNow),
                ex.Message,
                heuristics,
                eventStore,
                ex.Message);
        }

        if (!hashResult.Success)
        {
            string errorText = hashResult.Error ?? "SHA-256 calculation failed.";
            Log(eventStore, "FileScanHashError",
                $"Hash check failed for {filePath}: {errorText}");

            return CreateErrorResult(
                new FileIdentity(
                    filePath,
                    new HashResult(hashResult.Sha256 ?? string.Empty,
                        string.Empty,
                        hashResult.FileSizeBytes,
                        DateTime.UtcNow),
                    DateTime.UtcNow),
                errorText,
                heuristics,
                eventStore,
                errorText);
        }

        var identity = new FileIdentity(
            filePath,
            new HashResult(
                hashResult.Sha256,
                string.Empty,
                hashResult.FileSizeBytes,
                DateTime.UtcNow),
            DateTime.UtcNow);

        var outcome = verdict switch
        {
            Verdict.Clean => ScanOutcome.Clean,
            Verdict.Suspicious => ScanOutcome.Suspicious,
            Verdict.Malicious => ScanOutcome.Malicious,
            _ => ScanOutcome.Error
        };

        return new ScanResult(
            identity,
            outcome,
            verdict,
            riskScore,
            heuristics,
            pe,
            null,
            null,
            null);
    }

    internal static Verdict ApplyHeuristic(
        Verdict currentVerdict,
        ICollection<HeuristicFinding> existingFindings,
        HeuristicFinding finding)
    {
        if (existingFindings.Any(item =>
                string.Equals(item.RuleId, finding.RuleId,
                    StringComparison.Ordinal)))
        {
            return currentVerdict;
        }

        existingFindings.Add(finding);

        if (currentVerdict == Verdict.Malicious)
            return Verdict.Malicious;

        return currentVerdict == Verdict.Clean
            ? Verdict.Suspicious
            : currentVerdict;
    }

    private static void Log(
        EventStore? eventStore,
        string type,
        string message)
    {
        eventStore?.Add(type, message);
    }

    private static ScanResult CreateErrorResult(
        FileIdentity file,
        string error,
        IReadOnlyList<HeuristicFinding> heuristics,
        EventStore? eventStore,
        string? eventMessage)
    {
        Log(eventStore, "FileScanError", eventMessage ?? error);

        return new ScanResult(
            file,
            ScanOutcome.Error,
            Verdict.Suspicious,
            0,
            heuristics,
            null,
            null,
            null,
            error);
    }
}
