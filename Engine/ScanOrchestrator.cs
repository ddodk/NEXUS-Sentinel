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

public static class ScanOrchestrator
{
    public static async Task<ScanResult> AnalyzeFileAsync(
        string filePath,
        EventStore? eventStore = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return Fail(
                filePath,
                "File path is empty.",
                eventStore,
                "FileScanInvalidInput");
        }

        if (!File.Exists(filePath))
        {
            return Fail(
                filePath,
                "File does not exist.",
                eventStore,
                "FileScanMissingFile");
        }

        var identity = new FileIdentity(
            filePath,
            new HashResult(string.Empty, string.Empty, 0, DateTime.UtcNow),
            DateTime.UtcNow);

        try
        {
            FileScanResult hashResult = await FileHashService.CalculateSha256Async(
                filePath,
                cancellationToken).ConfigureAwait(false);

            if (!hashResult.Success)
            {
                string errorText = hashResult.Error ?? "SHA-256 calculation failed.";
                Log(eventStore, "FileScanHashError", $"Hash check failed for {filePath}: {errorText}");
                return Fail(filePath, errorText, eventStore, "FileScanHashError");
            }

            identity = new FileIdentity(
                filePath,
                new HashResult(
                    hashResult.Sha256,
                    string.Empty,
                    hashResult.FileSizeBytes,
                    DateTime.UtcNow),
                DateTime.UtcNow);

            var heuristics = new List<HeuristicFinding>();
            Verdict verdict = Verdict.Clean;
            int riskScore = 0;

            PeAnalysisResult pe = PeParser.Parse(filePath);

            if (pe.FormatStatus == PeFormatStatus.ParseError)
            {
                string errorText = pe.ParseError ?? "PE parse error.";
                Log(eventStore, "FileScanParseError", $"PE parse failed for {filePath}: {errorText}");

                return new ScanResult(
                    identity,
                    ScanOutcome.Error,
                    Verdict.Suspicious,
                    riskScore,
                    heuristics,
                    pe,
                    null,
                    null,
                    errorText);
            }

            if (pe.FormatStatus == PeFormatStatus.PeCorrupted)
            {
                AddHeuristic(
                    heuristics,
                    ref verdict,
                    ref riskScore,
                    "PE_CORRUPTED",
                    pe.ParseError ?? "PE structure is corrupted.",
                    25,
                    "PE structure failed validation.");

                Log(eventStore, "FileScanPeCorrupted",$"PE structure is corrupted for {filePath}.");
            }

            ScanOutcome outcome = verdict switch
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
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (OutOfMemoryException ex)
        {
            Log(eventStore, "FileScanOutOfMemory", $"Out-of-memory while scanning {filePath}: {ex.Message}");
            return Fail(
                filePath,
                ex.Message,
                eventStore,
                "FileScanOutOfMemory");
        }
        catch (Exception ex)
        {
            Log(eventStore, "FileScanUnexpectedError", $"Unexpected error while scanning {filePath}: {ex.Message}");
            return Fail(
                filePath,
                ex.Message,
                eventStore,
                "FileScanUnexpectedError");
        }
    }

    private static ScanResult Fail(
        string? filePath,
        string error,
        EventStore? eventStore,
        string eventType)
    {
        string safePath = filePath ?? string.Empty;
        Log(eventStore, eventType, $"Scanning failed for {safePath}: {error}");

        return new ScanResult(
            new FileIdentity(
                safePath,
                new HashResult(string.Empty, string.Empty, 0, DateTime.UtcNow),
                DateTime.UtcNow),
            ScanOutcome.Error,
            Verdict.Suspicious,
            0,
            Array.Empty<HeuristicFinding>(),
            null,
            null,
            null,
            error);
    }

    private static void AddHeuristic(
        ICollection<HeuristicFinding> heuristics,
        ref Verdict verdict,
        ref int riskScore,
        string ruleId,
        string description,
        int weight,
        string evidence)
    {
        if (heuristics.Any(item =>
                string.Equals(item.RuleId, ruleId, StringComparison.Ordinal)))
        {
            return;
        }

        var finding = new HeuristicFinding(ruleId, description, weight, evidence);
        heuristics.Add(finding);
        riskScore += weight;

        if (verdict == Verdict.Malicious)
            return;

        if (verdict == Verdict.Clean)
            verdict = Verdict.Suspicious;
    }

    private static void Log(
        EventStore? eventStore,
        string type,
        string message)
    {
        eventStore?.Add(type, message);
    }
}
