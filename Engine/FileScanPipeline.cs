using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using NEXUS.Sentinel.Data;

namespace NexusSentinel.Engine;

public static class FileScanPipeline
{
    public static Task<ScanResult> AnalyzeFileAsync(
        string filePath,
        EventStore? eventStore = null,
        CancellationToken cancellationToken = default)
    {
        return ScanOrchestrator.AnalyzeFileAsync(
            filePath,
            eventStore,
            cancellationToken);
    }

    internal static Verdict ApplyHeuristic(
        Verdict currentVerdict,
        ICollection<HeuristicFinding> existingFindings,
        HeuristicFinding finding)
    {
        return ScanOrchestrator.ApplyHeuristic(
            currentVerdict,
            existingFindings,
            finding);
    }
}
