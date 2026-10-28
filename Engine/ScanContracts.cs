using System;
using System.Collections.Generic;

namespace NexusSentinel.Engine;

public enum Verdict
{
    Clean,
    Suspicious,
    Malicious,
    Inconclusive
}

public enum ScanOutcome
{
    Clean,
    Suspicious,
    Malicious,
    Error,
    Inconclusive
}

public enum PeFormatStatus
{
    NotPe,
    PeCorrupted,
    PeValid,
    ParseError
}

public enum SignatureStatus
{
    Unknown,
    NotChecked,
    NotSigned,
    SignedInvalid,
    SignedValid
}

public sealed record HashResult(
    string Sha256,
    string Sha512,
    long SizeBytes,
    DateTime LastWriteUtc);

public sealed record FileIdentity(
    string FullPath,
    HashResult Hash,
    DateTime CapturedAtUtc);

public sealed record HeuristicFinding(
    string RuleId,
    string Description,
    int Weight,
    string Evidence);

public sealed record PeAnalysisResult(
    PeFormatStatus FormatStatus,
    SignatureStatus Signature,
    string? SignerSubject,
    bool HasWriteExecuteSection,
    double MaxSectionEntropy,
    bool HasOverlay,
    int SectionsRead,
    int SectionsRequested,
    IReadOnlyList<string> SuspiciousImports,
    string? ParseError);

public static class PeParserLimits
{
    public const int MaxSections = 96;
    public const int MaxSectionEntropyBytes = 4 * 1024 * 1024;
    public const int MaxTotalSectionEntropyBytes = 32 * 1024 * 1024;
    public const int EntropyChunkSize = 64 * 1024;
    public const int MaxOptionalHeaderSize = 4096;
    public const int MinOptionalHeaderSizePe32 = 96;
    public const int MinOptionalHeaderSizePe32Plus = 112;
    public const int DataDirectoryEntrySize = 8;
}

public sealed record ArchiveScanResult(
    int EntriesScanned,
    int EntriesSkipped,
    long TotalDecompressedBytes,
    bool BombGuardTriggered,
    bool IsCorrupted,
    bool DepthLimitHit);

public sealed record ScanResult(
    FileIdentity File,
    ScanOutcome Outcome,
    Verdict Verdict,
    int RiskScore,
    IReadOnlyList<HeuristicFinding> Heuristics,
    PeAnalysisResult? Pe,
    ArchiveScanResult? Archive,
    string? ThreatName,
    string? Error);

public sealed record ScanProgress(
    int Percent,
    string CurrentPath,
    string Stage);
