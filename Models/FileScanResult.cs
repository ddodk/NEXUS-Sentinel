namespace NEXUS.Sentinel.Models;

public sealed class FileScanResult
{
    public string FilePath { get; init; } = string.Empty;

    public string Sha256 { get; init; } = string.Empty;

    public string Sha512 { get; init; } = string.Empty;

    public long FileSizeBytes { get; init; }

    public DateTime LastWriteUtc { get; init; }

    public DateTime CheckedAt { get; init; }

    public bool Success { get; init; }

    public string Status { get; init; } = string.Empty;

    public string? Error { get; init; }
}
