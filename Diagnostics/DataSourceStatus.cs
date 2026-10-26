
using System;

namespace NEXUS.Sentinel.Diagnostics;

public enum DataSourceState
{
    Unknown,
    Available,
    Partial,
    Denied,
    Disabled,
    Error
}

public enum DataCompleteness
{
    Unknown,
    Partial,
    Full
}

public sealed class DataSourceStatus
{
    public string Name { get; set; } = "";

    public DataSourceState State { get; set; }
        = DataSourceState.Unknown;

    public DataCompleteness Completeness { get; set; }
        = DataCompleteness.Unknown;

    public DateTime? LastSuccessUtc { get; set; }

    public DateTime LastCheckedUtc { get; set; }

    public string? LastError { get; set; }

    public void MarkAvailable(
        DataCompleteness completeness = DataCompleteness.Full)
    {
        State = completeness == DataCompleteness.Full
            ? DataSourceState.Available
            : DataSourceState.Partial;

        Completeness = completeness;
        LastSuccessUtc = DateTime.UtcNow;
        LastCheckedUtc = DateTime.UtcNow;
        LastError = null;
    }

    public void MarkDenied(string reason)
    {
        State = DataSourceState.Denied;
        Completeness = DataCompleteness.Partial;
        LastCheckedUtc = DateTime.UtcNow;
        LastError = reason;
    }

    public void MarkDisabled(string reason)
    {
        State = DataSourceState.Disabled;
        Completeness = DataCompleteness.Unknown;
        LastCheckedUtc = DateTime.UtcNow;
        LastError = reason;
    }

    public void MarkError(string reason)
    {
        State = DataSourceState.Error;
        Completeness = DataCompleteness.Unknown;
        LastCheckedUtc = DateTime.UtcNow;
        LastError = reason;
    }
}
