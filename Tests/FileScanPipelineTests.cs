using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NexusSentinel.Engine;
using Xunit;

namespace NexusSentinel.Tests;

public sealed class FileScanPipelineTests
{
    private static string TempFile(byte[] content)
    {
        string path = Path.Combine(
            Path.GetTempPath(),
            $"nexus-scan-{Guid.NewGuid():N}.bin");

        File.WriteAllBytes(path, content);
        return path;
    }

    private static byte[] BuildPe32(
        ushort sections = 0,
        ushort optionalSize = 224,
        uint directories = 0,
        byte[]? sectionData = null,
        uint? rawSize = null,
        uint? rawPointer = null,
        int? forceFileLength = null)
    {
        const int peOffset = 0x40;
        const int fileHeaderSize = 20;
        const int sectionHeaderSize = 40;

        int optionalStart = peOffset + 4 + fileHeaderSize;
        int sectionsStart = optionalStart + optionalSize;
        int dataStart = sectionsStart + sections * sectionHeaderSize;
        int dataLength = sectionData?.Length ?? 0;
        int naturalLength = dataStart + dataLength;
        int totalLength = forceFileLength ?? naturalLength;

        if (totalLength < 0 || totalLength > naturalLength)
            throw new ArgumentOutOfRangeException(nameof(forceFileLength));

        byte[] data = new byte[totalLength];

        void Put16(int offset, ushort value) =>
            BitConverter.GetBytes(value).CopyTo(data, offset);

        void Put32(int offset, uint value) =>
            BitConverter.GetBytes(value).CopyTo(data, offset);

        Put16(0, 0x5A4D);
        Put32(0x3C, peOffset);
        Put32(peOffset, 0x00004550);

        int fileHeader = peOffset + 4;
        Put16(fileHeader, 0x8664);
        Put16(fileHeader + 2, sections);
        Put16(fileHeader + 16, optionalSize);

        if (optionalSize >= 2)
            Put16(optionalStart, 0x010B);

        int directoryCountOffset = optionalStart + 92;

        if (directoryCountOffset + 4 <= optionalStart + optionalSize)
            Put32(directoryCountOffset, directories);

        if (sections > 0 && sectionsStart + sectionHeaderSize <= totalLength)
        {
            int section = sectionsStart;
            uint sectionRawSize = rawSize ?? (uint)(sectionData?.Length ?? 0);
            uint sectionRawPointer = rawPointer ?? (uint)dataStart;

            Put32(section + 16, sectionRawSize);
            Put32(section + 20, sectionRawPointer);
            Put32(section + 36, 0xE0000000);
        }

        if (sectionData is not null && dataStart + sectionData.Length <= totalLength)
            sectionData.CopyTo(data, dataStart);

        return data;
    }

    [Fact]
    public async Task ValidPe_ContinuesNormalAnalysis()
    {
        string path = TempFile(BuildPe32(optionalSize: 96));

        try
        {
            var result = await FileScanPipeline.AnalyzeFileAsync(
                path,
                new NEXUS.Sentinel.Data.EventStore(512));

            Assert.Equal(ScanOutcome.Clean, result.Outcome);
            Assert.Equal(Verdict.Clean, result.Verdict);
            Assert.Equal(PeFormatStatus.PeValid, result.Pe?.FormatStatus);
            Assert.DoesNotContain(
                result.Heuristics,
                item => item.RuleId == "PE_CORRUPTED");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task NonPeFile_DoesNotGetPeCorruptedHeuristic()
    {
        string path = TempFile(System.Text.Encoding.UTF8.GetBytes("hello"));

        try
        {
            var result = await FileScanPipeline.AnalyzeFileAsync(
                path,
                new NEXUS.Sentinel.Data.EventStore(512));

            Assert.Equal(PeFormatStatus.NotPe, result.Pe?.FormatStatus);
            Assert.DoesNotContain(
                result.Heuristics,
                item => item.RuleId == "PE_CORRUPTED");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task CorruptedPe_AddsPeCorruptedWithWeight25AndSuspiciousVerdict()
    {
        byte[] data = new byte[128];
        BitConverter.GetBytes((ushort)0x5A4D).CopyTo(data, 0);
        BitConverter.GetBytes((uint)64).CopyTo(data, 0x3C);

        string path = TempFile(data);

        try
        {
            var result = await FileScanPipeline.AnalyzeFileAsync(
                path,
                new NEXUS.Sentinel.Data.EventStore(512));

            Assert.Equal(ScanOutcome.Suspicious, result.Outcome);
            Assert.Equal(Verdict.Suspicious, result.Verdict);

            var heuristic = Assert.Single(
                result.Heuristics.Where(item => item.RuleId == "PE_CORRUPTED"));

            Assert.Equal(25, heuristic.Weight);
            Assert.Contains("PE_CORRUPTED", heuristic.RuleId);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ParseError_ReturnsErrorOutcome()
    {
        string missingPath = Path.Combine(
            Path.GetTempPath(),
            $"missing-{Guid.NewGuid():N}.bin");

        var result = await FileScanPipeline.AnalyzeFileAsync(
            missingPath,
            new NEXUS.Sentinel.Data.EventStore(512));

        Assert.Equal(ScanOutcome.Error, result.Outcome);
        Assert.NotEqual(Verdict.Clean, result.Verdict);
    }

    [Fact]
    public void MaliciousVerdict_IsNotDowngradedByPeCorruption()
    {
        var findings = new List<HeuristicFinding>();

        var verdict = FileScanPipeline.ApplyHeuristic(
            Verdict.Malicious,
            findings,
            new HeuristicFinding(
                "PE_CORRUPTED",
                "Corrupted PE",
                25,
                "test"));

        Assert.Equal(Verdict.Malicious, verdict);
        Assert.Single(findings);
    }

    [Fact]
    public void RepeatedHeuristic_IsNotDuplicated()
    {
        var findings = new List<HeuristicFinding>();

        var first = FileScanPipeline.ApplyHeuristic(
            Verdict.Clean,
            findings,
            new HeuristicFinding("PE_CORRUPTED", "Corrupted PE", 25, "test"));

        var second = FileScanPipeline.ApplyHeuristic(
            Verdict.Clean,
            findings,
            new HeuristicFinding("PE_CORRUPTED", "Corrupted PE", 25, "test"));

        Assert.Equal(Verdict.Suspicious, first);
        Assert.Equal(Verdict.Suspicious, second);
        Assert.Single(findings);
    }

    [Fact]
    public async Task Cancellation_IsNotMaskedAsCleanOrRegularError()
    {
        string path = TempFile(BuildPe32(optionalSize: 96));
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        try
        {
            await Assert.ThrowsAsync<OperationCanceledException>(
                () => FileScanPipeline.AnalyzeFileAsync(
                    path,
                    new NEXUS.Sentinel.Data.EventStore(512),
                    cts.Token));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
