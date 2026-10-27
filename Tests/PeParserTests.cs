
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using NexusSentinel.Engine;
using NEXUS.Sentinel.Models;
using NEXUS.Sentinel.Services;
using Xunit;

namespace NexusSentinel.Tests;

public sealed class PeParserTests
{
    private static string TempFile(byte[] content)
    {
        string path = Path.Combine(
            Path.GetTempPath(),
            $"nexus-{Guid.NewGuid():N}.bin");

        File.WriteAllBytes(path, content);
        return path;
    }

    private static byte[] BuildPe(
        ushort numberOfSections = 0,
        ushort optionalHeaderSize = 224,
        ushort magic = 0x010B,
        uint numberOfDirectories = 0,
        byte[]? sectionData = null,
        uint? rawSizeOverride = null,
        uint? rawPointerOverride = null,
        int? forceFileLength = null)
    {
        const int peOffset = 0x40;
        const int fileHeaderSize = 20;
        const int sectionHeaderSize = 40;

        int optionalStart = peOffset + 4 + fileHeaderSize;
        int sectionsStart = optionalStart + optionalHeaderSize;
        int dataStart = sectionsStart + numberOfSections * sectionHeaderSize;
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

        Put16(0, 0x5A4D); // MZ
        Put32(0x3C, peOffset);
        Put32(peOffset, 0x00004550); // PE signature

        int fileHeader = peOffset + 4;
        Put16(fileHeader, 0x8664);
        Put16(fileHeader + 2, numberOfSections);
        Put16(fileHeader + 16, optionalHeaderSize);

        if (optionalHeaderSize >= 2)
            Put16(optionalStart, magic);

        int directoryCountOffset = magic == 0x010B
            ? optionalStart + 92
            : optionalStart + 108;

        if (directoryCountOffset + 4 <= optionalStart + optionalHeaderSize)
            Put32(directoryCountOffset, numberOfDirectories);

        if (numberOfSections > 0 &&
            sectionsStart + sectionHeaderSize <= totalLength)
        {
            int section = sectionsStart;

            uint rawSize = rawSizeOverride ??
                (uint)(sectionData?.Length ?? 0);

            uint rawPointer = rawPointerOverride ??
                (uint)dataStart;

            Put32(section + 16, rawSize);
            Put32(section + 20, rawPointer);

            // Read + write + execute section.
            Put32(section + 36, 0xE0000000);
        }

        if (sectionData is not null &&
            dataStart + sectionData.Length <= totalLength)
        {
            sectionData.CopyTo(data, dataStart);
        }

        return data;
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
        return BuildPe(
            sections,
            optionalSize,
            0x010B,
            directories,
            sectionData,
            rawSize,
            rawPointer,
            forceFileLength);
    }

    private static byte[] BuildPe32Plus(
        ushort sections = 0,
        ushort optionalSize = 240,
        uint directories = 0,
        byte[]? sectionData = null)
    {
        return BuildPe(
            sections,
            optionalSize,
            0x020B,
            directories,
            sectionData);
    }

    [Fact]
    public void NotPe_For_Text_File()
    {
        string path = TempFile(
            System.Text.Encoding.UTF8.GetBytes("hello"));

        try
        {
            Assert.Equal(
                PeFormatStatus.NotPe,
                PeParser.Parse(path).FormatStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void NotPe_For_File_Shorter_Than_64_Bytes()
    {
        string path = TempFile(new byte[20]);

        try
        {
            Assert.Equal(
                PeFormatStatus.NotPe,
                PeParser.Parse(path).FormatStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void NotPe_For_No_Mz()
    {
        byte[] data = new byte[128];
        string path = TempFile(data);

        try
        {
            Assert.Equal(
                PeFormatStatus.NotPe,
                PeParser.Parse(path).FormatStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Corrupted_For_Mz_Without_Pe_Signature()
    {
        byte[] data = new byte[128];
        BitConverter.GetBytes((ushort)0x5A4D).CopyTo(data, 0);
        BitConverter.GetBytes((uint)64).CopyTo(data, 0x3C);

        string path = TempFile(data);

        try
        {
            Assert.Equal(
                PeFormatStatus.PeCorrupted,
                PeParser.Parse(path).FormatStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Corrupted_For_Truncated_Pe_Header()
    {
        byte[] data = new byte[80];
        BitConverter.GetBytes((ushort)0x5A4D).CopyTo(data, 0);
        BitConverter.GetBytes((uint)64).CopyTo(data, 0x3C);
        BitConverter.GetBytes(0x00004550u).CopyTo(data, 64);

        string path = TempFile(data);

        try
        {
            Assert.Equal(
                PeFormatStatus.PeCorrupted,
                PeParser.Parse(path).FormatStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Corrupted_For_Offset_Beyond_File()
    {
        byte[] data = new byte[128];
        BitConverter.GetBytes((ushort)0x5A4D).CopyTo(data, 0);
        BitConverter.GetBytes((uint)200).CopyTo(data, 0x3C);

        string path = TempFile(data);

        try
        {
            Assert.Equal(
                PeFormatStatus.PeCorrupted,
                PeParser.Parse(path).FormatStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Corrupted_For_Too_Many_Sections()
    {
        string path = TempFile(
            BuildPe32(sections: 200));

        try
        {
            Assert.Equal(
                PeFormatStatus.PeCorrupted,
                PeParser.Parse(path).FormatStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Corrupted_For_Zero_Optional_Header_Size()
    {
        string path = TempFile(
            BuildPe32(optionalSize: 0));

        try
        {
            Assert.Equal(
                PeFormatStatus.PeCorrupted,
                PeParser.Parse(path).FormatStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData(95, 0x010B)]
    [InlineData(111, 0x020B)]
    public void Corrupted_For_Too_Small_Optional_Header(
        ushort optionalSize,
        ushort magic)
    {
        string path = TempFile(
            BuildPe(0, optionalSize, magic));

        try
        {
            Assert.Equal(
                PeFormatStatus.PeCorrupted,
                PeParser.Parse(path).FormatStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Corrupted_When_DataDirectories_Do_Not_Fit()
    {
        string path = TempFile(
            BuildPe32(optionalSize: 224, directories: 100));

        try
        {
            Assert.Equal(
                PeFormatStatus.PeCorrupted,
                PeParser.Parse(path).FormatStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Corrupted_When_Pe32Plus_DataDirectories_Do_Not_Fit()
    {
        string path = TempFile(
            BuildPe32Plus(optionalSize: 112, directories: 1));

        try
        {
            Assert.Equal(
                PeFormatStatus.PeCorrupted,
                PeParser.Parse(path).FormatStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Valid_Pe32_With_Minimum_Optional_Header()
    {
        string path = TempFile(
            BuildPe32(optionalSize: 96));

        try
        {
            Assert.Equal(
                PeFormatStatus.PeValid,
                PeParser.Parse(path).FormatStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Valid_Pe32Plus_With_Minimum_Optional_Header()
    {
        string path = TempFile(
            BuildPe32Plus(optionalSize: 112));

        try
        {
            Assert.Equal(
                PeFormatStatus.PeValid,
                PeParser.Parse(path).FormatStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Valid_Pe32_With_One_Directory_At_Boundary()
    {
        string path = TempFile(
            BuildPe32(optionalSize: 104, directories: 1));

        try
        {
            Assert.Equal(
                PeFormatStatus.PeValid,
                PeParser.Parse(path).FormatStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Corrupted_When_Section_Table_Is_Truncated()
    {
        string path = TempFile(
            BuildPe32(
                sections: 2,
                optionalSize: 224,
                forceFileLength: 352));

        try
        {
            Assert.Equal(
                PeFormatStatus.PeCorrupted,
                PeParser.Parse(path).FormatStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Corrupted_When_Raw_Section_Exceeds_File()
    {
        string path = TempFile(
            BuildPe32(
                sections: 1,
                sectionData: new byte[16],
                rawSize: 1000));

        try
        {
            Assert.Equal(
                PeFormatStatus.PeCorrupted,
                PeParser.Parse(path).FormatStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Corrupted_When_Raw_Pointer_Exceeds_File()
    {
        string path = TempFile(
            BuildPe32(
                sections: 1,
                sectionData: new byte[16],
                rawPointer: 100000));

        try
        {
            Assert.Equal(
                PeFormatStatus.PeCorrupted,
                PeParser.Parse(path).FormatStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ParseError_For_Missing_File()
    {
        string path = Path.Combine(
            Path.GetTempPath(),
            $"missing-{Guid.NewGuid():N}.bin");

        Assert.Equal(
            PeFormatStatus.ParseError,
            PeParser.Parse(path).FormatStatus);
    }

    [Fact]
    public void ParseError_For_Empty_Path()
    {
        Assert.Equal(
            PeFormatStatus.ParseError,
            PeParser.Parse("").FormatStatus);
    }

    [Fact]
    public void Valid_Pe_With_One_Section_Reads_Entropy()
    {
        byte[] section = new byte[4096];
        new Random(1234).NextBytes(section);

        string path = TempFile(
            BuildPe32(sections: 1, sectionData: section));

        try
        {
            PeAnalysisResult result = PeParser.Parse(path);

            Assert.Equal(PeFormatStatus.PeValid, result.FormatStatus);
            Assert.Equal(1, result.SectionsRead);
            Assert.True(result.HasWriteExecuteSection);
            Assert.True(result.MaxSectionEntropy > 7.0);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Entropy_Is_Capped_Per_Section()
    {
        const int dataLength = 10 * 1024 * 1024;
        byte[] section = new byte[dataLength];

        // The parser reads only the first 4 MiB of this section.
        new Random(1234).NextBytes(
            section.AsSpan(4 * 1024 * 1024).ToArray());

        string path = TempFile(
            BuildPe32(sections: 1, sectionData: section));

        try
        {
            PeAnalysisResult result = PeParser.Parse(path);

            Assert.Equal(PeFormatStatus.PeValid, result.FormatStatus);
            Assert.True(result.MaxSectionEntropy < 0.01);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Scan_Valid_Pe_Computes_Hash_And_Parses_Structure()
    {
        string path = TempFile(BuildPe32());

        try
        {
            ScanResult result = await new ScanOrchestrator().ScanAsync(path);

            Assert.Equal(64, result.File.Hash.Sha256.Length);
            Assert.Equal(PeFormatStatus.PeValid, result.Pe?.FormatStatus);
            Assert.Equal(Verdict.Suspicious, result.Verdict);
            Assert.Equal(ScanOutcome.Suspicious, result.Outcome);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Scan_Non_Pe_Does_Not_Run_Pe_Heuristics()
    {
        string path = TempFile(
            System.Text.Encoding.UTF8.GetBytes("ordinary document"));
        bool peAnalysisRan = false;
        var scanner = new ScanOrchestrator(
            analyzePe: _ =>
            {
                peAnalysisRan = true;
                return Array.Empty<HeuristicFinding>();
            });

        try
        {
            ScanResult result = await scanner.ScanAsync(path);

            Assert.Equal(PeFormatStatus.NotPe, result.Pe?.FormatStatus);
            Assert.False(peAnalysisRan);
            Assert.NotEqual(ScanOutcome.Error, result.Outcome);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Scan_Corrupted_Pe_Adds_One_Weighted_Finding()
    {
        string path = TempFile(BuildPe32(
            sections: 1,
            rawSize: 1024,
            rawPointer: 1024));
        var scanner = new ScanOrchestrator(
            analyzePe: _ => new[]
            {
                new HeuristicFinding(
                    "PE_CORRUPTED", "duplicate", 25, "duplicate")
            });

        try
        {
            ScanResult result = await scanner.ScanAsync(path);
            HeuristicFinding[] findings = result.Heuristics
                .Where(finding => finding.RuleId == "PE_CORRUPTED")
                .ToArray();

            Assert.Equal(PeFormatStatus.PeCorrupted, result.Pe?.FormatStatus);
            HeuristicFinding finding = Assert.Single(findings);
            Assert.Equal(25, finding.Weight);
            Assert.Equal(Verdict.Suspicious, result.Verdict);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Scan_Read_Error_Is_Logged_And_Not_Clean()
    {
        string path = TempFile(new byte[] { 1, 2, 3 });
        File.Delete(path);
        var loggedEvents = new System.Collections.Generic.List<string>();
        var scanner = new ScanOrchestrator(
            (type, _) => loggedEvents.Add(type));

        try
        {
            ScanResult result = await scanner.ScanAsync(path);

            Assert.Equal(ScanOutcome.Error, result.Outcome);
            Assert.NotEqual(Verdict.Clean, result.Verdict);
            Assert.False(string.IsNullOrWhiteSpace(result.Error));
            Assert.Contains("FileScanError", loggedEvents);
        }
        finally
        {
            if (File.Exists(path))
                File.Delete(path);
        }
    }

    [Fact]
    public async Task Scan_Parse_Error_Is_An_Error_Not_Clean()
    {
        string path = TempFile(new byte[] { 1, 2, 3 });
        var parseError = new PeAnalysisResult(
            PeFormatStatus.ParseError,
            SignatureStatus.NotChecked,
            null,
            false,
            0,
            false,
            0,
            0,
            Array.Empty<string>(),
            "parse failed");
        var scanner = new ScanOrchestrator(parsePe: _ => parseError);

        try
        {
            ScanResult result = await scanner.ScanAsync(path);

            Assert.Equal(ScanOutcome.Error, result.Outcome);
            Assert.NotEqual(Verdict.Clean, result.Verdict);
            Assert.Equal(PeFormatStatus.ParseError, result.Pe?.FormatStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Scan_Preserves_Malicious_Verdict()
    {
        string path = TempFile(BuildPe32());
        var scanner = new ScanOrchestrator(
            analyzePe: _ => new[]
            {
                new HeuristicFinding("TEST_HIGH_RISK", "test", 75, "test")
            });

        try
        {
            ScanResult result = await scanner.ScanAsync(path);

            Assert.Equal(Verdict.Malicious, result.Verdict);
            Assert.Equal(ScanOutcome.Malicious, result.Outcome);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Scan_Cancellation_Is_Propagated()
    {
        string path = TempFile(new byte[] { 1, 2, 3 });
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => new ScanOrchestrator().ScanAsync(
                    path, cancellation.Token));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(5 * 1024 * 1024)]
    public async Task FileHashService_Computes_Sha256_And_Sha512(int length)
    {
        byte[] content = new byte[length];
        new Random(1234).NextBytes(content);
        string path = TempFile(content);

        try
        {
            var result = await FileHashService.CalculateSha256Async(path);

            Assert.True(result.Success, result.Error);
            Assert.Equal(
                Convert.ToHexString(SHA256.HashData(content)),
                result.Sha256);
            Assert.Equal(
                Convert.ToHexString(SHA512.HashData(content)),
                result.Sha512);
            Assert.Equal(length, result.FileSizeBytes);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Scan_OutOfMemory_Is_Propagated()
    {
        string path = TempFile(new byte[] { 1, 2, 3 });
        var scanner = new ScanOrchestrator(
            hashFile: (_, _) => Task.FromException<FileScanResult>(
                new OutOfMemoryException()));

        try
        {
            await Assert.ThrowsAsync<OutOfMemoryException>(
                () => scanner.ScanAsync(path));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
