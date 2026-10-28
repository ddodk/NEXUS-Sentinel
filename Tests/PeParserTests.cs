
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using NexusSentinel.Engine;
using NEXUS.Sentinel;
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
        int? forceFileLength = null,
        ushort? machineOverride = null)
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
        ushort machine = machineOverride ?? (magic switch
        {
            0x010B => (ushort)0x014C,
            0x020B => (ushort)0x8664,
            _ => (ushort)0x8664
        });
        Put16(fileHeader, machine);
        Put16(fileHeader + 2, numberOfSections);
        Put16(fileHeader + 16, optionalHeaderSize);

        if (optionalHeaderSize >= 2)
            Put16(optionalStart, magic);

        if (optionalHeaderSize >= 64)
            Put32(optionalStart + 60, (uint)dataStart);

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
        int? forceFileLength = null,
        ushort? machineOverride = null)
    {
        return BuildPe(
            sections,
            optionalSize,
            0x010B,
            directories,
            sectionData,
            rawSize,
            rawPointer,
            forceFileLength,
            machineOverride);
    }

    private static byte[] BuildPe32Plus(
        ushort sections = 0,
        ushort optionalSize = 240,
        uint directories = 0,
        byte[]? sectionData = null,
        ushort? machineOverride = null)
    {
        return BuildPe(
            sections,
            optionalSize,
            0x020B,
            directories,
            sectionData,
            machineOverride: machineOverride);
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
    public void Corrupted_For_Truncated_Dos_Header_With_Mz()
    {
        string path = TempFile(new byte[] { 0x4D, 0x5A, 0, 0 });

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
    public void Corrupted_For_Maximum_Pe_Header_Offset()
    {
        byte[] data = new byte[128];
        BitConverter.GetBytes((ushort)0x5A4D).CopyTo(data, 0);
        BitConverter.GetBytes(uint.MaxValue).CopyTo(data, 0x3C);
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
    public void Corrupted_For_Unknown_Optional_Header_Magic()
    {
        string path = TempFile(BuildPe(0, 224, 0x9999));

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
    public void Corrupted_When_SizeOfHeaders_Is_Truncated()
    {
        byte[] data = BuildPe32();
        const int optionalStart = 0x40 + 4 + 20;
        BitConverter.GetBytes(64u).CopyTo(data, optionalStart + 60);
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
    public void Corrupted_When_DataDirectory_Rva_Is_Not_FileBacked()
    {
        byte[] data = BuildPe32(directories: 1);
        const int optionalStart = 0x40 + 4 + 20;
        const int firstDirectory = optionalStart + 96;
        BitConverter.GetBytes(0x70000000u).CopyTo(data, firstDirectory);
        BitConverter.GetBytes(16u).CopyTo(data, firstDirectory + 4);
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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Corrupted_When_Coff_Machine_And_Optional_Header_Conflict(
        bool pe32Plus)
    {
        byte[] data = pe32Plus
            ? BuildPe32Plus(machineOverride: 0x014C)
            : BuildPe32(machineOverride: 0x8664);
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
    public void Valid_Pe_Header_Alignment_Is_Not_Reported_As_Overlay()
    {
        byte[] data = BuildPe32(optionalSize: 96);
        Array.Resize(ref data, 512);
        const int optionalStart = 0x40 + 4 + 20;
        BitConverter.GetBytes(512u).CopyTo(data, optionalStart + 60);
        string path = TempFile(data);

        try
        {
            PeAnalysisResult result = PeParser.Parse(path);

            Assert.Equal(PeFormatStatus.PeValid, result.FormatStatus);
            Assert.False(result.HasOverlay);
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
    public void Valid_Data_Directory_Range_Ends_At_Section_Boundary()
    {
        byte[] data = BuildPe32(
            sections: 1,
            optionalSize: 104,
            directories: 1,
            sectionData: new byte[16],
            rawSize: 16);
        const int optionalStart = 0x40 + 4 + 20;
        const int sectionTable = optionalStart + 104;
        const int firstDirectory = optionalStart + 96;
        BitConverter.GetBytes(16u).CopyTo(data, sectionTable + 8);
        BitConverter.GetBytes(0x1000u).CopyTo(data, sectionTable + 12);
        BitConverter.GetBytes(0x100Fu).CopyTo(data, firstDirectory);
        BitConverter.GetBytes(1u).CopyTo(data, firstDirectory + 4);
        string path = TempFile(data);

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
    public void Corrupted_When_Data_Directory_Crosses_Section_Boundary()
    {
        byte[] data = BuildPe32(
            sections: 1,
            optionalSize: 104,
            directories: 1,
            sectionData: new byte[16],
            rawSize: 16);
        const int optionalStart = 0x40 + 4 + 20;
        const int sectionTable = optionalStart + 104;
        const int firstDirectory = optionalStart + 96;
        BitConverter.GetBytes(16u).CopyTo(data, sectionTable + 8);
        BitConverter.GetBytes(0x1000u).CopyTo(data, sectionTable + 12);
        BitConverter.GetBytes(0x100Fu).CopyTo(data, firstDirectory);
        BitConverter.GetBytes(2u).CopyTo(data, firstDirectory + 4);
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
    public void Corrupted_When_Raw_Section_Ranges_Overlap()
    {
        const int peOffset = 0x40;
        const int optionalStart = peOffset + 4 + 20;
        const int sectionTable = optionalStart + 224;
        const int rawData = sectionTable + 2 * 40;
        byte[] data = BuildPe32(
            sections: 2,
            sectionData: new byte[128],
            rawSize: 64);

        BitConverter.GetBytes(64u).CopyTo(data, sectionTable + 8);
        BitConverter.GetBytes(0x1000u).CopyTo(data, sectionTable + 12);
        BitConverter.GetBytes(0x2000u).CopyTo(data, sectionTable + 40 + 12);
        BitConverter.GetBytes(64u).CopyTo(data, sectionTable + 40 + 16);
        BitConverter.GetBytes((uint)(rawData + 32)).CopyTo(
            data,
            sectionTable + 40 + 20);
        BitConverter.GetBytes(64u).CopyTo(data, sectionTable + 40 + 8);
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
    public void Corrupted_When_Virtual_Section_Ranges_Overlap()
    {
        const int peOffset = 0x40;
        const int optionalStart = peOffset + 4 + 20;
        const int sectionTable = optionalStart + 224;
        byte[] data = BuildPe32(sections: 2);

        BitConverter.GetBytes(64u).CopyTo(data, sectionTable + 8);
        BitConverter.GetBytes(0x1000u).CopyTo(data, sectionTable + 12);
        BitConverter.GetBytes(64u).CopyTo(data, sectionTable + 40 + 8);
        BitConverter.GetBytes(0x1030u).CopyTo(data, sectionTable + 40 + 12);
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
    public void Corrupted_When_Virtual_Section_Range_Exceeds_Rva_Space()
    {
        const int peOffset = 0x40;
        const int optionalStart = peOffset + 4 + 20;
        const int sectionTable = optionalStart + 224;
        byte[] data = BuildPe32(sections: 1);

        BitConverter.GetBytes(uint.MaxValue).CopyTo(data, sectionTable + 8);
        BitConverter.GetBytes(0xFFFFFFF0u).CopyTo(data, sectionTable + 12);
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
            section.AsSpan(4 * 1024 * 1024));

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
            Assert.Empty(result.Heuristics);
            Assert.Equal(0, result.RiskScore);
            Assert.Equal(Verdict.Inconclusive, result.Verdict);
            Assert.Equal(ScanOutcome.Inconclusive, result.Outcome);
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
            Assert.Equal(Verdict.Inconclusive, result.Verdict);
            Assert.Equal(ScanOutcome.Inconclusive, result.Outcome);
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
        bool peAnalysisRan = false;
        var scanner = new ScanOrchestrator(
            analyzePe: _ =>
            {
                peAnalysisRan = true;
                return new[]
                {
                    new HeuristicFinding(
                        "PE_CORRUPTED", "incorrect weight", 99, "provided by analyzer")
                };
            });

        try
        {
            ScanResult result = await scanner.ScanAsync(path);
            HeuristicFinding[] findings = result.Heuristics
                .Where(finding => finding.RuleId == "PE_CORRUPTED")
                .ToArray();

            Assert.Equal(PeFormatStatus.PeCorrupted, result.Pe?.FormatStatus);
            Assert.False(peAnalysisRan);
            HeuristicFinding finding = Assert.Single(findings);
            Assert.Equal(25, finding.Weight);
            Assert.Equal(Verdict.Suspicious, result.Verdict);
            Assert.Equal(ScanOutcome.Suspicious, result.Outcome);
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
        var loggedEvents = new System.Collections.Generic.List<(string Type, string Message)>();
        var scanner = new ScanOrchestrator(
            (type, message) => loggedEvents.Add((type, message)));

        try
        {
            ScanResult result = await scanner.ScanAsync(path);

            Assert.Equal(ScanOutcome.Error, result.Outcome);
            Assert.Equal(Verdict.Inconclusive, result.Verdict);
            Assert.False(string.IsNullOrWhiteSpace(result.Error));
            Assert.Contains(
                loggedEvents,
                item => item.Type == "FileScanError");
            Assert.DoesNotContain(path, loggedEvents[0].Message);
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
            Assert.Equal(Verdict.Inconclusive, result.Verdict);
            Assert.Equal(PeFormatStatus.ParseError, result.Pe?.FormatStatus);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Scan_Unexpected_Parser_Exception_Is_Logged_And_Error()
    {
        string path = TempFile(BuildPe32());
        var loggedEvents = new System.Collections.Generic.List<(string Type, string Message)>();
        var scanner = new ScanOrchestrator(
            (type, message) => loggedEvents.Add((type, message)),
            parsePe: _ => throw new InvalidOperationException("unexpected"));

        try
        {
            ScanResult result = await scanner.ScanAsync(path);

            Assert.Equal(ScanOutcome.Error, result.Outcome);
            Assert.Equal(Verdict.Inconclusive, result.Verdict);
            Assert.Contains(
                loggedEvents,
                item => item.Type == "FileScanError");
            Assert.DoesNotContain(path, loggedEvents[0].Message);
            Assert.Contains("unexpected", loggedEvents[0].Message);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Scan_Redacts_File_Path_From_Error_Results()
    {
        string path = TempFile(new byte[] { 1, 2, 3 });
        var scanner = new ScanOrchestrator(
            hashFile: (filePath, _) => Task.FromResult(new FileScanResult
            {
                FilePath = filePath,
                Success = false,
                Status = "Read failed",
                Error = $"Cannot read {filePath}"
            }));

        try
        {
            ScanResult result = await scanner.ScanAsync(path);

            Assert.Equal(ScanOutcome.Error, result.Outcome);
            Assert.DoesNotContain(path, result.Error);
            Assert.Contains("<file>", result.Error);
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
    public async Task Scan_Low_Weight_Finding_Is_Not_Clean()
    {
        string path = TempFile(BuildPe32());
        var scanner = new ScanOrchestrator(
            analyzePe: _ => new[]
            {
                new HeuristicFinding(
                    "LOW_WEIGHT_TEST",
                    "Test finding",
                    1,
                    "Test evidence")
            });

        try
        {
            ScanResult result = await scanner.ScanAsync(path);

            Assert.Equal(Verdict.Suspicious, result.Verdict);
            Assert.Equal(ScanOutcome.Suspicious, result.Outcome);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Scan_Deduplicates_Heuristics_By_Rule_Id()
    {
        string path = TempFile(BuildPe32());
        var scanner = new ScanOrchestrator(
            analyzePe: _ => new[]
            {
                new HeuristicFinding("DUPLICATE_RULE", "first", 5, "first"),
                new HeuristicFinding("duplicate_rule", "second", 10, "second")
            });

        try
        {
            ScanResult result = await scanner.ScanAsync(path);

            HeuristicFinding finding = Assert.Single(result.Heuristics);
            Assert.Equal("first", finding.Evidence);
            Assert.Equal(5, result.RiskScore);
            Assert.Equal(Verdict.Suspicious, result.Verdict);
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
    public async Task FileHashService_Rejects_Files_Above_Size_Limit()
    {
        string path = Path.Combine(
            Path.GetTempPath(),
            $"nexus-{Guid.NewGuid():N}.bin");

        try
        {
            using (var stream = new FileStream(
                       path,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None))
            {
                stream.SetLength(FileHashService.MaxFileSizeBytes + 1);
            }

            FileScanResult result =
                await FileHashService.CalculateSha256Async(path);

            Assert.False(result.Success);
            Assert.Contains("превышает лимит", result.Error);
            Assert.Empty(result.Sha256);
            Assert.Empty(result.Sha512);
        }
        finally
        {
            if (File.Exists(path))
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

    [Fact]
    public async Task Cancellation_Takes_Precedence_Over_Invalid_Paths()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new ScanOrchestrator().ScanAsync("", cancellation.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => FileHashService.CalculateSha256Async("", cancellation.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => AuthenticodeVerifier.VerifyAsync("", cancellation.Token));
        Assert.ThrowsAny<OperationCanceledException>(
            () => PeParser.Parse("", cancellation.Token));
    }

    [Fact]
    public async Task Scan_Returns_Error_When_File_Changes_During_Analysis()
    {
        string path = TempFile(BuildPe32());
        var scanner = new ScanOrchestrator(
            hashFile: async (filePath, token) =>
            {
                FileScanResult hash =
                    await FileHashService.CalculateSha256Async(
                        filePath, token);

                return new FileScanResult
                {
                    FilePath = hash.FilePath,
                    Sha256 = hash.Sha256,
                    Sha512 = hash.Sha512,
                    FileSizeBytes = hash.FileSizeBytes,
                    LastWriteUtc = hash.LastWriteUtc.AddSeconds(-10),
                    CheckedAt = hash.CheckedAt,
                    Success = hash.Success,
                    Status = hash.Status,
                    Error = hash.Error
                };
            });

        try
        {
            ScanResult result = await scanner.ScanAsync(path);

            Assert.Equal(ScanOutcome.Error, result.Outcome);
            Assert.NotEqual(Verdict.Clean, result.Verdict);
            Assert.Contains("изменился", result.Error);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Scan_Propagates_Cancellation_From_Parser()
    {
        string path = TempFile(BuildPe32());
        using var cancellation = new CancellationTokenSource();
        var scanner = new ScanOrchestrator(
            parsePeWithCancellation: (_, token) =>
            {
                cancellation.Cancel();
                token.ThrowIfCancellationRequested();
                throw new InvalidOperationException("unreachable");
            });

        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => scanner.ScanAsync(path, cancellation.Token));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task AuthenticodeVerifier_Returns_Error_For_Missing_File()
    {
        string path = Path.Combine(
            Path.GetTempPath(),
            $"missing-{Guid.NewGuid():N}.exe");

        AuthenticodeResult result =
            await AuthenticodeVerifier.VerifyAsync(path);

        Assert.Equal("CheckFailed", result.Status);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
    }

    [Fact]
    public async Task AuthenticodeVerifier_Reports_Platform_Result_For_Existing_File()
    {
        string path = TempFile(new byte[] { 1, 2, 3, 4 });

        try
        {
            AuthenticodeResult result =
                await AuthenticodeVerifier.VerifyAsync(path);

            Assert.Contains(
                result.Status,
                new[]
                {
                    "Valid",
                    "NotSigned",
                    "HashMismatch",
                    "NotTrusted",
                    "UnknownError",
                    "CheckFailed"
                });

            if (result.Status == "CheckFailed")
                Assert.False(string.IsNullOrWhiteSpace(result.Error));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task AuthenticodeVerifier_Propagates_Cancellation()
    {
        string path = TempFile(new byte[] { 1 });
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => AuthenticodeVerifier.VerifyAsync(
                    path,
                    cancellation.Token));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData("NotSigned", "", "NotSigned", false)]
    [InlineData("HashMismatch", "", "HashMismatch", false)]
    [InlineData("NotTrusted", "2020-01-01T00:00:00.0000000+00:00", "NotTrusted", true)]
    [InlineData("NotTrusted", "2099-01-01T00:00:00.0000000+00:00", "NotTrusted", false)]
    [InlineData("Valid", "2020-01-01T00:00:00.0000000+00:00", "Valid", false)]
    public void AuthenticodeResult_Preserves_Windows_Status_Semantics(
        string windowsStatus,
        string notAfter,
        string expectedStatus,
        bool certificateExpired)
    {
        string json = "{\"Status\":\"" + windowsStatus +
            "\",\"NotAfter\":\"" + notAfter + "\"}";

        AuthenticodeResult result = AuthenticodeVerifier.ParseResult(json);

        Assert.Equal(expectedStatus, result.Status);
        Assert.Equal(expectedStatus == "Valid", result.IsValid);
        Assert.Equal(certificateExpired, result.SignerCertificateExpired);
    }
}
