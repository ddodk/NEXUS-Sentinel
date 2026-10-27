using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;

namespace NexusSentinel.Engine;

public static class PeParser
{
    private const ushort DosSignature = 0x5A4D;
    private const uint PeSignature = 0x00004550;
    private const ushort Pe32Magic = 0x010B;
    private const ushort Pe32PlusMagic = 0x020B;

    public static PeAnalysisResult Parse(string path)
    {
        return Parse(path, CancellationToken.None);
    }

    public static PeAnalysisResult Parse(
        string path,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(path))
        {
            return Error("File path is empty.");
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: PeParserLimits.EntropyChunkSize,
                options: FileOptions.SequentialScan);

            long fileLength = stream.Length;

            if (fileLength < sizeof(ushort))
                return NotPe();

            using var reader = new BinaryReader(stream);

            if (ReadUInt16(reader, 0) != DosSignature)
                return NotPe();

            if (fileLength < 64)
                return Corrupted("DOS header is truncated.");

            uint peOffsetValue = ReadUInt32(reader, 0x3C);
            long peOffset = peOffsetValue;

            if (peOffset < 64 || peOffset > fileLength - 24)
                return Corrupted("PE header is outside the file.");

            if (ReadUInt32(reader, peOffset) != PeSignature)
                return Corrupted("PE signature is missing.");

            long fileHeader = peOffset + 4;
            ushort numberOfSections = ReadUInt16(reader, fileHeader + 2);
            ushort optionalHeaderSize = ReadUInt16(reader, fileHeader + 16);

            if (numberOfSections > PeParserLimits.MaxSections)
                return Corrupted("Section count exceeds the configured limit.");

            if (optionalHeaderSize > PeParserLimits.MaxOptionalHeaderSize)
                return Corrupted("Optional header is too large.");

            long optionalStart = fileHeader + 20;
            long optionalEnd = optionalStart + optionalHeaderSize;

            if (optionalEnd < optionalStart || optionalEnd > fileLength)
                return Corrupted("Optional header is truncated.");

            if (optionalHeaderSize < 2)
                return Corrupted("Optional header is too small.");

            ushort magic = ReadUInt16(reader, optionalStart);

            int minimumSize;
            long numberOfDirectoriesOffset;

            if (magic == Pe32Magic)
            {
                minimumSize = PeParserLimits.MinOptionalHeaderSizePe32;
                numberOfDirectoriesOffset = optionalStart + 92;
            }
            else if (magic == Pe32PlusMagic)
            {
                minimumSize = PeParserLimits.MinOptionalHeaderSizePe32Plus;
                numberOfDirectoriesOffset = optionalStart + 108;
            }
            else
            {
                return Corrupted("Unknown optional header format.");
            }

            if (optionalHeaderSize < minimumSize)
                return Corrupted("Optional header is smaller than its minimum size.");

            uint numberOfDirectories = ReadUInt32(reader, numberOfDirectoriesOffset);
            long directoryBytes = (long)numberOfDirectories *
                                  PeParserLimits.DataDirectoryEntrySize;
            long directoryStart = numberOfDirectoriesOffset + 4;

            if (directoryBytes > optionalEnd - directoryStart)
                return Corrupted("Data directories exceed the optional header.");

            var dataDirectories = new List<(int Index, uint Address, uint Size)>();

            for (int i = 0; i < numberOfDirectories; i++)
            {
                long directoryOffset = directoryStart +
                    (long)i * PeParserLimits.DataDirectoryEntrySize;
                uint address = ReadUInt32(reader, directoryOffset);
                uint size = ReadUInt32(reader, directoryOffset + 4);

                if (address == 0 && size == 0)
                    continue;

                if (address == 0 || size == 0)
                    return Corrupted("Data directory has an incomplete range.");

                dataDirectories.Add((i, address, size));
            }

            long sectionsStart = optionalEnd;
            long sectionBytes = (long)numberOfSections * 40;

            if (sectionsStart > fileLength - sectionBytes)
                return Corrupted("Section table is truncated.");

            uint sizeOfHeaders = ReadUInt32(reader, optionalStart + 60);

            if (sizeOfHeaders < sectionsStart + sectionBytes ||
                sizeOfHeaders > fileLength)
            {
                return Corrupted("PE header size is outside the file.");
            }

            double maxEntropy = 0;
            bool hasWriteExecuteSection = false;
            long lastRawEnd = sizeOfHeaders;
            int sectionsRead = 0;
            int entropyBytesRemaining =
                PeParserLimits.MaxTotalSectionEntropyBytes;
            var sections = new List<SectionRange>(numberOfSections);

            for (int i = 0; i < numberOfSections; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                long sectionOffset = sectionsStart + (long)i * 40;

                uint virtualSize = ReadUInt32(reader, sectionOffset + 8);
                uint virtualAddress = ReadUInt32(reader, sectionOffset + 12);
                uint rawSize = ReadUInt32(reader, sectionOffset + 16);
                uint rawPointer = ReadUInt32(reader, sectionOffset + 20);
                uint characteristics = ReadUInt32(reader, sectionOffset + 36);

                if (rawSize > 0)
                {
                    long rawEnd = (long)rawPointer + rawSize;

                    if (rawEnd < rawPointer ||
                        rawEnd > fileLength ||
                        rawPointer < sizeOfHeaders)
                        return Corrupted("Section raw data exceeds the file.");

                    foreach (SectionRange existingSection in sections)
                    {
                        if (existingSection.RawSize == 0)
                            continue;

                        long existingEnd = (long)existingSection.RawPointer +
                                           existingSection.RawSize;

                        if (rawPointer < existingEnd &&
                            existingSection.RawPointer < rawEnd)
                        {
                            return Corrupted(
                                "Section raw data ranges overlap.");
                        }
                    }

                    if (rawEnd > lastRawEnd)
                        lastRawEnd = rawEnd;
                }

                long virtualSizeForRange = Math.Max(virtualSize, rawSize);

                if (virtualSizeForRange > (long)uint.MaxValue + 1L - virtualAddress)
                    return Corrupted("Section virtual range exceeds RVA space.");

                long virtualEnd = (long)virtualAddress + virtualSizeForRange;

                foreach (SectionRange existingSection in sections)
                {
                    long existingSize = Math.Max(
                        existingSection.VirtualSize,
                        existingSection.RawSize);
                    long existingEnd =
                        (long)existingSection.VirtualAddress + existingSize;

                    if (virtualSizeForRange > 0 &&
                        existingSize > 0 &&
                        virtualAddress < existingEnd &&
                        existingSection.VirtualAddress < virtualEnd)
                    {
                        return Corrupted("Section virtual ranges overlap.");
                    }
                }

                sections.Add(new SectionRange(
                    virtualAddress,
                    virtualSize,
                    rawPointer,
                    rawSize));

                const uint MemExecute = 0x20000000;
                const uint MemWrite = 0x80000000;

                if ((characteristics & MemExecute) != 0 &&
                    (characteristics & MemWrite) != 0)
                {
                    hasWriteExecuteSection = true;
                }

                int bytesToRead = Math.Min(
                    entropyBytesRemaining,
                    (int)Math.Min(
                        rawSize,
                        PeParserLimits.MaxSectionEntropyBytes));

                if (bytesToRead > 0)
                {
                    double entropy = CalculateEntropy(
                        stream,
                        rawPointer,
                        bytesToRead,
                        cancellationToken);

                    entropyBytesRemaining -= bytesToRead;

                    if (entropy > maxEntropy)
                        maxEntropy = entropy;
                }

                sectionsRead++;
            }

            for (int i = 0; i < dataDirectories.Count; i++)
            {
                (int index, uint address, uint size) = dataDirectories[i];

                bool valid = index == 4
                    ? (long)address + size <= fileLength
                    : IsRvaRangeInFile(
                        address,
                        size,
                        sizeOfHeaders,
                        fileLength,
                        sections);

                if (!valid)
                    return Corrupted("Data directory range exceeds file data.");
            }

            bool hasOverlay = lastRawEnd < fileLength;

            return new PeAnalysisResult(
                PeFormatStatus.PeValid,
                SignatureStatus.NotChecked,
                null,
                hasWriteExecuteSection,
                maxEntropy,
                hasOverlay,
                sectionsRead,
                numberOfSections,
                Array.Empty<string>(),
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
        catch (Exception ex) when (
            ex is IOException ||
            ex is UnauthorizedAccessException ||
            ex is ArgumentException ||
            ex is NotSupportedException)
        {
            return Error(ex.Message);
        }
    }

    private static ushort ReadUInt16(BinaryReader reader, long offset)
    {
        reader.BaseStream.Position = offset;
        return reader.ReadUInt16();
    }

    private static bool IsRvaRangeInFile(
        uint address,
        uint size,
        uint sizeOfHeaders,
        long fileLength,
        IReadOnlyList<SectionRange> sections)
    {
        long rangeStart = address;
        long rangeSize = size;

        if (rangeStart < sizeOfHeaders)
        {
            return rangeStart + rangeSize <= sizeOfHeaders
                && rangeStart + rangeSize <= fileLength;
        }

        foreach (SectionRange section in sections)
        {
            long delta = rangeStart - section.VirtualAddress;

            long virtualExtent = Math.Max(
                section.VirtualSize,
                section.RawSize);

            if (delta < 0 || delta > virtualExtent || delta > section.RawSize)
                continue;

            if (rangeSize > section.RawSize - delta)
                continue;

            long fileStart = (long)section.RawPointer + delta;
            return fileStart + rangeSize <= fileLength;
        }

        return false;
    }

    private static uint ReadUInt32(BinaryReader reader, long offset)
    {
        reader.BaseStream.Position = offset;
        return reader.ReadUInt32();
    }

    private static double CalculateEntropy(
        Stream stream,
        long offset,
        int length,
        CancellationToken cancellationToken)
    {
        long originalPosition = stream.Position;
        stream.Position = offset;

        var frequencies = new long[256];
        var buffer = new byte[PeParserLimits.EntropyChunkSize];
        int remaining = length;

        try
        {
            while (remaining > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();

                int requested = Math.Min(buffer.Length, remaining);
                int read = stream.Read(buffer, 0, requested);

                if (read <= 0)
                    throw new EndOfStreamException(
                        "Section data changed while it was being read.");

                for (int i = 0; i < read; i++)
                    frequencies[buffer[i]]++;

                remaining -= read;
            }
        }
        finally
        {
            stream.Position = originalPosition;
        }

        long total = length - remaining;
        if (total <= 0)
            return 0;

        double entropy = 0;

        foreach (long count in frequencies)
        {
            if (count == 0)
                continue;

            double probability = (double)count / total;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }

    private static PeAnalysisResult NotPe()
    {
        return new PeAnalysisResult(
            PeFormatStatus.NotPe,
            SignatureStatus.NotChecked,
            null,
            false,
            0,
            false,
            0,
            0,
            Array.Empty<string>(),
            null);
    }

    private static PeAnalysisResult Corrupted(string message)
    {
        return new PeAnalysisResult(
            PeFormatStatus.PeCorrupted,
            SignatureStatus.NotChecked,
            null,
            false,
            0,
            false,
            0,
            0,
            Array.Empty<string>(),
            message);
    }

    private static PeAnalysisResult Error(string message)
    {
        return new PeAnalysisResult(
            PeFormatStatus.ParseError,
            SignatureStatus.NotChecked,
            null,
            false,
            0,
            false,
            0,
            0,
            Array.Empty<string>(),
            message);
    }

    private sealed record SectionRange(
        uint VirtualAddress,
        uint VirtualSize,
        uint RawPointer,
        uint RawSize);
}
