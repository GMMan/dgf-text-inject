using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Text;
using AsmResolver;
using AsmResolver.PE.File;
using AsmResolver.PE.File.Headers;

namespace DgfTextInject
{
    class Program
    {
        static Encoding shiftJisEncoding;

        static void Main(string[] args)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            shiftJisEncoding = Encoding.GetEncoding(932);

            if (args.Length != 4)
            {
                Console.WriteLine("Usage: DgfTextInject <exeSrcPath> <exeDestPath> <lectSrcPath> <lsSrcPath>");
                Environment.Exit(2);
            }

            string exeSrcPath = args[0];
            string exeDestPath = args[1];
            string lectSrcPath = args[2];
            string lsSrcPath = args[3];

            try
            {
                int numLectEntries = 151;
                uint lectdatRva = 0x15FE10;
                int lectStringsSize = 0;

                int numLsEntries = 24;
                uint lsmenuRva = 0x1D9488;
                int lsStringsSize = 0;

                var pe = PEFile.FromFile(exeSrcPath);

                // This dumps text files
                //using (StreamWriter sw = File.CreateText(lectSrcPath))
                //    DumpStrings(pe, lectdatRva, numLectEntries, 0x2c, 0x50, sw);
                //using (StreamWriter sw = File.CreateText(lsSrcPath))
                //    DumpStrings(pe, lsmenuRva, numLsEntries, 0x04, 0x0c, sw);
                //return;

                string[] newLectStrings = File.ReadAllLines(lectSrcPath);
                if (newLectStrings.Length != numLectEntries)
                    throw new InvalidDataException("Lectures source file does not contain same number of lines as number of lecture definitions.");
                uint newLectSpace = CalcSpaceRequired(newLectStrings);

                string[] newLsStrings = File.ReadAllLines(lsSrcPath);
                if (newLsStrings.Length != numLsEntries)
                    throw new InvalidDataException("LS source file does not contain same number of lines as number of LS definitions.");
                uint newLsSpace = CalcSpaceRequired(newLsStrings);

                bool lectInNewSection = true; // newLectSpace > lectStringsSize;
                bool lsInNewSection = true; //  newLsSpace > lsStringsSize;

                Dictionary<string, uint> writtenLectStrings = new Dictionary<string, uint>();
                Dictionary<string, uint> writtenLsStrings = new Dictionary<string, uint>();
                List<uint> lectOffsets = new List<uint>();
                List<uint> lsOffsets = new List<uint>();

                using MemoryStream newSectionMs = new MemoryStream();
                using MemoryStream newLectMs = new MemoryStream();
                using MemoryStream newLsMs = new MemoryStream();

                WriteStrings(lectInNewSection ? newSectionMs : newLectMs, newLectStrings, writtenLectStrings, lectOffsets);
                WriteStrings(lsInNewSection ? newSectionMs : newLsMs, newLsStrings, writtenLsStrings, lsOffsets);

                PESection newSection = null;
                if (lectInNewSection || lsInNewSection)
                {
                    newSection = new PESection(".trans", SectionFlags.MemoryRead | SectionFlags.ContentInitializedData);
                    newSection.Contents = new DataSegment(newSectionMs.ToArray());
                    pe.Sections.Add(newSection);
                    pe.UpdateHeaders();
                }

                uint additionalNewSectOffset = 0;
                uint stringsRva = UpdateTable(pe, lectdatRva, 0x2c, 0x50, lectOffsets, lectInNewSection ? (uint?)(newSection.Rva + additionalNewSectOffset) : null);
                if (lectInNewSection)
                {
                    additionalNewSectOffset += newLectSpace;
                }
                else
                {
                    var dataSect = pe.GetSectionContainingRva(stringsRva);
                    using (MemoryStream ms = new MemoryStream((dataSect.Contents as DataSegment).Data))
                    {
                        ms.Seek(stringsRva - dataSect.Rva, SeekOrigin.Begin);
                        ms.Write(newLectMs.ToArray());
                    }
                }
                stringsRva = UpdateTable(pe, lsmenuRva, 0x04, 0x0c, lsOffsets, lsInNewSection ? (uint?)(newSection.Rva + additionalNewSectOffset) : null);
                if (lsInNewSection)
                {
                    additionalNewSectOffset += newLsSpace;
                }
                else
                {
                    var dataSect = pe.GetSectionContainingRva(stringsRva);
                    using (MemoryStream ms = new MemoryStream((dataSect.Contents as DataSegment).Data))
                    {
                        ms.Seek(stringsRva - dataSect.Rva, SeekOrigin.Begin);
                        ms.Write(newLsMs.ToArray());
                    }
                }

                pe.Write(exeDestPath);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Something went wrong: " + ex.ToString());
                Environment.Exit(1);
            }
        }

        static void DumpStrings(PEFile pe, uint tableRva, int numEntries, int entryPointerOffset, int entrySize, StreamWriter sw)
        {
            var tableSection = pe.GetSectionContainingRva(tableRva);
            var tableData = ((tableSection.Contents as VirtualSegment).PhysicalContents as DataSegment).Data;
            using MemoryStream tableMs = new MemoryStream(tableData);
            tableMs.Seek(tableRva - tableSection.Rva, SeekOrigin.Begin);
            BinaryReader br = new BinaryReader(tableMs);

            for (int i = 0; i < numEntries; ++i)
            {
                var tablePos = tableMs.Position;
                tableMs.Seek(entryPointerOffset, SeekOrigin.Current);
                uint stringVa = br.ReadUInt32();
                tableMs.Seek((long)(stringVa - pe.OptionalHeader.ImageBase - tableSection.Rva), SeekOrigin.Begin);
                List<byte> stringBytes = new List<byte>();
                byte b;
                while ((b = br.ReadByte()) != 0)
                {
                    stringBytes.Add(b);
                }
                sw.WriteLine(shiftJisEncoding.GetString(stringBytes.ToArray()));
                tableMs.Seek(tablePos + entrySize, SeekOrigin.Begin);
            }
        }

        static uint UpdateTable(PEFile pe, uint tableRva, int entryPointerOffset, int entrySize, List<uint> offsets, uint? newSectionRva)
        {
            var tableSection = pe.GetSectionContainingRva(tableRva);
            var tableData = ((tableSection.Contents as VirtualSegment).PhysicalContents as DataSegment).Data;
            using MemoryStream tableMs = new MemoryStream(tableData);
            tableMs.Seek(tableRva - tableSection.Rva, SeekOrigin.Begin);
            BinaryWriter bw = new BinaryWriter(tableMs);

            uint dataBaseVa;
            if (newSectionRva.HasValue)
            {
                dataBaseVa = (uint)(pe.OptionalHeader.ImageBase + newSectionRva.Value);
            }
            else
            {
                // Get first string offset
                tableMs.Seek(entryPointerOffset, SeekOrigin.Current);
                BinaryReader br = new BinaryReader(tableMs);
                dataBaseVa = br.ReadUInt32();
                tableMs.Seek(-(entryPointerOffset + 4), SeekOrigin.Current);
            }

            foreach (var offset in offsets)
            {
                tableMs.Seek(entryPointerOffset, SeekOrigin.Current);
                bw.Write(dataBaseVa + offset);
                tableMs.Seek(entrySize - entryPointerOffset - 4, SeekOrigin.Current);
            }

            tableMs.Flush();
            return (uint)(dataBaseVa - pe.OptionalHeader.ImageBase);
        }

        static uint CalcSpaceRequired(string[] strings)
        {
            uint space = 0;
            foreach (var s in new HashSet<string>(strings))
            {
                // 4-byte align strings
                space += (uint)((shiftJisEncoding.GetByteCount(s) + 1 + 3) & ~3);
            }
            return space;
        }

        static void WriteStrings(Stream destStream, string[] strings, Dictionary<string, uint> offsetsList, List<uint> finalOffsets)
        {
            var startOffset = destStream.Position;
            foreach (var s in strings)
            {
                if (offsetsList.ContainsKey(s))
                {
                    finalOffsets.Add(offsetsList[s]);
                }
                else
                {
                    var offset = destStream.Position - startOffset;
                    byte[] encodedString = shiftJisEncoding.GetBytes(s);
                    var paddedLength = (encodedString.Length + 1 + 3) & ~3;
                    destStream.Write(encodedString);
                    destStream.Write(new byte[paddedLength - encodedString.Length]);
                    offsetsList.Add(s, (uint)offset);
                    finalOffsets.Add((uint)offset);
                }
            }
        }
    }
}
