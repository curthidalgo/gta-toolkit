﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RageLib.Resources.RDR2.PC.Drawables
{
    // VertexBuffer
    // VFT - 0x0000000140912400
    public class VertexBuffer : DatBase64
    {
        public override long BlockLength => 0x40;

        // structure data
        public uint VertexCount;
        public ushort VertexStride;
        public ushort Unknown_0Eh;          // 0x0000
        public uint Flags;
        public uint Unknown_14h;            // 0x00000000
        public ulong DataPointer;
        public ulong Unknown_20h;           // 0x0000000000000000
        public ulong Unknown_28h;           // 0x0000000000000000
        public ulong Unknown_30h_Pointer;
        public ulong Unknown_38h_Pointer;

        // reference data
        public VertexData_RDR2_pc Data;
        public Struct_15 Unknown_30h_Data;
        public Struct_21 Unknown_38h_Data;

        public override void Read(ResourceDataReader reader, params object[] parameters)
        {
            base.Read(reader, parameters);

            // read structure data


            // read reference data
        }

        public override void Write(ResourceDataWriter writer, params object[] parameters)
        {
            base.Write(writer, parameters);

            // write structure data


            // write reference data
        }
    }

    // TODO: Replace this and the one for GTA5 with an array of bytes
    public class VertexData_RDR2_pc : ResourceSystemBlock
    {
        public override long BlockLength => Data != null ? Data.Length : 0;

        // structure data
        public byte[] Data;

        /// <summary>
        /// Reads the data-block from a stream.
        /// </summary>
        public override void Read(ResourceDataReader reader, params object[] parameters)
        {
            int stride = Convert.ToInt32(parameters[0]);
            int count = Convert.ToInt32(parameters[1]);

            Data = reader.ReadBytes(count * stride);
        }

        /// <summary>
        /// Writes the data-block to a stream.
        /// </summary>
        public override void Write(ResourceDataWriter writer, params object[] parameters)
        {
            writer.Write(Data);
        }
    }
}
