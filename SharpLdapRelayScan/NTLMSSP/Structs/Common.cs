using SharpLdapRelayScan.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpLdapRelayScan.SPNEGO.Structs
{
    class Common
    {
    }

    public enum NegotiateFlags : uint
    {
        FLAG_NEGOTIATE_56 = 0x80000000,
        FLAG_NEGOTIATE_KEY_EXCH = 0x40000000,
        FLAG_NEGOTIATE_128 = 0x20000000,
        FLAG_NEGOTIATE_0x10000000 = 0x10000000,
        FLAG_NEGOTIATE_0x08000000 = 0x08000000,
        FLAG_NEGOTIATE_0x04000000 = 0x04000000,
        FLAG_NEGOTIATE_VERSION = 0x02000000,
        FLAG_NEGOTIATE_0x01000000 = 0x01000000,
        FLAG_NEGOTIATE_TARGET_INFO = 0x00800000,
        FLAG_REQUEST_NOT_NT_SESSION_KEY = 0x00400000,
        FLAG_NEGOTIATE_0x00200000 = 0x00200000,
        FLAG_NEGOTIATE_IDENTIFY = 0x00100000,
        FLAG_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000,
        FLAG_TARGET_TYPE_SHARE = 0x00040000,
        FLAG_TARGET_TYPE_SERVER = 0x00020000,
        FLAG_TARGET_TYPE_DOMAIN = 0x00010000,
        FLAG_NEGOTIATE_ALWAYS_SIGN = 0x00008000,
        FLAG_NEGOTIATE_0x00004000 = 0x00004000,
        FLAG_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000,
        FLAG_NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x00001000,
        FLAG_NEGOTIATE_ANONYMOUS = 0x00000800,
        FLAG_NEGOTIATE_NT_ONLY = 0x00000400,
        FLAG_NEGOTIATE_NTLM = 0x00000200,
        FLAG_NEGOTIATE_0x00000100 = 0x00000100,
        FLAG_NEGOTIATE_LM_KEY = 0x00000080,
        FLAG_NEGOTIATE_DATAGRAM = 0x00000040,
        FLAG_NEGOTIATE_SEAL = 0x00000020,
        FLAG_NEGOTIATE_SIGN = 0x00000010,
        FLAG_REQUEST_0x00000008 = 0x00000008,
        FLAG_REQUEST_TARGET = 0x00000004,
        FLAG_NEGOTIATE_OEM = 0x00000002,
        FLAG_NEGOTIATE_UNICODE = 0x00000001,
        FLAG_NEGOTIATE_NONE = 0x00000000

    }


    public class NtlmFields
    {

        public ushort length;
        public ushort maxLength;
        public uint offset;


        public NtlmFields()
        {
            length = 0;
            maxLength = 0;
            offset = 0;
        }

        public NtlmFields(byte[] data)
        {

            this.length = BitConverter.ToUInt16(data, 0);
            this.maxLength = BitConverter.ToUInt16(data, 2);
            this.offset = BitConverter.ToUInt32(data, 4);

        }

        public byte[] ReadData(byte[] data) {
            if (data == null) {
                return null;
            }
            if (data.Length - this.offset < this.length) {
                return null;
            }
            return data.RangeSubset<byte>((int)this.offset, this.length);
        }

        public byte[] ToBytes()
        {

            IEnumerable<byte> bytes = new byte[] { };

            bytes = bytes
                .Concat(BitConverter.GetBytes(length))
                .Concat(BitConverter.GetBytes(maxLength))
                .Concat(BitConverter.GetBytes(offset));

            return bytes.ToArray();
        }

        override public string ToString()
        {

            string result = "";

            result += "Length: " + length.ToString() + " - ";
            result += "Max Length: " + maxLength.ToString() + " - ";
            result += "Offset: " + offset + " ";

            return result;
        }

    }

    public class Version
    {
        public byte ProductMajorVersion;
        public byte ProductMinorVersion;
        public byte[] ProductBuild;
        public byte[] Reserved;
        public byte NTLMRevisionCurrent;

        public Version()
        {

            this.ProductMajorVersion = 0x0A;                    // Windows 10
            this.ProductMinorVersion = 0x00;                    // Windows 10.0
            this.ProductBuild = new byte[2] { 0x13, 0x06 };     // 1555
            this.Reserved = new byte[3] { 0x00, 0x00, 0x00 };   // Reserved = 0
            this.NTLMRevisionCurrent = 0x0F;                    // NTLMSSP_REVISION_W2K3

        }

        public Version(byte[] data)
        {

            this.ProductMajorVersion = data[0];
            this.ProductMinorVersion = data[1];
            this.ProductBuild = new byte[2] { data[3], data[2] };
            this.Reserved = new byte[3] { data[6], data[5], data[4] };
            this.NTLMRevisionCurrent = data[7];

        }

        public byte[] ToBytes()
        {
            // Absolutely not elegant, but I don't care
            return new byte[] {
                this.ProductMajorVersion,
                this.ProductMinorVersion,
                this.ProductBuild[0], this.ProductBuild[1],
                this.Reserved[0], this.Reserved[1], this.Reserved[2],
                this.NTLMRevisionCurrent
            };
        }


        override public string ToString()
        {
            string result = "  Product Version: " + ((int)this.ProductMajorVersion).ToString() + ((int)this.ProductMajorVersion).ToString() + Environment.NewLine;
            result += "  Product Build: " + BitConverter.ToUInt16(this.ProductBuild, 0).ToString() + Environment.NewLine;
            result += "  Reserved: " + BitConverter.ToString(this.Reserved).Replace("-", "") + Environment.NewLine;
            result += "  NTLM Version: " + ((int)this.NTLMRevisionCurrent).ToString() + Environment.NewLine;

            return result;
        }
    }

    public enum MsvAvFlags : uint
    {
        CONSTRAINED_AUTH = 0x00000001,
        MIC_PRESENT = 0x00000002,
        SPN_UNTRUSTED = 0x00000004
    }

    public enum AVPairType : ushort
    {
        Dummy = 0xFFFF,
        MsvAvEOL = 0x0000,
        MsvAvNbComputerName = 0x0001,
        MsvAvNbDomainName = 0x0002,
        MsvAvDnsComputerName = 0x0003,  // The fully qualified domain name (FQDN) of the computer. The name MUST be in Unicode, and is not null-terminated.
        MsvAvDnsDomainName = 0x0004,    // The FQDN of the domain. The name MUST be in Unicode, and is not null-terminated.
        MsvAvDnsTreeName = 0x0005,      // The FQDN of the forest. The name MUST be in Unicode, and is not null-terminated.<13>
        MsvAvFlags = 0x0006,            // A 32-bit value indicating server or client configuration.
        MsvAvTimestamp = 0x0007,        // A FILETIME structure ([MS-DTYP] section 2.3.3) in little-endian byte order that contains the server local time. This structure is always sent in the CHALLENGE_MESSAGE.<16>
        MsvAvSingleHost = 0x0008,       // A Single_Host_Data (section 2.2.2.2) structure. The Value field contains a platform-specific blob, as well as a MachineID created at computer startup to identify the calling machine.<17>
        MsvAvTargetName = 0x0009,       // The SPN of the target server. The name MUST be in Unicode and is not null-terminated.<18>
        MsvChannelBindings = 0x000A     // A channel bindings hash. The Value field contains an MD5 hash ([RFC4121] section 4.1.1.2) of a gss_channel_bindings_struct ([RFC2744] section 3.11). An all-zero value of the hash is used to indicate absence of channel bindings.<19>

    }

    public class AVPair
    {
        public AVPairType type;
        public ushort length;
        public byte[] data;

        public AVPair(AVPairType type, byte[] data)
        {
            this.type = type;
            this.data = data;
            this.length = (ushort)data.Length;
        }

        public AVPair(byte[] data)
        {
            this.type = (AVPairType)BitConverter.ToUInt16(data, 0);
            this.length = BitConverter.ToUInt16(data, 2);
            if (this.length != 0)
            {
                this.data = BinTools.RangeSubset(data, 4, this.length);
            }
            else
            {
                this.data = new byte[] { };
            }
        }

        public byte[] ToBytes()
        {

            IEnumerable<byte> bytes = new byte[] { };

            bytes = bytes
                .Concat(BitConverter.GetBytes((ushort)type))
                .Concat(BitConverter.GetBytes(length))
                .Concat(data);

            return bytes.ToArray();
        }

        override public string ToString()
        {
            string result = "";
            if (this.type == AVPairType.MsvAvFlags)
            {
                result = BitConverter.ToInt32(this.data, 0).ToString();
            }
            if (this.type == AVPairType.MsvAvTimestamp)
            {
                result = BitConverter.ToInt64(this.data, 0).ToString();
            }
            else
            {
                try
                {
                    result = Encoding.Unicode.GetString(this.data);
                }
                catch { }
            }
            return result;
        }
    }

    public class AVPairs
    {
        public List<AVPair> avPairs;

        public AVPairs()
        {
            avPairs = new List<AVPair>();
        }

        public AVPairs(byte[] data)
        {
            avPairs = new List<AVPair>();
            AVPairType currentType = AVPairType.Dummy;
            int seek = 0;
            while (currentType != AVPairType.MsvAvEOL && seek < data.Length)
            {
                AVPair avPair = new AVPair(BinTools.RangeSubset(data, seek, data.Length - seek));
                avPairs.Add(avPair);
                currentType = avPair.type;

                // payload + header
                seek += avPair.length + 4;
            }
        }

        public int Index(AVPairType type) { 
            return avPairs.FindIndex(x => x.type == type);
        }
        public AVPair Get(AVPairType type) {
            int index = this.Index(type);
            if (index >= 0) {
                return avPairs[index];
            }
            return null;
        }

        public void Delete(AVPairType type) {
            int index = this.Index(type);
            if (index >= 0)
            {
                this.avPairs.RemoveAt(index);
            }
        }

        public void AddNew(AVPairType type, byte[] data) {
            AVPair newAVPair = new AVPair(type, data);
            this.Add(newAVPair);
        }

        public void Add(AVPair avPair) {

            int index = this.Index(avPair.type);
            if (index >= 0) {
                avPairs[index] = avPair;
                return;
            }
            this.avPairs.Add(avPair);
        }

        public int Length()
        {
            return this.avPairs.Count();
        }

        public bool IsEmpty()
        {
            return this.avPairs.Count() == 0;
        }

        public byte[] ToBytes()
        {
            IEnumerable<byte> bytes = new byte[] { };

            foreach (AVPair avp in avPairs)
            {
                bytes = bytes.Concat(avp.ToBytes());
            }

            return bytes.ToArray();
        }

        public void RemoveCBT()
        {
            AVPair pair = avPairs.Find(x => x.type == AVPairType.MsvChannelBindings);
            if (pair != null)
            {
                avPairs.Remove(pair);
            }
        }

        public void TamperCBT()
        {

            int index = avPairs.FindIndex(x => x.type == AVPairType.MsvChannelBindings);
            if (index >= 0)
            {
                byte[] data = Encoding.ASCII.GetBytes(new string((char)0, avPairs[index].data.Length));
                avPairs[index].data = data;
            }
        }

        override public string ToString()
        {
            string result = "";
            foreach (AVPair avp in avPairs)
            {
                result += avp.type.ToString() + ": ";
                result += avp.ToString() + Environment.NewLine;
            }
            return result;
        }
    }




}
