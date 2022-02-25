using SharpLdapRelayScan.SPNEGO.Structs;
using SharpLdapRelayScan.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Version = SharpLdapRelayScan.SPNEGO.Structs.Version;

namespace SharpLdapRelayScan.SPNEGO.Messages
{
    public class NtlmChallenge
    {

        private byte[] payload;
        private byte[] serverChallenge;
        private byte[] reserved;
        private string signature;
        private int messageType;
        private NegotiateFlags flags;
        private NtlmFields targetNameFields;
        private NtlmFields targetInfoFields;
        private NtlmFields domain;
        private NtlmFields workstationame;
        private Version version;

        // High Level Information
        public string TargetName;
        public AVPairs TargetInfo;
        public byte[] RawData;

        public byte[] ServerChallenge { get => serverChallenge; set => serverChallenge = value; }
        public NegotiateFlags Flags { get => flags; set => flags = value; }

        public NtlmChallenge()
        {
            this.RawData = null;
            this.signature = "NTLMSSP\0";
            this.messageType = 2;
            this.targetNameFields = new NtlmFields();
            this.targetInfoFields = new NtlmFields();
            this.flags = NegotiateFlags.FLAG_NEGOTIATE_NONE;
            this.version = new Version();
            this.payload = new byte[] { };
            this.reserved = new byte[8] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, };

            // High Level Information
            this.TargetName = "";
            this.TargetInfo = new AVPairs();

        }

        public NtlmChallenge(byte[] data)
        {
            this.RawData = data;
            int seek = 0;
            var sign = Encoding.UTF8.GetString(data.RangeSubset<byte>(seek, 8));
            if (!String.Equals(sign, "NTLMSSP\0"))
            {
                Console.WriteLine("[-] Wrong Signature in NTLMSSP Challenge: {0}", sign);
            }
            // Forward 8 bytes 
            seek += 8;
            this.signature = sign;
            this.messageType = BitConverter.ToInt32(data, seek);
            // Forward 4 bytes (sizeof(int)) 
            seek += 4;
            // NtlmFields doesn't implement a way to slice the data
            // buffer passed to it, so we need to take care of it here
            this.targetNameFields = new NtlmFields(data.RangeSubset<byte>(seek, 8));
            // Forward 8 bytes 
            seek += 8;
            
            this.ServerChallenge = data.RangeSubset<byte>(seek, 8);
            // Forward 8 bytes 
            seek += 8;

            this.flags = (NegotiateFlags)BitConverter.ToUInt32(data, seek);
            // Forward 4 bytes (sizeof(int)) 
            seek += 4;

            this.reserved = data.RangeSubset<byte>(seek, 8);
            foreach (byte b in this.reserved)
            {
                if (b != 0x00)
                {
                    Console.WriteLine("[-] Error: A reserved byte is != 0");
                }
            }
            // Forward 8 bytes 
            seek += 8;

            this.targetInfoFields = new NtlmFields(data.RangeSubset<byte>(seek, 8));
            // Forward 8 bytes 
            seek += 8;

            if ((flags & NegotiateFlags.FLAG_NEGOTIATE_VERSION) == flags)
            {
                version = new Version(data.RangeSubset<byte>(seek, 8));
            }
            // Forward 8 bytes 
            seek += 8;

            this.payload = data.RangeSubset<byte>(seek, data.Length - seek);

            byte[] raw;
            if (this.targetNameFields.length > 0)
            {
                raw = data.RangeSubset<byte>((int)this.targetNameFields.offset, this.targetNameFields.length);
                this.TargetName = Encoding.Unicode.GetString(raw);
            }
            if (this.targetInfoFields.length > 0)
            {
                raw = data.RangeSubset<byte>((int)this.targetInfoFields.offset, this.targetInfoFields.length);
                this.TargetInfo = new AVPairs(raw);
            }

        }

        public byte[] ToBytes()
        {

            IEnumerable<byte> bytes = new byte[] { };
            byte[] tempData = new byte[] { };

            // Signature
            tempData = Encoding.Unicode.GetBytes(this.signature);
            bytes = bytes.Concat(tempData);
            // Message Type
            bytes = bytes.Concat(BitConverter.GetBytes(this.messageType));
            // Flags
            bytes = bytes.Concat(BitConverter.GetBytes((uint)this.flags));
            // Domain Fields
            bytes = bytes.Concat(this.domain.ToBytes());
            // Workstation
            bytes = bytes.Concat(this.workstationame.ToBytes());
            // Payload
            bytes = bytes.Concat(this.payload);

            return bytes.ToArray();

        }

        override public string ToString()
        {
            string result = "Signature: " + this.signature + Environment.NewLine;
            result += "Message Type: " + this.messageType.ToString() + Environment.NewLine;
            result += "Targets Name Fields: " + this.targetNameFields.ToString() + Environment.NewLine;
            result += "Flags: 0x" + this.flags.ToString("X") + Environment.NewLine;
            result += "Server Challenge " + BitConverter.ToString(this.ServerChallenge).Replace("-", "") + Environment.NewLine;
            result += "Reserved " + BitConverter.ToString(this.reserved).Replace("-", "") + Environment.NewLine;
            result += "Target Info Fields: " + this.targetInfoFields.ToString() + Environment.NewLine;
            if (this.version != null)
            {
                result += "Version: " + this.version.ToString() + Environment.NewLine;
            }
            result += "Payload: " + BitConverter.ToString(this.payload).Replace("-", "") + Environment.NewLine;

            if (!String.IsNullOrEmpty(this.TargetName))
            {
                result += "Targets Name: " + this.TargetName + Environment.NewLine;
            }
            if (!this.TargetInfo.IsEmpty())
            {
                result += "MsvAV Structures: " + Environment.NewLine + this.TargetInfo.ToString() + Environment.NewLine;
            }
            return result;
        }

    }



}
