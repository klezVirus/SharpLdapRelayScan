using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SharpLdapRelayScan.SPNEGO.Structs;
using Version = SharpLdapRelayScan.SPNEGO.Structs.Version;

namespace SharpLdapRelayScan.SPNEGO.Messages
{
    public class NtlmNegotiate
    {

        private byte[] payload;
        private string signature;
        private int messageType;
        private NegotiateFlags flags;
        private NtlmFields domain;
        private NtlmFields workstationame;
        private Version version;


        public NtlmNegotiate()
        {
            this.signature = "NTLMSSP\0";
            this.messageType = 1;
            this.flags = NegotiateFlags.FLAG_NEGOTIATE_NONE;
            this.version = new Version();
            this.workstationame = new NtlmFields();
            this.domain = new NtlmFields();
            this.payload = new byte[] { };
        }

        public static NtlmNegotiate Construct(NegotiateFlags flags, string domain = null, string workstation = null)
        {

            NtlmNegotiate nego = new NtlmNegotiate();
            if (flags != NegotiateFlags.FLAG_NEGOTIATE_NONE)
            {
                nego.flags = flags;
            }

            IEnumerable<byte> payload = new byte[] { };
            uint payload_offset = 32;
            byte[] tempData;

            if ((flags & NegotiateFlags.FLAG_NEGOTIATE_VERSION) == flags && nego.version == null)
            {
                Console.WriteLine("Negotiate Version Flag Set but Version not provided, removing flag");
                flags -= NegotiateFlags.FLAG_NEGOTIATE_VERSION;
            }
            else
            {
                payload = payload.Concat(nego.version.ToBytes());
                payload_offset += 8;
            }
            if ((flags & NegotiateFlags.FLAG_NEGOTIATE_OEM_DOMAIN_SUPPLIED) == flags && !string.IsNullOrEmpty(domain))
            {
                // UTF-16LE
                tempData = Encoding.Unicode.GetBytes(domain);
                nego.domain.length = (ushort)tempData.Length;
                nego.domain.offset = payload_offset;
                payload = payload.Concat(tempData);
                payload_offset += (uint)tempData.Length;

            }

            if ((flags & NegotiateFlags.FLAG_NEGOTIATE_OEM_WORKSTATION_SUPPLIED) == flags && !string.IsNullOrEmpty(workstation))
            {
                // UTF-16LE
                tempData = Encoding.Unicode.GetBytes(workstation);
                nego.workstationame.length = (ushort)tempData.Length;
                nego.workstationame.offset = payload_offset;
                payload = payload.Concat(tempData);
                payload_offset += (uint)tempData.Length;

            }

            // Finally updates payload
            nego.payload = payload.ToArray();

            return nego;

        }

        public byte[] ToBytes()
        {

            IEnumerable<byte> bytes = new byte[] { };
            byte[] tempData = new byte[] { };

            // Signature
            tempData = Encoding.UTF8.GetBytes(this.signature);
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

    }

}
