using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using SharpLdapRelayScan.NTLMSSP.Structs;
using Version = SharpLdapRelayScan.NTLMSSP.Structs.Version;

namespace SharpLdapRelayScan.NTLMSSP.Messages
{
    public class NtlmAuthenticate
    {

        private byte[] payload;
        private string signature;
        private int messageType;
        private NtlmFields lmChallengeResponseFields;
        private NtlmFields ntChallengeResponseFields;
        private NtlmFields encryptedRandomSessionKeyFields;
        private NtlmFields domainFields;
        private NtlmFields usernameFields;
        private NtlmFields workstationFields;
        private NegotiateFlags flags;
        private Version version;
        private byte[] mic;

        // High Level Variables
        private byte[] LMChallenge;
        private byte[] NTChallenge;
        private string domain;
        private string username;
        private string workstation;
        private string encryptedRandomSession;
        private NTLMv2Response ntlmResponse;
        private LMv2Response lmResponse;

        // this is a global variable that needs to be indicated
        private bool NTLMv2; 

        public NtlmAuthenticate()
        {
            this.signature = "NTLMSSP\0";
            this.messageType = 3;
            this.flags = NegotiateFlags.FLAG_NEGOTIATE_NONE;
            this.version = new Version();
            this.workstationFields = new NtlmFields();
            this.domainFields = new NtlmFields();
            this.usernameFields = new NtlmFields();
            this.encryptedRandomSessionKeyFields = new NtlmFields();
            this.ntChallengeResponseFields = new NtlmFields();
            this.lmChallengeResponseFields = new NtlmFields();

            this.payload = new byte[] { };
            this.mic = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        }

        public static NtlmAuthenticate Construct(NtlmChallenge ntlmChallenge, string username, string password, byte[] cbData = null, NegotiateFlags flags = NegotiateFlags.FLAG_NEGOTIATE_NONE)
        {
            // We define a variable to store the non-fixed length payload
            IEnumerable<byte> payload = new byte[] { };
            // And a variable byte-array for the partial additions
            byte[] tempArray;

            // We need to keep track of the payload position to set all the NtlmFields 
            int seek = 8 + 4 + 8 + 8 + 8 + 8 + 8 + 4;

            // We define a temporary index
            int temp;

            // First, we collect the AV Pairs from the server
            AVPairs targetInfo = ntlmChallenge.TargetInfo;
            // Next, we generate the NtlmCredentials we need
            // We need username, password and domain
            string domain = targetInfo.Get(AVPairType.MsvAvDnsDomainName).ToString();
            NetNTLMCredentials credentials = NetNTLMCredentials.Construct(username, password, domain, ntlmChallenge.ServerChallenge);

            // We also need a NTLM Response
            LMv2Response lmResponse = new LMv2Response();

            // First thing, we delete the EOL element
            ntlmChallenge.TargetInfo.Delete(AVPairType.MsvAvEOL);
            // We set the target name
            ntlmChallenge.TargetInfo.AddNew(AVPairType.MsvAvTargetName, targetInfo.Get(AVPairType.MsvAvDnsComputerName).data);

            // Here, we take care of the case when we need a CBT to be present, but needs to be miscalculated
            if (cbData != null)
            {
                byte[] cbt = new MD5CryptoServiceProvider().ComputeHash(cbData);
                ntlmChallenge.TargetInfo.AddNew(AVPairType.MsvChannelBindings, cbt);
            }
            // We restore the EOL element
            ntlmChallenge.TargetInfo.AddNew(AVPairType.MsvAvEOL, new byte[] { });

            NTLMv2Response ntlmResponse = new NTLMv2Response(credentials, targetInfo);

            // Init Auth Message
            NtlmAuthenticate auth = new NtlmAuthenticate();
            // Version
            seek += 8;
            // MIC
            seek += 16;
            tempArray = lmResponse.ToBytes();
            temp = tempArray.Length;
            if (temp > 0) {
                // LM Response is empty
                auth.lmChallengeResponseFields.offset = (ushort)seek;
                auth.lmChallengeResponseFields.length = (ushort)temp;
                auth.lmChallengeResponseFields.maxLength = (ushort)temp;
                seek += temp;
                payload = payload.Concat(tempArray);
            }
            tempArray = ntlmResponse.ToBytes();
            temp = tempArray.Length;
            if (temp > 0)
            {
                // NT Response
                auth.ntChallengeResponseFields.offset = (ushort)seek;
                auth.ntChallengeResponseFields.length = (ushort)temp;
                auth.ntChallengeResponseFields.maxLength = (ushort)temp;
                seek += temp;
                payload = payload.Concat(tempArray);
            }

            if (flags != NegotiateFlags.FLAG_NEGOTIATE_NONE)
            {
                // We overwrite the flags
                auth.flags = flags;
            }
            else {
                // We copy the flags from the last Binding response
                auth.flags = ntlmChallenge.Flags;
            }

            // Domain            
            if (!String.IsNullOrEmpty(credentials.Credential.Domain)) {
                tempArray = Encoding.Unicode.GetBytes(credentials.Credential.Domain);
                temp = tempArray.Length;
                // Domain Fields
                auth.domainFields.offset = (ushort)seek;
                auth.domainFields.length = (ushort)temp;
                auth.domainFields.maxLength = (ushort)temp;
                seek += temp;
                payload = payload.Concat(tempArray);
            }

            // Username
            if (!String.IsNullOrEmpty(credentials.Credential.UserName))
            {
                tempArray = Encoding.Unicode.GetBytes(credentials.Credential.UserName);
                temp = tempArray.Length;
                // Username Fields
                auth.usernameFields.offset = (ushort)seek;
                auth.usernameFields.length = (ushort)temp;
                auth.usernameFields.maxLength = (ushort)temp;
                seek += temp;
                payload = payload.Concat(tempArray);
            }

            // WorkStation
            if (!String.IsNullOrEmpty(Environment.MachineName))
            {
                tempArray = Encoding.Unicode.GetBytes(Environment.MachineName);
                temp = tempArray.Length;
                // Workstation Fields
                auth.workstationFields.offset = (ushort)seek;
                auth.workstationFields.length = (ushort)temp;
                auth.workstationFields.maxLength = (ushort)temp;
                seek += temp;
                payload = payload.Concat(tempArray);
            }

            // TODO: Encrypted Session

            auth.payload = payload.ToArray();
            return auth;

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
            // LM Challenge
            bytes = bytes.Concat(this.lmChallengeResponseFields.ToBytes());
            // NTLM Challenge
            bytes = bytes.Concat(this.ntChallengeResponseFields.ToBytes());
            // Domain Fields
            bytes = bytes.Concat(this.domainFields.ToBytes());
            // Username Fields
            bytes = bytes.Concat(this.usernameFields.ToBytes());
            // Workstation
            bytes = bytes.Concat(this.workstationFields.ToBytes());

            // TODO: EncryptedRandomSessionKey

            // Flags
            bytes = bytes.Concat(BitConverter.GetBytes((uint)this.flags));
            // Version
            bytes = bytes.Concat(this.version.ToBytes());
            // MIC
            bytes = bytes.Concat(this.mic);
            // Payload
            bytes = bytes.Concat(this.payload);

            return bytes.ToArray();

        }

        override public string ToString()
        {

            // Signature
            string result = "Signature: " + this.signature + Environment.NewLine;
            // Message Type
            result += "Message Type: " + this.messageType.ToString() + Environment.NewLine;
            
            // LM Challenge
            result += "LM Challenge: " + this.lmChallengeResponseFields.ToString() + Environment.NewLine;
            // LM Challenge
            result += "NT Challenge: " + this.ntChallengeResponseFields.ToString() + Environment.NewLine;
            
            result += "Domain Name Fields: " + this.domainFields.ToString() + Environment.NewLine;

            result += "Username Name Fields: " + this.usernameFields.ToString() + Environment.NewLine;
            result += "Workstation Name Fields: " + this.workstationFields.ToString() + Environment.NewLine;
            
            result += "Flags: 0x" + this.flags.ToString("X") + Environment.NewLine;

            if (this.version != null)
            {
                result += "Version: " + this.version.ToString() + Environment.NewLine;
            }
            result += "MIC " + BitConverter.ToString(this.mic).Replace("-", "") + Environment.NewLine;
            result += "Payload: " + BitConverter.ToString(this.payload).Replace("-", "") + Environment.NewLine;

            return result;

        }

    }

}
