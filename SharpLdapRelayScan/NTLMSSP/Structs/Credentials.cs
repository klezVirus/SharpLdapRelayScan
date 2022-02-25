using SharpLdapRelayScan.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

namespace SharpLdapRelayScan.NTLMSSP.Structs
{
    public class NetNTLMCredentials
    {

        private NetworkCredential credential;
        private byte[] LMResponse;
        private byte[] NTResponse;
        private byte[] LMHash;
        private byte[] NTHash;
        private byte[] sessionBaseKey;
        private byte[] randomSessionKey;
        private byte[] clientChallenge;
        private byte[] serverChallenge;


        public NetNTLMCredentials(string username, string password, string domain) {

            Credential = new NetworkCredential(username, password, domain);
            ClientChallenge = Crypto.RandomByteArray(8);
            randomSessionKey = Crypto.RandomByteArray(16);
            LMHash = NtlmCredentialHelper.LmHash(password);
            NTHash = NtlmCredentialHelper.NtHash2(username, password, domain);
            ServerChallenge = null;
            sessionBaseKey = null;
        
        }

        public NetworkCredential Credential { get => credential; set => credential = value; }
        public byte[] ServerChallenge { get => serverChallenge; set => serverChallenge = value; }
        public byte[] ClientChallenge { get => clientChallenge; set => clientChallenge = value; }
        public byte[] NtlmV2Hash { get => NTHash; set => NTHash = value; }

        public static NetNTLMCredentials Construct(string username, string password, string domain, byte[] serverChallenge) {

            NetNTLMCredentials netNTLMCredentials = new NetNTLMCredentials(username, password, domain);
            netNTLMCredentials.ServerChallenge = serverChallenge;
            return netNTLMCredentials;
        }

    }

    public class NetNTLMCredentialsEx
    {
    }


    public class LMv2Response
    {

        byte[] payload;
        public LMv2Response() {

            payload = new byte[] { };

        }

        public byte[] ToBytes() {
            return payload;
        }
        
        override public string ToString() {
            return "LM Response: " + BitConverter.ToString(this.payload).Replace("-", "");
        }
    }
    public class NTLMv2Response 
    {
        private byte[] ntProofStr;
        private byte[] responseType;
        private byte[] hiResponseType;
        private byte[] reserved1;
        private byte[] timestamp;
        private int reserved2;
        private byte[] challengeFromClient;
        private int reserved3;
        private AVPairs details;

        public NTLMv2Response(NetNTLMCredentials credentials, AVPairs details) {

            responseType = new byte[] { 0x01 };
            hiResponseType = new byte[] { 0x01 };
            reserved1 = new byte[6] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            reserved2 = reserved3 = 0;
            challengeFromClient = Crypto.RandomByteArray(8);
            this.details = details;
            timestamp = BitConverter.GetBytes(DateTime.Now.ToFileTimeUtc());
            // hmac.new(response_key_nt, self.server_challenge + temp, digestmod=hashlib.md5).digest()
            ntProofStr = __generateNtProof(credentials.ServerChallenge, credentials.NtlmV2Hash);

        }

        public byte[] ToBytes() {

            IEnumerable<byte> bytes = new byte[] { };
            // NT Proof
            bytes = bytes.Concat(this.ntProofStr);
            // Response Type
            bytes = bytes.Concat(this.responseType);
            // Hi Response Type
            bytes = bytes.Concat(this.hiResponseType);
            // Reserved1
            bytes = bytes.Concat(this.reserved1);
            // Timestamp
            bytes = bytes.Concat(this.timestamp);
            // Client Challenge
            bytes = bytes.Concat(this.challengeFromClient);
            // Reserved2
            bytes = bytes.Concat(BitConverter.GetBytes(this.reserved2));
            // Details (AVPairs)
            bytes = bytes.Concat(this.details.ToBytes());
            // Reserved3
            bytes = bytes.Concat(BitConverter.GetBytes(this.reserved3));
            
            return bytes.ToArray();

        }

        private byte[] __generateNtProof(byte[] serverChallenge, byte[] NtlmV2Hash) {

            IEnumerable<byte> bytes = new byte[] { };
            // Server Challenge
            bytes = bytes.Concat(serverChallenge);
            // Response Type
            bytes = bytes.Concat(this.responseType);
            // Hi Response Type
            bytes = bytes.Concat(this.hiResponseType);
            // Reserved1
            bytes = bytes.Concat(this.reserved1);
            // Timestamp
            bytes = bytes.Concat(this.timestamp);
            // Client Challenge
            bytes = bytes.Concat(this.challengeFromClient);
            // Reserved2
            bytes = bytes.Concat(BitConverter.GetBytes(this.reserved2));
            // Details (AVPairs)
            bytes = bytes.Concat(this.details.ToBytes());
            // Reserved3
            bytes = bytes.Concat(BitConverter.GetBytes(this.reserved3));

            // Debugging
            var md5 = new HMACMD5(NtlmV2Hash);
            byte[] temp = bytes.ToArray();
            byte[] result = md5.ComputeHash(temp);
#if DEVDEBUG
            Console.WriteLine("[DEBUG] NTProof - " + BitConverter.ToString(result));
#endif
            return result;
        }

        override public string ToString() {

            string result = "";
            // Response Type
            result += "Message Type: " + BitConverter.ToString(this.responseType).Replace("-", "") + Environment.NewLine;
            // Hi Response Type
            result += "Hi Response Type: " + BitConverter.ToString(this.responseType).Replace("-", "") + Environment.NewLine;
            // Reserved1
            result += "Reserved1: " + BitConverter.ToString(this.responseType).Replace("-", "") + Environment.NewLine;
            // Timestamp
            result += "Timestamp: " + String.Format("{0:r}", new DateTime(BitConverter.ToInt64(this.timestamp, 0))) + Environment.NewLine;
            // Client Challenge
            result += "Client Challenge: " + BitConverter.ToString(this.responseType).Replace("-", "") + Environment.NewLine;
            // Reserved2
            result += "Reserved2: " + BitConverter.ToString(this.responseType).Replace("-", "") + Environment.NewLine;
            // Details (AVPairs)
            result += "Details: " + Environment.NewLine + this.details.ToString() + Environment.NewLine;
            // Reserved3
            result += "Reserved3: " + BitConverter.ToString(this.responseType).Replace("-", "") + Environment.NewLine;

            return result;

        }

    }


    public static class NtlmCredentialHelper 
    {

        public static byte[] NtHash(string password)
        {
            if (String.IsNullOrEmpty(password))
            {
                return null;
            }
            return Crypto.Md4Hash(password);
        }
        public static byte[] NtHash2(string username, string password, string domain)
        {
            if (String.IsNullOrEmpty(password))
            {
                return null;
            }
            var ntHashV1 = NtHash(password);

            var md5 = new HMACMD5(ntHashV1);

            byte[] hash = md5.ComputeHash(Encoding.Unicode.GetBytes(username.ToUpperInvariant() + domain.ToUpperInvariant()));

            return hash;
        }

        private static byte[] ComputeHalf(byte[] Half)
        {

            if (Half.Length == 0)
                return new byte[] { 0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE };
            else if (Half.Length > 7)
                throw new NotSupportedException("Password halves greater than 7 " +
                "characters are not supported");

            Array.Resize(ref Half, 7);

            StringBuilder binaryString = new StringBuilder();

            foreach (char c in Half)
            {
                string s = Convert.ToString(c, 2);

                int padLen = 8 - s.Length;

                binaryString.Append(new string('0', padLen) + s);
            }

            for (int y = 8; y > 0; y--)
                binaryString.Insert(y * 7, '0');

            string binary = binaryString.ToString();

            byte[] key = new byte[8];

            for (int y = 0; y < 8; y++)
                key[y] = Convert.ToByte(binary.Substring(y * 8, 8), 2);

            DESCryptoServiceProvider des = new DESCryptoServiceProvider();

            des.Key = key;
            des.IV = new byte[8];

            using (MemoryStream stream = new MemoryStream())
            {
                using (CryptoStream cryptStream = new CryptoStream(stream,
                des.CreateEncryptor(), CryptoStreamMode.Write))
                using (StreamWriter writer = new StreamWriter(cryptStream))
                    writer.Write("KGS!@#$%");

                byte[] b = stream.ToArray();

                Array.Resize(ref b, 8);

                return b;
            }
        }

        public static byte[] LmHash(string password)
        {
            if (password.Length > 14)
                throw new NotSupportedException("Passwords greater than 14 " +
                "characters are not supported");

            byte[] passBytes = Encoding.ASCII.GetBytes(password.ToUpper());

            byte[][] passHalves = new byte[2][];

            if (passBytes.Length > 7)
            {
                int len = passBytes.Length - 7;

                passHalves[0] = new byte[7];
                passHalves[1] = new byte[len];

                Array.Copy(passBytes, passHalves[0], 7);
                Array.Copy(passBytes, 7, passHalves[1], 0, len);
            }
            else
            {
                passHalves[0] = passBytes;
                passHalves[1] = new byte[0];
            }

            for (int x = 0; x < 2; x++)
                passHalves[x] = ComputeHalf(passHalves[x]);

            byte[] hash = new byte[16];

            Array.Copy(passHalves[0], hash, 8);
            Array.Copy(passHalves[1], 0, hash, 8, 8);

            return hash;
        }
    
        public static byte[] ComputeKex() {
            return null;
        }
    }

}
