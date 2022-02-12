using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using CommandLine;

namespace SharpLdapRelayScan
{
    class Program
    {

        public enum CheckMethods
        {
            Ldaps,
            Both
        }

        public class Options
        {
            [Option('v', "verbose", Required = false, HelpText = "Set output to verbose messages")]
            public bool Verbose { get; set; }

            [Option('d', "dc-ip", Required = false, Default = "10.0.10.131", HelpText = "DNS Nameserver on network. Any DC's IPv4 address should work")]
            public string DomainController { get; set; }
            
            [Option('u', "user", Required = false, Default = "d3adc0de", HelpText = "Domain User")]
            public string Username { get; set; }

            [Option('p', "password", Required = false, Default = "Passw0rd!", HelpText = "Domain User's Password")]
            public string Password { get; set; }

            [Option('m', "method", Required = false, Default = "Both", HelpText = "LDAPS or BOTH - LDAPS checks for channel binding, BOTH checks for LDAP signing and LDAP channel binding [authentication required]")]
            public string Method { get; set; }
        }

        static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options>(args)
                .WithParsed(RunOptions)
                .WithNotParsed(HandleParseError);

        }

        static void RunOptions(Options opts)
        {
            var method = (CheckMethods)Enum.Parse(typeof(CheckMethods), opts.Method, true);
            var credentials = new NetworkCredential(opts.Username, opts.Password);
            List<string> serverIds = new List<string>();


            if (!string.IsNullOrEmpty(opts.DomainController))
            {
                serverIds.Add(opts.DomainController);
            }
            else
            {

                foreach (DomainController dc in GetListOfDomainControllers())
                {
                    serverIds.Add(dc.IPAddress.ToString());
                }
            }

            Console.WriteLine("Checking DCs for LDAP NTLM relay protections");

            switch (method)
            {
                case CheckMethods.Both:
                    LdapTest(serverIds, credentials);
                    LdapsTest(serverIds, credentials);
                    break;
                case CheckMethods.Ldaps:
                    LdapsTest(serverIds, credentials);
                    break;
                default:
                    break;
            }
        }

        private static void LdapsTest(List<string> serverIds, NetworkCredential credentials)
        {
            foreach(string serverId_s in serverIds)
            {
                try
                {
                    var serverId = new LdapDirectoryIdentifier(serverId_s, 636);

                    Console.WriteLine("[*] Testing {0}", serverId.Servers[0]);
                    var conn = new LdapConnection(serverId, credentials) {
                        AuthType = AuthType.Ntlm,
                        SessionOptions =
                        {
                            ProtocolVersion = 3,
                            SecureSocketLayer = true

                }
                    };
                    conn.SessionOptions.VerifyServerCertificate += (sender, certificate) => true;
                    int errCode = -1;
                    try
                    {
                        errCode = DSReimpl.LdapsBind2(conn, credentials, false);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("[-] Connection Error: {0}", e.StackTrace);
                    }
                    if (errCode == 8)
                    {
                        Console.WriteLine("[-] LDAP Signing required. That sucks...");
                    }
                    else
                    {
                        Console.WriteLine("[-] LDAP Signing not required! Yeah!");
                    }
                    conn.Dispose();
                }
                catch (Exception e){
                    Console.WriteLine("  [-] Exception: {0}. Skipping", e.Message);
                }
            }
        }

        private static void LdapTest(List<string> serverIds, NetworkCredential credentials)
        {
            foreach (string serverId_s in serverIds)
            {
                try
                {
                    var serverId = new LdapDirectoryIdentifier(serverId_s);
                    
                    Console.WriteLine("[*] Testing {0}", serverId.Servers[0]);
                    var conn = new LdapConnection(serverId, credentials, AuthType.Sicily);
                    int errCode = -1;
                    try
                    {
                        errCode = DSReimpl.Bind(conn, credentials, false);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("[-] Connection Error: {0}", e.Message);
                    }
                    if (errCode == 8)
                    {
                        Console.WriteLine("[-] LDAP Signing required. That sucks...");
                    }
                    else
                    {
                        Console.WriteLine("[-] LDAP Signing not required! Yeah!");
                    }
                    conn.Dispose();
                }
                catch
                {
                    Console.WriteLine("  [-] Exception: Skipping");
                }
            }
        }

        static void HandleParseError(IEnumerable<Error> errs)
        {
            foreach (Error err in errs)
            {
                Console.Error.WriteLine(err.ToString());
            }
        }

        private static DomainControllerCollection GetListOfDomainControllers()
        {
            try
            {
                Domain domain = Domain.GetCurrentDomain();
                Console.WriteLine("[*] Searching DCs");
                int dcNum = 0;
                foreach (DomainController dc in domain.DomainControllers)
                {
                    Console.WriteLine("  Name: {0}", dc.Name);
                    Console.WriteLine("  IP Address: {0}", dc.IPAddress);
                    dcNum++;
                }
                if (dcNum == 0) {
                    Console.WriteLine("  No DC found");
                }

                return domain.DomainControllers;
            }
            catch
            {
                return null;
            }
        }
    }
}
