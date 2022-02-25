using SharpLdapRelayScan.DirectoryServices;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Net;

namespace SharpLdapRelayScan
{
    class Program
    {

        public enum CheckMethods
        {
            Ldap,
            Ldaps,
            Both
        }

        public class Options
        {
            public Options() {
                Verbose = false;
                Method = "BOTH";
                Username = Environment.UserName;
                Domain = Environment.UserDomainName;
                DomainController = Password = null;
            }

            public bool Verbose { get; set; }
            public string DomainController { get; set; }
            public string Domain { get; set; }
            public string Username { get; set; }
            public string Password { get; set; }
            public string Method { get; set; }
        }

        static void PrintHelp() {
            string helpText = @"
#### SharpRelayLdapScan -- by klezVirus

  -v, --verbose     Set output to verbose messages
  -d, --dcip        DNS Nameserver on network. Any DC's IPv4 address should work
  -u, --user        Domain User
  -p, --password    Required. Domain User's Password
  -m, --method      (Default: Both) LDAP, LDAPS or BOTH - LDAPS checks for channel binding,
                    LDAP for signing and BOTH... both
  --help            Display this help screen.
  --version         Display version information.";
            Console.WriteLine(helpText);

        }

        static void Main(string[] args)
        {
            Options opts = new Options();

            string[] allowedMethods = new string[] { "ldap", "ldaps", "both" };


            foreach (var entry in args.Select((value, index) => new { index, value }))
            {
                string argument = entry.value.ToUpper().Replace("--", "/").Replace("-", "/");

                switch (argument)
                {
                    case "/V":
                    case "/VERBOSE":
                        opts.Verbose = true;
                        break;

                    case "/M":
                    case "/METHOD":
                        var method = args[entry.index + 1];
                        if (!String.IsNullOrEmpty(method) && allowedMethods.Contains<string>(method.ToLowerInvariant())) {
                            opts.Method = method;
                        }
                        break;
                        
                    case "/U":
                    case "/USER":
                        opts.Username = args[entry.index + 1];
                        break;

                    case "/P":
                    case "/PASSWORD":
                        opts.Password = args[entry.index + 1];
                        break;
                    case "/D":
                    case "/DOMAIN":
                        opts.Domain = args[entry.index + 1];
                        break;
                    case "/DC":
                        opts.DomainController = args[entry.index + 1];
                        break;
                    case "/H":
                    case "/HELP":
                        PrintHelp();
                        return;
                }
            }

            if (String.IsNullOrEmpty(opts.Password)) {
                Console.WriteLine("[-] A Password needs to be specified");
                return;
            }

            RunOptions(opts);
        }

        static void RunOptions(Options opts)
        {
            var method = (CheckMethods)Enum.Parse(typeof(CheckMethods), opts.Method, true);

            List<string> serverIds = new List<string>();

            if (!string.IsNullOrEmpty(opts.Username))
            {
                opts.Username = Environment.UserName;
            }
            
            if (!string.IsNullOrEmpty(opts.DomainController))
            {
                serverIds.Add(opts.DomainController);
            }
            else
            {
                DomainControllerCollection dcCollection = GetListOfDomainControllers();

                if (dcCollection == null || dcCollection.Count == 0) {
                    Console.WriteLine("[-] No DC detected, are you in a domain?");
                    return;
                }

                foreach (DomainController dc in dcCollection)
                {
                    serverIds.Add(dc.IPAddress.ToString());
                }
            }

            Console.WriteLine("Checking DCs for LDAP NTLM relay protections");

            switch (method)
            {
                case CheckMethods.Ldap:
                    LdapTest(serverIds, opts);
                    break;
                case CheckMethods.Ldaps:
                    NovellLdapsTest(serverIds, opts);
                    break;
                case CheckMethods.Both:
                    LdapTest(serverIds, opts);
                    NovellLdapsTest(serverIds, opts);
                    break;
                default:
                    break;
            }
        }

        private static void LdapsTest(List<string> serverIds, Options options)
        {
            foreach (string serverId_s in serverIds)
            {
                try
                {
                    Console.WriteLine("[*] Testing {0}", serverId_s);
                    var conn = new CustomLdapConnection(serverId_s, options.Username, options.Domain, options.Password, true);
                    int errCode = -1;
                    try
                    {
                        errCode = conn.LdapsBind2();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("[-] Connection Error: {0}", e.StackTrace);
                    }
                    conn.Dispose();
                }
                catch (Exception e)
                {
                    Console.WriteLine("  [-] Exception: {0}. Skipping", e.Message);
                }
            }
        }
        private static void NovellLdapsTest(List<string> serverIds, Options options)
        {
            Console.WriteLine("{0}[*] LDAP SSL Channel Binding Enforcement Test", Environment.NewLine);

            foreach (string serverId_s in serverIds)
            {
                Console.WriteLine("  [*] Testing {0}", serverId_s);
                try
                {
                    LdapsTester.ChannelBindingTest(serverId_s, "", options.Username, options.Password, 636, options.Verbose);

                }
                catch (Exception e)
                {
                    Console.WriteLine("  [-] Exception: {0}. Skipping", e.StackTrace);
                    Debug.WriteLine(e.ToString());
                }
            }
        }

        private static void LdapTest(List<string> serverIds, Options options)
        {
            Console.WriteLine("{0}[*] LDAP SSL Enforcement Test", Environment.NewLine);

            foreach (string serverId_s in serverIds)
            {
                Console.WriteLine("  [*] Testing {0}", serverId_s);
                try
                {
                    LdapsTester.SslSigningTest(serverId_s, options.Domain, options.Username, options.Password, 389, options.Verbose);

                }
                catch (Exception e)
                {
                    Console.WriteLine("  [-] Exception: {0}. Skipping", e.StackTrace);
                    Debug.WriteLine(e.ToString());
                }
            }
        }

        static void HandleParseError(IEnumerable<Exception> errs)
        {
            foreach (Exception err in errs)
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
                if (dcNum == 0)
                {
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
