using CommandLine;
using SharpLdapRelayScan.DirectoryServices;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.ActiveDirectory;
using System.Net;

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

            [Option('d', "dcip", Required = false, HelpText = "DNS Nameserver on network. Any DC's IPv4 address should work")]
            public string DomainController { get; set; }

            [Option('u', "user", Required = false,  HelpText = "Domain User")]
            public string Username { get; set; }

            [Option('p', "password", Required = true, HelpText = "Domain User's Password")]
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
                case CheckMethods.Both:
                    LdapTest(serverIds, opts);
                    NovellLdapsTest(serverIds, opts);
                    break;
                case CheckMethods.Ldaps:
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
                    var conn = new CustomLdapConnection(serverId_s, options.Username, Environment.UserDomainName, options.Password, true);
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
                try
                {
                    Console.WriteLine("  [*] Testing {0}", serverId_s);
                    var conn = new CustomLdapConnection(serverId_s, options.Username, Environment.UserDomainName, options.Password, false, options.Verbose);
                    int errCode = -1;
                    try
                    {
                        errCode = conn.Bind();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("  [-] Connection Error: {0}", e.Message);
                    }
                    if (errCode == 8)
                    {
                        Console.WriteLine("    [-] LDAP Signing required. That sucks...");
                    }
                    else
                    {
                        Console.WriteLine("    [+] LDAP Signing not required! Yeah!");
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
