using Novell.Directory.Ldap;
using SharpLdapRelayScan.DirectoryServices;
using System;

namespace SharpLdapRelayScan
{
    public static class LdapsTester
    {

        public static void ChannelBindingTest(string ldapHost, string domain, string username, string password, int ldapPort = 636, bool verbose = false)
        {

            // Creating DN for the user
            string dn = string.Format("{0}@{1}", username, domain);
            // Creating an LdapConnection instance
            LdapConnection ldapConn = new LdapConnection(verbose)
            {
                SecureSocketLayer = true
            };

            Uri ldapURI = new Uri($"ldaps://{ldapHost}:{ldapPort}");
            ldapHost = ldapURI.Host + (ldapURI.Port == 0 ? "" : ":" + ldapURI.Port);
            
            //Connect function will create a socket connection to the server
            ldapConn.Connect(ldapHost, ldapPort);
            
            for (int i = 0; i < 6; i++) { 
            //Bind function will Bind the user object  Credentials to the Server
                ldapConn.Bind(username, domain, password, i);
            }

            if (ldapConn.ldapEnforceChannelBinding == 0) {
                Console.WriteLine("    [+] (LDAPS) Channel binding set to `{0}`, party time!");
            } else if (ldapConn.ldapEnforceChannelBinding == 1) 
            {
                Console.WriteLine("    [-] (LDAPS) channel binding is set to `when supported` {0}{1} - this may prevent an NTLM relay depending on the {0}{1}   client's support for channel binding.", Environment.NewLine, "       ");
            } 
            else 
            {
                Console.WriteLine("    [-] (LDAPS) channel binding set to `required`, no fun allowed");
            }


            ldapConn.Disconnect();
        }
        
        
        public static void SslSigningTest(string ldapHost, string domain, string username, string password, int ldapPort = 389, bool verbose = false)
        {

            // Creating an LdapConnection instance
            var ldapConn = new CustomLdapConnection(ldapHost, username, Environment.UserDomainName, password, false, verbose);

            Uri ldapURI = new Uri($"ldaps://{ldapHost}:{ldapPort}");
            ldapHost = ldapURI.Host + (ldapURI.Port == 0 ? "" : ":" + ldapURI.Port);
           
            //Bind function will Bind the user object  Credentials to the Server
            // -- Check if SSL Signing is in place (valid creds required)
            int errCode = ldapConn.Bind();

            bool validCreds = (errCode == 8 || errCode == 0);
            
            // This call is unuseful, and a second login attempt
            // Validate(ldapHost, domain, username, password, ldapPort, verbose);
            
            if (!validCreds) {
                Console.WriteLine("    [/] The credentials provided seems ivalid.");
                return;
            }

            if (!ldapConn.EnforceSslSigning) {
                Console.WriteLine("    [+] LDAP Signing not required! Yeah!");
            } 
            else 
            {
                Console.WriteLine("    [-] LDAP Signing required. That sucks...");
            }
        }

        public static bool Validate(string ldapHost, string domain, string username, string password, int ldapPort = 389, bool verbose = false) {
            Novell.Directory.Ldap.LdapConnection ldapConn = new Novell.Directory.Ldap.LdapConnection();
            ldapConn.Connect(ldapHost, ldapPort);
            bool res = false;
            // Creating DN for the user

            string dn = "";
            if (!String.IsNullOrEmpty(domain))
            {
                dn = string.Format("{0}@{1}", username, domain);
            }
            else {
                Console.WriteLine("    [-] Failed to validate credentials. Retry with a valid Domain Name (/domain)");
                return false;
            }
            try
            {
                ldapConn.Bind(dn, password);
                // Successful Binding
                res = true;
            }
            catch (LdapException ex) {
                if (ex.ResultCode == 8 || ex.ResultCode == 0) {
                    res = true;
                }
            }
            ldapConn.Disconnect();
            return res;

        }
    }
}
