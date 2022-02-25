using Novell.Directory.Ldap;
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

    }
}
