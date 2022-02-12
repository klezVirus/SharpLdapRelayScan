using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static Security;

namespace SharpLdapRelayScan
{
    public class SSPIHandler
    { 

        public ConnectionHandle ldapHandle;
        public SecHandle old_sspictx;
        public SecHandle new_sspictx;

        public SSPIHandler(ConnectionHandle ldapHandle)
        {
            Console.WriteLine("LDAP HANDLE: {0}", ldapHandle.DangerousGetHandle());
            Wldap32.ldap_get_option_security_ctx(ldapHandle, LdapOption.LDAP_OPT_SECURITY_CONTEXT, out old_sspictx);
            
            this.ldapHandle = ldapHandle;

            Console.WriteLine("SSPI CTX LOWER: {0}", old_sspictx.dwLower);
            Console.WriteLine("SSPI CTX UPPER: {0}", old_sspictx.dwUpper);
            new_sspictx = new SecHandle()
            {
                dwLower = IntPtr.Zero,
                dwUpper = IntPtr.Zero
            };

        }

        public void Tamper()
        {

            IntPtr pCtxtHandle = IntPtr.Zero;
            Marshal.StructureToPtr(this.new_sspictx, pCtxtHandle, false);
            Wldap32.ldap_set_option_security_ctx(this.ldapHandle, LdapOption.LDAP_OPT_SECURITY_CONTEXT, ref pCtxtHandle);

        }

    }
}