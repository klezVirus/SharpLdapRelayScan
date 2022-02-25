using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using static Security;

namespace SharpLdapRelayScan.DirectoryServices
{
    public class CustomLdapConnection
    {
        private string server;
        private LdapConnection connection;
        private NetworkCredential networkCredential;
        private IntPtr lpLastError;
        private SEC_WINNT_AUTH_IDENTITY_EX identity;
        private bool verbose;

        public CustomLdapConnection(string server, string username, string domain, string password, bool ssl = false, bool verbose = false)
        {

            LdapDirectoryIdentifier serverId;
            this.verbose = verbose;
            this.server = server + (ssl ? ":636" : "");
            this.networkCredential = new NetworkCredential(username, password, domain);

            identity = new SEC_WINNT_AUTH_IDENTITY_EX();
            identity.version = 512;
            identity.length = Marshal.SizeOf(typeof(SEC_WINNT_AUTH_IDENTITY_EX));
            identity.flags = 2;
            if (networkCredential != null)
            {
                identity.user = username;
                identity.userLength = ((username == null) ? 0 : username.Length);
                identity.domain = domain;
                identity.domainLength = ((domain == null) ? 0 : domain.Length);
                identity.password = password;
                identity.passwordLength = ((password == null) ? 0 : password.Length);
            }


            if (!ssl)
            {
                serverId = new LdapDirectoryIdentifier(server);
                this.connection = new LdapConnection(serverId, this.networkCredential, AuthType.Sicily);

            }
            else
            {
                serverId = new LdapDirectoryIdentifier(server, 636);
                this.connection = new LdapConnection(serverId, this.networkCredential, AuthType.Sicily)
                {
                    AuthType = AuthType.Ntlm,
                    SessionOptions =
                        {
                            ProtocolVersion = 3,
                            SecureSocketLayer = true,
                            TcpKeepAlive = true,
                            PingKeepAliveTimeout = new TimeSpan(10),

                        }
                };
                this.connection.SessionOptions.VerifyServerCertificate += (sender, certificate) => true;
            }

        }


        [EnvironmentPermission(SecurityAction.Assert, Unrestricted = true)]
        [SecurityPermission(SecurityAction.Assert, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public int Bind()
        {
            if (this.connection == null)
            {
                return -1;
            }

            int num;
            SafeHandleZeroOrMinusOneIsInvalid safeHandle = ReflectionHelper.GetPrivateFieldValue<SafeHandleZeroOrMinusOneIsInvalid>(connection, "ldapHandle");
            IntPtr rawHandle = ReflectionHelper.GetPrivateFieldValue<IntPtr>(safeHandle, "handle");
            ConnectionHandle ldapHandle = new ConnectionHandle(rawHandle, true);

            if (ldapHandle == null)
            {
                Console.WriteLine("[-] Failed to get connection handle");
                return -1;
            }

            num = Wldap32.ldap_bind_s(ldapHandle, null, identity, BindMethod.LDAP_AUTH_SICILY);

            Wldap32.ldap_get_option_errorstring(ldapHandle, LdapOption.LDAP_OPT_SERVER_ERROR, out lpLastError);

            if (this.verbose) { 
                Console.WriteLine("    [DEBUG] RET CODE: {0}", num);
                Console.WriteLine("    [DEBUG] LAST ERR: {0}", Marshal.PtrToStringAuto(lpLastError));
            }
            return num;
        }

        public List<string> GetSupportedOIDs()
        {

            List<string> oids = new List<string>();

            // Issue a base level search request with a null search base:
            SearchRequest sReq = new SearchRequest(
              null,
              "(objectClass=*)",
              System.DirectoryServices.Protocols.SearchScope.Base,
              "supportedControl");
            SearchResponse sRes = (SearchResponse)connection.SendRequest(sReq);
            foreach (String supportedControlOID in
              sRes.Entries[0].Attributes["supportedControl"].GetValues(typeof(String)))
            {
                oids.Add(supportedControlOID);
            }

            return oids;
        }

        [EnvironmentPermission(SecurityAction.Assert, Unrestricted = true)]
        [SecurityPermission(SecurityAction.Assert, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public int LdapsBind()
        {

            if (connection == null)
            {
                return -1;
            }

            int num;
            SafeHandleZeroOrMinusOneIsInvalid safeHandle = ReflectionHelper.GetPrivateFieldValue<SafeHandleZeroOrMinusOneIsInvalid>(connection, "ldapHandle");
            IntPtr rawHandle = ReflectionHelper.GetPrivateFieldValue<IntPtr>(safeHandle, "handle");
            ConnectionHandle ldapHandle = new ConnectionHandle(rawHandle, true);

            num = Wldap32.ldap_bind_s(ldapHandle, null, identity, BindMethod.LDAP_AUTH_SICILY);

            if (ldapHandle == null)
            {
                Console.WriteLine("[-] Failed to get connection handle");
                return -1;
            }

            SecHandle ctxHandle;

            Wldap32.ldap_get_option_security_ctx(ldapHandle, LdapOption.LDAP_OPT_SECURITY_CONTEXT, out ctxHandle);

            if (ctxHandle.dwLower == IntPtr.Zero && ctxHandle.dwUpper == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get SChannel CTX handle");
                return -1;
            }
            Console.WriteLine("[+] SChannel CTX handle upper: {0:16X}", ctxHandle.dwUpper);
            Console.WriteLine("[+] SChannel CTX handle lower: {0:16X}", ctxHandle.dwLower);


            // SecPkgContext_Sizes bindings = new SecPkgContext_Sizes();
            // QueryContextAttributes(ref ctxHandle, ContextAttributes.SECPKG_ATTR_SIZES, out bindings);

            IntPtr data = IntPtr.Zero;

            SecError status = QueryContextAttributes(ref ctxHandle, ContextAttributes.SECPKG_ATTR_ENDPOINT_BINDINGS, out data);

            if (SecError.SEC_E_INVALID_HANDLE == status)
            {
                Console.WriteLine("[-] Error: Invalid Handle");
                return -1;
            }
            else if (SecError.SEC_E_UNSUPPORTED_FUNCTION == status)
            {
                Console.WriteLine("[-] Error: Unsupported Function");
                return -1;
            }
            else if (SecError.SEC_E_OK != status)
            {
                Console.WriteLine("[-] Error: Uknown Error");
                return -1;
            }
            else
            {
                Console.WriteLine("[+] QueryContextAttributes: Completed Successfully");
            }

            if (data == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get Context Attributes");
                return -1;
            }

            Console.WriteLine("Context Attributes at: {0}", data);

            IntPtr lpError;
            Wldap32.ldap_get_option_errorstring(ldapHandle, LdapOption.LDAP_OPT_SERVER_ERROR, out lpError);

            num = Wldap32.ldap_bind_s(ldapHandle, null, identity, BindMethod.LDAP_AUTH_SICILY);

            Console.WriteLine("--- RET CODE: {0}", num);
            Console.WriteLine("--- LAST ERR: {0}", Marshal.PtrToStringAuto(lpError));
            return num;
        }


        [EnvironmentPermission(SecurityAction.Assert, Unrestricted = true)]
        [SecurityPermission(SecurityAction.Assert, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public int LdapsBind2()
        {

            if (connection == null)
            {
                return -1;
            }

            int num;
            SafeHandleZeroOrMinusOneIsInvalid safeHandle = ReflectionHelper.GetPrivateFieldValue<SafeHandleZeroOrMinusOneIsInvalid>(connection, "ldapHandle");
            IntPtr rawHandle = ReflectionHelper.GetPrivateFieldValue<IntPtr>(safeHandle, "handle");
            ConnectionHandle ldapHandle = new ConnectionHandle(rawHandle, true);

            if (ldapHandle == null)
            {
                Console.WriteLine("[-] Failed to get connection handle");
                return -1;
            }

            string method = "NTLM";

            byte[] serverChallenge = WinAuthEndPoint.AcquireInitialSecurityToken(identity, "ldap/" + server, method, new Guid());
            if (serverChallenge == null)
            {
                Console.WriteLine("[-] Error acquiring security token using {0}", method);
                return 0;
            }

            GCHandle pinnedArray = GCHandle.Alloc(serverChallenge, GCHandleType.Pinned);
            IntPtr pointer = pinnedArray.AddrOfPinnedObject();

            berval cred = new berval
            {
                bv_len = serverChallenge.Length,
                bv_val = pointer
            };

            IntPtr lpError;
            int errorNum;
            berval scred;
            Console.WriteLine("[*] Binding");

            Wldap32.ldap_set_option_int(ldapHandle, LdapOption.LDAP_OPT_SSL, 0x0a); // LDAP_OPT_ON = 0x0a 
            num = Wldap32.ldap_sasl_bindW(ldapHandle, "", "GSSAPI", ref cred, IntPtr.Zero, IntPtr.Zero, out scred);
            Console.WriteLine("--- RET CODE: {0}", num);
            Console.WriteLine("--- MESSAGE NUM: {0} {1}", scred.bv_val, scred.bv_len);
            Wldap32.ldap_get_option_errorstring(ldapHandle, LdapOption.LDAP_OPT_DIAGNOSTIC_MESSAGE, out lpError);
            Console.WriteLine("--- DIAGNOSTIC ERR: {0}", Marshal.PtrToStringAuto(lpError));

            Wldap32.ldap_get_option_error(ldapHandle, LdapOption.LDAP_OPT_ERROR_NUMBER, out errorNum);
            Console.WriteLine("--- LAST ERR NUM: {0}", errorNum);


            Wldap32.ldap_get_option_errorstring(ldapHandle, LdapOption.LDAP_OPT_SERVER_ERROR, out lpError);
            Console.WriteLine("--- LAST ERR: {0}", Marshal.PtrToStringAuto(lpError));
            pinnedArray.Free();

            byte[] token = WinAuthEndPoint.AcquireFinalSecurityToken("ldap/" + server, serverChallenge, new Guid());

            return num;
        }

        public void Dispose()
        {

            connection.Dispose();
        }
    }



}
