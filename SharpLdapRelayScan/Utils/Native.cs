using Microsoft.Win32.SafeHandles;
using System;
using System.DirectoryServices.Protocols;
using System.Runtime.InteropServices;
using System.Security;
using static Security;

namespace SharpLdapRelayScan
{

    [SuppressUnmanagedCodeSecurity]
    public class ConnectionHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal ConnectionHandle() : base(true)
        {
            base.SetHandle(Wldap32.ldap_init(null, 389));
            if (!(this.handle == (IntPtr)0))
            {
                return;
            }
            int num = Wldap32.LdapGetLastError();
            throw new LdapException(num);
        }

        internal ConnectionHandle(IntPtr value, bool disposeHandle) : base(true)
        {
            this.needDispose = disposeHandle;
            if (!(value == (IntPtr)0))
            {
                base.SetHandle(value);
                return;
            }
            int num = Wldap32.LdapGetLastError();
            throw new LdapException(num);
        }

        protected override bool ReleaseHandle()
        {
            if (this.handle != (IntPtr)0)
            {
                if (this.needDispose)
                {
                    Wldap32.ldap_unbind(this.handle);
                }
                this.handle = (IntPtr)0;
            }
            return true;
        }

        internal bool needDispose;
    }

    [ComVisible(false)]
    [SuppressUnmanagedCodeSecurity]
    public static class Wldap32
    {
        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_bind_sW", SetLastError = true)]
        public static extern int ldap_bind_s([In] ConnectionHandle ldapHandle, string dn, SEC_WINNT_AUTH_IDENTITY_EX credentials, BindMethod method);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_bind", SetLastError = true)]
        public static extern int ldap_bind([In] ConnectionHandle ldapHandle, string dn, string credentials, BindMethod method);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_initW", SetLastError = true)]
        public static extern IntPtr ldap_init(string hostName, int portNumber);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int ldap_connect([In] ConnectionHandle ldapHandle, LDAP_TIMEVAL timeout);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int ldap_unbind([In] IntPtr ldapHandle);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int LdapGetLastError();

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int LdapMapErrorToWin32(int LdapError);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "cldap_openW", SetLastError = true)]
        public static extern IntPtr cldap_open(string hostName, int portNumber);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_simple_bind_sW")]
        public static extern int ldap_simple_bind_s([In] ConnectionHandle ldapHandle, string distinguishedName, string password);

        [DllImport("wldap32.dll", EntryPoint = "ldap_sasl_bind_sW", CallingConvention = CallingConvention.Cdecl)]
        public static extern int ldap_sasl_bindW([In] ConnectionHandle ldapHandle, [In] string distinguishedName, [In] string AuthMechanism, [In] ref berval binaryValu, [In] IntPtr ServerCtrls, [In] IntPtr ClientCtrls, [Out] out berval data);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_delete_extW")]
        public static extern int ldap_delete_ext([In] ConnectionHandle ldapHandle, string dn, IntPtr servercontrol, IntPtr clientcontrol, ref int messageNumber);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_parse_resultW")]
        public static extern int ldap_parse_result([In] ConnectionHandle ldapHandle, [In] IntPtr result, ref int serverError, ref IntPtr dn, ref IntPtr message, ref IntPtr referral, ref IntPtr control, byte freeIt);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_parse_resultW")]
        public static extern int ldap_parse_result_referral([In] ConnectionHandle ldapHandle, [In] IntPtr result, IntPtr serverError, IntPtr dn, IntPtr message, ref IntPtr referral, IntPtr control, byte freeIt);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_memfreeW")]
        public static extern void ldap_memfree([In] IntPtr value);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_value_freeW")]
        public static extern int ldap_value_free([In] IntPtr value);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_controls_freeW")]
        public static extern int ldap_controls_free([In] IntPtr value);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        public static extern int ldap_abandon([In] ConnectionHandle ldapHandle, [In] int messagId);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_start_tls_sW")]
        public static extern int ldap_start_tls(ConnectionHandle ldapHandle, ref int ServerReturnValue, ref IntPtr Message, IntPtr ServerControls, IntPtr ClientControls);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_stop_tls_s")]
        public static extern byte ldap_stop_tls(ConnectionHandle ldapHandle);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_rename_extW")]
        public static extern int ldap_rename([In] ConnectionHandle ldapHandle, string dn, string newRdn, string newParentDn, int deleteOldRdn, IntPtr servercontrol, IntPtr clientcontrol, ref int messageNumber);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_add_extW")]
        public static extern int ldap_add([In] ConnectionHandle ldapHandle, string dn, IntPtr attrs, IntPtr servercontrol, IntPtr clientcontrol, ref int messageNumber);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_modify_extW")]
        public static extern int ldap_modify([In] ConnectionHandle ldapHandle, string dn, IntPtr attrs, IntPtr servercontrol, IntPtr clientcontrol, ref int messageNumber);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_parse_extended_resultW")]
        public static extern int ldap_parse_extended_result([In] ConnectionHandle ldapHandle, [In] IntPtr result, ref IntPtr oid, ref IntPtr data, byte freeIt);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        public static extern int ldap_msgfree([In] IntPtr result);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_set_optionW")]
        public static extern int ldap_set_option_clientcert([In] ConnectionHandle ldapHandle, [In] LdapOption option, QUERYCLIENTCERT outValue);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_set_optionW")]
        public static extern int ldap_set_option_int([In] ConnectionHandle ldapHandle, [In] LdapOption option, uint value);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_get_optionW")]
        public static extern int ldap_get_option_errorstring([In] ConnectionHandle ldapHandle, [In] LdapOption option, [Out] out IntPtr outValue);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_get_optionW")]
        public static extern int ldap_get_option_error([In] ConnectionHandle ldapHandle, [In] LdapOption option, [Out] out int outValue);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_set_optionW")]
        public static extern int ldap_set_option_security_ctx([In] ConnectionHandle ldapHandle, [In] LdapOption option, [In] ref IntPtr pSecHandle);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_get_optionW")]
        public static extern int ldap_get_option_security_ctx([In] ConnectionHandle ldapHandle, [In] LdapOption option, [Out] out SecHandle pSecHandle);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_search_extW")]
        public static extern int ldap_search([In] ConnectionHandle ldapHandle, string dn, int scope, string filter, IntPtr attributes, bool attributeOnly, IntPtr servercontrol, IntPtr clientcontrol, int timelimit, int sizelimit, ref int messageNumber);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        public static extern IntPtr ldap_first_entry([In] ConnectionHandle ldapHandle, [In] IntPtr result);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        public static extern IntPtr ldap_next_entry([In] ConnectionHandle ldapHandle, [In] IntPtr result);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        public static extern IntPtr ldap_first_reference([In] ConnectionHandle ldapHandle, [In] IntPtr result);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        public static extern IntPtr ldap_next_reference([In] ConnectionHandle ldapHandle, [In] IntPtr result);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_get_dnW")]
        public static extern IntPtr ldap_get_dn([In] ConnectionHandle ldapHandle, [In] IntPtr result);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_first_attributeW")]
        public static extern IntPtr ldap_first_attribute([In] ConnectionHandle ldapHandle, [In] IntPtr result, ref IntPtr address);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_next_attributeW")]
        public static extern IntPtr ldap_next_attribute([In] ConnectionHandle ldapHandle, [In] IntPtr result, [In][Out] IntPtr address);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        public static extern IntPtr ber_free([In] IntPtr berelement, int option);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_get_values_lenW")]
        public static extern IntPtr ldap_get_values_len([In] ConnectionHandle ldapHandle, [In] IntPtr result, string name);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        public static extern IntPtr ldap_value_free_len([In] IntPtr berelement);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_parse_referenceW")]
        public static extern int ldap_parse_reference([In] ConnectionHandle ldapHandle, [In] IntPtr result, ref IntPtr referrals);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_create_sort_controlW")]
        public static extern int ldap_create_sort_control(ConnectionHandle handle, IntPtr keys, byte critical, ref IntPtr control);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_control_freeW")]
        public static extern int ldap_control_free(IntPtr control);

        [DllImport("Crypt32.dll", CharSet = CharSet.Unicode)]
        public static extern int CertFreeCRLContext(IntPtr certContext);

        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        public static extern int ldap_result2error([In] ConnectionHandle ldapHandle, [In] IntPtr result, int freeIt);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate bool QUERYCLIENTCERT(IntPtr Connection, IntPtr trusted_CAs, ref IntPtr certificateHandle);

        public const int SEC_WINNT_AUTH_IDENTITY_UNICODE = 2;
        public const int SEC_WINNT_AUTH_IDENTITY_VERSION = 512;
        public const string MICROSOFT_KERBEROS_NAME_W = "Kerberos";

    }


    [StructLayout(LayoutKind.Sequential)]
    public struct berval
    {
        public int bv_len;
        public IntPtr bv_val;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SEC_WINNT_AUTH_IDENTITY_EX
    {
        public int version;
        public int length;
        public string user;
        public int userLength;
        public string domain;
        public int domainLength;
        public string password;
        public int passwordLength;
        public int flags;
        public string packageList;
        public int packageListLength;
    }

    public enum BindMethod : uint
    {
        LDAP_AUTH_SIMPLE = 128U,
        LDAP_AUTH_SASL = 131U,
        LDAP_AUTH_OTHERKIND = 134U,
        LDAP_AUTH_SICILY = 646U,
        LDAP_AUTH_MSN = 2182U,
        LDAP_AUTH_NTLM = 4230U,
        LDAP_AUTH_DPA = 8326U,
        LDAP_AUTH_NEGOTIATE = 1158U,
        LDAP_AUTH_SSPI = 1158U,
        LDAP_AUTH_DIGEST = 16518U,
        LDAP_AUTH_EXTERNAL = 166U
    }

    [StructLayout(LayoutKind.Sequential)]
    public class LDAP_TIMEVAL
    {
        public int tv_sec;
        public int tv_usec;
    }

    public enum LdapOption
    {
        LDAP_OPT_DESC = 1,
        LDAP_OPT_DEREF,
        LDAP_OPT_SIZELIMIT,
        LDAP_OPT_TIMELIMIT,
        LDAP_OPT_REFERRALS = 8,
        LDAP_OPT_RESTART,
        LDAP_OPT_SSL,
        LDAP_OPT_REFERRAL_HOP_LIMIT = 16,
        LDAP_OPT_VERSION,
        LDAP_OPT_API_FEATURE_INFO = 21,
        LDAP_OPT_HOST_NAME = 48,
        LDAP_OPT_ERROR_NUMBER,
        LDAP_OPT_ERROR_STRING,
        LDAP_OPT_SERVER_ERROR,
        LDAP_OPT_SERVER_EXT_ERROR,
        LDAP_OPT_HOST_REACHABLE = 62,
        LDAP_OPT_PING_KEEP_ALIVE = 54,
        LDAP_OPT_PING_WAIT_TIME,
        LDAP_OPT_PING_LIMIT,
        LDAP_OPT_DNSDOMAIN_NAME = 59,
        LDAP_OPT_GETDSNAME_FLAGS = 61,
        LDAP_OPT_PROMPT_CREDENTIALS = 63,
        LDAP_OPT_TCP_KEEPALIVE,
        LDAP_OPT_FAST_CONCURRENT_BIND,
        LDAP_OPT_SEND_TIMEOUT,
        LDAP_OPT_REFERRAL_CALLBACK = 112,
        LDAP_OPT_CLIENT_CERTIFICATE = 128,
        LDAP_OPT_SERVER_CERTIFICATE,
        LDAP_OPT_AUTO_RECONNECT = 145,
        LDAP_OPT_SSPI_FLAGS,
        LDAP_OPT_SSL_INFO,
        LDAP_OPT_SIGN = 149,
        LDAP_OPT_ENCRYPT,
        LDAP_OPT_SASL_METHOD,
        LDAP_OPT_AREC_EXCLUSIVE = 152,
        LDAP_OPT_SECURITY_CONTEXT = 153,
        LDAP_OPT_ROOTDSE_CACHE,
        LDAP_OPT_DIAGNOSTIC_MESSAGE = 50
    }
}

public static class Security
{


    public enum SecError : uint
    {
        SEC_E_INVALID_HANDLE = 0x80100003,
        SEC_E_UNSUPPORTED_FUNCTION = 0x80090302,
        SEC_E_OK = 0

    }

    public enum ContextAttributes : uint
    {

        SECPKG_ATTR_C_ACCESS_TOKEN = 0x80000012,
        SECPKG_ATTR_C_FULL_ACCESS_TOKEN = 0x80000082,
        SECPKG_ATTR_CERT_TRUST_STATUS = 0x80000084,
        SECPKG_ATTR_CREDS = 0x80000080,
        SECPKG_ATTR_CREDS_2 = 0x80000086,
        SECPKG_ATTR_NEGOTIATION_PACKAGE = 0x80000081,
        SECPKG_ATTR_PACKAGE_INFO = 0x00000010,
        SECPKG_ATTR_SERVER_AUTH_FLAGS = 0x80000083,
        SECPKG_ATTR_SIZES = 0x00000000,
        SECPKG_ATTR_SUBJECT_SECURITY_ATTRIBUTES = 0x00000124,
        SECPKG_ATTR_ENDPOINT_BINDINGS = 0x0000001A,
        SECPKG_ATTR_UNIQUE_BINDINGS = 0x00000019

    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecInteger
    {
        public uint LowPart;
        public int HighPart;
        public SecInteger(int dummy)
        {
            LowPart = 0;
            HighPart = 0;
        }
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct SecHandle
    {
        public IntPtr dwLower;
        public IntPtr dwUpper;
        public SecHandle(int dummy)
        {
            dwLower = dwUpper = IntPtr.Zero;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecBuffer
    {
        public int cbBuffer;
        public int BufferType;
        public IntPtr pvBuffer;
    }

    /// <summary>
    /// Simplified SecBufferDesc struct with only one SecBuffer
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SecBufferDesc
    {
        public int ulVersion;
        public int cBuffers;
        public IntPtr pBuffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecPkgContext_Sizes
    {
        public uint cbMaxToken;
        public uint cbMaxSignature;
        public uint cbBlockSize;
        public uint cbSecurityTrailer;
    };


    [DllImport("secur32.dll")]
    public static extern int AcquireCredentialsHandle(
        string pszPrincipal,
        string pszPackage,
        int fCredentialUse,
        IntPtr pvLogonID,
        IntPtr pAuthData,
        IntPtr pGetKeyFn,
        IntPtr pvGetKeyArgument,
        ref SecHandle phCredential,
        out SecHandle ptsExpiry
    );

    [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern int InitializeSecurityContext(
        ref SecHandle phCredential,
        ref SecHandle phContext,
        string pszTargetName,
        int fContextReq,
        int Reserved1,
        int TargetDataRep,
        ref SecBufferDesc pInput,
        int Reserved2,
        out SecHandle phNewContext,
        out SecBufferDesc pOutput,
        out int pfContextAttr,
        out SecHandle ptsExpiry);

    [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern int InitializeSecurityContext(
        ref SecHandle phCredential,
        IntPtr phContext,
        string pszTargetName,
        int fContextReq,
        int Reserved1,
        int TargetDataRep,
        IntPtr pInput,
        int Reserved2,
        out SecHandle phNewContext,
        out SecBufferDesc pOutput,
        out int pfContextAttr,
        out SecHandle ptsExpiry);

    [DllImport("Secur32.dll")]
    public extern static int FreeContextBuffer(
        IntPtr pvContextBuffer
    );

    [DllImport("Secur32.dll")]
    public extern static int FreeCredentialsHandle(
        ref SecHandle phCredential
    );

    [DllImport("Secur32.dll")]
    public extern static int DeleteSecurityContext(
        ref SecHandle phContext
    );

    /*
	   SECURITY_STATUS SEC_ENTRY SetContextAttributesW(
		  [in] PCtxtHandle   phContext,
		  [in] unsigned long ulAttribute,
		  [in] void          *pBuffer,
		  [in] unsigned long cbBuffer
		);
	 */
    [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = false)]
    public static extern int SetContextAttributes(
        ref SecHandle phContext,
        uint ulAttribute,
        SecPkgContext_Sizes pContextAttributes,
        uint contextAttributesSize
        );

    /*
	   SECURITY_STATUS SEC_ENTRY DeleteSecurityPackageW(
		  [in] LPWSTR pszPackageName
		);
	 */
    [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = false)]
    public static extern int DeleteSecurityPackage(
        string pszPackageName
        );

    /*
	   SECURITY_STATUS SEC_ENTRY QueryContextAttributesA(
		  [in]  PCtxtHandle   phContext,
		  [in]  unsigned long ulAttribute,
		  [out] void          *pBuffer
		);
	*/
    [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = false)]
    public static extern SecError QueryContextAttributes(
        ref SecHandle phContext,
        ContextAttributes ulAttribute,
        out SecPkgContext_Sizes pContextAttributes
        );

    [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = false)]
    public static extern SecError QueryContextAttributes(
        ref SecHandle phContext,
        ContextAttributes ulAttribute,
        out SecPkgContext_Bindings pContextAttributes
        );

    [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = false)]
    public static extern SecError QueryContextAttributes(
        ref SecHandle phContext,
        ContextAttributes ulAttribute,
        out IntPtr pContextAttributes
        );

    [StructLayout(LayoutKind.Sequential)]
    public class SecSizes
    {
        public int MaxToken;
        public int MaxSignature;
        public int BlockSize;
        public int SecurityTrailer;

        public unsafe SecSizes(byte[] memory)
        {
            fixed (void* voidPtr = memory)
            {
                IntPtr unmanagedAddress = new IntPtr(voidPtr);
                MaxToken = Marshal.ReadInt32(unmanagedAddress);
                MaxSignature = Marshal.ReadInt32(unmanagedAddress, 4);
                BlockSize = Marshal.ReadInt32(unmanagedAddress, 8);
                SecurityTrailer = Marshal.ReadInt32(unmanagedAddress, 12);
            }
        }
        public static readonly int SizeOf = Marshal.SizeOf(typeof(SecSizes));
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecPkgContext_Bindings
    {
        // see SecPkgContext_Bindings in 
        public int BindingsLength;
        public IntPtr pBindings;
    }
}
