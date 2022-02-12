using Microsoft.Win32.SafeHandles;
using System;
using System.DirectoryServices.Protocols;
using System.Runtime.InteropServices;
using System.Security;
using static Security;
using static SharpLdapRelayScan.SSPIHandler;

namespace SharpLdapRelayScan
{

	[SuppressUnmanagedCodeSecurity]
	public class ConnectionHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		// Token: 0x0600030D RID: 781 RVA: 0x0000ED24 File Offset: 0x0000CF24
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

		// Token: 0x0600030E RID: 782 RVA: 0x0000ED80 File Offset: 0x0000CF80
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

		// Token: 0x0600030F RID: 783 RVA: 0x0000EDD4 File Offset: 0x0000CFD4
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

		// Token: 0x0400020A RID: 522
		internal bool needDispose;
	}

	// Token: 0x02000095 RID: 149
	[ComVisible(false)]
	[SuppressUnmanagedCodeSecurity]
	public static class Wldap32
	{
		// Token: 0x0600031C RID: 796
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_bind_sW", SetLastError = true)]
		public static extern int ldap_bind_s([In] ConnectionHandle ldapHandle, string dn, SEC_WINNT_AUTH_IDENTITY_EX credentials, BindMethod method);
		
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_bind", SetLastError = true)]
		public static extern int ldap_bind([In] ConnectionHandle ldapHandle, string dn, string credentials, BindMethod method);

		// Token: 0x0600031D RID: 797
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_initW", SetLastError = true)]
		public static extern IntPtr ldap_init(string hostName, int portNumber);

		// Token: 0x0600031E RID: 798
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, ExactSpelling = true)]
		public static extern int ldap_connect([In] ConnectionHandle ldapHandle, LDAP_TIMEVAL timeout);

		// Token: 0x0600031F RID: 799
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, ExactSpelling = true)]
		public static extern int ldap_unbind([In] IntPtr ldapHandle);


		// Token: 0x06000329 RID: 809
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
		public static extern int LdapGetLastError();

		// Token: 0x06000329 RID: 809
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
		public static extern int LdapMapErrorToWin32(int LdapError);

		// Token: 0x0600032A RID: 810
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "cldap_openW", SetLastError = true)]
		public static extern IntPtr cldap_open(string hostName, int portNumber);

		// Token: 0x0600032B RID: 811
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_simple_bind_sW")]
		public static extern int ldap_simple_bind_s([In] ConnectionHandle ldapHandle, string distinguishedName, string password);

		[DllImport("wldap32.dll", EntryPoint = "ldap_sasl_bind_sW", CallingConvention = CallingConvention.Cdecl)]
		public static extern int ldap_sasl_bindW([In] ConnectionHandle ldapHandle, [In] string distinguishedName, [In] string AuthMechanism, [In] ref berval binaryValu, [In] IntPtr ServerCtrls, [In] IntPtr ClientCtrls, [Out] out berval data);

		// Token: 0x0600032C RID: 812
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_delete_extW")]
		public static extern int ldap_delete_ext([In] ConnectionHandle ldapHandle, string dn, IntPtr servercontrol, IntPtr clientcontrol, ref int messageNumber);

		// Token: 0x0600032E RID: 814
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_parse_resultW")]
		public static extern int ldap_parse_result([In] ConnectionHandle ldapHandle, [In] IntPtr result, ref int serverError, ref IntPtr dn, ref IntPtr message, ref IntPtr referral, ref IntPtr control, byte freeIt);

		// Token: 0x0600032F RID: 815
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_parse_resultW")]
		public static extern int ldap_parse_result_referral([In] ConnectionHandle ldapHandle, [In] IntPtr result, IntPtr serverError, IntPtr dn, IntPtr message, ref IntPtr referral, IntPtr control, byte freeIt);

		// Token: 0x06000330 RID: 816
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_memfreeW")]
		public static extern void ldap_memfree([In] IntPtr value);

		// Token: 0x06000331 RID: 817
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_value_freeW")]
		public static extern int ldap_value_free([In] IntPtr value);

		// Token: 0x06000332 RID: 818
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_controls_freeW")]
		public static extern int ldap_controls_free([In] IntPtr value);

		// Token: 0x06000333 RID: 819
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern int ldap_abandon([In] ConnectionHandle ldapHandle, [In] int messagId);

		// Token: 0x06000334 RID: 820
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_start_tls_sW")]
		public static extern int ldap_start_tls(ConnectionHandle ldapHandle, ref int ServerReturnValue, ref IntPtr Message, IntPtr ServerControls, IntPtr ClientControls);

		// Token: 0x06000335 RID: 821
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_stop_tls_s")]
		public static extern byte ldap_stop_tls(ConnectionHandle ldapHandle);

		// Token: 0x06000336 RID: 822
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_rename_extW")]
		public static extern int ldap_rename([In] ConnectionHandle ldapHandle, string dn, string newRdn, string newParentDn, int deleteOldRdn, IntPtr servercontrol, IntPtr clientcontrol, ref int messageNumber);

		// Token: 0x06000338 RID: 824
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_add_extW")]
		public static extern int ldap_add([In] ConnectionHandle ldapHandle, string dn, IntPtr attrs, IntPtr servercontrol, IntPtr clientcontrol, ref int messageNumber);

		// Token: 0x06000339 RID: 825
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_modify_extW")]
		public static extern int ldap_modify([In] ConnectionHandle ldapHandle, string dn, IntPtr attrs, IntPtr servercontrol, IntPtr clientcontrol, ref int messageNumber);

		// Token: 0x0600033B RID: 827
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_parse_extended_resultW")]
		public static extern int ldap_parse_extended_result([In] ConnectionHandle ldapHandle, [In] IntPtr result, ref IntPtr oid, ref IntPtr data, byte freeIt);

		// Token: 0x0600033C RID: 828
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern int ldap_msgfree([In] IntPtr result);

		// Token: 0x06000327 RID: 807
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_set_optionW")]
		public static extern int ldap_set_option_clientcert([In] ConnectionHandle ldapHandle, [In] LdapOption option, QUERYCLIENTCERT outValue);

		// Token: 0x06000327 RID: 807
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_get_optionW")]
		public static extern int ldap_get_option_errorstring([In] ConnectionHandle ldapHandle, [In] LdapOption option, [Out] out IntPtr outValue);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_set_optionW")]
		public static extern int ldap_set_option_security_ctx([In] ConnectionHandle ldapHandle, [In] LdapOption option, [In] ref IntPtr pSecHandle);

		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_get_optionW")]
		public static extern int ldap_get_option_security_ctx([In] ConnectionHandle ldapHandle, [In] LdapOption option, [Out] out SecHandle pSecHandle);

		// Token: 0x0600033D RID: 829
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_search_extW")]
		public static extern int ldap_search([In] ConnectionHandle ldapHandle, string dn, int scope, string filter, IntPtr attributes, bool attributeOnly, IntPtr servercontrol, IntPtr clientcontrol, int timelimit, int sizelimit, ref int messageNumber);

		// Token: 0x0600033E RID: 830
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern IntPtr ldap_first_entry([In] ConnectionHandle ldapHandle, [In] IntPtr result);

		// Token: 0x0600033F RID: 831
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern IntPtr ldap_next_entry([In] ConnectionHandle ldapHandle, [In] IntPtr result);

		// Token: 0x06000340 RID: 832
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern IntPtr ldap_first_reference([In] ConnectionHandle ldapHandle, [In] IntPtr result);

		// Token: 0x06000341 RID: 833
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern IntPtr ldap_next_reference([In] ConnectionHandle ldapHandle, [In] IntPtr result);

		// Token: 0x06000342 RID: 834
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_get_dnW")]
		public static extern IntPtr ldap_get_dn([In] ConnectionHandle ldapHandle, [In] IntPtr result);

		// Token: 0x06000343 RID: 835
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_first_attributeW")]
		public static extern IntPtr ldap_first_attribute([In] ConnectionHandle ldapHandle, [In] IntPtr result, ref IntPtr address);

		// Token: 0x06000344 RID: 836
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_next_attributeW")]
		public static extern IntPtr ldap_next_attribute([In] ConnectionHandle ldapHandle, [In] IntPtr result, [In][Out] IntPtr address);

		// Token: 0x06000345 RID: 837
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern IntPtr ber_free([In] IntPtr berelement, int option);

		// Token: 0x06000346 RID: 838
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_get_values_lenW")]
		public static extern IntPtr ldap_get_values_len([In] ConnectionHandle ldapHandle, [In] IntPtr result, string name);

		// Token: 0x06000347 RID: 839
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern IntPtr ldap_value_free_len([In] IntPtr berelement);

		// Token: 0x06000348 RID: 840
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_parse_referenceW")]
		public static extern int ldap_parse_reference([In] ConnectionHandle ldapHandle, [In] IntPtr result, ref IntPtr referrals);

		// Token: 0x06000356 RID: 854
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_create_sort_controlW")]
		public static extern int ldap_create_sort_control(ConnectionHandle handle, IntPtr keys, byte critical, ref IntPtr control);

		// Token: 0x06000357 RID: 855
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "ldap_control_freeW")]
		public static extern int ldap_control_free(IntPtr control);

		// Token: 0x06000358 RID: 856
		[DllImport("Crypt32.dll", CharSet = CharSet.Unicode)]
		public static extern int CertFreeCRLContext(IntPtr certContext);

		// Token: 0x06000359 RID: 857
		[DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		public static extern int ldap_result2error([In] ConnectionHandle ldapHandle, [In] IntPtr result, int freeIt);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate bool QUERYCLIENTCERT(IntPtr Connection, IntPtr trusted_CAs, ref IntPtr certificateHandle);

		// Token: 0x0400026B RID: 619
		public const int SEC_WINNT_AUTH_IDENTITY_UNICODE = 2;

		// Token: 0x0400026C RID: 620
		public const int SEC_WINNT_AUTH_IDENTITY_VERSION = 512;

		// Token: 0x0400026D RID: 621
		public const string MICROSOFT_KERBEROS_NAME_W = "Kerberos";


	}
	[StructLayout(LayoutKind.Sequential)]
	public struct berval
	{
		public int bv_len;
		public IntPtr bv_val;
	}
	// Token: 0x02000088 RID: 136
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	public class SEC_WINNT_AUTH_IDENTITY_EX
	{
		// Token: 0x0400020D RID: 525
		public int version;

		// Token: 0x0400020E RID: 526
		public int length;

		// Token: 0x0400020F RID: 527
		public string user;

		// Token: 0x04000210 RID: 528
		public int userLength;

		// Token: 0x04000211 RID: 529
		public string domain;

		// Token: 0x04000212 RID: 530
		public int domainLength;

		// Token: 0x04000213 RID: 531
		public string password;

		// Token: 0x04000214 RID: 532
		public int passwordLength;

		// Token: 0x04000215 RID: 533
		public int flags;

		// Token: 0x04000216 RID: 534
		public string packageList;

		// Token: 0x04000217 RID: 535
		public int packageListLength;
	}

	// Token: 0x02000089 RID: 137
	public enum BindMethod : uint
	{
		// Token: 0x04000219 RID: 537
		LDAP_AUTH_SIMPLE = 128U,
		// Token: 0x0400021A RID: 538
		LDAP_AUTH_SASL = 131U,
		// Token: 0x0400021B RID: 539
		LDAP_AUTH_OTHERKIND = 134U,
		// Token: 0x0400021C RID: 540
		LDAP_AUTH_SICILY = 646U,
		// Token: 0x0400021D RID: 541
		LDAP_AUTH_MSN = 2182U,
		// Token: 0x0400021E RID: 542
		LDAP_AUTH_NTLM = 4230U,
		// Token: 0x0400021F RID: 543
		LDAP_AUTH_DPA = 8326U,
		// Token: 0x04000220 RID: 544
		LDAP_AUTH_NEGOTIATE = 1158U,
		// Token: 0x04000221 RID: 545
		LDAP_AUTH_SSPI = 1158U,
		// Token: 0x04000222 RID: 546
		LDAP_AUTH_DIGEST = 16518U,
		// Token: 0x04000223 RID: 547
		LDAP_AUTH_EXTERNAL = 166U
	}

	[StructLayout(LayoutKind.Sequential)]
	public class LDAP_TIMEVAL
	{
		// Token: 0x0400024F RID: 591
		public int tv_sec;

		// Token: 0x04000250 RID: 592
		public int tv_usec;
	}

	// Token: 0x0200008A RID: 138
	public enum LdapOption
	{
		// Token: 0x04000225 RID: 549
		LDAP_OPT_DESC = 1,
		// Token: 0x04000226 RID: 550
		LDAP_OPT_DEREF,
		// Token: 0x04000227 RID: 551
		LDAP_OPT_SIZELIMIT,
		// Token: 0x04000228 RID: 552
		LDAP_OPT_TIMELIMIT,
		// Token: 0x04000229 RID: 553
		LDAP_OPT_REFERRALS = 8,
		// Token: 0x0400022A RID: 554
		LDAP_OPT_RESTART,
		// Token: 0x0400022B RID: 555
		LDAP_OPT_SSL,
		// Token: 0x0400022C RID: 556
		LDAP_OPT_REFERRAL_HOP_LIMIT = 16,
		// Token: 0x0400022D RID: 557
		LDAP_OPT_VERSION,
		// Token: 0x0400022E RID: 558
		LDAP_OPT_API_FEATURE_INFO = 21,
		// Token: 0x0400022F RID: 559
		LDAP_OPT_HOST_NAME = 48,
		// Token: 0x04000230 RID: 560
		LDAP_OPT_ERROR_NUMBER,
		// Token: 0x04000231 RID: 561
		LDAP_OPT_ERROR_STRING,
		// Token: 0x04000232 RID: 562
		LDAP_OPT_SERVER_ERROR,
		// Token: 0x04000233 RID: 563
		LDAP_OPT_SERVER_EXT_ERROR,
		// Token: 0x04000234 RID: 564
		LDAP_OPT_HOST_REACHABLE = 62,
		// Token: 0x04000235 RID: 565
		LDAP_OPT_PING_KEEP_ALIVE = 54,
		// Token: 0x04000236 RID: 566
		LDAP_OPT_PING_WAIT_TIME,
		// Token: 0x04000237 RID: 567
		LDAP_OPT_PING_LIMIT,
		// Token: 0x04000238 RID: 568
		LDAP_OPT_DNSDOMAIN_NAME = 59,
		// Token: 0x04000239 RID: 569
		LDAP_OPT_GETDSNAME_FLAGS = 61,
		// Token: 0x0400023A RID: 570
		LDAP_OPT_PROMPT_CREDENTIALS = 63,
		// Token: 0x0400023B RID: 571
		LDAP_OPT_TCP_KEEPALIVE,
		// Token: 0x0400023C RID: 572
		LDAP_OPT_FAST_CONCURRENT_BIND,
		// Token: 0x0400023D RID: 573
		LDAP_OPT_SEND_TIMEOUT,
		// Token: 0x0400023E RID: 574
		LDAP_OPT_REFERRAL_CALLBACK = 112,
		// Token: 0x0400023F RID: 575
		LDAP_OPT_CLIENT_CERTIFICATE = 128,
		// Token: 0x04000240 RID: 576
		LDAP_OPT_SERVER_CERTIFICATE,
		// Token: 0x04000241 RID: 577
		LDAP_OPT_AUTO_RECONNECT = 145,
		// Token: 0x04000242 RID: 578
		LDAP_OPT_SSPI_FLAGS,
		// Token: 0x04000243 RID: 579
		LDAP_OPT_SSL_INFO,
		// Token: 0x04000244 RID: 580
		LDAP_OPT_SIGN = 149,
		// Token: 0x04000245 RID: 581
		LDAP_OPT_ENCRYPT,
		// Token: 0x04000246 RID: 582
		LDAP_OPT_SASL_METHOD,
		// Token: 0x04000247 RID: 583
		LDAP_OPT_AREC_EXCLUSIVE = 152,
		// Token: 0x04000248 RID: 584
		LDAP_OPT_SECURITY_CONTEXT = 153,
		// Token: 0x04000249 RID: 585
		LDAP_OPT_ROOTDSE_CACHE
	}
}

public static class Security { 

	[StructLayout(LayoutKind.Sequential)]
	public struct SecHandle
	{
		public IntPtr dwLower;
		public IntPtr dwUpper;
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

	[DllImport("Secur32.dll")]
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

	[DllImport("secur32", CharSet = CharSet.Auto, SetLastError = true)]
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

	[DllImport("secur32", CharSet = CharSet.Auto, SetLastError = true)]
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

}
