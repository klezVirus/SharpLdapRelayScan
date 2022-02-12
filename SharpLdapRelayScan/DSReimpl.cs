using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Text;
using System.Threading.Tasks;

namespace SharpLdapRelayScan
{
	public static class DSReimpl
	{


		[EnvironmentPermission(SecurityAction.Assert, Unrestricted = true)]
		[SecurityPermission(SecurityAction.Assert, Flags = SecurityPermissionFlag.UnmanagedCode)]
		public static int Bind(LdapConnection connection, NetworkCredential newCredential, bool needSetCredential)
		{
			if (connection.AuthType == AuthType.Anonymous && newCredential != null && ((newCredential.Password != null && newCredential.Password.Length != 0) || (newCredential.UserName != null && newCredential.UserName.Length != 0)))
			{
				throw new InvalidOperationException("InvalidAuthCredential");
			}
			NetworkCredential networkCredential;
			if (needSetCredential)
			{
				networkCredential = new NetworkCredential(newCredential.UserName, newCredential.Password, newCredential.Domain);
			}
			else
			{
				networkCredential = newCredential;
			}
			if (connection == null)
			{
				return -1;
			}
			string text;
			string text2;
			string text3;
			if (networkCredential != null && networkCredential.UserName.Length == 0 && networkCredential.Password.Length == 0 && networkCredential.Domain.Length == 0)
			{
				text = null;
				text2 = null;
				text3 = null;
			}
			else
			{
				text = ((networkCredential == null) ? null : networkCredential.UserName);
				text2 = ((networkCredential == null) ? null : networkCredential.Domain);
				text3 = ((networkCredential == null) ? null : networkCredential.Password);
			}
			int num;
			SafeHandleZeroOrMinusOneIsInvalid safeHandle = ReflectionHelper.GetPrivateFieldValue<SafeHandleZeroOrMinusOneIsInvalid>(connection, "ldapHandle");
			IntPtr rawHandle = ReflectionHelper.GetPrivateFieldValue<IntPtr>(safeHandle, "handle");
			ConnectionHandle ldapHandle = new ConnectionHandle(rawHandle, true);
				
			//SSPIHandler handler = new SSPIHandler(ldapHandle);
			//handler.Tamper();
			
			if (ldapHandle == null)
			{
				Console.WriteLine("[-] Failed to get connection handle");
				return -1;
			}


			if (connection.AuthType == AuthType.Anonymous)
			{
				num = Wldap32.ldap_simple_bind_s(ldapHandle, null, null);
			}
			else if (connection.AuthType == AuthType.Basic)
			{
				StringBuilder stringBuilder = new StringBuilder(100);
				if (text2 != null && text2.Length != 0)
				{
					stringBuilder.Append(text2);
					stringBuilder.Append("\\");
				}
				stringBuilder.Append(text);
				num = Wldap32.ldap_simple_bind_s(ldapHandle, stringBuilder.ToString(), text3);
			}
			else
			{
				SEC_WINNT_AUTH_IDENTITY_EX sec_WINNT_AUTH_IDENTITY_EX = new SEC_WINNT_AUTH_IDENTITY_EX();
				sec_WINNT_AUTH_IDENTITY_EX.version = 512;
				sec_WINNT_AUTH_IDENTITY_EX.length = Marshal.SizeOf(typeof(SEC_WINNT_AUTH_IDENTITY_EX));
				sec_WINNT_AUTH_IDENTITY_EX.flags = 2;
				if (connection.AuthType == AuthType.Kerberos)
				{
					sec_WINNT_AUTH_IDENTITY_EX.packageList = "Kerberos";
					sec_WINNT_AUTH_IDENTITY_EX.packageListLength = sec_WINNT_AUTH_IDENTITY_EX.packageList.Length;
				}
				if (networkCredential != null)
				{
					sec_WINNT_AUTH_IDENTITY_EX.user = text;
					sec_WINNT_AUTH_IDENTITY_EX.userLength = ((text == null) ? 0 : text.Length);
					sec_WINNT_AUTH_IDENTITY_EX.domain = text2;
					sec_WINNT_AUTH_IDENTITY_EX.domainLength = ((text2 == null) ? 0 : text2.Length);
					sec_WINNT_AUTH_IDENTITY_EX.password = text3;
					sec_WINNT_AUTH_IDENTITY_EX.passwordLength = ((text3 == null) ? 0 : text3.Length);
				}
				BindMethod method = BindMethod.LDAP_AUTH_NEGOTIATE;
				switch (connection.AuthType)
				{
					case AuthType.Negotiate:
						method = BindMethod.LDAP_AUTH_NEGOTIATE;
						break;
					case AuthType.Ntlm:
						method = BindMethod.LDAP_AUTH_NTLM;
						break;
					case AuthType.Digest:
						method = BindMethod.LDAP_AUTH_DIGEST;
						break;
					case AuthType.Sicily:
						method = BindMethod.LDAP_AUTH_SICILY;
						break;
					case AuthType.Dpa:
						method = BindMethod.LDAP_AUTH_DPA;
						break;
					case AuthType.Msn:
						method = BindMethod.LDAP_AUTH_MSN;
						break;
					case AuthType.External:
						method = BindMethod.LDAP_AUTH_EXTERNAL;
						break;
					case AuthType.Kerberos:
						method = BindMethod.LDAP_AUTH_NEGOTIATE;
						break;
				}
				if (networkCredential == null && connection.AuthType == AuthType.External)
				{
					num = Wldap32.ldap_bind_s(ldapHandle, null, null, method);
				}
				else
				{
					num = Wldap32.ldap_bind_s(ldapHandle, null, sec_WINNT_AUTH_IDENTITY_EX, method);
				}
			}
			IntPtr lpError;
			
			Wldap32.ldap_get_option_errorstring(ldapHandle, LdapOption.LDAP_OPT_SERVER_ERROR, out lpError);


			Console.WriteLine("--- RET CODE: {0}", num);
			Console.WriteLine("--- LAST ERR: {0}", Marshal.PtrToStringAuto(lpError));
			return num;
		}

		public static List<string> GetSupportedOIDs(LdapConnection connection) {

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
		public static int LdapsBind(LdapConnection connection, NetworkCredential newCredential, bool needSetCredential)
		{
			
			if (connection == null)
			{
				return -1;
			}

			

			NetworkCredential networkCredential = newCredential;


			int num;
			SafeHandleZeroOrMinusOneIsInvalid safeHandle = ReflectionHelper.GetPrivateFieldValue<SafeHandleZeroOrMinusOneIsInvalid>(connection, "ldapHandle");
			IntPtr rawHandle = ReflectionHelper.GetPrivateFieldValue<IntPtr>(safeHandle, "handle");
			ConnectionHandle ldapHandle = new ConnectionHandle(rawHandle, true);

			if (ldapHandle == null)
			{
				Console.WriteLine("[-] Failed to get connection handle");
				return -1;
			}
			
			SEC_WINNT_AUTH_IDENTITY_EX sec_WINNT_AUTH_IDENTITY_EX = new SEC_WINNT_AUTH_IDENTITY_EX();
			sec_WINNT_AUTH_IDENTITY_EX.version = 512;
			sec_WINNT_AUTH_IDENTITY_EX.length = Marshal.SizeOf(typeof(SEC_WINNT_AUTH_IDENTITY_EX));
			sec_WINNT_AUTH_IDENTITY_EX.flags = 2;
			
			if (networkCredential != null)
			{
				sec_WINNT_AUTH_IDENTITY_EX.user = networkCredential.UserName;
				sec_WINNT_AUTH_IDENTITY_EX.userLength = ((networkCredential.UserName == null) ? 0 : networkCredential.UserName.Length);
				sec_WINNT_AUTH_IDENTITY_EX.domain = networkCredential.Domain;
				sec_WINNT_AUTH_IDENTITY_EX.domainLength = ((networkCredential.Domain == null) ? 0 : networkCredential.Domain.Length);
				sec_WINNT_AUTH_IDENTITY_EX.password = networkCredential.Password;
				sec_WINNT_AUTH_IDENTITY_EX.passwordLength = ((networkCredential.Password == null) ? 0 : networkCredential.Password.Length);
			}
			BindMethod method = BindMethod.LDAP_AUTH_SSPI;
			
			num = Wldap32.ldap_bind_s(ldapHandle, null, sec_WINNT_AUTH_IDENTITY_EX, method);
			
			IntPtr lpError;

			Wldap32.ldap_get_option_errorstring(ldapHandle, LdapOption.LDAP_OPT_SERVER_ERROR, out lpError);


			Console.WriteLine("--- RET CODE: {0}", num);
			Console.WriteLine("--- LAST ERR: {0}", Marshal.PtrToStringAuto(lpError));
			return num;
		}		
		
		
		[EnvironmentPermission(SecurityAction.Assert, Unrestricted = true)]
		[SecurityPermission(SecurityAction.Assert, Flags = SecurityPermissionFlag.UnmanagedCode)]
		public static int LdapsBind2(LdapConnection connection, NetworkCredential newCredential, bool needSetCredential)
		{
			
			if (connection == null)
			{
				return -1;
			}

			NetworkCredential networkCredential = newCredential;

			int num;
			SafeHandleZeroOrMinusOneIsInvalid safeHandle = ReflectionHelper.GetPrivateFieldValue<SafeHandleZeroOrMinusOneIsInvalid>(connection, "ldapHandle");
			IntPtr rawHandle = ReflectionHelper.GetPrivateFieldValue<IntPtr>(safeHandle, "handle");
			ConnectionHandle ldapHandle = new ConnectionHandle(rawHandle, true);

			if (ldapHandle == null)
			{
				Console.WriteLine("[-] Failed to get connection handle");
				return -1;
			}
			Console.WriteLine("[*] Check point");

			SEC_WINNT_AUTH_IDENTITY_EX sec_WINNT_AUTH_IDENTITY_EX = new SEC_WINNT_AUTH_IDENTITY_EX();
			sec_WINNT_AUTH_IDENTITY_EX.version = 512;
			sec_WINNT_AUTH_IDENTITY_EX.length = Marshal.SizeOf(typeof(SEC_WINNT_AUTH_IDENTITY_EX));
			sec_WINNT_AUTH_IDENTITY_EX.flags = 2;
			
			if (networkCredential != null)
			{
				sec_WINNT_AUTH_IDENTITY_EX.user = networkCredential.UserName;
				sec_WINNT_AUTH_IDENTITY_EX.userLength = ((networkCredential.UserName == null) ? 0 : networkCredential.UserName.Length);
				sec_WINNT_AUTH_IDENTITY_EX.domain = networkCredential.Domain;
				sec_WINNT_AUTH_IDENTITY_EX.domainLength = ((networkCredential.Domain == null) ? 0 : networkCredential.Domain.Length);
				sec_WINNT_AUTH_IDENTITY_EX.password = networkCredential.Password;
				sec_WINNT_AUTH_IDENTITY_EX.passwordLength = ((networkCredential.Password == null) ? 0 : networkCredential.Password.Length);
			}
			BindMethod method = BindMethod.LDAP_AUTH_SSPI;

			byte[] serverChallenge = WinAuthEndPoint.AcquireInitialSecurityToken(System.Environment.MachineName, "NTLM", new Guid());
			byte[] token = WinAuthEndPoint.AcquireFinalSecurityToken(System.Environment.MachineName, serverChallenge, new Guid());

			GCHandle pinnedArray = GCHandle.Alloc(serverChallenge, GCHandleType.Pinned);
			IntPtr pointer = pinnedArray.AddrOfPinnedObject();

			berval cred = new berval {
				bv_len = serverChallenge.Length,
				bv_val = pointer
			};

			berval messageNumber;
			Console.WriteLine("[*] Binding");

			num = Wldap32.ldap_sasl_bindW(ldapHandle, null, "GSS-SPNEGO", ref cred, IntPtr.Zero, IntPtr.Zero, out messageNumber);
			Console.WriteLine("--- MESSAGE NUM: {0}", messageNumber.bv_val);

			IntPtr lpError;

			Wldap32.ldap_get_option_errorstring(ldapHandle, LdapOption.LDAP_OPT_SERVER_ERROR, out lpError);


			Console.WriteLine("--- RET CODE: {0}", num);
			Console.WriteLine("--- LAST ERR: {0}", Marshal.PtrToStringAuto(lpError));
			pinnedArray.Free();
			return num;
		}
	}



}
