using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading.Tasks;

namespace SharpLdapRelayScan
{
    using static Common;

    public class WinAuthEndPoint
    {
        /// <summary>
        /// Keep track of auth states for reuse in final challenge response
        /// </summary>
        private static readonly IDictionary<Guid, State> authStates = new ConcurrentDictionary<Guid, State>();


        /// <summary>
        /// Acquire the intial client token to send
        /// </summary>
        /// <param name="hostname"></param>
        /// <param name="authScheme"></param>
        /// <param name="requestId"></param>
        /// <returns></returns>
        public static byte[] AcquireInitialSecurityToken(string hostname, string authScheme, Guid requestId)
        {
            byte[] token;

            //null for initial call
            var serverToken = new SecurityBufferDescription();

            var clientToken = new SecurityBufferDescription(MaximumTokenSize);

            try
            {
                int result;

                var state = new State();

                result = AcquireCredentialsHandle(
                    WindowsIdentity.GetCurrent().Name,
                    authScheme,
                    SecurityCredentialsMutual,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    0,
                    IntPtr.Zero,
                    ref state.Credentials,
                    ref NewLifeTime);

                if (result != SuccessfulResult)
                {
                    // Credentials acquire operation failed.
                    return null;
                }

                result = InitializeSecurityContext(ref state.Credentials,
                    IntPtr.Zero,
                    hostname,
                    StandardContextAttributes,
                    0,
                    SecurityNativeDataRepresentation,
                    ref serverToken,
                    0,
                    out state.Context,
                    out clientToken,
                    out NewContextAttributes,
                    out NewLifeTime);


                if (result != IntermediateResult)
                {
                    // Client challenge issue operation failed.
                    return null;
                }

                token = clientToken.GetBytes();
                authStates.Add(requestId, state);
            }
            finally
            {
                clientToken.Dispose();
                serverToken.Dispose();
            }

            return token;
        }
        public static byte[] AcquireInitialSecurityToken(SEC_WINNT_AUTH_IDENTITY_EX winnt_auth, string hostname, string authScheme, Guid requestId)
        {
            byte[] token = new byte[] { };

            //null for initial call
            var serverToken = new SecurityBufferDescription();

            var clientToken = new SecurityBufferDescription(MaximumTokenSize);

            IntPtr p_winnt_auth = Marshal.AllocHGlobal(Marshal.SizeOf<SEC_WINNT_AUTH_IDENTITY_EX>());
            Marshal.StructureToPtr<SEC_WINNT_AUTH_IDENTITY_EX>(winnt_auth, p_winnt_auth, false);

            try
            {
                int result;

                var state = new State();

                result = AcquireCredentialsHandle(
                    null,
                    authScheme,
                    SecurityCredentialsMutual,
                    IntPtr.Zero,
                    p_winnt_auth,
                    0,
                    IntPtr.Zero,
                    ref state.Credentials,
                    ref NewLifeTime);

                if (result != SuccessfulResult)
                {
                    // Credentials acquire operation failed.
                    return null;
                }

                result = InitializeSecurityContext(ref state.Credentials,
                    IntPtr.Zero,
                    hostname,
                    StandardContextAttributes,
                    0,
                    SecurityNativeDataRepresentation,
                    ref serverToken,
                    0,
                    out state.Context,
                    out clientToken,
                    out NewContextAttributes,
                    out NewLifeTime);


                if (result != IntermediateResult)
                {
                    Console.WriteLine("Client challenge issue operation failed");
                    // Client challenge issue operation failed.
                    return null;
                }

                token = clientToken.GetBytes();
                authStates.Add(requestId, state);
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Exception thrown");
                Console.WriteLine(e.StackTrace);
            }
            finally
            {
                clientToken.Dispose();
                serverToken.Dispose();
                Marshal.FreeHGlobal(p_winnt_auth);
            }

            return token;
        }

        /// <summary>
        /// Acquire the final token to send
        /// </summary>
        /// <param name="hostname"></param>
        /// <param name="serverChallenge"></param>
        /// <param name="requestId"></param>
        /// <returns></returns>
        public static byte[] AcquireFinalSecurityToken(string hostname, byte[] serverChallenge, Guid requestId)
        {
            byte[] token;

            //user server challenge
            var serverToken = new SecurityBufferDescription(serverChallenge);

            var clientToken = new SecurityBufferDescription(MaximumTokenSize);

            try
            {
                int result;

                var state = authStates[requestId];

                state.UpdatePresence();

                result = InitializeSecurityContext(ref state.Credentials,
                    ref state.Context,
                    hostname,
                    StandardContextAttributes,
                    0,
                    SecurityNativeDataRepresentation,
                    ref serverToken,
                    0,
                    out state.Context,
                    out clientToken,
                    out NewContextAttributes,
                    out NewLifeTime);


                if (result != SuccessfulResult)
                {
                    // Client challenge issue operation failed.
                    return null;
                }

                authStates.Remove(requestId);
                token = clientToken.GetBytes();
            }
            finally
            {
                clientToken.Dispose();
                serverToken.Dispose();
            }

            return token;
        }

        /// <summary>
        /// Clear any hanging states
        /// </summary>
        /// <param name="stateCacheTimeOutMinutes"></param>
        internal static async void ClearIdleStates(int stateCacheTimeOutMinutes)
        {
            var cutOff = DateTime.Now.AddMinutes(-1 * stateCacheTimeOutMinutes);

            var outdated = authStates.Where(x => x.Value.LastSeen < cutOff).ToList();

            foreach (var cache in outdated)
            {
                authStates.Remove(cache.Key);
            }

            //after a minute come back to check for outdated certificates in cache
            await Task.Delay(1000 * 60);
        }

        #region Native calls to secur32.dll

        [DllImport("secur32.dll", SetLastError = true)]
        static extern int InitializeSecurityContext(ref SecurityHandle phCredential, //PCredHandle
            IntPtr phContext, //PCtxtHandle
            string pszTargetName,
            int fContextReq,
            int reserved1,
            int targetDataRep,
            ref SecurityBufferDescription pInput, //PSecBufferDesc SecBufferDesc
            int reserved2,
            out SecurityHandle phNewContext, //PCtxtHandle
            out SecurityBufferDescription pOutput, //PSecBufferDesc SecBufferDesc
            out uint pfContextAttr, //managed ulong == 64 bits!!!
            out SecurityInteger ptsExpiry); //PTimeStamp

        [DllImport("secur32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int InitializeSecurityContext(ref SecurityHandle phCredential, //PCredHandle
            ref SecurityHandle phContext, //PCtxtHandle
            string pszTargetName,
            int fContextReq,
            int reserved1,
            int targetDataRep,
            ref SecurityBufferDescription secBufferDesc, //PSecBufferDesc SecBufferDesc
            int reserved2,
            out SecurityHandle phNewContext, //PCtxtHandle
            out SecurityBufferDescription pOutput, //PSecBufferDesc SecBufferDesc
            out uint pfContextAttr, //managed ulong == 64 bits!!!
            out SecurityInteger ptsExpiry); //PTimeStamp

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        private static extern int AcquireCredentialsHandle(
            string pszPrincipal, //SEC_CHAR*
            string pszPackage, //SEC_CHAR* //"Kerberos","NTLM","Negotiative"
            int fCredentialUse,
            IntPtr pAuthenticationId, //_LUID AuthenticationID,//pvLogonID, //PLUID
            IntPtr pAuthData, //PVOID
            int pGetKeyFn, //SEC_GET_KEY_FN
            IntPtr pvGetKeyArgument, //PVOID
            ref SecurityHandle phCredential, //SecHandle //PCtxtHandle ref
            ref SecurityInteger ptsExpiry); //PTimeStamp //TimeStamp ref

        #endregion
    }
}
