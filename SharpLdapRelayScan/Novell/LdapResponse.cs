/******************************************************************************
* The MIT License
* Copyright (c) 2003 Novell Inc.  www.novell.com
* 
* Permission is hereby granted, free of charge, to any person obtaining  a copy
* of this software and associated documentation files (the Software), to deal
* in the Software without restriction, including  without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
* copies of the Software, and to  permit persons to whom the Software is 
* furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in 
* all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*******************************************************************************/
//
// Novell.Directory.Ldap.LdapResponse.cs
//
// Author:
//   Sunil Kumar (Sunilk@novell.com)
//
// (C) 2003 Novell, Inc (http://www.novell.com)
//

using Novell.Directory.Ldap.Asn1;
using Novell.Directory.Ldap.Rfc2251;
using Novell.Directory.Ldap.Utilclass;
using System;
using System.Text;

namespace Novell.Directory.Ldap
{

    /// <summary>  A message received from an LdapServer
    /// in response to an asynchronous request.
    /// 
    /// </summary>
    /// <seealso cref="LdapConnection.Search">
    /// </seealso>

    /*
	* Note: Exceptions generated by the reader thread are returned
	* to the application as an exception in an LdapResponse.  Thus
	* if <code>exception</code> has a value, it is not a server response,
	* but instad an exception returned to the application from the API.
	*/
    [Serializable]
    public class LdapResponse : LdapMessage
    {
        /// <summary> Returns any error message in the response.
        /// 
        /// </summary>
        /// <returns> Any error message in the response.
        /// </returns>
        virtual public System.String ErrorMessage
        {
            get
            {
                if (exception != null)
                {
                    return exception.LdapErrorMessage;
                }

                /*				RfcResponse resp=(RfcResponse)( message.Response);
                                if(resp == null)
                                    Console.WriteLine(" Response is null");
                                else
                                    Console.WriteLine(" Response is non null");
                                string str=resp.getErrorMessage().stringValue();
                                if( str==null)
                                     Console.WriteLine("str is null..");
                                Console.WriteLine(" Response is non null" + str);
                                return str;
                */
                return ((RfcResponse)message.Response).getErrorMessage().stringValue();
            }

        }
        /// <summary> Returns the partially matched DN field from the server response,
        /// if the response contains one.
        /// 
        /// </summary>
        /// <returns> The partially matched DN field, if the response contains one.
        /// 
        /// </returns>
        virtual public System.String MatchedDN
        {
            get
            {
                if (exception != null)
                {
                    return exception.MatchedDN;
                }
                return ((RfcResponse)message.Response).getMatchedDN().stringValue();
            }

        }
        /// <summary> Returns all referrals in a server response, if the response contains any.
        /// 
        /// </summary>
        /// <returns> All the referrals in the server response.
        /// </returns>
        virtual public System.String[] Referrals
        {
            get
            {
                System.String[] referrals = null;
                RfcReferral ref_Renamed = ((RfcResponse)message.Response).getReferral();

                if (ref_Renamed == null)
                {
                    referrals = new System.String[0];
                }
                else
                {
                    // convert RFC 2251 Referral to String[]
                    int size = ref_Renamed.size();
                    referrals = new System.String[size];
                    for (int i = 0; i < size; i++)
                    {
                        System.String aRef = ((Asn1OctetString)ref_Renamed.get_Renamed(i)).stringValue();
                        try
                        {
                            // get the referral URL
                            LdapUrl urlRef = new LdapUrl(aRef);
                            if ((System.Object)urlRef.getDN() == null)
                            {
                                RfcLdapMessage origMsg = base.Asn1Object.RequestingMessage.Asn1Object;
                                System.String dn;
                                if ((System.Object)(dn = origMsg.RequestDN) != null)
                                {
                                    urlRef.setDN(dn);
                                    aRef = urlRef.ToString();
                                }
                            }
                        }
                        catch (System.UriFormatException mex)
                        {
                            ;
                        }
                        finally
                        {
                            referrals[i] = aRef;
                        }
                    }
                }
                return referrals;
            }

        }
        /// <summary> Returns the result code in a server response.
        /// 
        ///  For a list of result codes, see the LdapException class. 
        /// 
        /// </summary>
        /// <returns> The result code.
        /// </returns>
        virtual public int ResultCode
        {
            get
            {
                if (exception != null)
                {
                    return exception.ResultCode;
                }
                if (((RfcResponse)message.Response) is RfcIntermediateResponse)
                    return 0;
                return ((RfcResponse)message.Response).getResultCode().intValue();
            }

        }
        /// <summary> Checks the resultCode and generates the appropriate exception or
        /// null if success.
        /// </summary>
        virtual internal LdapException ResultException
        {
            /* package */

            get
            {
                LdapException ex = null;
                switch (ResultCode)
                {

                    case LdapException.SUCCESS:
                    case LdapException.COMPARE_TRUE:
                    case LdapException.COMPARE_FALSE:
                        break;

                    case LdapException.REFERRAL:
                        System.String[] refs = Referrals;
                        ex = new LdapReferralException("Automatic referral following not enabled", LdapException.REFERRAL, ErrorMessage);
                        ((LdapReferralException)ex).setReferrals(refs);
                        break;

                    default:
                        ex = new LdapException(LdapException.resultCodeToString(ResultCode), ResultCode, ErrorMessage, MatchedDN);
                        break;

                }
                return ex;
            }

        }
        /// <summary> Returns any controls in the message.
        /// 
        /// </summary>
        /// <seealso cref="Novell.Directory.Ldap.LdapMessage.Controls">
        /// </seealso>
        override public LdapControl[] Controls
        {
            get
            {
                if (exception != null)
                {
                    return null;
                }
                return base.Controls;
            }

        }
        /// <summary> Returns the message ID.
        /// 
        /// </summary>
        /// <seealso cref="Novell.Directory.Ldap.LdapMessage.MessageID">
        /// </seealso>
        override public int MessageID
        {
            get
            {
                if (exception != null)
                {
                    return exception.MessageID;
                }
                return base.MessageID;
            }

        }
        /// <summary> Returns the Ldap operation type of the message.
        /// 
        /// </summary>
        /// <returns> The operation type of the message.
        /// 
        /// </returns>
        /// <seealso cref="Novell.Directory.Ldap.LdapMessage.Type">
        /// </seealso>
        override public int Type
        {
            get
            {
                if (exception != null)
                {
                    return exception.ReplyType;
                }
                return base.Type;
            }

        }
        /// <summary> Returns an embedded exception response
        /// 
        /// </summary>
        /// <returns> an embedded exception if any
        /// </returns>
        virtual internal LdapException Exception
        {
            /*package*/

            get
            {
                return exception;
            }

        }
        /// <summary> Indicates the referral instance being followed if the
        /// connection created to follow referrals.
        /// 
        /// </summary>
        /// <returns> the referral being followed
        /// </returns>
        virtual internal ReferralInfo ActiveReferral
        {
            /*package*/

            get
            {
                return activeReferral;
            }

        }
        private InterThreadException exception = null;
        private ReferralInfo activeReferral;

        /// <summary> Creates an LdapResponse using an LdapException.
        /// Used to wake up the user following an abandon.
        /// Note: The abandon doesn't have to be user initiated
        /// but may be the result of error conditions.
        /// 
        /// Referral information is available if this connection created solely
        /// to follow a referral.
        /// 
        /// </summary>
        /// <param name="ex"> The exception
        /// 
        /// </param>
        /// <param name="activeReferral"> The referral actually used to create the
        /// connection
        /// </param>
        public LdapResponse(InterThreadException ex, ReferralInfo activeReferral)
        {
            exception = ex;
            this.activeReferral = activeReferral;

            return;
        }

        /// <summary> Creates a response LdapMessage when receiving an asynchronous
        /// response from a server.
        /// 
        /// </summary>
        /// <param name="message"> The RfcLdapMessage from a server.
        /// </param>
        /*package*/
        internal LdapResponse(RfcLdapMessage message) : base(message)
        {
            return;
        }

        /// <summary> Creates a SUCCESS response LdapMessage. Typically the response
        /// comes from a source other than a BER encoded Ldap message,
        /// such as from DSML.  Other values which are allowed in a response
        /// are set to their empty values.
        /// 
        /// </summary>
        /// <param name="type"> The message type as defined in LdapMessage.
        /// 
        /// </param>
        /// <seealso cref="LdapMessage">
        /// </seealso>
        public LdapResponse(int type) : this(type, LdapException.SUCCESS, null, null, null, null)
        {
            return;
        }

        /// <summary> Creates a response LdapMessage from parameters. Typically the data
        /// comes from a source other than a BER encoded Ldap message,
        /// such as from DSML.
        /// 
        /// </summary>
        /// <param name="type"> The message type as defined in LdapMessage.
        /// 
        /// </param>
        /// <param name="resultCode"> The result code as defined in LdapException.
        /// 
        /// </param>
        /// <param name="matchedDN">  The name of the lowest entry that was matched
        /// for some error result codes, an empty string
        /// or <code>null</code> if none.
        /// 
        /// </param>
        /// <param name="serverMessage"> A diagnostic message returned by the server,
        /// an empty string or <code>null</code> if none.
        /// 
        /// </param>
        /// <param name="referrals">  The referral URLs returned for a REFERRAL result
        /// code or <code>null</code> if none.
        /// 
        /// </param>
        /// <param name="controls">   Any controls returned by the server or
        /// <code>null</code> if none.
        /// 
        /// </param>
        /// <seealso cref="LdapMessage">
        /// </seealso>
        /// <seealso cref="LdapException">
        /// </seealso>
        public LdapResponse(int type, int resultCode, System.String matchedDN, System.String serverMessage, System.String[] referrals, LdapControl[] controls) : base(new RfcLdapMessage(RfcResultFactory(type, resultCode, matchedDN, serverMessage, referrals)))
        {

            return;
        }

        private static Asn1Sequence RfcResultFactory(int type, int resultCode, System.String matchedDN, System.String serverMessage, System.String[] referrals)
        {
            Asn1Sequence ret;

            if ((System.Object)matchedDN == null)
                matchedDN = "";
            if ((System.Object)serverMessage == null)
                serverMessage = "";

            switch (type)
            {

                case SEARCH_RESULT:
                    ret = new RfcSearchResultDone(new Asn1Enumerated(resultCode), new RfcLdapDN(matchedDN), new RfcLdapString(serverMessage), null);
                    break;

                case BIND_RESPONSE:
                    ret = null; // new Asn new SicilyResponse(SupportClass.ToSByteArray(Encoding.Unicode.GetBytes(serverMessage)));
                    break;

                case SEARCH_RESPONSE:
                    ret = null; // Not yet implemented
                    break;

                case MODIFY_RESPONSE:
                    ret = new RfcModifyResponse(new Asn1Enumerated(resultCode), new RfcLdapDN(matchedDN), new RfcLdapString(serverMessage), null);
                    break;

                case ADD_RESPONSE:
                    ret = new RfcAddResponse(new Asn1Enumerated(resultCode), new RfcLdapDN(matchedDN), new RfcLdapString(serverMessage), null);
                    break;

                case DEL_RESPONSE:
                    ret = new RfcDelResponse(new Asn1Enumerated(resultCode), new RfcLdapDN(matchedDN), new RfcLdapString(serverMessage), null);
                    break;

                case MODIFY_RDN_RESPONSE:
                    ret = new RfcModifyDNResponse(new Asn1Enumerated(resultCode), new RfcLdapDN(matchedDN), new RfcLdapString(serverMessage), null);
                    break;

                case COMPARE_RESPONSE:
                    ret = new RfcCompareResponse(new Asn1Enumerated(resultCode), new RfcLdapDN(matchedDN), new RfcLdapString(serverMessage), null);
                    break;

                case SEARCH_RESULT_REFERENCE:
                    ret = null; // Not yet implemented
                    break;

                case EXTENDED_RESPONSE:
                    ret = null; // Not yet implemented
                    break;

                default:
                    throw new System.SystemException("Type " + type + " Not Supported");

            }
            return ret;
        }

        /// <summary> Checks the resultCode and throws the appropriate exception.
        /// 
        /// </summary>
        /// <exception> LdapException A general exception which includes an error
        /// message and an Ldap error code.
        /// </exception>
        /* package */
        internal virtual void chkResultCode()
        {
            if (exception != null)
            {
                throw exception;
            }
            else
            {
                LdapException ex = ResultException;
                if (ex != null)
                {
                    throw ex;
                }
                return;
            }
        }

        /* Methods from LdapMessage */

        /// <summary> Indicates if this response is an embedded exception response
        /// 
        /// </summary>
        /// <returns> true if contains an embedded Ldapexception
        /// </returns>
        /*package*/
        internal virtual bool hasException()
        {
            return (exception != null);
        }

        public static explicit operator LdapResponse(RfcLdapMessage v)
        {
            throw new NotImplementedException();
        }
    }
}
