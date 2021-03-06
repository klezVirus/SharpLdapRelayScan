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
// Novell.Directory.Ldap.Extensions.SendAllUpdatesRequest.cs
//
// Author:
//   Sunil Kumar (Sunilk@novell.com)
//
// (C) 2003 Novell, Inc (http://www.novell.com)
//

using Novell.Directory.Ldap.Asn1;
using Novell.Directory.Ldap.Utilclass;

namespace Novell.Directory.Ldap.Extensions
{

    /// <summary> 
    /// Schedules an updated request to be sent to all directory servers in a
    /// replica ring.
    /// 
    /// The sendAllUpdatesRequest extension uses the following OID:
    /// 2.16.840.1.113719.1.27.100.23
    /// 
    /// The requestValue has the following format:
    /// 
    /// requestValue ::=
    ///     partitionRoot   LdapDN
    ///     origServerDN    LdapDN
    /// </summary>
    public class SendAllUpdatesRequest : LdapExtendedOperation
    {

        /// <summary> 
        /// Constructs an extended operation object for sending updates to a replica ring.
        /// 
        /// </summary>
        /// <param name="partitionRoot">The distinguished name of the replica
        /// that will be updated.
        /// 
        /// </param>
        /// <param name="origServerDN"> The distinguished name of the server that sends the
        /// updates to the replica ring.
        /// 
        /// </param>
        /// <exception> LdapException A general exception which includes an error message
        /// and an Ldap error code.
        /// </exception>
        public SendAllUpdatesRequest(System.String partitionRoot, System.String origServerDN) : base(ReplicationConstants.SEND_ALL_UPDATES_REQ, null)
        {

            try
            {

                if (((System.Object)partitionRoot == null) || ((System.Object)origServerDN == null))
                    throw new System.ArgumentException(ExceptionMessages.PARAM_ERROR);
                System.IO.MemoryStream encodedData = new System.IO.MemoryStream();
                LBEREncoder encoder = new LBEREncoder();

                Asn1OctetString asn1_partitionRoot = new Asn1OctetString(partitionRoot);
                Asn1OctetString asn1_origServerDN = new Asn1OctetString(origServerDN);

                asn1_partitionRoot.encode(encoder, encodedData);
                asn1_origServerDN.encode(encoder, encodedData);

                setValue(SupportClass.ToSByteArray(encodedData.ToArray()));
            }
            catch (System.IO.IOException ioe)
            {
                throw new LdapException(ExceptionMessages.ENCODING_ERROR, LdapException.ENCODING_ERROR, (System.String)null);
            }
        }
    }
}
