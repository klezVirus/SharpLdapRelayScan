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
// Novell.Directory.Ldap.Extensions.GetReplicaInfoRequest.cs
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
    /// Reads information about a replica.
    /// 
    /// The information available includes such items as  replicas state, last
    /// modification time, and replica type. 
    /// 
    /// To read other information about a replica, you must
    /// create an instance of this class and then call the
    /// extendedOperation method with this object as the required
    /// LdapExtendedOperation parameter.
    /// 
    /// The getReplicaInfoRequest extension uses the following OID:
    /// 2.16.840.1.113719.1.27.100.17
    /// 
    /// The requestValue has the following format:
    /// 
    /// requestValue ::=
    ///  serverDN     LdapDN
    ///  partitionDN  LdapDN
    /// </summary>
    public class GetReplicaInfoRequest : LdapExtendedOperation
    {

        static GetReplicaInfoRequest()
        {
            /*
				* Register the extendedresponse class which is returned by the
				* server in response to a ListReplicasRequest
				*/
            try
            {
                LdapExtendedResponse.register(ReplicationConstants.GET_REPLICA_INFO_RES, System.Type.GetType("Novell.Directory.Ldap.Extensions.GetReplicaInfoResponse"));
            }
            catch (System.Exception e)
            {
                System.Console.Error.WriteLine("Could not register Extended Response -" + " Class not found");
            }
        }

        /// <summary> 
        /// Constructs an extended operations object for reading replica information.
        /// 
        /// </summary>
        /// <param name="serverDN">The server on which the replica resides.
        /// 
        /// </param>
        /// <param name="partitionDN">The distinguished name of the replica to be read.
        /// 
        /// </param>
        /// <exception> LdapException A general exception which includes an error
        /// message and an Ldap error code.
        /// </exception>
        public GetReplicaInfoRequest(System.String serverDN, System.String partitionDN) : base(ReplicationConstants.GET_REPLICA_INFO_REQ, null)
        {

            try
            {

                if (((System.Object)serverDN == null) || ((System.Object)partitionDN == null))
                    throw new System.ArgumentException(ExceptionMessages.PARAM_ERROR);

                System.IO.MemoryStream encodedData = new System.IO.MemoryStream();
                LBEREncoder encoder = new LBEREncoder();

                Asn1OctetString asn1_serverDN = new Asn1OctetString(serverDN);
                Asn1OctetString asn1_partitionDN = new Asn1OctetString(partitionDN);

                asn1_serverDN.encode(encoder, encodedData);
                asn1_partitionDN.encode(encoder, encodedData);

                setValue(SupportClass.ToSByteArray(encodedData.ToArray()));
            }
            catch (System.IO.IOException ioe)
            {
                throw new LdapException(ExceptionMessages.ENCODING_ERROR, LdapException.ENCODING_ERROR, (System.String)null);
            }
        }
    }
}
