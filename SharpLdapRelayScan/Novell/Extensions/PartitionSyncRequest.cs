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
// Novell.Directory.Ldap.Extensions.PartitionSyncRequest.cs
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
    /// Synchronizes all replicas of a naming context.
    /// 
    /// The PartitionSyncRequest extension uses the following OID:
    /// 2.16.840.1.113719.1.27.100.25
    /// 
    /// The requestValue has the following format:
    /// 
    /// requestValue ::=
    ///  serverName      LdapDN
    ///  partitionRoot   LdapDN
    ///  delay           INTEGER
    /// </summary>
    public class PartitionSyncRequest : LdapExtendedOperation
    {

        /// <summary> 
        /// Constructs an extended operation object for synchronizing the replicas
        /// of a partition.
        /// 
        /// </summary>
        /// <param name="serverName">    The distinquished name of server containing the
        /// naming context.
        /// 
        /// </param>
        /// <param name="partitionRoot"> The distinguished name of the naming context
        /// to synchronize.
        /// 
        /// </param>
        /// <param name="delay">         The time, in seconds, to delay before the synchronization
        /// should start.
        /// 
        /// </param>
        /// <exception> LdapException A general exception which includes an error message
        /// and an Ldap error code.
        /// </exception>
        public PartitionSyncRequest(System.String serverName, System.String partitionRoot, int delay) : base(ReplicationConstants.NAMING_CONTEXT_SYNC_REQ, null)
        {

            try
            {

                if (((System.Object)serverName == null) || ((System.Object)partitionRoot == null))
                    throw new System.ArgumentException(ExceptionMessages.PARAM_ERROR);

                System.IO.MemoryStream encodedData = new System.IO.MemoryStream();
                LBEREncoder encoder = new LBEREncoder();

                Asn1OctetString asn1_serverName = new Asn1OctetString(serverName);
                Asn1OctetString asn1_partitionRoot = new Asn1OctetString(partitionRoot);
                Asn1Integer asn1_delay = new Asn1Integer(delay);

                asn1_serverName.encode(encoder, encodedData);
                asn1_partitionRoot.encode(encoder, encodedData);
                asn1_delay.encode(encoder, encodedData);

                setValue(SupportClass.ToSByteArray(encodedData.ToArray()));
            }
            catch (System.IO.IOException ioe)
            {
                throw new LdapException(ExceptionMessages.ENCODING_ERROR, LdapException.ENCODING_ERROR, (System.String)null);
            }
        }
    }
}
