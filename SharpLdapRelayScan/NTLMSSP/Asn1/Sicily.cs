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
// Novell.Directory.Ldap.Rfc2251.RfcSaslCredentials.cs
//
// Author:
//   Alessandro Magnosi (klez.virus@gmail.com)
//

using Novell.Directory.Ldap.Asn1;

namespace Novell.Directory.Ldap
{

    /// <summary> Represents a Windows Ldap Sicily Pakage Discovery.
    /// 
    /// <pre>
    /// SicilyPackageDiscovery ::= OCTET STRING
    /// </pre>
    /// </summary>
    public class SicilyPackageDiscovery : Asn1Tagged
    {
        /// <summary> ASN.1 SicilyPackageDiscovery tag definition.</summary>
        public const int TAG = 0x09;

        /// <summary> ID is added for Optimization.
        /// Id needs only be one Value for every instance,
        /// thus we create it only once.
        /// </summary>
        protected internal static readonly Asn1Identifier ID = new Asn1Identifier(Asn1Identifier.CONTEXT, false, TAG);

        //*************************************************************************
        // Constructors for SicilyPackageDiscovery
        //*************************************************************************

        /// <summary> </summary>
        public SicilyPackageDiscovery() : base(ID, new Asn1OctetString(new sbyte[] { }), false)
        {
        }
    }
    /// <summary> Represents a Windows Ldap Sicily Negotiate.
    /// 
    /// <pre>
    /// SicilyPackageDiscovery ::= OCTET STRING
    /// </pre>
    /// </summary>
    public class SicilyNegotiate : Asn1Tagged
    {
        /// <summary> ASN.1 SicilyNegotiate implicit tag definition.</summary>
        public const int TAG = 0x0A;

        /// <summary> ID is added for Optimization.
        /// Id needs only be one Value for every instance,
        /// thus we create it only once.
        /// </summary>
        protected internal static readonly Asn1Identifier ID = new Asn1Identifier(Asn1Identifier.CONTEXT, false, TAG);

        //*************************************************************************
        // Constructors for SicilyNegotiate
        //*************************************************************************

        /// <summary> </summary>
        public SicilyNegotiate(sbyte[] content) : base(ID, new Asn1OctetString(content), false)
        {
        }
    }
    /// <summary> Represents a Windows Ldap Sicily Response.
    /// 
    /// <pre>
    /// SicilyPackageDiscovery ::= OCTET STRING
    /// </pre>
    /// </summary>
    public class SicilyResponse : Asn1Tagged
    {
        /// <summary> ASN.1 SicilyResponse implicit tag definition.</summary>
        public const int TAG = 0x0B;

        /// <summary> ID is added for Optimization.
        /// Id needs only be one Value for every instance,
        /// thus we create it only once.
        /// </summary>
        protected internal static readonly Asn1Identifier ID = new Asn1Identifier(Asn1Identifier.CONTEXT, false, TAG);

        //*************************************************************************
        // Constructors for SicilyResponse
        //*************************************************************************

        /// <summary> </summary>
        public SicilyResponse(sbyte[] content) : base(ID, new Asn1OctetString(content), false)
        {
        }
    }

}
