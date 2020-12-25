//MIT License

//Copyright (c) 2018 Dina Heidar

//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

namespace SamlCore.AspNetCore.Authentication.Saml2
{
    /// <summary>
    /// 
    /// </summary>
    public static class Saml2Constants
    {
#pragma warning disable 1591
        /// <summary>
        /// 
        /// </summary>
        /// 
        public const string Version = "2.0";
        public static class Namespaces
        {
            /// <summary>
            /// The metadata namespace
            /// </summary>
            public const string MetadataNamespace = "urn:oasis:names:tc:SAML:2.0:metadata";
            /// <summary>
            /// The protocol
            /// </summary>
            public const string Protocol = "urn:oasis:names:tc:SAML:2.0:protocol";
            /// <summary>
            /// The address namespace
            /// </summary>
            public const string AddressNamespace = "http://www.w3.org/2005/08/addressing";
            /// <summary>
            /// The fed namespace
            /// </summary>
            public const string FedNamespace = "http://docs.oasis-open.org/wsfed/federation/200706";
            /// <summary>
            /// The ds namespace
            /// </summary>
            public const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";
        }
        public static class Reasons
        {
            /// <summary>
            ///     Specifies that the message is being sent because the principal wishes to terminate the indicated session.
            /// </summary>
            public const string User = "urn:oasis:names:tc:SAML:2.0:logout:user";

            /// <summary>
            ///     Specifies that the message is being sent because an administrator wishes to terminate the indicated
            ///     session for that principal.
            /// </summary>
            public const string Admin = "urn:oasis:names:tc:SAML:2.0:logout:admin";
        }

        public static class ResponseTypes
        {
            /// <summary>
            /// The authn response
            /// </summary>
            public const string AuthnResponse = "Response";
            /// <summary>
            /// The logout response
            /// </summary>
            public const string LogoutResponse = "LogoutResponse";
        }

        /// <summary>
        /// 
        /// </summary>
        public static class ProtocolBindings
        {
            /// <summary>
            /// The HTTP redirect
            /// </summary>
            public const string HTTP_Redirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
            /// <summary>
            /// The HTTP post
            /// </summary>
            public const string HTTP_Post = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
            /// <summary>
            /// The HTTP artifact
            /// </summary>
            public const string HTTP_Artifact = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
        }

        /// <summary>
        /// 
        /// </summary>
        public static class Saml2FaultCodes
        {
            /// <summary>
            /// The already signed in
            /// </summary>
            public const string AlreadySignedIn = "AlreadySignedIn";
            /// <summary>
            /// The bad request
            /// </summary>
            public const string BadRequest = "BadRequest";
            /// <summary>
            /// The issuer name not supported
            /// </summary>
            public const string IssuerNameNotSupported = "IssuerNameNotSupported";
            /// <summary>
            /// The need fresher credentials
            /// </summary>
            public const string NeedFresherCredentials = "NeedFresherCredentials";
            /// <summary>
            /// The no match in scope
            /// </summary>
            public const string NoMatchInScope = "NoMatchInScope";
            /// <summary>
            /// The no pseudonym in scope
            /// </summary>
            public const string NoPseudonymInScope = "NoPseudonymInScope";
            /// <summary>
            /// The not signed in
            /// </summary>
            public const string NotSignedIn = "NotSignedIn";
            /// <summary>
            /// The RST parameter not accepted
            /// </summary>
            public const string RstParameterNotAccepted = "RstParameterNotAccepted";
            /// <summary>
            /// The specific policy
            /// </summary>
            public const string SpecificPolicy = "SpecificPolicy";
            /// <summary>
            /// The unsupported claims dialect
            /// </summary>
            public const string UnsupportedClaimsDialect = "UnsupportedClaimsDialect";
            /// <summary>
            /// The unsupported encoding
            /// </summary>
            public const string UnsupportedEncoding = "UnsupportedEncoding";
        }

        /// <summary>
        /// 
        /// </summary>
        public static class Parameters
        {
            /// <summary>
            /// The saml request
            /// </summary>
            public const string SamlRequest = "SAMLRequest";
            /// <summary>
            /// The relay state
            /// </summary>
            public const string RelayState = "RelayState";
            /// <summary>
            /// The sig alg
            /// </summary>
            public const string SigAlg = "SigAlg";
            /// <summary>
            /// The signature
            /// </summary>
            public const string Signature = "Signature";
            /// <summary>
            /// The saml response
            /// </summary>
            public const string SamlResponse = "SAMLResponse";
        }

        /// <summary>
        /// 
        /// </summary>
        public static class Attributes
        {
            /// <summary>
            /// The entity identifier
            /// </summary>
            public const string EntityId = "entityID";
            /// <summary>
            /// The algorithm
            /// </summary>
            public const string Algorithm = "Algorithm";
            /// <summary>
            /// The location
            /// </summary>
            public const string Location = "Location";
            /// <summary>
            /// The binding
            /// </summary>
            public const string Binding = "Binding";
            /// <summary>
            /// The identifier
            /// </summary>
            public const string Id = "ID";
            /// <summary>
            /// The protocol support enumeration
            /// </summary>
            public const string ProtocolSupportEnumeration = "protocolSupportEnumeration";
            /// <summary>
            /// The type
            /// </summary>
            public const string Type = "type";
            /// <summary>
            /// The use
            /// </summary>
            public const string Use = "use";
        }

        /// <summary>
        /// 
        /// </summary>
        /// https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf section 3.2.2.2
        public static class StatusCodes
        {
            /// <summary>
            /// The success
            /// </summary>
            public const string Success = "urn:oasis:names:tc:SAML:2.0:status:Success";
            /// <summary>
            /// The requester
            /// </summary>
            public const string Requester = "urn:oasis:names:tc:SAML:2.0:status:Requester";
            /// <summary>
            /// The responder
            /// </summary>
            public const string Responder = "urn:oasis:names:tc:SAML:2.0:status:Responder";
            /// <summary>
            /// The version mismatch
            /// </summary>
            public const string VersionMismatch = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";
            /// <summary>
            /// The authn failed
            /// </summary>
            public const string AuthnFailed = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
            /// <summary>
            /// The invalid attribute name or value
            /// </summary>
            public const string InvalidAttrNameOrValue = "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue";
            /// <summary>
            /// The invalid name identifier policy
            /// </summary>
            public const string InvalidNameIdPolicy = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy";
            /// <summary>
            /// The no authn context
            /// </summary>
            public const string NoAuthnContext = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext";
            /// <summary>
            /// The no available idp
            /// </summary>
            public const string NoAvailableIDP = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP";
            /// <summary>
            /// The no passive
            /// </summary>
            public const string NoPassive = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";
            /// <summary>
            /// The no supported idp
            /// </summary>
            public const string NoSupportedIDP = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP";
            /// <summary>
            /// The partial logout
            /// </summary>
            public const string PartialLogout = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";
            /// <summary>
            /// The proxy count exceeded
            /// </summary>
            public const string ProxyCountExceeded = "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded";
            /// <summary>
            /// The request denied
            /// </summary>
            public const string RequestDenied = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied";
            /// <summary>
            /// The request unsupported
            /// </summary>
            public const string RequestUnsupported = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported";
            /// <summary>
            /// The request version deprecated
            /// </summary>
            public const string RequestVersionDeprecated = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated";
            /// <summary>
            /// The request version too high
            /// </summary>
            public const string RequestVersionTooHigh = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh";
            /// <summary>
            /// The request version too low
            /// </summary>
            public const string RequestVersionTooLow = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow";
            /// <summary>
            /// The resource not recognized
            /// </summary>
            public const string ResourceNotRecognized = "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized";
            /// <summary>
            /// The too many responses
            /// </summary>
            public const string TooManyResponses = "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses";
            /// <summary>
            /// The unknown attribute profile
            /// </summary>
            public const string UnknownAttrProfile = "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile";
            /// <summary>
            /// The unknown principal
            /// </summary>
            public const string UnknownPrincipal = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal";
            /// <summary>
            /// The unsupported binding
            /// </summary>
            public const string UnsupportedBinding = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding";
        }

        /// <summary>
        /// 
        /// </summary>
        public static class AuthnContextClassRefTypes
        {
            /// <summary>
            /// The user name and password
            /// </summary>
            public const string UserNameAndPassword = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";
            /// <summary>
            /// The password protected transport
            /// </summary>
            public const string PasswordProtectedTransport = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
            /// <summary>
            /// The transport layer security client
            /// </summary>
            public const string TransportLayerSecurityClient = "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient";
            /// <summary>
            /// The X509 certificate
            /// </summary>
            public const string X509Certificate = "urn:oasis:names:tc:SAML:2.0:ac:classes:X509";
            /// <summary>
            /// The integrated windows authentication
            /// </summary>
            public const string IntegratedWindowsAuthentication = "urn:federation:authentication:windows";
            /// <summary>
            /// The kerberose
            /// </summary>
            public const string Kerberose = "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos";
        }

        /// <summary>
        /// 
        /// </summary>
        public static class Elements
        {
            /// <summary>
            /// The entity descriptor
            /// </summary>
            public const string EntityDescriptor = "EntityDescriptor";
            /// <summary>
            /// The idpsso descriptor
            /// </summary>
            public const string IdpssoDescriptor = "IDPSSODescriptor";
            /// <summary>
            /// The key descriptor
            /// </summary>
            public const string KeyDescriptor = "KeyDescriptor";
            /// <summary>
            /// The role descriptor
            /// </summary>
            public const string RoleDescriptor = "RoleDescriptor";
            /// <summary>
            /// The passive requestor endpoint
            /// </summary>
            public const string PassiveRequestorEndpoint = "PassiveRequestorEndpoint";
            /// <summary>
            /// The spsso descriptor
            /// </summary>
            public const string SpssoDescriptor = "SPSSODescriptor";
            /// <summary>
            /// The single logout service
            /// </summary>
            public const string SingleLogoutService = "SingleLogoutService";
            /// <summary>
            /// The single sign on service
            /// </summary>
            public const string SingleSignOnService = "SingleSignOnService";
            /// <summary>
            /// The name identifier format
            /// </summary>
            public const string NameIDFormat = "NameIDFormat";
            /// <summary>
            /// The assertion consumer service
            /// </summary>
            public const string AssertionConsumerService = "AssertionConsumerService";
            /// <summary>
            /// The signature method
            /// </summary>
            public const string SignatureMethod = "SignatureMethod";
            /// <summary>
            /// The digest method
            /// </summary>
            public const string DigestMethod = "DigestMethod";
            /// <summary>
            /// The status
            /// </summary>
            public const string Status = "Status";
            /// <summary>
            /// The address
            /// </summary>
            public const string Address = "Address";
            /// <summary>
            /// The endpoint reference
            /// </summary>
            public const string EndpointReference = "EndpointReference";
            /// <summary>
            /// The X509 certificate
            /// </summary>
            public const string X509Certificate = "X509Certificate";
        }

        /// <summary>
        /// 
        /// </summary>
        public static class NameIDFormats
        {
            /// <summary>
            /// The email
            /// </summary>
            public const string Email = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
            /// <summary>
            /// The persistent
            /// </summary>
            public const string Persistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
            /// <summary>
            /// The transient
            /// </summary>
            public const string Transient = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
            /// <summary>
            /// The unspecified
            /// </summary>
            public const string Unspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
            /// <summary>
            /// The encrypted
            /// </summary>
            public const string Encrypted = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted";
            /// <summary>
            /// The entity identifier
            /// </summary>
            public const string EntityIdentifier = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
            /// <summary>
            /// The kerberos principal name
            /// </summary>
            public const string KerberosPrincipalName = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos";
            /// <summary>
            /// The subject name
            /// </summary>
            public const string SubjectName = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
            /// <summary>
            /// The windows domain qualified name
            /// </summary>
            public const string WindowsDomainQualifiedName = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName";
        }


        /// <summary>
        /// 
        /// </summary>
        public static class Types
        {
            /// <summary>
            /// The application service type
            /// </summary>
            public const string ApplicationServiceType = "ApplicationServiceType";
            /// <summary>
            /// The security token service type
            /// </summary>
            public const string SecurityTokenServiceType = "SecurityTokenServiceType";
        }

        /// <summary>
        /// 
        /// </summary>
        public static class KeyUse
        {
            /// <summary>
            /// The signing
            /// </summary>
            public const string Signing = "signing";
        }

        /// <summary>
        /// xmlns string.
        /// </summary>
        internal static string Xmlns = "xmlns";

        /// <summary>
        /// Prefix names.
        /// </summary>
        internal static class Prefixes
        {
            /// <summary>
            /// The fed
            /// </summary>
            public const string Fed = "fed";
            /// <summary>
            /// The ds
            /// </summary>
            public const string Ds = "ds";
            /// <summary>
            /// The xsi
            /// </summary>
            public const string Xsi = "xsi";
            /// <summary>
            /// The wsa
            /// </summary>
            public const string Wsa = "wsa";
            /// <summary>
            /// The md
            /// </summary>
            public const string Md = "md";
        }
#pragma warning restore 1591
    }
}