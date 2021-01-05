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
using Microsoft.AspNetCore.Http;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using System.Xml;
using System.Xml.Serialization;
using static SamlCore.AspNetCore.Authentication.Saml2.Saml2Constants;

namespace SamlCore.AspNetCore.Authentication.Saml2
{
    /// <summary>
    /// 
    /// </summary>
    /// <seealso cref="SamlCore.AspNetCore.Authentication.Saml2.ISaml2Service" />
    public class Saml2Service : ISaml2Service
    {
        /// <summary>
        /// Gets the service provider certficate.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <returns></returns>
        private X509Certificate2 GetServiceProviderCertficate(Saml2Options options)
        {
            return options.ServiceProvider.X509Certificate2;
        }

        /// <summary>
        /// Gets the identity provider certficate.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="serialNumber">The serial number.</param>
        /// <returns></returns>
        private X509Certificate2 GetIdentityProviderCertficate(Saml2Options options, string serialNumber)
        {
            X509Certificate2 cert = options.Configuration.X509Certificate2.Where(c => c.SerialNumber == serialNumber).FirstOrDefault();
            if (cert == null)
            {
                throw new Exception("No matching certificate found. Assertion is not from known Idp.");
            }
            return cert;
        }

        /// <summary>
        /// Creates the authn request.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="authnRequestId">The authn request identifier.</param>
        /// <param name="relayState">State of the relay.</param>
        /// <param name="assertionConsumerServiceUrl">The assertion consumer service URL.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentException">Signing key must be an instance of either RSA or DSA.</exception>
        public string CreateAuthnRequest(Saml2Options options, string authnRequestId, string relayState, string assertionConsumerServiceUrl)
        {
            NameIDType entityID = new NameIDType()
            {
                Value = options.ServiceProvider.EntityId
            };

            var singleSignOnService = options.Configuration.SingleSignOnServices.FirstOrDefault(x => x.Binding == options.AssertionConsumerServiceProtocolBinding);
            X509Certificate2 spCertificate = GetServiceProviderCertficate(options);

            AuthnRequest authnRequest = new AuthnRequest()
            {
                ID = authnRequestId,
                Issuer = entityID,
                Version = Saml2Constants.Version,
                ForceAuthn = options.ForceAuthn,
                ForceAuthnSpecified = true,
                IsPassive = options.IsPassive,
                IsPassiveSpecified = true,
                NameIDPolicy = new NameIDPolicyType()
                {
                    Format = options.NameIDType.Format,
                    SPNameQualifier = options.NameIDType.SPNameQualifier,
                    AllowCreate = true,
                    AllowCreateSpecified = true
                },
                Destination = singleSignOnService.Location.ToString(),
                ProtocolBinding = singleSignOnService.Binding.ToString(),
                IssueInstant = DateTime.UtcNow,
                AssertionConsumerServiceURL = assertionConsumerServiceUrl,
            };

            if (options.RequestedAuthn != null)
            {
                authnRequest.RequestedAuthnContext = options.RequestedAuthn.RequestedAuthnContext;
            }

            string singleSignOnUrl = options.Configuration.SingleSignOnServices.FirstOrDefault().Location;

            //serialize AuthnRequest to xml string  
            string xmlTemplate = string.Empty;
            XmlSerializer xmlSerializer = new XmlSerializer(typeof(AuthnRequest));
            using (MemoryStream memStm = new MemoryStream())
            {
                xmlSerializer.Serialize(memStm, authnRequest);
                memStm.Position = 0;
                xmlTemplate = new StreamReader(memStm).ReadToEnd();
            }

            //create xml document from string
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlTemplate);
            xmlDoc.PreserveWhitespace = false;
            string request = xmlDoc.OuterXml;

            var result = new StringBuilder();
            result.AddMessageParameter(request, null);
            result.AddRelayState(request, relayState);
            if (options.ServiceProvider.X509Certificate2 != null)
            {
                AsymmetricAlgorithm spPrivateKey = spCertificate.PrivateKey;
                string hashingAlgorithm = options.Configuration.Signature.SignedInfo.SignatureMethod;
                // Check if the key is of a supported type. [SAMLBind] sect. 3.4.4.1 specifies this.
                if (!(spPrivateKey is RSA || spPrivateKey is DSA || spPrivateKey == null))
                    throw new ArgumentException("Signing key must be an instance of either RSA or DSA.");

                AddSignature(result, spPrivateKey, hashingAlgorithm, options.ServiceProvider.HashAlgorithm);
            }
            return $"{singleSignOnUrl}?{result}";
        }

        /// <summary>
        /// Creates the logout request.
        /// The "LogoutRequest" message MUST be signed if the HTTP POST or Redirect binding is used.
        /// Logout request MUST be signed according to http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf Sect 4.4.3.1
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="logoutRequestId">The logout request identifier.</param>
        /// <param name="sessionIndex">Index of the session.</param>
        /// <param name="relayState">State of the relay.</param>
        /// <param name="forcedSignout">if set to <c>true</c> [forced signout].</param>
        /// <returns></returns>
        /// <exception cref="System.ArgumentException">Signing key must be an instance of either RSA or DSA.</exception>
        /// <exception cref="ArgumentException">Signing key must be an instance of either RSA or DSA.</exception>
        public string CreateLogoutRequest(Saml2Options options,
            string logoutRequestId,
            string sessionIndex,
            string relayState,
            bool forcedSignout = false)
        {
            NameIDType entityID = new NameIDType()
            {
                Value = options.ServiceProvider.EntityId
            };

            var singleLogoutService = options.Configuration.SingleLogoutServices.FirstOrDefault(x => x.Binding == options.SingleLogoutServiceProtocolBinding);

            LogoutRequest logoutRequest = new LogoutRequest()
            {
                ID = logoutRequestId,
                Issuer = entityID,
                Version = Saml2Constants.Version,
                Reason = (forcedSignout == false ? Saml2Constants.Reasons.User : Saml2Constants.Reasons.Admin),
                SessionIndex = new string[] { sessionIndex },
                Destination = singleLogoutService.Location.ToString(),
                IssueInstant = DateTime.UtcNow,
                Item = new NameIDType()
                {
                    Format = options.NameIDType.Format,
                    NameQualifier = options.NameIDType.NameQualifier,
                    SPProvidedID = options.NameIDType.SPProvidedID,
                    SPNameQualifier = options.NameIDType.SPNameQualifier,
                    Value = options.NameIDType.Value
                }
            };

            string singleLogoutUrl = options.Configuration.SingleLogoutServices.FirstOrDefault().Location;

            //serialize AuthnRequest to xml string  
            string xmlTemplate = string.Empty;
            XmlSerializer xmlSerializer = new XmlSerializer(typeof(LogoutRequest));
            using (MemoryStream memStm = new MemoryStream())
            {
                xmlSerializer.Serialize(memStm, logoutRequest);
                memStm.Position = 0;
                xmlTemplate = new StreamReader(memStm).ReadToEnd();
            }

            //create xml document from string
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlTemplate);
            xmlDoc.PreserveWhitespace = false;
            string request = xmlDoc.OuterXml;

            var result = new StringBuilder();
            result.AddMessageParameter(request, null);
            result.AddRelayState(request, relayState);
            if (options.hasCertificate)
            {
                X509Certificate2 spCertificate = GetServiceProviderCertficate(options);
                string hashingAlgorithm = options.Configuration.Signature.SignedInfo.SignatureMethod;
                AsymmetricAlgorithm spPrivateKey = spCertificate.PrivateKey;
                // Check if the key is of a supported type. [SAMLBind] sect. 3.4.4.1 specifies this.
                if (!(spPrivateKey is RSA || spPrivateKey is DSA || spPrivateKey == null))
                    throw new ArgumentException("Signing key must be an instance of either RSA or DSA.");
                AddSignature(result, spPrivateKey, hashingAlgorithm, options.ServiceProvider.HashAlgorithm);
            }
            return $"{singleLogoutUrl}?{result}";
        }

        /// <summary>
        /// Adds the signature.
        /// </summary>
        /// <param name="result">The result.</param>
        /// <param name="signingKey">The signing key.</param>
        /// <param name="hashingAlgorithm">The hashing algorithm.</param>
        /// <param name="hashAlgorithmName">Name of the hash algorithm.</param>
        private void AddSignature(StringBuilder result, AsymmetricAlgorithm signingKey, string hashingAlgorithm, HashAlgorithmName hashAlgorithmName)
        {
            if (signingKey == null)
                return;
            result.Append(string.Format("&{0}=", Parameters.SigAlg));

            var urlEncoded = hashingAlgorithm.UrlEncode();
            result.Append(urlEncoded.UpperCaseUrlEncode());

            // Calculate the signature of the URL as described in [SAMLBind] section 3.4.4.1.            
            var signature = SignData(signingKey, Encoding.UTF8.GetBytes(result.ToString()), hashAlgorithmName);

            result.AppendFormat("&{0}=", Parameters.Signature);
            result.Append(HttpUtility.UrlEncode(Convert.ToBase64String(signature)));
        }

        /// <summary>
        /// Signs the data.
        /// </summary>
        /// <param name="spPrivateKey">The sp private key.</param>
        /// <param name="data">The data.</param>
        /// <param name="hashAlgorithmName">Name of the hash algorithm.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentException">Signing key must be an instance of either RSA or DSA.</exception>
        private byte[] SignData(AsymmetricAlgorithm spPrivateKey, byte[] data, HashAlgorithmName hashAlgorithmName)
        {
            if (spPrivateKey is RSA)
            {
                var rsa = (RSA)spPrivateKey;
                return rsa.SignData(data, hashAlgorithmName, RSASignaturePadding.Pkcs1);
            }
            else if (spPrivateKey is DSA)
            {
                var dsa = (DSA)spPrivateKey;
                return dsa.CreateSignature(data);
            }
            throw new ArgumentException("Signing key must be an instance of either RSA or DSA.");
        }

        /// <summary>
        /// Determines whether [is logout request] [the specified request].
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns>
        ///   <c>true</c> if [is logout request] [the specified request]; otherwise, <c>false</c>.
        /// </returns>
        public bool IsLogoutRequest(HttpRequest request)
        {
            if (request == null)
                return false;

            if (request.Method == HttpMethods.Get)
                return request.Query.ContainsKey(Saml2Constants.Parameters.SamlRequest);

            if (request.Method != HttpMethods.Post)
                return false;

            var form = request.Form;
            return form != null && form.ContainsKey(Saml2Constants.Parameters.SamlRequest);
        }

        /// <summary>
        /// Gets the saml response token.
        /// </summary>
        /// <param name="base64EncodedSamlResponse">The base64 encoded saml response.</param>
        /// <param name="responseType">Type of the response.</param>
        /// <param name="options"></param>
        /// <returns></returns>
        /// <exception cref="Exception">Response signature is not valid</exception>
        /// <exception cref="ArgumentException">Cannot verify signature.</exception>
        public ResponseType GetSamlResponseToken(string base64EncodedSamlResponse, string responseType, Saml2Options options)
        {
            var doc = new XmlDocument
            {
                XmlResolver = null,
                PreserveWhitespace = true
            };

            if (base64EncodedSamlResponse.Contains("%"))
            {
                base64EncodedSamlResponse = HttpUtility.UrlDecode(base64EncodedSamlResponse);
            }

            byte[] bytes = Convert.FromBase64String(base64EncodedSamlResponse);
            string samlResponse = Encoding.UTF8.GetString(bytes);
            doc.LoadXml(samlResponse);

            if (options.RequireMessageSigned)
            {
                if (!ValidateX509CertificateSignature(doc, options))
                {
                    throw new Exception("Response signature is not valid");
                }
            }

            ResponseType samlResponseToken;
            XmlSerializer xmlSerializers = new XmlSerializer(typeof(ResponseType), new XmlRootAttribute { ElementName = responseType, Namespace = Saml2Constants.Namespaces.Protocol, IsNullable = false });
            using (XmlReader reader = new XmlNodeReader(doc))
            {
                samlResponseToken = (ResponseType)xmlSerializers.Deserialize(reader);
            }
            return samlResponseToken;
        }

        /// <summary>
        /// Validates the X509 certificate signature.
        /// </summary>
        /// <param name="xmlDoc">The XML document.</param>
        /// <param name="options">The options.</param>
        /// <returns></returns>
        public bool ValidateX509CertificateSignature(XmlDocument xmlDoc, Saml2Options options)
        {
            XmlNodeList XMLSignatures = xmlDoc.GetElementsByTagName(Saml2Constants.Parameters.Signature, Saml2Constants.Namespaces.DsNamespace);

            // Checking If the Response or the Assertion has been signed once and only once.
            if (XMLSignatures.Count != 1) return false;

            var signedXmlDoc = new SignedXml(xmlDoc);
            signedXmlDoc.LoadXml((XmlElement)XMLSignatures[0]);

            //IDP might have multiple siing certs. Get the correct one and check it
            KeyInfoX509Data x509data = signedXmlDoc.Signature.KeyInfo.OfType<KeyInfoX509Data>().First();
            X509Certificate2 cert = (X509Certificate2)x509data.Certificates[0];
            string serialNumber = cert.SerialNumber;
            return signedXmlDoc.CheckSignature(GetIdentityProviderCertficate(options, serialNumber), options.VerifySignatureOnly);
        }

        /// <summary>
        /// Checks if replay attack.
        /// </summary>
        /// <param name="inResponseTo">The in response to.</param>
        /// <param name="base64OriginalSamlRequestId">The base64 original saml request identifier.</param>
        /// <exception cref="System.Exception">Empty protocol message id is not allowed.
        /// or
        /// Replay attack.</exception>
        /// <exception cref="Exception">Empty protocol message id is not allowed.
        /// or
        /// Replay attack.</exception>
        public void CheckIfReplayAttack(string inResponseTo, string base64OriginalSamlRequestId)
        {
            string originalSamlRequestId = base64OriginalSamlRequestId.Base64Decode();

            if (string.IsNullOrEmpty(originalSamlRequestId) || string.IsNullOrEmpty(inResponseTo))
            {
                throw new Exception("Empty protocol message id is not allowed.");
            }

            if (!inResponseTo.Equals(originalSamlRequestId, StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception("Replay attack.");
            }
        }

        /// <summary>
        /// Checks the status.
        /// </summary>
        /// <param name="idpSamlResponseToken">The idp saml response token.</param>
        /// <exception cref="Exception"></exception>
        public void CheckStatus(ResponseType idpSamlResponseToken)
        {
            var status = idpSamlResponseToken.Status.StatusCode;
            if (status.Value != Saml2Constants.StatusCodes.Success)
            {
                //TODO write exception values as switch
                throw new Exception(status.Value);
            }
        }

        /// <summary>
        /// Gets the assertion.
        /// </summary>
        /// <param name="idpSamlResponseToken">The idp saml response token.</param>
        /// <param name="options">The options.</param>
        /// <returns></returns>
        /// <exception cref="Exception">Missing assertion
        /// or
        /// Unable to parse the decrypted assertion.</exception>
        /// <exception cref="System.Exception">Missing assertion
        /// or
        /// Unable to parse the decrypted assertion.</exception>
        public string GetAssertion(ResponseType idpSamlResponseToken, Saml2Options options)
        {
            string token;
            string xmlTemplate;
            var assertion = idpSamlResponseToken.Items[0];
            if (assertion == null)
            {
                throw new Exception("Missing assertion");
            }

            //check if its a decrypted assertion
            if (assertion.GetType() == typeof(EncryptedElementType))
            {
                EncryptedElementType encryptedElement = (EncryptedElementType)assertion;
                SymmetricAlgorithm sessionKey;

                if (encryptedElement.EncryptedData.EncryptionMethod != null)
                {
                    sessionKey = ExtractSessionKey(encryptedElement, options.ServiceProvider.X509Certificate2.PrivateKey);

                    var encryptedXml = new EncryptedXml();
                    XmlSerializer xmlSerializer = new XmlSerializer(typeof(EncryptedDataType));
                    using (MemoryStream memStm = new MemoryStream())
                    {
                        xmlSerializer.Serialize(memStm, encryptedElement.EncryptedData);
                        memStm.Position = 0;
                        xmlTemplate = new StreamReader(memStm).ReadToEnd();
                    }

                    var doc = new XmlDocument();
                    doc.PreserveWhitespace = true;
                    doc.LoadXml(xmlTemplate);
                    var t = doc.GetElementsByTagName("EncryptedData");
                    var encryptedData = new EncryptedData();
                    encryptedData.LoadXml((XmlElement)t[0]);

                    byte[] plaintext = encryptedXml.DecryptData(encryptedData, sessionKey);
                    token = Encoding.UTF8.GetString(plaintext);
                    return token;
                }
            }
            else
            {
                XmlSerializer xmlSerializer = new XmlSerializer(typeof(AssertionType));
                using (MemoryStream memStm = new MemoryStream())
                {
                    xmlSerializer.Serialize(memStm, assertion);
                    memStm.Position = 0;
                    xmlTemplate = new StreamReader(memStm).ReadToEnd();
                }

                var doc = new XmlDocument();
                doc.PreserveWhitespace = false;
                doc.LoadXml(xmlTemplate);

                string request = doc.OuterXml;
                return request;
            }
            throw new Exception("Unable to parse the decrypted assertion.");
        }

        /// <summary>
        /// Extracts the session key.
        /// </summary>
        /// <param name="encryptedElement">The encrypted element.</param>
        /// <param name="privateKey">The private key.</param>
        /// <returns></returns>
        /// <exception cref="Exception">Unable to locate assertion decryption key.</exception>
        private SymmetricAlgorithm ExtractSessionKey(EncryptedElementType encryptedElement, AsymmetricAlgorithm privateKey)
        {
            if (encryptedElement.EncryptedData != null)
            {
                if (encryptedElement.EncryptedData.KeyInfo.Items[0] != null)
                {
                    XmlElement encryptedKeyElement = (XmlElement)encryptedElement.EncryptedData.KeyInfo.Items[0];
                    var encryptedKey = new EncryptedKey();
                    encryptedKey.LoadXml(encryptedKeyElement);
                    return ToSymmetricKey(encryptedKey, encryptedElement.EncryptedData.EncryptionMethod.Algorithm, privateKey);
                }
            }
            throw new NotImplementedException("Unable to locate assertion decryption key.");
        }

        /// <summary>
        /// To the symmetric key.
        /// </summary>
        /// <param name="encryptedKey">The encrypted key.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="privateKey">The private key.</param>
        /// <returns></returns>
        /// <exception cref="System.NotImplementedException">Unable to decode CipherData of type \"CipherReference\".</exception>
        /// <exception cref="NotImplementedException">Unable to decode CipherData of type \"CipherReference\".</exception>
        private SymmetricAlgorithm ToSymmetricKey(EncryptedKey encryptedKey, string hashAlgorithm, AsymmetricAlgorithm privateKey)
        {

            bool useOaep = encryptedKey.EncryptionMethod.KeyAlgorithm == EncryptedXml.XmlEncRSAOAEPUrl;

            if (encryptedKey.CipherData != null)
            {
                byte[] cipherValue = encryptedKey.CipherData.CipherValue;
                var key = GetKeyInstance(hashAlgorithm);
                key.Key = EncryptedXml.DecryptKey(cipherValue, (RSA)privateKey, useOaep);
                return key;
            }

            throw new NotImplementedException("Unable to decode CipherData of type \"CipherReference\".");
        }

        /// <summary>
        /// Gets the key instance.
        /// </summary>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <returns></returns>
        private static SymmetricAlgorithm GetKeyInstance(string hashAlgorithm)
        {
            Rijndael key = Rijndael.Create(hashAlgorithm);
            return key;
        }
    }
}