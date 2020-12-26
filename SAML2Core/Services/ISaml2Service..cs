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
using System.Xml;

namespace SamlCore.AspNetCore.Authentication.Saml2
{
    /// <summary>
    /// 
    /// </summary>
    public interface ISaml2Service
    {
        /// <summary>
        /// Creates the authn request.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="authnRequestId">The authn request identifier.</param>
        /// <param name="relayState">State of the relay.</param>
        /// <param name="assertionConsumerServiceUrl">The assertion consumer service URL.</param>
        /// <returns></returns>
        string CreateAuthnRequest(Saml2Options options, string authnRequestId, string relayState, string assertionConsumerServiceUrl);

        /// <summary>
        /// Determines whether [is logout request] [the specified request].
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns>
        ///   <c>true</c> if [is logout request] [the specified request]; otherwise, <c>false</c>.
        /// </returns>
        bool IsLogoutRequest(HttpRequest request);

        /// <summary>
        /// Gets the saml response token.
        /// </summary>
        /// <param name="base64EncodedSamlResponse">The base64 encoded saml response.</param>
        /// <param name="responseType">Type of the response.</param>
        /// <param name="options">The options.</param>
        /// <returns></returns>
        ResponseType GetSamlResponseToken(string base64EncodedSamlResponse, string responseType, Saml2Options options);
        /// <summary>
        /// Validates the X509 certificate signature.
        /// </summary>
        /// <param name="xmlDoc">The XML document.</param>
        /// <param name="options">The options.</param>
        /// <returns></returns>
        bool ValidateX509CertificateSignature(XmlDocument xmlDoc, Saml2Options options);
        /// <summary>
        /// Checks if replay attack.
        /// </summary>
        /// <param name="inResponseTo">The in response to.</param>
        /// <param name="originalSamlRequestId">The original saml request identifier.</param>
        void CheckIfReplayAttack(string inResponseTo, string originalSamlRequestId);
        /// <summary>
        /// Checks the status.
        /// </summary>
        /// <param name="idpSamlResponseToken">The idp saml response token.</param>
        void CheckStatus(ResponseType idpSamlResponseToken);
        /// <summary>
        /// Gets the assertion.
        /// </summary>
        /// <param name="idpSamlResponseToken">The idp saml response token.</param>
        /// <param name="options">The options.</param>
        /// <returns></returns>
        string GetAssertion(ResponseType idpSamlResponseToken, Saml2Options options);

        /// <summary>
        /// Creates the logout request.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="logoutRequestId">The logout request identifier.</param>
        /// <param name="sessionIndex">Index of the session.</param>
        /// <param name="relayState">State of the relay.</param>
        /// <param name="signOutUrl">The sign out URL.</param>
        /// <returns></returns>
        string CreateLogoutRequest(Saml2Options options, string logoutRequestId, string sessionIndex, string relayState, string signOutUrl);
    }
}