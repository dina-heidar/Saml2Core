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

using SamlCore.AspNetCore.Authentication.Saml2;

namespace SAML2Core.Models
{
    /// <summary>
    /// 
    /// </summary>
    public class RequestAuth
    {
        /// <summary>
        /// Gets or sets the comparison.
        /// </summary>
        /// <value>
        /// The comparison.
        /// </value>
        public AuthnContextComparisonType Comparison { get; set; }
        /// <summary>
        /// Gets or sets the authn context class reference types.
        /// </summary>
        /// <value>
        /// The authn context class reference types.
        /// </value>
        public string AuthnContextClassRefType { get; set; }

        internal RequestedAuthnContextType RequestedAuthnContext { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="RequestAuth"/> class.
        /// </summary>
        /// <param name="comparisonType">Type of the comparison.</param>
        /// <param name="authnContextClassRefType">Type of the authn context class reference.</param>
        public RequestAuth(AuthnContextComparisonType comparisonType,
            string authnContextClassRefType)
        {
            RequestedAuthnContext = new RequestedAuthnContextType
            {
                Comparison = comparisonType,
                ComparisonSpecified = true,
                Items = new[] {
                        authnContextClassRefType
                    },
                ItemsElementName = new ItemsChoiceType7[] {
                        ItemsChoiceType7.AuthnContextClassRef
                    }
            };
        }
    }
}
