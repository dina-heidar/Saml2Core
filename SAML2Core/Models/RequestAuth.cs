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
