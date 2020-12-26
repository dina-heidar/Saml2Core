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
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using SamlCore.AspNetCore.Authentication.Saml2;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// 
    /// </summary>
    public static class Saml2Extensions
    {
        /// <summary>
        /// Adds the saml core.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddSamlCore(this AuthenticationBuilder builder)
          => builder.AddSamlCore(Saml2Defaults.AuthenticationScheme, _ => { });

        /// <summary>
        /// Adds the saml core.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="configureOptions">The configure options.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddSamlCore(this AuthenticationBuilder builder, Action<Saml2Options> configureOptions)
        => builder.AddSamlCore(Saml2Defaults.AuthenticationScheme, configureOptions);

        /// <summary>
        /// Adds the saml core.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="configureOptions">The configure options.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddSamlCore(this AuthenticationBuilder builder, string authenticationScheme, Action<Saml2Options> configureOptions)
         => builder.AddSamlCore(authenticationScheme, Saml2Defaults.DisplayName, configureOptions);

        /// <summary>
        /// Adds the saml core.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="displayName">The display name.</param>
        /// <param name="configureOptions">The configure options.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddSamlCore(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<Saml2Options> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<Saml2Options>, Saml2PostConfigureOptions>());
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ISaml2Service, Saml2Service>());
            builder.Services.TryAddEnumerable(ServiceDescriptor.Transient<IDocumentRetriever, FileDocumentRetriever>());
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IHttpContextAccessor, HttpContextAccessor>());

            return builder.AddRemoteScheme<Saml2Options, Saml2Handler>(authenticationScheme, displayName, configureOptions);
        }
    }
}