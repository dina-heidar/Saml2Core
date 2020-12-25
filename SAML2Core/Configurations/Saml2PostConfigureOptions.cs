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
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using SamlCore.AspNetCore.Authentication.Saml2.Metadata;
using System;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Xml;
using System.Xml.Serialization;

namespace SamlCore.AspNetCore.Authentication.Saml2
{
    /// <summary>
    /// Used to setup defaults for all <see cref="Saml2Options" />.
    /// </summary>  
    public class Saml2PostConfigureOptions : IPostConfigureOptions<Saml2Options>
    {
        /// <summary>
        /// The idoc
        /// </summary>
        private readonly IDocumentRetriever _idoc;
        /// <summary>
        /// The dp
        /// </summary>
        private readonly IDataProtectionProvider _dp;
        /// <summary>
        /// The HTTP context accessor
        /// </summary>
        private readonly IHttpContextAccessor _httpContextAccessor;

        /// <summary>
        /// Gets the safe settings.
        /// </summary>
        /// <value>
        /// The safe settings.
        /// </value>
        public static XmlReaderSettings SafeSettings { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml2PostConfigureOptions" /> class.
        /// </summary>
        /// <param name="dataProtection">The data protection.</param>
        /// <param name="idoc">The idoc.</param>
        /// <param name="httpContextAccessor">The HTTP context accessor.</param>
        public Saml2PostConfigureOptions(IDataProtectionProvider dataProtection, IDocumentRetriever idoc, IHttpContextAccessor httpContextAccessor)
        {
            _dp = dataProtection;
            _idoc = idoc;
            _httpContextAccessor = httpContextAccessor;
        }

        /// <summary>
        /// Invoked to post configure a TOptions instance.
        /// </summary>
        /// <param name="name">The name of the options instance being configured.</param>
        /// <param name="options">The options instance to configure.</param>
        /// <exception cref="InvalidOperationException">
        /// Service Provider certificate could not be found.
        /// or
        /// Multiple Service Provider certificates were found, must only provide one.
        /// or
        /// The certificate for this service providerhas no private key.
        /// or
        /// The MetadataAddress must use HTTPS unless disabled for development by setting RequireHttpsMetadata=false.
        /// </exception>
        public void PostConfigure(string name, Saml2Options options)
        {
            options.DataProtectionProvider = options.DataProtectionProvider ?? _dp;

            if (string.IsNullOrEmpty(options.SignOutScheme))
            {
                options.SignOutScheme = options.SignInScheme;
            }

            if (options.StateDataFormat == null)
            {
                var dataProtector = options.DataProtectionProvider.CreateProtector(
                    typeof(Saml2Handler).FullName, name, "v1");
                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }
            var request = _httpContextAccessor.HttpContext.Request;
            if (options.ServiceProvider.AssertionConsumerServices != null)
            {
                foreach (var assertionConsumerService in options.ServiceProvider.AssertionConsumerServices)
                {
                    if (string.IsNullOrEmpty(assertionConsumerService.Location))
                    {
                        assertionConsumerService.Location = request.Scheme + "://" + request.Host.Value + options.CallbackPath;
                    }
                    else
                    {
                        Uri uriAppUrlResult;
                        bool appProductionURLresult = Uri.TryCreate(assertionConsumerService.Location, UriKind.Absolute, out uriAppUrlResult)
                            && (uriAppUrlResult.Scheme == Uri.UriSchemeHttp || uriAppUrlResult.Scheme == Uri.UriSchemeHttps);
                        if (!appProductionURLresult)
                        {
                            throw new InvalidOperationException("AssertionConsumerService is not a valid URL.");
                        }
                    }
                }
            }

            if (options.ServiceProvider.SingleLogoutServices != null)
            {
                foreach (var singleLogoutService in options.ServiceProvider.SingleLogoutServices)
                {
                    if (string.IsNullOrEmpty(singleLogoutService.Location))
                    {
                        singleLogoutService.Location = request.Scheme + "://" + request.Host.Value + options.SignOutPath;
                    }
                    else
                    {
                        Uri uriAppUrlResult;
                        bool appProductionURLresult = Uri.TryCreate(singleLogoutService.Location, UriKind.Absolute, out uriAppUrlResult)
                            && (uriAppUrlResult.Scheme == Uri.UriSchemeHttp || uriAppUrlResult.Scheme == Uri.UriSchemeHttps);
                        if (!appProductionURLresult)
                        {
                            throw new InvalidOperationException("SingleLogoutService is not a valid URL.");
                        }
                    }
                }
            }
            if (options.ServiceProvider.X509Certificate2 != null)
            {
                options.hasCertificate = true;
            }

            if (options.Backchannel == null)
            {
                options.Backchannel = new HttpClient(options.BackchannelHttpHandler ?? new HttpClientHandler());
                options.Backchannel.DefaultRequestHeaders.UserAgent.ParseAdd("ASP.NET SamlCore handler");
                options.Backchannel.Timeout = options.BackchannelTimeout;
                options.Backchannel.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
            }

            if (string.IsNullOrEmpty(options.TokenValidationParameters.ValidAudience))
            {
                options.TokenValidationParameters.ValidAudience = options.ServiceProvider.EntityId;
            }

            if (options.ConfigurationManager == null)
            {
                if (options.Configuration != null)
                {
                    options.ConfigurationManager = new StaticConfigurationManager<Saml2Configuration>(options.Configuration);
                }
                else if (!string.IsNullOrEmpty(options.MetadataAddress))
                {
                    Uri uriResult;
                    bool result = Uri.TryCreate(options.MetadataAddress, UriKind.Absolute, out uriResult)
                        && (uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps);

                    if (result)
                    {
                        if (options.RequireHttpsMetadata && !options.MetadataAddress.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                        {
                            throw new InvalidOperationException("The MetadataAddress must use HTTPS unless disabled for development by setting RequireHttpsMetadata=false.");
                        }
                        options.ConfigurationManager = new ConfigurationManager<Saml2Configuration>(options.MetadataAddress, new Saml2ConfigurationRetriever(),
                           new HttpDocumentRetriever(options.Backchannel) { RequireHttps = options.RequireHttpsMetadata });
                    }
                    else
                    {
                        _idoc.GetDocumentAsync(options.MetadataAddress, default(CancellationToken));
                        options.ConfigurationManager = new ConfigurationManager<Saml2Configuration>(options.MetadataAddress, new Saml2ConfigurationRetriever(), _idoc);
                    }
                }
            }
            if (options.CreateMetadataFile)
            {
                //delete the metadata.xml if exists
                string[] xmlList = Directory.GetFiles(options.DefaultMetadataFolderLocation, "*.xml");
                foreach (string f in xmlList)
                {
                    if (f == options.DefaultMetadataFolderLocation + "\\" + options.DefaultMetadataFileName + ".xml")
                    {
                        File.Delete(f);
                    }
                }

                //overwrite or create metadata.xml if set to true
                IndexedEndpointType[] AssertionConsumerService = options.ServiceProvider.AssertionConsumerServices;
                EndpointType[] SingleLogoutServices = options.ServiceProvider.SingleLogoutServices;

                Metadata.KeyDescriptorType[] KeyDescriptor = null;
                if (options.hasCertificate)
                {
                    KeyDescriptor = new Metadata.KeyDescriptorType[]
                             {
                                new Metadata.KeyDescriptorType()
                                {
                                    useSpecified= true,
                                    use = KeyTypes.signing,
                                    KeyInfo = new Metadata.KeyInfoType()
                                    {
                                        ItemsElementName = new []{ Metadata.ItemsChoiceType2.X509Data},
                                        Items = new Metadata.X509DataType[]
                                        {
                                            new Metadata.X509DataType()
                                            {
                                                Items = new object[]{options.ServiceProvider.X509Certificate2.GetRawCertData() },
                                                ItemsElementName = new [] { Metadata.ItemsChoiceType.X509Certificate }
                                            }
                                        }
                                    }
                                 },
                                new Metadata.KeyDescriptorType()
                                {
                                    useSpecified= true,
                                    use = KeyTypes.encryption,
                                    KeyInfo = new Metadata.KeyInfoType()
                                    {
                                        ItemsElementName = new []{ Metadata.ItemsChoiceType2.X509Data},
                                        Items = new Metadata.X509DataType[]
                                        {
                                            new Metadata.X509DataType()
                                            {
                                                Items = new object[]{ options.ServiceProvider.X509Certificate2.GetRawCertData() },
                                                ItemsElementName = new [] { Metadata.ItemsChoiceType.X509Certificate }
                                            }
                                        }
                                    }
                                 }
                             };
                }
                var entityDescriptor = new EntityDescriptorType()
                {
                    entityID = options.ServiceProvider.EntityId,
                    Items = new object[]
                {
                        new SPSSODescriptorType()
                        {
                            NameIDFormat = new [] {options.NameIDType.Format??Saml2Constants.NameIDFormats.Email},
                            protocolSupportEnumeration = new []{Saml2Constants.Namespaces.Protocol },
                            AuthnRequestsSignedSpecified = true,
                            AuthnRequestsSigned = options.hasCertificate,
                            WantAssertionsSignedSpecified= true,
                            WantAssertionsSigned=options.WantAssertionsSigned,
                            KeyDescriptor= KeyDescriptor,
                            SingleLogoutService = SingleLogoutServices,

                            AssertionConsumerService = AssertionConsumerService,
                            AttributeConsumingService =  new AttributeConsumingServiceType[]
                            {
                                new AttributeConsumingServiceType
                                {
                                    ServiceName =  new localizedNameType[]
                                    {
                                        new localizedNameType()
                                        {
                                            Value = options.ServiceProvider.ServiceName,
                                            lang = options.ServiceProvider.Language
                                        }
                                    },
                                    ServiceDescription = new localizedNameType[]
                                    {
                                        new localizedNameType()
                                        {
                                            Value= options.ServiceProvider.ServiceDescription,
                                            lang = options.ServiceProvider.Language
                                        }
                                    },
                                    index=0,
                                    isDefault =true,
                                    isDefaultSpecified = true,
                                    RequestedAttribute = new RequestedAttributeType[] //this doesnt work with ADFS
                                    {
                                        new RequestedAttributeType
                                        {
                                            isRequired = true,
                                            isRequiredSpecified = true,
                                            NameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                                            Name= "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
                                            FriendlyName = "Name"
                                        },
                                        new RequestedAttributeType
                                        {
                                            isRequired = true,
                                            isRequiredSpecified = true,
                                            NameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                                            Name = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                                            FriendlyName = "E-Mail-Adresses"
                                        },
                                        new RequestedAttributeType
                                        {
                                            isRequired = true,
                                            isRequiredSpecified = true,
                                            NameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                                            Name= "nameid:persistent",
                                            FriendlyName = "mail"
                                        }
                                    }
                                }
                            },
                           Organization = new OrganizationType()
                                {
                                 OrganizationDisplayName = new localizedNameType[]{
                                     new localizedNameType
                                     {
                                         lang = options.ServiceProvider.Language,
                                         Value = options.ServiceProvider.OrganizationDisplayName
                                     },
                                 },
                                 OrganizationName = new localizedNameType[]{
                                     new localizedNameType
                                     {
                                         lang = options.ServiceProvider.Language,
                                         Value = options.ServiceProvider.OrganizationName
                                     },
                                 },
                                 OrganizationURL = new localizedURIType[]{
                                     new localizedURIType
                                     {
                                         lang = options.ServiceProvider.Language,
                                         Value = options.ServiceProvider.OrganizationURL
                                     },
                                 },
                            },
                       },
                },
                    ContactPerson = new ContactType[]
                {
                        new ContactType()
                        {
                            Company = options.ServiceProvider.ContactPerson.Company,
                            GivenName = options.ServiceProvider.ContactPerson.GivenName,
                            EmailAddress = options.ServiceProvider.ContactPerson.EmailAddress,
                            contactType = options.ServiceProvider.ContactPerson.contactType,
                            TelephoneNumber = options.ServiceProvider.ContactPerson.TelephoneNumber
                        }
                }
                };

                //generate the sp metadata xml file
                string xmlTemplate = string.Empty;
                XmlSerializer xmlSerializer = new XmlSerializer(typeof(EntityDescriptorType));
                using (MemoryStream memStm = new MemoryStream())
                {
                    xmlSerializer.Serialize(memStm, entityDescriptor);
                    memStm.Position = 0;
                    xmlTemplate = new StreamReader(memStm).ReadToEnd();
                }

                //create xml document from string
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.LoadXml(xmlTemplate);
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Save(options.DefaultMetadataFolderLocation + "\\" + options.DefaultMetadataFileName + ".xml");
            }
        }
    }
}