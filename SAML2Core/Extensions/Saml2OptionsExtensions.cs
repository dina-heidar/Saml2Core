using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml.Serialization;
using SamlCore.AspNetCore.Authentication.Saml2;
using SamlCore.AspNetCore.Authentication.Saml2.Metadata;

namespace SAML2Core.Extensions
{
    public static class Saml2OptionsExtensions
    {
        public static string ToXmlMetadata(this Saml2Options options)
        {
            IndexedEndpointType[] AssertionConsumerService = options.ServiceProvider.AssertionConsumerServices;
                EndpointType[] SingleLogoutServices = options.ServiceProvider.SingleLogoutServices;

                SamlCore.AspNetCore.Authentication.Saml2.Metadata.KeyDescriptorType[] KeyDescriptor = null;
                if (options.hasCertificate)
                {
                    KeyDescriptor = new SamlCore.AspNetCore.Authentication.Saml2.Metadata.KeyDescriptorType[]
                             {
                                new SamlCore.AspNetCore.Authentication.Saml2.Metadata.KeyDescriptorType()
                                {
                                    useSpecified= true,
                                    use = KeyTypes.signing,
                                    KeyInfo = new SamlCore.AspNetCore.Authentication.Saml2.Metadata.KeyInfoType()
                                    {
                                        ItemsElementName = new []{ SamlCore.AspNetCore.Authentication.Saml2.Metadata.ItemsChoiceType2.X509Data},
                                        Items = new SamlCore.AspNetCore.Authentication.Saml2.Metadata.X509DataType[]
                                        {
                                            new SamlCore.AspNetCore.Authentication.Saml2.Metadata.X509DataType()
                                            {
                                                Items = new object[]{options.ServiceProvider.X509Certificate2.GetRawCertData() },
                                                ItemsElementName = new [] { SamlCore.AspNetCore.Authentication.Saml2.Metadata.ItemsChoiceType.X509Certificate }
                                            }
                                        }
                                    }
                                 },
                                new SamlCore.AspNetCore.Authentication.Saml2.Metadata.KeyDescriptorType()
                                {
                                    useSpecified= true,
                                    use = KeyTypes.encryption,
                                    KeyInfo = new SamlCore.AspNetCore.Authentication.Saml2.Metadata.KeyInfoType()
                                    {
                                        ItemsElementName = new []{ SamlCore.AspNetCore.Authentication.Saml2.Metadata.ItemsChoiceType2.X509Data},
                                        Items = new SamlCore.AspNetCore.Authentication.Saml2.Metadata.X509DataType[]
                                        {
                                            new SamlCore.AspNetCore.Authentication.Saml2.Metadata.X509DataType()
                                            {
                                                Items = new object[]{ options.ServiceProvider.X509Certificate2.GetRawCertData() },
                                                ItemsElementName = new [] { SamlCore.AspNetCore.Authentication.Saml2.Metadata.ItemsChoiceType.X509Certificate }
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
                            NameIDFormat = new [] {Saml2Constants.NameIDFormats.Email},
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

                return xmlTemplate;
        }
    }
}
