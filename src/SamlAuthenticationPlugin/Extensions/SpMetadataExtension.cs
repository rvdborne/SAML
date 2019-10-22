using System;
using System.Globalization;
using System.IdentityModel.Metadata;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.Text;
using System.Web;
using System.Xml;
using System.Xml.Linq;
using Telligent.Evolution.Extensibility;
using Telligent.Evolution.Extensibility.Api.Version1;
using Telligent.Evolution.Extensibility.Version1;
using Telligent.Services.SamlAuthenticationPlugin.Components;

namespace Telligent.Services.SamlAuthenticationPlugin.Extensions
{
    public class SpMetadataExtension
    {
        public void GenerateMetadataFile()
        {
            var pluginManager = PluginManager.GetSingleton<SpMetaDataPlugin>();
            var descriptor = new EntityDescriptor(new EntityId{Id = pluginManager.EntityId});

            //var idpSignInUrl = IdpGetSignInUrl(pluginManager.IdpMetaDataUrl);

            var spd = new ServiceProviderSingleSignOnDescriptor
            {
                AuthenticationRequestsSigned = pluginManager.AuthnRequestsSigned,
                WantAssertionsSigned = pluginManager.WantAssertionsSigned,
                ValidUntil = DateTime.Now.AddDays(365)
            };
            
            spd.ProtocolsSupported.Add(new Uri("urn:oasis:names:tc:SAML:2.0:protocol"));
            spd.NameIdentifierFormats.Add(new Uri(pluginManager.NameId));
            
            var consumerService = new IndexedProtocolEndpoint
            {
                Index = 0,
                IsDefault = true,
                Location = new Uri($"{Apis.Get<ICoreUrls>().Home()}samlresponse"),
                Binding = new Uri("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
            };
            
            spd.AssertionConsumerServices.Add(1, consumerService);

            // Organizational Info
            if (!string.IsNullOrEmpty(pluginManager.OrgName) || !string.IsNullOrEmpty(pluginManager.OrgDisplayName) || !string.IsNullOrEmpty(pluginManager.OrgUrl))
                descriptor.Organization = new Organization();

            if (!string.IsNullOrEmpty(pluginManager.OrgName))
                descriptor.Organization.Names.Add(new LocalizedName(pluginManager.OrgName, CultureInfo.InvariantCulture));

            if (!string.IsNullOrEmpty(pluginManager.OrgDisplayName))
                descriptor.Organization.DisplayNames.Add(new LocalizedName(pluginManager.OrgDisplayName,
                    CultureInfo.InvariantCulture));

            if (!string.IsNullOrEmpty(pluginManager.OrgUrl))
                descriptor.Organization.Urls.Add(new LocalizedUri(new Uri(pluginManager.OrgUrl),
                    CultureInfo.InvariantCulture));

            // Tech contact info
            if (!string.IsNullOrEmpty(pluginManager.OrgName) && !string.IsNullOrEmpty(pluginManager.TechEmail) &&
                !string.IsNullOrEmpty(pluginManager.SupportEmail))
            {
                descriptor.Contacts.Add(new ContactPerson { Company = pluginManager.OrgName, EmailAddresses = { pluginManager.TechEmail, pluginManager.SupportEmail }, Type = ContactType.Support });
            }

            // Handle the signing certificate if provided
            if (!string.IsNullOrEmpty(pluginManager.PrivateKey) && !string.IsNullOrEmpty(pluginManager.X509Cert))
            {
                var cert = GetX509Cert(pluginManager.X509Cert, pluginManager.PrivateKey);
                var signingCredentials = new X509SigningCredentials(cert);
                var signingKey = new KeyDescriptor(signingCredentials.SigningKeyIdentifier)
                {
                    Use = KeyType.Signing
                };

                var encryptionKey = new KeyDescriptor(signingCredentials.SigningKeyIdentifier)
                {
                    Use = KeyType.Encryption
                };

                // Add signing key if a cert is provided.
                spd.Keys.Add(signingKey);
                spd.Keys.Add(encryptionKey);
                descriptor.SigningCredentials = signingCredentials;
            }

            descriptor.RoleDescriptors.Add(spd);

            var xml = WriteXml(descriptor);
            var context = HttpContext.Current;

            context.ClearError();
            context.Response.Cache.SetLastModified(DateTime.Now);
            context.Response.ContentType = "text/xml";
            context.Response.ContentEncoding = Encoding.UTF8;
            context.Response.AddHeader("content-disposition", "attachment; filename=community-metadata.xml");
            context.Response.Write(xml);
            context.Response.Flush();
            context.Response.End();
        }

        public string WriteXml(EntityDescriptor d)
        {
            var ser = new MetadataSerializer();
            var sb = new StringBuilder();
            
            using (var sr = new StringWriter(sb))
            using (var xmlWriter = XmlWriter.Create(sr, new XmlWriterSettings { OmitXmlDeclaration = false, Indent = true, IndentChars = "    "}))
            {
                ser.WriteMetadata(xmlWriter, d);
            }

            return sb.ToString();
        }

        private string IdpGetSignInUrl(string idpMetadataUrl)
        {
            if (!string.IsNullOrEmpty(idpMetadataUrl))
            {
                var xmlDoc = XDocument.Load(idpMetadataUrl);

                var signInUrl = xmlDoc.Descendants("md:IDPSSODescriptor").Descendants("md:SingleSignOnService").Where(x =>
                    x.Attribute("Binding").Value == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST").Select(u => u.Attribute("Location").Value).First();

                return signInUrl;
                //idpEntityDescriptor = GetIdpEntityDescriptor(xmlDoc.OuterXml);
            }

            return "";
        }

        private EntityDescriptor GetIdpEntityDescriptor(string metadata)
        {
            using (var reader = XmlReader.Create(new StringReader(metadata)))
            {
                var ser = new MetadataSerializer();
                ser.RevocationMode = X509RevocationMode.NoCheck;
                ser.CertificateValidationMode = X509CertificateValidationMode.None;
                
                var metadataObject = ser.ReadMetadata(reader);

                return (EntityDescriptor)metadataObject;
            }
        }

        private X509Certificate2 GetX509Cert(string certContent, string keyContent)
        {
            var certBytes = Crypto.GetBytesFromPem(certContent, Crypto.PemStringType.Certificate);
            var keyBytes = Crypto.GetBytesFromPem(keyContent, Crypto.PemStringType.RsaPrivateKey);
            
            var cert = new X509Certificate2(certBytes);
            var prov = Crypto.DecodeRsaPrivateKey(keyBytes);
            cert.PrivateKey = prov;

            return cert;
        }
    }
}
