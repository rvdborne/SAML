using System;
using System.Globalization;
using System.IdentityModel.Metadata;
using System.IO;
using System.Text;
using System.Web;
using System.Xml;
using Telligent.Evolution.Extensibility;
using Telligent.Evolution.Extensibility.Api.Version1;
using Telligent.Evolution.Extensibility.Version1;

namespace Telligent.Services.SamlAuthenticationPlugin.Extensions
{
    public class SpMetadataExtension
    {
        public void GenerateMetadataFile()
        {
            var pluginManager = PluginManager.GetSingleton<SpMetaDataPlugin>();
            //var descriptor = new EntityDescriptor { EntityId = { Id = pluginManager.EntityId } };
            var descriptor = new EntityDescriptor(new EntityId{Id = pluginManager.EntityId});

            var spd = new ServiceProviderSingleSignOnDescriptor
            {
                AuthenticationRequestsSigned = pluginManager.AuthnRequestsSigned,
                WantAssertionsSigned = pluginManager.WantAssertionsSigned
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

            if(!string.IsNullOrEmpty(pluginManager.OrgName) || !string.IsNullOrEmpty(pluginManager.OrgDisplayName) || !string.IsNullOrEmpty(pluginManager.OrgUrl))
                descriptor.Organization = new Organization();

            if (!string.IsNullOrEmpty(pluginManager.OrgName))
                descriptor.Organization.Names.Add(new LocalizedName(pluginManager.OrgName, CultureInfo.InvariantCulture));

            if (!string.IsNullOrEmpty(pluginManager.OrgDisplayName))
                descriptor.Organization.DisplayNames.Add(new LocalizedName(pluginManager.OrgDisplayName,
                    CultureInfo.InvariantCulture));

            if (!string.IsNullOrEmpty(pluginManager.OrgUrl))
                descriptor.Organization.Urls.Add(new LocalizedUri(new Uri(pluginManager.OrgUrl),
                    CultureInfo.InvariantCulture));

            if (!string.IsNullOrEmpty(pluginManager.OrgName) && !string.IsNullOrEmpty(pluginManager.TechEmail) &&
                !string.IsNullOrEmpty(pluginManager.SupportEmail))
            {
                descriptor.Contacts.Add(new ContactPerson { Company = pluginManager.OrgName, EmailAddresses = { pluginManager.TechEmail, pluginManager.SupportEmail }, Type = ContactType.Support });
            }

            descriptor.RoleDescriptors.Add(spd);

            var ser = new MetadataSerializer();
            var sb = new StringBuilder();

            using(var sr = new StringWriter(sb))
            using (var xmlWriter = XmlWriter.Create(sr, new XmlWriterSettings {OmitXmlDeclaration = true}))
            {
                ser.WriteMetadata(xmlWriter, descriptor);
            }

            var context = HttpContext.Current;
            context.ClearError();
            context.Response.Cache.SetLastModified(DateTime.Now);
            context.Response.ContentType = "text/xml";
            context.Response.ContentEncoding = Encoding.UTF8;
            context.Response.AddHeader("content-disposition", "attachment; filename=community-metadata.xml");
            context.Response.Write(sb.ToString());
            context.Response.Flush();
            context.Response.End();
        }
    }
}
