using Telligent.Evolution.Extensibility.UI.Version1;
using Telligent.Evolution.Extensibility.Version1;
using Telligent.Services.SamlAuthenticationPlugin.Extensions;
using IConfigurablePlugin = Telligent.Evolution.Extensibility.Version2.IConfigurablePlugin;
using IPluginConfiguration = Telligent.Evolution.Extensibility.Version2.IPluginConfiguration;
using IRequiredConfigurationPlugin = Telligent.Evolution.Extensibility.Version2.IRequiredConfigurationPlugin;

namespace Telligent.Services.SamlAuthenticationPlugin
{
    public class SpMetaDataPlugin : IScriptedContentFragmentExtension, IRequiredConfigurationPlugin, ISingletonPlugin
    {
        private const string _nameIdFormatUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
        private const string _nameIdFormatEmail = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
        private const string _nameIdFormatEntity = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
        private const string _nameIdFormatTransient = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
        private const string _nameIdFormatPersistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
        private const string _nameIdFormatEncrypted = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted";
        private const string _nameIdFormatKerberos = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos";

        public void Initialize(){}

        public string Name => "SAML - SP Meta Data Plugin";
        public string Description => "This plugin allows an admin user to generate the SP Metadata file.";
        public string ExtensionName => "saml_v1_spmetadata";
        public object Extension => new SpMetadataExtension();

        protected IPluginConfiguration Configuration
        {
            get;
            private set;
        }


        public void Update(IPluginConfiguration configuration)
        {
            Configuration = configuration;
        }

        Evolution.Extensibility.Configuration.Version1.PropertyGroup[] IConfigurablePlugin.ConfigurationOptions
        {
            get
            {
                var group = new Evolution.Extensibility.Configuration.Version1.PropertyGroup
                {
                    Id = "metadata",
                    LabelText = "Metadata",
                    OrderNumber = 1
                };

                var entityId = new Evolution.Extensibility.Configuration.Version1.Property
                {
                    Id = "entityid",
                    LabelText = "Metadata Entity Id",
                    DataType = "String",
                    OrderNumber = 1,
                    DefaultValue = "",
                    DescriptionText = ""
                };
                group.Properties.Add(entityId);

                var nameIdFormat = new Evolution.Extensibility.Configuration.Version1.Property
                {
                    Id = "nameidformat",
                    LabelText = "NameId Format",
                    DataType = "String",
                    OrderNumber = 2,
                    DefaultValue = _nameIdFormatUnspecified,
                    DescriptionText = "This is the Format of the NameId. (Optional)"
                };
                nameIdFormat.SelectableValues.Add(new Evolution.Extensibility.Configuration.Version1.PropertyValue{ Value = _nameIdFormatUnspecified, LabelText = "Unspecified", OrderNumber = 1 });
                nameIdFormat.SelectableValues.Add(new Evolution.Extensibility.Configuration.Version1.PropertyValue{ Value = _nameIdFormatEmail, LabelText = "Email", OrderNumber = 2 });
                nameIdFormat.SelectableValues.Add(new Evolution.Extensibility.Configuration.Version1.PropertyValue{ Value = _nameIdFormatEntity, LabelText = "Entity", OrderNumber = 3 });
                nameIdFormat.SelectableValues.Add(new Evolution.Extensibility.Configuration.Version1.PropertyValue{ Value = _nameIdFormatTransient, LabelText = "Transient", OrderNumber = 4 });
                nameIdFormat.SelectableValues.Add(new Evolution.Extensibility.Configuration.Version1.PropertyValue{ Value = _nameIdFormatPersistent, LabelText = "Persistent", OrderNumber = 5 });
                nameIdFormat.SelectableValues.Add(new Evolution.Extensibility.Configuration.Version1.PropertyValue{ Value = _nameIdFormatEncrypted, LabelText = "Encrypted", OrderNumber = 6 });
                nameIdFormat.SelectableValues.Add(new Evolution.Extensibility.Configuration.Version1.PropertyValue{ Value = _nameIdFormatKerberos, LabelText = "Kerberos", OrderNumber = 7 });
                group.Properties.Add(nameIdFormat);

                var authnRequestSigned = new Evolution.Extensibility.Configuration.Version1.Property
                {
                    Id = "authnsigned",
                    LabelText = "AuthN Requests Signed",
                    DataType = "Bool",
                    OrderNumber = 3,
                    DefaultValue = "false",
                    DescriptionText = "AuthN Requests Signed (Optional)"
                };
                group.Properties.Add(authnRequestSigned);

                var wantAssertionsSigned = new Evolution.Extensibility.Configuration.Version1.Property
                {
                    Id = "signassertions",
                    LabelText = "Want Assertions Signed",
                    DataType = "Bool",
                    OrderNumber = 4,
                    DefaultValue = "false",
                    DescriptionText = "Want Assertions Signed (Optional)"
                };
                group.Properties.Add(wantAssertionsSigned);

                var orgName = new Evolution.Extensibility.Configuration.Version1.Property
                {
                    Id = "orgname",
                    LabelText = "Organization Name",
                    DataType = "String",
                    OrderNumber = 5,
                    DefaultValue = "",
                    DescriptionText = "Organization Name (Optional)"
                };
                group.Properties.Add(orgName);

                var orgDisplayName = new Evolution.Extensibility.Configuration.Version1.Property
                {
                    Id = "orgdisplayname",
                    LabelText = "Organization DisplayName",
                    DataType = "String",
                    OrderNumber = 6,
                    DefaultValue = "",
                    DescriptionText = "Organization DisplayName (Optional)"
                };
                group.Properties.Add(orgDisplayName);

                var orgUrl = new Evolution.Extensibility.Configuration.Version1.Property
                {
                    Id = "orgurl",
                    LabelText = "Orginzational URL",
                    DataType = "String",
                    OrderNumber = 7,
                    DefaultValue = "",
                    DescriptionText = "Organization URL (Optional)"
                };
                group.Properties.Add(orgUrl);

                var techName = new Evolution.Extensibility.Configuration.Version1.Property
                {
                    Id = "techname",
                    LabelText = "Technical Contact Name",
                    DataType = "String",
                    OrderNumber = 8,
                    DefaultValue = "",
                    DescriptionText = "Technical Contact Name (Optional)"
                };
                group.Properties.Add(techName);

                var techEmail = new Evolution.Extensibility.Configuration.Version1.Property
                {
                    Id = "techemail",
                    LabelText = "Technical Contact Email",
                    DataType = "String",
                    OrderNumber = 9,
                    DefaultValue = "",
                    DescriptionText = "Technical Contact Email (Optional)"
                };
                group.Properties.Add(techEmail);

                var supportEmail = new Evolution.Extensibility.Configuration.Version1.Property
                {
                    Id = "supportemail",
                    LabelText = "Support Contact Email",
                    DataType = "String",
                    OrderNumber = 10,
                    DefaultValue = "",
                    DescriptionText = "Support Contact Email (Optional)"
                };
                group.Properties.Add(supportEmail);

                return new[] {group};
            }
        }

        #region Properties

        public string EntityId => Configuration.GetString("entityid");
        public string NameId => Configuration.GetString("nameidformat");
        public bool AuthnRequestsSigned => Configuration.GetBool("authnsigned").Value;
        public bool WantAssertionsSigned => Configuration.GetBool("signassertions").Value;
        public string OrgName => Configuration.GetString("orgname");
        public string OrgDisplayName => Configuration.GetString("orgdisplayname");
        public string OrgUrl => Configuration.GetString("orgurl");
        public string TechEmail => Configuration.GetString("techemail");
        public string SupportEmail => Configuration.GetString("supportemail");

        #endregion

        public bool IsConfigured => !string.IsNullOrEmpty(EntityId);
    }
}
