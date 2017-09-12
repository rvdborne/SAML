using Telligent.DynamicConfiguration.Components;
using Telligent.Evolution.Extensibility.Version1;
using Telligent.Services.SamlAuthenticationPlugin.Components;
using Telligent.Services.SamlAuthenticationPlugin.Extensibility;

namespace Telligent.Services.SamlAuthenticationPlugin
{
    public class SamlDisplayNameGenerator : ISamlDisplayNameGenerator, IRequiredConfigurationPlugin
    {
        public static string PluginName = "SAML Display Name Generator";

        public SamlTokenData GenerateDisplayName(SamlTokenData samlTokenData)
        {
            if (samlTokenData == null)
                return null;

            var displayName = samlTokenData.GetAttribute(DisplayNameAttribute);
            if (!string.IsNullOrEmpty(displayName))
                samlTokenData.CommonName = displayName;

            return samlTokenData;
        }

        public string DisplayNameAttribute
        {
            get { return Configuration.GetString("DisplayNameAttribute"); }
        }

        public bool Enabled
        {
            get { return this.IsConfigured; }
        }

        #region IPlugin

        public string Description
        {
            get { return "Extends the SAML plugin with basic logic for setting display names for new user accounts"; }
        }

        public void Initialize()
        {
        }

        public string Name
        {
            get { return PluginName; }
        }

        public string[] Categories
        {
            get { return SamlHelpers.ExtensionPluginCategories; }
        }


        #endregion

        #region Configuration

        public bool IsConfigured
        {
            get
            {
                if (string.IsNullOrEmpty(DisplayNameAttribute))
                    return false;

                return true;
            }
        }

        protected IPluginConfiguration Configuration
        {
            get;
            private set;
        }


        public void Update(IPluginConfiguration configuration)
        {
            Configuration = configuration;
        }

        public DynamicConfiguration.Components.PropertyGroup[] ConfigurationOptions
        {
            get
            {
                PropertyGroup[] groups = new[] { new PropertyGroup("options", "Options", 0) };


                var displayNameClaim = new Property("DisplayNameAttribute", "Display Name Attribute Name", PropertyType.String, 1, "displayname") { DescriptionText = "The name saml attribute containing the display name for a user. (Used for account auto-creation.)" }; ;
                displayNameClaim.Rules.Add(new PropertyRule(typeof(Telligent.Evolution.Controls.PropertyRules.TrimStringRule), false));
                groups[0].Properties.Add(displayNameClaim);

                return groups;

            }
        }

        #endregion
    }
}
