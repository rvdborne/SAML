using Telligent.Evolution.Extensibility.Configuration.Version1;
using Verint.Services.SamlAuthenticationPlugin.Components;
using Verint.Services.SamlAuthenticationPlugin.Extensibility;

using IPluginConfiguration = Telligent.Evolution.Extensibility.Version2.IPluginConfiguration;
using IRequiredConfigurationPlugin = Telligent.Evolution.Extensibility.Version2.IRequiredConfigurationPlugin;

namespace Verint.Services.SamlAuthenticationPlugin.Extensions
{
    public class SamlDisplayNameGenerator : ISamlDisplayNameGenerator, IRequiredConfigurationPlugin
    {
        public static string PluginName = "SAML Display Name Generator";

        public SamlTokenData GenerateDisplayName(SamlTokenData samlTokenData)
        {
            if (samlTokenData == null)
                return null;

            if (!string.IsNullOrWhiteSpace(samlTokenData.CommonName) && !Override)
                return samlTokenData;

            var displayName = string.Empty;
            if (DisplayNameAttribute.Contains("}"))
            {
                var displayNameParts = DisplayNameAttribute.Split('{', '}');
                bool foundAttribute = false;
                string templatedDisplayName = string.Empty;
                foreach (var displayNamePart in displayNameParts)
                {
                    if (DisplayNameAttribute.Contains(string.Concat("{", displayNamePart, "}")))
                    {
                        var attribute = samlTokenData.GetAttribute(displayNamePart);
                        if(!string.IsNullOrEmpty(attribute))
                        {
                            foundAttribute = true;
                            templatedDisplayName = templatedDisplayName + attribute;
                        }
                    }
                    else
                    {
                        templatedDisplayName = templatedDisplayName + displayNamePart;
                    }
                }
                if (foundAttribute) //only use this display name if we managed to find at least one saml attribute
                    displayName = templatedDisplayName;
            }
            else
            {
                displayName = samlTokenData.GetAttribute(DisplayNameAttribute);
            }

            if (!string.IsNullOrEmpty(displayName))
                samlTokenData.CommonName = displayName;

            return samlTokenData;
        }

        public string DisplayNameAttribute => Configuration.GetString("DisplayNameAttribute");

        public bool Override => Configuration.GetBool("Override").Value;

        public bool Enabled => this.IsConfigured;

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

        public bool IsConfigured => !string.IsNullOrEmpty(DisplayNameAttribute);

        protected IPluginConfiguration Configuration
        {
            get;
            private set;
        }


        public void Update(IPluginConfiguration configuration)
        {
            Configuration = configuration;
        }

        public PropertyGroup[] ConfigurationOptions
        {
            get
            {
                var groups = new[] { new PropertyGroup{Id = "options", LabelText = "Options", OrderNumber = 0} };

                var displayNameClaim = new Property
                {
                    Id = "DisplayNameAttribute",
                    LabelText = "Display Name Attribute Name",
                    DataType = "String",
                    DefaultValue = "displayname",
                    DescriptionText = "The name saml attribute containing the display name for a user. (Used for account auto-creation.  Will replace claims in {first} {last} syntax to parse a pattern)"
                };
                displayNameClaim.Rules.Add(new PropertyRule{Name = "trim"});
                groups[0].Properties.Add(displayNameClaim);

                var overrideDisplayName = new Property
                {
                    Id = "Override",
                    LabelText = "Override the existing display name",
                    DataType = "Bool",
                    OrderNumber = 2,
                    DefaultValue = "false",
                    DescriptionText = "Override the existing display name"
                };
                groups[0].Properties.Add(overrideDisplayName);

                return groups;
            }
        }

        #endregion
    }
}
