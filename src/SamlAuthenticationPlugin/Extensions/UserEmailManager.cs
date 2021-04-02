using System;
using Telligent.Evolution.Extensibility;
using Telligent.Evolution.Extensibility.Api.Entities.Version1;
using Telligent.Evolution.Extensibility.Api.Version1;
using Telligent.Evolution.Extensibility.Configuration.Version1;
using Verint.Services.SamlAuthenticationPlugin.Components;
using Verint.Services.SamlAuthenticationPlugin.Extensibility.Events;

using IPluginConfiguration = Telligent.Evolution.Extensibility.Version2.IPluginConfiguration;
using IRequiredConfigurationPlugin = Telligent.Evolution.Extensibility.Version2.IRequiredConfigurationPlugin;

namespace Verint.Services.SamlAuthenticationPlugin.Extensions
{
    public class UserEmailManager : IRequiredConfigurationPlugin
    {
        #region IPlugin

        public string Description => "Resets Verint private email address fields based on SAML claim / attribute";

        public string Name => "SAML User Email Manager";
        public bool Enabled => this.IsConfigured;
        public void Initialize()
        {
            SamlEvents.Instance.AfterAuthenticate += Instance_AfterAuthenticate;
            SamlEvents.Instance.AfterCreate += Instance_AfterCreate;
        }
        
        private void Instance_AfterCreate(SamlAfterUserCreateEventArgs e)
        {
            ManageUser(e.User, e.SamlTokenData);
        }

        private void Instance_AfterAuthenticate(SamlAfterAuthenticateEventArgs e)
        {
            ManageUser(e.User, e.SamlTokenData);
        }

        private void ManageUser(User user, SamlTokenData samlTokenData)
        {
            var apiUsers = Apis.Get<IUsers>();

            apiUsers.RunAsUser(apiUsers.ServiceUserName, () =>
            {
                if (user.PrivateEmail.ToLower() != samlTokenData.Email.ToLower())
                {
                    try
                    {
                        apiUsers.Update(new UsersUpdateOptions { PrivateEmail = samlTokenData.Email, Id = user.Id });
                    }
                    catch (Exception ex)
                    {
                        Apis.Get<IExceptions>().Log(ex);
                        Apis.Get<IEventLog>().Write("UserEmailManager Error ManageUser: " + ex.Message + " : " + ex.StackTrace, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 1, EventType = "Error" });
                    }
                }
            });
        }
        
        public string[] Categories => SamlHelpers.ExtensionPluginCategories;

        #endregion

        #region Configuration
        
        public bool UpdateEmail => Configuration.GetBool("updateEmail").Value;
        
        public bool IsConfigured => (UpdateEmail);

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
                var updateEmail = new Property
                {
                    Id = "updateEmail",
                    LabelText = "Update Email",
                    DataType = "Bool",
                    OrderNumber = 100,
                    DefaultValue = "true",
                    DescriptionText = "If checked, each login the community will validate that the user's private email matches the SAML claim and if not it will attempt to update the user to use the correct email."
                };
                groups[0].Properties.Add(updateEmail);

                return groups;
            }
        }

        #endregion
    }
}
