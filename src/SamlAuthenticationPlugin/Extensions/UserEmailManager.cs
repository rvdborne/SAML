using System;
using Telligent.DynamicConfiguration.Components;
using Telligent.Evolution.Extensibility;
using Telligent.Evolution.Extensibility.Api.Entities.Version1;
using Telligent.Evolution.Extensibility.Api.Version1;
using Telligent.Evolution.Extensibility.Version1;
using Telligent.Services.SamlAuthenticationPlugin.Components;
using Telligent.Services.SamlAuthenticationPlugin.Extensibility.Events;

namespace Telligent.Services.SamlAuthenticationPlugin.Extensions
{
    public class UserEmailManager : IRequiredConfigurationPlugin
    {

        public static string PluginName = "SAML User Email Manager";
        private IUsers _usersApi;
        private IEventLog _eventLogApi;


        public UserEmailManager()
        {

        }

        #region IPlugin

        public string Description
        {
            get { return "Resets Telligent private email address fields based on SAML calim / attributre"; }
        }

        public string Name
        {
            get { return PluginName; }
        }


        public bool Enabled
        {
            get { return this.IsConfigured; }
        }

        public void Initialize()
        {
            _usersApi = Apis.Get<IUsers>();
            _eventLogApi = Apis.Get<IEventLog>();

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


            _usersApi.RunAsUser("admin", () =>
            {

                if (user.PrivateEmail.ToLower() != samlTokenData.Email.ToLower())
                {
                    try
                    {
                        _usersApi.Update(new UsersUpdateOptions { PrivateEmail = samlTokenData.Email, Id = user.Id });
                    }
                    catch (Exception ex)
                    {
                        _eventLogApi.Write("UserEmailManager Error ManageUser: " + ex.Message + " : " + ex.StackTrace, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 1, EventType = "Error" });
                    }

                }

            });

        }





        public string[] Categories
        {
            get { return SamlHelpers.ExtensionPluginCategories; }
        }


        #endregion

        #region Configuration


        public bool UpdateEmail
        {
            get { return Configuration.GetBool("updateEmail"); }
        }



        public bool IsConfigured
        {
            get
            {
                return (UpdateEmail);
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


                var updateEmail = new Property("updateEmail", "Update Email", PropertyType.Bool, 100, "true") { DescriptionText = "If checked, each login the communtiy will validate that the user's private email matches the SAML claim and if not it will attempt to update the user to use the correct email." };
                groups[0].Properties.Add(updateEmail);

                return groups;

            }
        }

        #endregion
    }
}
