using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Telligent.Evolution.Extensibility;
using Telligent.Evolution.Extensibility.Api.Entities.Version1;
using Telligent.Evolution.Extensibility.Api.Version1;
using Telligent.Evolution.Extensibility.Version2;
using Verint.Services.SamlAuthenticationPlugin.Components;
using Verint.Services.SamlAuthenticationPlugin.Extensibility.Events;
using Property = Telligent.Evolution.Extensibility.Configuration.Version1.Property;
using PropertyGroup = Telligent.Evolution.Extensibility.Configuration.Version1.PropertyGroup;
using PropertyRule = Telligent.Evolution.Extensibility.Configuration.Version1.PropertyRule;

namespace Verint.Services.SamlAuthenticationPlugin.Extensions
{
    public class ProfileAttributeManager : IRequiredConfigurationPlugin
    {
        #region IPlugin

        public string Description => "Sets Telligent user profile fields based on SAML calims / attributres, optionally can also update those claims on login";

        public string Name => "SAML Profile Attribute Manager";

        public bool Enabled => IsConfigured;

        public void Initialize()
        {
            SamlEvents.Instance.AfterAuthenticate += Instance_AfterAuthenticate;
            SamlEvents.Instance.AfterCreate += Instance_AfterCreate;
            Apis.Get<IUsers>().Events.BeforeUpdate += Events_BeforeUpdate;
        }

        private void Events_BeforeUpdate(UserBeforeUpdateEventArgs e)
        {
            if (!MakeReadonly) return;

            var samlTokenData = SqlData.GetSamlTokenStoreData(e.Id.Value);
            if (samlTokenData == null) return;

            var usersSamlTokenProfileData = GetSamlTokenProfileData(samlTokenData);

            var updatedProfileFields = UpdatedProfileFields(usersSamlTokenProfileData, ConvertTitlesToNames(e.ProfileFields));
            if (updatedProfileFields != null)
            {
                e.ProfileFields = updatedProfileFields;
            }
        }

        /// <summary>
        /// Converts the users ProfileFields collection into something that can be saved, when you get a user profile field you get "lables" and "values"
        /// But when you save it you need to use "Names" and "Values", This class expects everyting to be the "Name" or Profile Field "Key"
        /// </summary>
        /// <param name="profileFields"></param>
        /// <returns></returns>
        private ApiList<ProfileField> ConvertTitlesToNames(ApiList<ProfileField> profileFields)
        {
            var cleanedProfileFields = new ApiList<ProfileField>();
            var allProfileFields = Apis.Get<IUserProfileFields>().List(new UserProfileFieldsListOptions() { PageSize = int.MaxValue });
            foreach(var profileField in profileFields)
            {
                var fieldDefinition = allProfileFields.Where(i => i.Name == profileField.Label).First();
                if (fieldDefinition != null)
                    cleanedProfileFields.Add(new ProfileField() { Label = fieldDefinition.Name, Value = profileField.Value });
            }

            return cleanedProfileFields;
        }

        private void Instance_AfterCreate(SamlAfterUserCreateEventArgs e)
        {
            ManageUserProfileFields(e.User, e.SamlTokenData);
        }

        private void Instance_AfterAuthenticate(SamlAfterAuthenticateEventArgs e)
        {
            ManageUserProfileFields(e.User, e.SamlTokenData);
        }

        private void ManageUserProfileFields(User user, SamlTokenData samlTokenData)
        {
            var apiUser = Apis.Get<IUsers>();
            apiUser.RunAsUser(apiUser.ServiceUserName, () =>
            {
                var usersSamlTokenProfileData = GetSamlTokenProfileData(samlTokenData);

                CreateMissingProfileFields(usersSamlTokenProfileData.Keys);

                var updatedProfileFields = UpdatedProfileFields(usersSamlTokenProfileData, ConvertTitlesToNames(user.ProfileFields));
                if (updatedProfileFields != null)
                {
                    UpdateProfileFields(user.Id.Value, updatedProfileFields);
                }

            });

        }
        
        private Dictionary<string, string> GetSamlTokenProfileData(SamlTokenData samlTokenData)
        {
            var extractedProfileData = new Dictionary<string, string>();

            foreach (var claim in samlTokenData.Attributes)
            {
                try
                {
                    var key = string.Concat(ProfileFieldPrefix, Regex.Replace(claim.ClaimType, @"[^\w\-]", string.Empty)).ToLower();
                    if (!extractedProfileData.ContainsKey(key))
                    {
                        extractedProfileData.Add(key, claim.Value);
                    }
                    else
                    {
                        extractedProfileData[key] = extractedProfileData[key] + "," + claim.Value;
                    }
                }
                catch (Exception ex)
                {
                    Apis.Get<IExceptions>().Log(ex);
                    Apis.Get<IEventLog>().Write("ProfileAttributeManager Error GetSamlTokenProfileData: " + ex.Message + " : " + ex.StackTrace, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 1, EventType = "Error" });
                }
                 
            }

            return extractedProfileData;
        }
        
        private void CreateMissingProfileFields(IEnumerable<string> profileFieldNames)
        {
            var apiUserProfileFields = Apis.Get<IUserProfileFields>();
            var profileFieldTypePlainText = apiUserProfileFields.ProfileFieldTypes.Where(i => i.Name == "Plain Text").FirstOrDefault();  //type 4
            foreach (string profileFieldName in profileFieldNames)
            {
                try
                {
                    if (apiUserProfileFields.Get(profileFieldName) == null)
                    {
                        apiUserProfileFields.Create(profileFieldName, profileFieldTypePlainText.Id, new UserProfileFieldsCreateOptions() { IsSearchable = false });
                    }
                }
                catch (Exception ex)
                {
                    Apis.Get<IExceptions>().Log(ex);
                    Apis.Get<IEventLog>().Write("ProfileAttributeManager Error CreateMissingProfileFields: " + ex.Message + " : " + ex.StackTrace, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 1, EventType = "Error" });
                }

            }
        }

        private ApiList<ProfileField> UpdatedProfileFields(Dictionary<string, string> usersSamlTokenProfileData, ApiList<ProfileField> currentProfileFields)
        {
            //get a list of user profile fields with the matching prefix
            var samlProfileFields = GetSamlProfileFields();
            var updatedProfileFields = new ApiList<ProfileField>();

            var hasChanges = false;
            foreach (var userProfileField in samlProfileFields)
            {
                try
                {
                    var userHasField = false;
                    //this checks the current users profile fields against saml (ie remove or update)
                    foreach (var profileField in currentProfileFields.Where(i => i.Label == userProfileField.Name))
                    {
                        //check to see if its in the saml token based on userProfileField name
                        if (!usersSamlTokenProfileData.ContainsKey(userProfileField.Name) && !string.IsNullOrWhiteSpace(profileField.Value))
                        {
                            updatedProfileFields.Add(new ProfileField() { Label = userProfileField.Name, Value = "" });
                            hasChanges = true;
                        }

                        if (usersSamlTokenProfileData.ContainsKey(userProfileField.Name) && profileField.Value != usersSamlTokenProfileData[userProfileField.Name])
                        {
                            updatedProfileFields.Add(new ProfileField() { Label = userProfileField.Name, Value = usersSamlTokenProfileData[userProfileField.Name] });
                            hasChanges = true;
                        }

                        userHasField = true;
                    }

                    //this checks the saml data against the user (ie adding missing entries)
                    if (!userHasField && usersSamlTokenProfileData.ContainsKey(userProfileField.Name))
                    {
                        updatedProfileFields.Add(new ProfileField() { Label = userProfileField.Name, Value = usersSamlTokenProfileData[userProfileField.Name] });
                        hasChanges = true;
                    }
                }
                catch (Exception ex)
                {
                    Apis.Get<IExceptions>().Log(ex);
                    Apis.Get<IEventLog>().Write("ProfileAttributeManager Error UpdatedProfileFields: " + ex.Message + " : " + ex.StackTrace, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 1, EventType = "Error" });
                }

            }

            return hasChanges ? updatedProfileFields : null;
        }
        
        public string[] Categories => SamlHelpers.ExtensionPluginCategories;

        #endregion

        private void UpdateProfileFields(int userId, IList<ProfileField> profileFields)
        {
            try
            {
                //for this to work the profilefield.title needs to be the internal name not the label
                Apis.Get<IUsers>().Update(new UsersUpdateOptions { ProfileFields = profileFields, Id = userId });
            }
            catch (Exception ex)
            {
                Apis.Get<IExceptions>().Log(ex);
                Apis.Get<IEventLog>().Write("ProfileAttributeManager Error UpdateProfileFields: " + ex.Message + " : " + ex.StackTrace, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 1, EventType = "Error" });
            }

        }

        private ApiList<UserProfileField> GetSamlProfileFields()
        {
            var samlProfileFields = new ApiList<UserProfileField>();
            var allProfileFields = Apis.Get<IUserProfileFields>().List(new UserProfileFieldsListOptions() { PageSize = int.MaxValue });
            foreach (var profileField in allProfileFields)
            {
                if (profileField.Name.StartsWith(ProfileFieldPrefix, StringComparison.InvariantCultureIgnoreCase))
                    samlProfileFields.Add(profileField);
            }

            return samlProfileFields;

        }

        #region Configuration

        public string ProfileFieldPrefix => Configuration.GetString("ProfileFieldPrefix");

        public bool AutoUpdate => Configuration.GetBool("autoUpdate").Value;

        public bool MakeReadonly => Configuration.GetBool("makeReadonly").Value;

        public bool IsConfigured
        {
            get
            {
                if (string.IsNullOrEmpty(ProfileFieldPrefix))
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

        public PropertyGroup[] ConfigurationOptions
        {
            get
            {
                var groups = new[]
                {
                    new PropertyGroup
                    {
                        Id = "Options",
                        LabelText = "Options",
                        OrderNumber = 0
                    }
                };

                var profileFieldPrefix = new Property
                {
                    Id = "ProfileFieldPrefix",
                    LabelText = "Profile Field Prefix",
                    DataType = "String",
                    OrderNumber = 1,
                    DefaultValue = "SAML_",
                    DescriptionText = "A prefix used to identify profile fields that should be updated by SAML claims (profile fields that start with this prefix that are not in the SAML claims will be emptied) (SAML will auto create these profile fields)"
                };
                profileFieldPrefix.Rules.Add(new PropertyRule{Name = "trim"});
                groups[0].Properties.Add(profileFieldPrefix);

                var autoUpdate = new Property
                {
                    Id = "autoUpdate",
                    LabelText = "Update Profile Fields On Login",
                    DataType = "Bool",
                    OrderNumber = 2,
                    DefaultValue = "true",
                    DescriptionText = "Update profile fields on every login with data from the saml token."
                };
                groups[0].Properties.Add(autoUpdate);

                var makeReadonly = new Property
                {
                    Id = "makeReadonly",
                    LabelText = "Make Readonly",
                    DataType = "Bool",
                    OrderNumber = 3,
                    DescriptionText = "Ensures profile fields match the current SAML token every time the user is saved.",
                    DefaultValue = "true"
                };
                groups[0].Properties.Add(makeReadonly);

                return groups;
            }
        }

        #endregion
    }
}
