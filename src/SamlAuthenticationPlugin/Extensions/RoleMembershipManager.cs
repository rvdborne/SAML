using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Telligent.DynamicConfiguration.Components;
using Telligent.Evolution.Extensibility;
using Telligent.Evolution.Extensibility.Api.Version1;
using Telligent.Evolution.Extensibility.Version1;
using Telligent.Services.SamlAuthenticationPlugin.Components;
using Telligent.Services.SamlAuthenticationPlugin.Extensibility.Events;
using Telligent.Evolution.Extensibility.Api.Entities.Version1;

namespace Telligent.Services.SamlAuthenticationPlugin.Extensions
{
    public class RoleMembershipManager : IRequiredConfigurationPlugin
    {
        public static string PluginName = "SAML User Role Manager";

        private IUsers _usersApi;
        private IUserProfileFields _userProfileFields;
        private IRoles _rolesApi;
        private IRoleUsers _roleUsersApi;
        private IEventLog _eventLogApi;

        public RoleMembershipManager()
        {
        }
        public string Description
        {
            get { return "Updates telligent user profile attributres when a user is created based on SAML claims, optionally can also update those claims on login"; }
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
            _userProfileFields = Apis.Get<IUserProfileFields>();
            _rolesApi = Apis.Get<IRoles>();
            _roleUsersApi = Apis.Get<IRoleUsers>();
            _eventLogApi = Apis.Get<IEventLog>();

            SamlEvents.Instance.AfterAuthenticate += Instance_AfterAuthenticate;
            SamlEvents.Instance.AfterCreate += Instance_AfterCreate;

        }

        private void Instance_AfterCreate(SamlAfterUserCreateEventArgs e)
        {
            ManageUserRoles(e.User, e.SamlTokenData);
        }

        private void Instance_AfterAuthenticate(SamlAfterAuthenticateEventArgs e)
        {
            ManageUserRoles(e.User, e.SamlTokenData);
        }


        private void ManageUserRoles(User user, SamlTokenData samlTokenData)
        {
            var usersSamlTokenRoles = GetSamlTokenRoles(samlTokenData);

            Apis.Get<IUsers>().RunAsUser("admin", () =>
            {

                CreateMissingRoles(usersSamlTokenRoles);
                AddRemoveUserFromManagedRoles(user, usersSamlTokenRoles);
            });

        }
        private List<String> GetSamlTokenRoles(SamlTokenData samlTokenData)
        {
            var samlUserRoles = new List<string>();
            foreach (var roleName in samlTokenData.GetAttributes(RoleClaim))
            {
                var samlRoleName = RoleNamePrefix + Regex.Replace(roleName, @"[^\w\-]", string.Empty);
                if (!samlUserRoles.Contains(samlRoleName))
                {
                    samlUserRoles.Add(samlRoleName);
                }

            }
            return samlUserRoles;
        }

        private void CreateMissingRoles(List<string> samlRoleNames)
        {
            foreach (string samlRole in samlRoleNames)
            {
                try
                {
                    if (!_rolesApi.Find(samlRole).Any())
                    {
                        _rolesApi.Create(samlRole, "Auto Created SAML based Role");
                    }
                }
                catch (Exception ex)
                {
                    _eventLogApi.Write("RoleMembershipManager Error CreateMissingRoles: " + ex.Message + " : " + ex.StackTrace, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 1, EventType = "Error" });
                }
            }
        }

        private void AddRemoveUserFromManagedRoles(User user, List<string> samlUserRoles)
        {
            var samlRoles = _rolesApi.List(null).Where(role => role.Name.ToLower().StartsWith(RoleNamePrefix.ToLower()));
            foreach (var samlRole in samlRoles)
            {
                try
                {
                    if (samlUserRoles.Contains(samlRole.Name)) //make sure the user is in all roles in their saml token
                    {
                        if (!_roleUsersApi.IsUserInRoles(user.Username, new string[] { samlRole.Name }))
                        {
                            _roleUsersApi.AddUserToRole(new RoleUserCreateOptions() { RoleName = samlRole.Name, UserId = user.Id });
                        }
                    }
                    else //remove user from roles not in their saml token
                    {
                        if (_roleUsersApi.IsUserInRoles(user.Username, new string[] { samlRole.Name }))
                        {
                            _roleUsersApi.RemoveUserFromRole(samlRole.Id.Value, new RoleUserDeleteOptions() { UserId = user.Id });
                        }
                    }
                }
                catch (Exception ex)
                {
                    _eventLogApi.Write("RoleMembershipManager Error AddRemoveUserFromManagedRoles: " + ex.Message + " : " + ex.StackTrace, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 1, EventType = "Error" });
                }
            }
        }

        public string[] Categories
        {
            get { return SamlHelpers.ExtensionPluginCategories; }
        }




        #region Configuration

        public string RoleNamePrefix
        {
            get { return Configuration.GetString("RoleNamePrefix"); }
        }

        public string RoleClaim
        {
            get { return Configuration.GetString("RoleClaim"); }
        }


        public bool IsConfigured
        {
            get
            {
                if (string.IsNullOrEmpty(RoleClaim))
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


                var RoleNamePrefix = new Property("RoleNamePrefix", "Role Name Prefix", PropertyType.String, 1, "SAML_") { DescriptionText = "A prefix used to identify Roles that should be updated by SAML claims (users will be removed from all roles that start with this prefix not specified in the relevant claim)" }; ;
                RoleNamePrefix.Rules.Add(new PropertyRule(typeof(Telligent.Evolution.Controls.PropertyRules.TrimStringRule), false));
                groups[0].Properties.Add(RoleNamePrefix);

                var RoleClaim = new Property("RoleClaim", "Role Claim", PropertyType.String, 1, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups") { DescriptionText = "The saml attribute name which contains the roles to map the user to." }; ;
                RoleClaim.Rules.Add(new PropertyRule(typeof(Telligent.Evolution.Controls.PropertyRules.TrimStringRule), false));
                groups[0].Properties.Add(RoleClaim);
                return groups;

            }
        }
        #endregion
    }
}

