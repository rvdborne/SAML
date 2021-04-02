using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Telligent.Evolution.Extensibility;
using Telligent.Evolution.Extensibility.Api.Version1;
using Verint.Services.SamlAuthenticationPlugin.Components;
using Verint.Services.SamlAuthenticationPlugin.Extensibility.Events;
using Telligent.Evolution.Extensibility.Api.Entities.Version1;
using Telligent.Evolution.Extensibility.Version2;

using Property = Telligent.Evolution.Extensibility.Configuration.Version1.Property;
using PropertyGroup = Telligent.Evolution.Extensibility.Configuration.Version1.PropertyGroup;
using PropertyRule = Telligent.Evolution.Extensibility.Configuration.Version1.PropertyRule;

namespace Verint.Services.SamlAuthenticationPlugin.Extensions
{
    public class RoleMembershipManager : IRequiredConfigurationPlugin
    {
        public static string PluginName = "SAML User Role Manager";

        public RoleMembershipManager()
        {
        }
        public string Description
        {
            get { return "Updates Verint Community user profile attributes when a user is created based on SAML claims, optionally can also update those claims on login"; }
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
        private List<string> GetSamlTokenRoles(SamlTokenData samlTokenData)
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
            var rolesApi = Apis.Get<IRoles>();
            var eventLogApi = Apis.Get<IEventLog>();
            foreach (var samlRole in samlRoleNames)
            {
                try
                {
                    if (!rolesApi.Find(samlRole).Any())
                    {
                        rolesApi.Create(samlRole, "Auto Created SAML based Role");
                    }
                }
                catch (Exception ex)
                {
                    eventLogApi.Write("RoleMembershipManager Error CreateMissingRoles: " + ex.Message + " : " + ex.StackTrace, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 1, EventType = "Error" });
                }
            }
        }

        private void AddRemoveUserFromManagedRoles(User user, List<string> samlUserRoles)
        {
            var rolesApi = Apis.Get<IRoles>();
            var roleUsersApi = Apis.Get<IRoleUsers>();
            var eventLogApi = Apis.Get<IEventLog>();
            var samlRoles = rolesApi.List(null).Where(role => role.Name.ToLower().StartsWith(RoleNamePrefix.ToLower()));
            foreach (var samlRole in samlRoles)
            {
                try
                {
                    if (samlUserRoles.Contains(samlRole.Name)) //make sure the user is in all roles in their saml token
                    {
                        if (!roleUsersApi.IsUserInRoles(user.Username, new string[] { samlRole.Name }))
                        {
                            roleUsersApi.AddUserToRole(new RoleUserCreateOptions() { RoleName = samlRole.Name, UserId = user.Id });
                        }
                    }
                    else //remove user from roles not in their saml token
                    {
                        if (roleUsersApi.IsUserInRoles(user.Username, new string[] { samlRole.Name }))
                        {
                            roleUsersApi.RemoveUserFromRole(samlRole.Id.Value, new RoleUserDeleteOptions() { UserId = user.Id });
                        }
                    }
                }
                catch (Exception ex)
                {
                    eventLogApi.Write("RoleMembershipManager Error AddRemoveUserFromManagedRoles: " + ex.Message + " : " + ex.StackTrace, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 1, EventType = "Error" });
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

        public PropertyGroup[] ConfigurationOptions
        {
            get
            {
                var groups = new[] { new PropertyGroup() { Id = "options", LabelText = "Options", OrderNumber = 0 } };
                var roleNamePrefix = new Property
                {
                    Id = "RoleNamePrefix",
                    LabelText = "Role Name Prefix",
                    DataType = "String",
                    OrderNumber = 1,
                    DefaultValue = "SAML_",
                    DescriptionText = "A prefix used to identify Roles that should be updated by SAML claims (users will be removed from all roles that start with this prefix not specified in the relevant claim)"
                };
                roleNamePrefix.Rules.Add(new PropertyRule { Name = "trim" });
                groups[0].Properties.Add(roleNamePrefix);

                var roleClaim = new Property
                {
                    Id = "RoleClaim",
                    LabelText = "Role Claim",
                    DataType = "String",
                    OrderNumber = 2,
                    DefaultValue = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups",
                    DescriptionText = "The saml attribute name which contains the roles to map the user to."
                };
                roleClaim.Rules.Add(new PropertyRule { Name = "trim" });
                groups[0].Properties.Add(roleClaim);

                return groups;

            }
        }

        #endregion
    }
}

