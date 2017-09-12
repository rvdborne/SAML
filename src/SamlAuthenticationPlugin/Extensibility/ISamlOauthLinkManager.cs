using Telligent.Evolution.Extensibility.Version1;
using Telligent.Services.SamlAuthenticationPlugin.Components;

namespace Telligent.Services.SamlAuthenticationPlugin.Extensibility
{
    /// <summary>
    /// Allows the plugin to use unsupported code to ensure the proper entries exist in the te_OAuth_Links table prior to sending the user
    /// back to the login form with the OAuth token.  The net effect is this code will automatically link all SAML IDs to Telligent Accounts
    /// Due to the fact that the te_OAuth_Links table only allows a single nameid to relate to a userid, in some cases it may be necessary to remove
    /// the existing te_OAuth_Links table and re-add it if you have a use case where the same user can log in via different saml logins 
    /// (ie same email associated with two seperate saml logins)
    /// </summary>
    public interface ISamlOAuthLinkManager : ISingletonPlugin, ICategorizedPlugin
    {
        bool Enabled { get; }
        void EnsureOAuthLink(SamlTokenData samlTokenData);

    }
}
