using Telligent.Evolution.Extensibility.Version1;
using Telligent.Services.SamlAuthenticationPlugin.Components;

namespace Telligent.Services.SamlAuthenticationPlugin.Extensibility
{
    /// <summary>
    /// Usually the username is just an attribute in the SAML token, in the case we need to use logic (like to strip a domain name or concat two fields, or parse the email)
    /// This plugin can be used to inject custom logic back into the SamlTokenData
    /// </summary>
    public interface ISamlUsernameGenerator : ISingletonPlugin, ICategorizedPlugin
    {

        bool Enabled { get; }
        SamlTokenData GenerateUsername(SamlTokenData samlTokenData);
    }
}
