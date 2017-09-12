using System.IdentityModel.Tokens;
using Telligent.Evolution.Extensibility.Version1;
using Telligent.Services.SamlAuthenticationPlugin.Components;

namespace Telligent.Services.SamlAuthenticationPlugin.Extensibility
{
    public interface ISamlTokenDataValidator : ISingletonPlugin, ICategorizedPlugin
    {
        bool Enabled { get; }
        void Validate(SecurityToken samlToken, SamlTokenData samlTokenData);
    }
}
