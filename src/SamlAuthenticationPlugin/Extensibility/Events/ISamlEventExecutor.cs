using Telligent.Services.SamlAuthenticationPlugin.Components;
using PublicEntity = Telligent.Evolution.Extensibility.Api.Entities.Version1.User;

namespace Telligent.Services.SamlAuthenticationPlugin.Extensibility.Events
{
    public delegate void SamlAfterAuthenticateEventHandler(SamlAfterAuthenticateEventArgs e);
    public delegate void SamlAfterUserCreateEventHandler(SamlAfterUserCreateEventArgs e);
    public interface ISamlEventExecutor
    {
        void OnAfterAuthenticate(PublicEntity user, SamlTokenData samlTokenData);
        void OnAfterUserCreate(PublicEntity user, SamlTokenData samlTokenData);
    }
}
