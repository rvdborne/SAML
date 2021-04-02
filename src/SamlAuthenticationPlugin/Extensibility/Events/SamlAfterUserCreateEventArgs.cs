using Verint.Services.SamlAuthenticationPlugin.Components;
using PublicEntity = Telligent.Evolution.Extensibility.Api.Entities.Version1.User;

namespace Verint.Services.SamlAuthenticationPlugin.Extensibility.Events
{
    public class SamlAfterUserCreateEventArgs
    {
        internal SamlAfterUserCreateEventArgs(PublicEntity user, SamlTokenData samlTokenData)
        {
            User = user;
            SamlTokenData = samlTokenData;
        }

        public PublicEntity User { get; private set; }
        public SamlTokenData SamlTokenData { get; private set; }
    }
}
