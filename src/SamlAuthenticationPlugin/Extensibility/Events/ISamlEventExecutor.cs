using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Verint.Services.SamlAuthenticationPlugin.Components;
using PublicEntity = Telligent.Evolution.Extensibility.Api.Entities.Version1.User;

namespace Verint.Services.SamlAuthenticationPlugin.Extensibility.Events
{
    public delegate void SamlAfterAuthenticateEventHandler(SamlAfterAuthenticateEventArgs e);
    public delegate void SamlAfterUserCreateEventHandler(SamlAfterUserCreateEventArgs e);

    public interface ISamlEventExecutor
    {
        void OnAfterAuthenticate(PublicEntity user, SamlTokenData samlTokenData);
        void OnAfterUserCreate(PublicEntity user, SamlTokenData samlTokenData);
    }
}
