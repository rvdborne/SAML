using Telligent.Evolution.Extensibility.Version1;
using Telligent.Services.SamlAuthenticationPlugin.Components;

namespace Telligent.Services.SamlAuthenticationPlugin.Extensibility
{
    public interface ISamlInvitationManager : ISingletonPlugin, ICategorizedPlugin
    {
        bool Enabled { get; }
        void ManageInvitation(SamlTokenData samlTokenData, string invitationKey);
    }
}
