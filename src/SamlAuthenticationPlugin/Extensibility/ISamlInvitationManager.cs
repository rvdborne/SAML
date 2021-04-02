using Telligent.Evolution.Extensibility.Version1;
using Verint.Services.SamlAuthenticationPlugin.Components;

namespace Verint.Services.SamlAuthenticationPlugin.Extensibility
{
    public interface ISamlInvitationManager : ISingletonPlugin, ICategorizedPlugin
    {
        bool Enabled { get; }
        void ManageInvitation(SamlTokenData samlTokenData, string invitationKey);
    }
}
