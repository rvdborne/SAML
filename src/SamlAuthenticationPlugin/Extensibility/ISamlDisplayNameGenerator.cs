using Telligent.Evolution.Extensibility.Version1;
using Verint.Services.SamlAuthenticationPlugin.Components;

namespace Verint.Services.SamlAuthenticationPlugin.Extensibility
{
    /// <summary>
    /// Sets the Display Name property of the SamlTokenData based on the optional logic implemented in the custom plugin
    /// The default behavior is to leave this property empty; in this case the username is used and display name is not set
    /// </summary>
    public interface ISamlDisplayNameGenerator : ISingletonPlugin, ICategorizedPlugin
    {
        bool Enabled { get; }
        SamlTokenData GenerateDisplayName(SamlTokenData samlTokenData);
    }
}
