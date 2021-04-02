using Telligent.Evolution.Extensibility.Version1;
using Verint.Services.SamlAuthenticationPlugin.Components;

namespace Verint.Services.SamlAuthenticationPlugin.Extensibility
{
    public interface ISamlUserLookup : ISingletonPlugin, ICategorizedPlugin
    {

        bool Enabled { get; }

        /// <summary>
        /// Looks up the existing user id from the samlToken using custom logic
        /// </summary>
        /// <param name="samlTokenData"></param>
        /// <returns>an updated SamlTokenData with the userid and other user found attributes (like username or email) populated / updated</returns>
        SamlTokenData GetUser(SamlTokenData samlTokenData);

    }
}
