using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Telligent.Evolution.Extensibility.Version1;
using Telligent.Services.SamlAuthenticationPlugin.Components;

namespace Telligent.Services.SamlAuthenticationPlugin.Extensibility
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
