using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Telligent.Services.SamlAuthenticationPlugin.Components
{
    public enum AuthnBinding
    {
        IDP_Initiated = 1,
        Redirect = 2,
        POST = 4,
        SignedRedirect = 8,
        SignedPOST = 16,
    }
}
