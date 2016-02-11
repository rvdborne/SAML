using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Telligent.Services.SamlAuthenticationPlugin.Components
{
    public enum SubjectRecipientValidationMode
    {
        ExactMatch = 1,
        HostOnly = 2,
        HostAndScheme = 4,
        None = 8,

    }
}
