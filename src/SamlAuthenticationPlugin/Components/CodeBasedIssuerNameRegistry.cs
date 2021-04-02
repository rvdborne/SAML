using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Linq;

namespace Verint.Services.SamlAuthenticationPlugin.Components
{
    /// <summary>
    /// A replacement for the stock ConfigurationBasedIssuerNameRegistery with "slightly" better error messages and a simplified constructor.
    /// </summary>
    public class CodeBasedIssuerNameRegistry : IssuerNameRegistry
    {

        private Dictionary<string, string> _configuredTrustedIssuers = new Dictionary<string, string>(new ThumbprintKeyComparer());

        public CodeBasedIssuerNameRegistry(IEnumerable<string> thumbprints)
        {
            foreach (string thumbprint in thumbprints)
                AddTrustedIssuer(thumbprint);
        }

        // Methods
        private void AddTrustedIssuer(string certificateThumbprint)
        {
            if (string.IsNullOrEmpty(certificateThumbprint))
            {
                throw new ArgumentNullException("certificateThumbprint");
            }
            
            if (!this._configuredTrustedIssuers.ContainsKey(certificateThumbprint))
                this._configuredTrustedIssuers.Add(certificateThumbprint, certificateThumbprint);
        }

        public override string GetIssuerName(SecurityToken securityToken)
        {
            if (securityToken == null)
            {
                throw new ArgumentNullException("securityToken");
            }
            X509SecurityToken token = securityToken as X509SecurityToken;
            if (token != null)
            {
                string thumbprint = token.Certificate.Thumbprint;

                if (this._configuredTrustedIssuers.ContainsKey(thumbprint))
                {
                    string str2 = this._configuredTrustedIssuers[thumbprint];
                    str2 = string.IsNullOrEmpty(str2) ? token.Certificate.Subject : str2;
                    return str2;
                }


                throw new KeyNotFoundException(string.Format("Could not find Thumbprint '{0}' in trusted issuers list : {1}  :: Char Codes {2} vs {3}", thumbprint, string.Join(",", _configuredTrustedIssuers.Keys.ToArray<string>()), SamlHelpers.ToCompositeString(thumbprint), SamlHelpers.ToCompositeString(string.Join(",", _configuredTrustedIssuers.Keys.ToArray<string>()))));
            }

            //Throw our own exception to make it easier to debug
            throw new ArgumentException("Unable to validate token issuer the provided token was not a X509SecurityToken; cant determine the thumbprint to match", "securityToken");

        }


        private class ThumbprintKeyComparer : IEqualityComparer<string>
        {
            // Methods
            public bool Equals(string x, string y)
            {
                return StringComparer.OrdinalIgnoreCase.Equals(x, y);
            }

            public int GetHashCode(string obj)
            {
                return obj.ToUpper(CultureInfo.InvariantCulture).GetHashCode();
            }
        }

    }



 

}
