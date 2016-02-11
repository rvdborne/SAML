using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace Telligent.Services.SamlAuthenticationPlugin.Components
{
    [Serializable]
    public class SamlAttribute
    {
        public SamlAttribute(){}
        public SamlAttribute(Claim claim)
        {
            ClaimType = claim.Type;
            Value = claim.Value;
            ValueType = claim.ValueType;
            Issuer = claim.Issuer;
            if (claim.Subject != null && !string.IsNullOrEmpty(claim.Subject.Name))
                SubjectName = claim.Subject.Name;
        }
        public SamlAttribute(System.IdentityModel.Tokens.SamlAttribute attribute)
        {
            ClaimType = attribute.Name;
            Value = attribute.AttributeValues[0];
            ValueType = "string";

            SubjectName = attribute.Namespace;
        }

        public static IEnumerable<SamlAttribute> SamlAttributeFromToken(System.IdentityModel.Tokens.SamlAttribute attribute)
        {
            var claims = attribute.AttributeValues.Select(value => new SamlAttribute()
                                                                       {
                                                                           ClaimType = attribute.Name, Value = value, ValueType = "string", SubjectName = attribute.Namespace
                                                                       }).ToList();

            return claims;
        }
        public static IEnumerable<SamlAttribute> SamlAttributeFromToken(System.IdentityModel.Tokens.Saml2Attribute attribute)
        {
            var claims = attribute.Values.Select(value => new SamlAttribute()
            {
                ClaimType = attribute.Name,
                Value = value,
                ValueType = "string",
                SubjectName = attribute.AttributeValueXsiType
            }).ToList();

            return claims;
        }
        public string ClaimType { get; set; }
        public string Value { get; set; }
        public string ValueType { get; set; }
        public string Issuer { get; set; }
        public string SubjectName { get; set; }
    }
}
