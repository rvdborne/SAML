using System;
using System.Collections.Generic;
using System.IO;
using Telligent.Evolution.Extensibility.Configuration.Version1;

namespace Verint.Services.SamlAuthenticationPlugin.Components
{
    public class CleanThumbprintRule : IPropertyRule
    {
        private string CleanThumbprint(string thumbprints)
        {
            var cleanedThumbprints = new List<string>();
            foreach (var thumbprint in thumbprints.Split(','))
            {
                var arr = thumbprint.ToCharArray();

                //faster than a regex
                arr = Array.FindAll<char>(arr, (c => (char.IsLetterOrDigit(c))));

                cleanedThumbprints.Add(new string(arr));
            }
            return string.Join(",", cleanedThumbprints.ToArray());
        }

        public void Initialize(){}

        public string Name => "SAML Clean Thumbprint Rule";
        public string Description => "Validates that the thumbprint contains valid characters.";
        public void Render(TextWriter writer, IPropertyRuleRenderingOptions options)
        {
            
        }

        public void Execute(IPropertyRuleExecutionOptions options)
        {
            if (options.GetValue(options.Property.Id) is string value)
                options.SetValue(options.Property.Id, CleanThumbprint(value.Trim()));
        }

        public string[] DataTypes => new[] {"string"};
        public string RuleName => "cleanthumbprint";
        public PropertyRuleOption[] Options => null;
    }
}
