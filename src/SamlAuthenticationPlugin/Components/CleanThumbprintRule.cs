using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Telligent.DynamicConfiguration.Components;

namespace Telligent.Services.SamlAuthenticationPlugin.Components
{
    public class CleanThumbprintRule : IPropertyRule
    {
        public void LoadConfiguration(PropertyRule rule, System.Xml.XmlNode node)
        {

        }

        /// <summary>
        /// Remove non printing characters such as byte order marks from certificate thumbprints
        /// </summary>
        /// <param name="property"></param>
        /// <param name="data"></param>
        public void ValueChanged(Property property, ConfigurationDataBase data)
        {
            if (property.DataType != PropertyType.String)
                return;

            var value = data.GetStringValue(property);
            if (!string.IsNullOrEmpty(value))
                data.SetStringValue(property, CleanThumbprint(value.Trim()));
        }

        private string CleanThumbprint(string thumbprints)
        {
            List<string> cleanedThumbprints = new List<string>();
            foreach (var thumbprint in thumbprints.Split(','))
            {
                char[] arr = thumbprint.ToCharArray();

                //faster than a regex
                arr = Array.FindAll<char>(arr, (c => (char.IsLetterOrDigit(c))));

                cleanedThumbprints.Add(arr.ToString());
            }
            return string.Join(",", cleanedThumbprints.ToArray());
        }

    }
}
