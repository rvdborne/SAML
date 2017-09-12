using System.IO;
using System.Text;

namespace Telligent.Services.SamlAuthenticationPlugin.Components
{
    internal static class EmbeddedResources
    {
        internal static string GetString(string path)
        {
            using (var stream = GetStream(path))
            {
                var data = new byte[stream.Length];
                stream.Read(data, 0, data.Length);
                var text = Encoding.UTF8.GetString(data);
                return text[0] > 255 ? text.Substring(1) : text;
            }
        }

        internal static Stream GetStream(string path)
        {
            if (typeof(SamlOAuthClient).Assembly.GetManifestResourceInfo(path) != null)
                return typeof(SamlOAuthClient).Assembly.GetManifestResourceStream(path);
            else
                return null;
        }
    }
}
