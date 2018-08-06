using System;
using System.IO;
using System.Web;
using Telligent.Evolution.Extensibility;
using Telligent.Evolution.Extensibility.Api.Version1;
using Telligent.Evolution.Extensibility.Version1;
using Telligent.Services.SamlAuthenticationPlugin.Extensibility;

namespace Telligent.Services.SamlAuthenticationPlugin.Components
{
    public class SamlResponseHandler : IHttpHandler
    {
        #region IHttpHandler Members

        public bool IsReusable => true;

        public void ProcessRequest(HttpContext context)
        {
            var samlPlugin = PluginManager.GetSingleton<SamlOAuthClient>();
            if (samlPlugin == null || !samlPlugin.Enabled)
                throw new InvalidOperationException("Unable to load the SamlAuthentication plugin; saml logins are not supported in the current configuration");

            if (SamlHelpers.IsSignInResponse)
            {

                //use httpcontextuser is set to true, so this code below will only ever fire if there is a HttpContextUser set
                SamlTokenData samlTokenData = null;

                if (!SamlHelpers.IsSignInResponse)
                    throw new NotSupportedException("Unable to detect a saml response; please check your identity provider is configured properly");

                //This call gets the saml token from the response, validates it and turns it into our internal class for use and storage
                samlTokenData = samlPlugin.TokenProcessor.GetSamlTokenData();

                if (samlTokenData == null)
                    throw new InvalidOperationException("No valid saml token was decected, login failed");

                if (samlTokenData.IsExistingUser())
                {
                    if (samlPlugin.PersistClaims)
                        SqlData.SaveSamlToken(samlTokenData);

                    //since new users will have oauth links auto created, we only run this code for existing users
                    var samlOAuthLinkManager = PluginManager.GetSingleton<ISamlOAuthLinkManager>();
                    if (samlOAuthLinkManager != null && samlOAuthLinkManager.Enabled)
                    {
                        // makes sure the user is not prompted to "link accounts" during the login form
                        //if there is no suitable entry in the te_OAuth_Links table
                        samlOAuthLinkManager.EnsureOAuthLink(samlTokenData);
                    }
                }

                //Store out the SAML Token Data in an encrypted cookie for use on the OAuth endpoint which requires a GET request
                var tokenKey = samlTokenData.SaveToSecureCookie();


                //build the oauth url based on the current url
                UriBuilder oAuthUrl = new UriBuilder(context.Request.Url);
                oAuthUrl.Path = oAuthUrl.Path.Replace("samlresponse/", string.Format("oauth", samlPlugin.ClientType)).Replace("samlresponse", string.Format("oauth", samlPlugin.ClientType));

                var queryString = HttpUtility.ParseQueryString(oAuthUrl.Query);

                queryString.Add("type", samlPlugin.ClientType);
                queryString.Add(SamlOAuthClient.oauthTokeyQuerystringKey, tokenKey.ToString());

                //Invitation Key
                string invitationKey = SamlHelpers.GetInvitationKey();
                if (!String.IsNullOrEmpty(invitationKey) && !queryString.ToString().ToLower().Contains("invitationkey="))
                    queryString.Add(SamlHelpers.InvitationKeyParameterName, invitationKey);

                //Return Url  (note this must return back to the login page, the actual final return url should be double encoded)
                string returnUrl = GetReturnUrl();
                if (!String.IsNullOrEmpty(returnUrl) && !queryString.ToString().ToLower().Contains("returnurl="))
                    queryString.Add(SamlHelpers.ReturnUrlParameterName,string.Format("{0}&{1}={2}", samlPlugin.CallbackUrl ,SamlHelpers.ReturnUrlParameterName,returnUrl)); //the ToString of the queryString object will properly encode the &ReturnUrl

                oAuthUrl.Query = queryString.ToString();

                //Ensure HTTPS so our secure cookie can be read
                if (samlPlugin.SecureCookie || HttpContext.Current.Request.IsSecureConnection)
                {
                    oAuthUrl.Scheme = Uri.UriSchemeHttps;
                    oAuthUrl.Port = -1; // default port for scheme
                }

                //redirect to the oauth endpoint
                var url = oAuthUrl.Uri.AbsoluteUri;
                context.Response.Redirect(oAuthUrl.Uri.AbsoluteUri);
                context.ApplicationInstance.CompleteRequest();
                context.Response.End();

            }
            else if (SamlHelpers.IsSignOutResponse)
            {
                var platformLogout = PluginManager.GetSingleton<IPlatformLogout>();
                if (platformLogout == null || !platformLogout.Enabled)
                    throw new NotSupportedException("Unable to support WSFederation logouts without an appropriate IPlatformLogout plugin");

                platformLogout.Logout();

                context.Response.Clear();
                context.Response.Buffer = true;
                // Read the original file from disk
                Stream myFileStream = EmbeddedResources.GetStream("Telligent.Services.SamlAuthenticationPlugin.Resources.Images.oauth.gif");
                long FileSize = myFileStream.Length;
                byte[] Buffer = new byte[(int)FileSize];
                myFileStream.Read(Buffer, 0, (int)FileSize);
                myFileStream.Close();

                // Tell the browser stuff about the file
                context.Response.AddHeader("Content-Length", FileSize.ToString());
                context.Response.AddHeader("Content-Disposition", "inline; filename=oauth.gif");
                context.Response.ContentType = "image/gif";

                // Send the data to the browser
                context.Response.BinaryWrite(Buffer);
                context.ApplicationInstance.CompleteRequest();
                context.Response.End();
                return;
            }

            //if this is not a sign-in response, we should probably redirect to login.aspx
            throw new ArgumentException("The SAML token was not found in the HttpContext.Current.Request, please check the configuration and try again");


        }

        internal string GetReturnUrl()
        {
            string returnUrl = SamlHelpers.GetCookieReturnUrl();

            SamlHelpers.ClearCookieReturnUrl();

            if (string.IsNullOrEmpty(returnUrl))
            {
                returnUrl = Apis.Get<IUrl>().Absolute(Apis.Get<ICoreUrls>().Home());
            }

            return returnUrl;
        }

        #endregion

    }
}
