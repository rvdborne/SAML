using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Web;
using System.Xml;
using Telligent.Evolution.Extensibility;
using Telligent.Evolution.Extensibility.Api.Version1;
using Telligent.Evolution.Extensibility.Version1;

namespace Verint.Services.SamlAuthenticationPlugin.Components
{
    public class SamlAuthnHandler : IHttpHandler

    {
        private const string SamlRequestTemplate = "<samlp:AuthnRequest ID=\"{0}\" Version=\"2.0\" IssueInstant=\"{1}\" Destination=\"{2}\" Consent=\"urn:oasis:names:tc:SAML:2.0:consent:unspecified\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" AssertionConsumerServiceIndex=\"0\" AttributeConsumingServiceIndex=\"0\"><saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">{3}</saml:Issuer><samlp:NameIDPolicy AllowCreate=\"true\" /></samlp:AuthnRequest>";
        //note old code had this in place of "Consent" ForceAuthn="false" IsPassive="false" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{url that accepts saml tokens}"
        private const string WsFederationSignInTemplate = "{0}?wa=wsignin1.0&wtrealm={1}&wreply={2}";
        private const string SamlHandlerContent = "<html><head><title>Working...</title></head><body><form method='POST' name='hiddenform' action='{0}'><input type='hidden' name='SAMLRequest' value='{1}' /><noscript><p>Script is disabled. Click Submit to continue.</p><input type='submit' value='Submit' /></noscript></form><script language='javascript'>window.setTimeout('document.forms[0].submit()', 0);</script></body></html>";


        #region IHttpHandler Members

        public bool IsReusable { get { return true; } }

        public void ProcessRequest(HttpContext context)
        {
            var returnUrl = "/";
            
            //protect against no httpcontext or cs context
            try
            {
                //exclude logout and register urls from setting the return url
                //grab the invitation key
                Guid? invitationKey = null;
                Guid parsedInvitationKey;
                //add user invitation guid if present...
                var i = SamlHelpers.GetInvitationKey();
                if (i != null)
                {
                    if (Guid.TryParse(i, out parsedInvitationKey))
                        invitationKey = parsedInvitationKey;
                }
                //note we still have the case where the invitation may be in the return url

                var returnUrlParam = context.Request.QueryString[SamlHelpers.ReturnUrlParameterName];
                if (string.IsNullOrEmpty(returnUrlParam))
                {
                    returnUrl = SamlHelpers.GetReturnUrl();
                }
                else if(IsValidReturnUrl(returnUrlParam)) //ignores pages like logout or register or errors
                {
                    returnUrl = context.Request[SamlHelpers.ReturnUrlParameterName];
                    //if there is more than one return url, just use the first
                    returnUrl = returnUrl.Split(',')[0];
                }
                SamlHelpers.SetCookieReturnUrl(returnUrl, invitationKey);
            }
            catch (Exception ex)
            {
                Apis.Get<IEventLog>().Write("Error Creating SAML return URL cookie:" + ex, new EventLogEntryWriteOptions{ Category= "SAML", EventType= "Error", EventId = 1000});
            }


            var samlPlugin = PluginManager.GetSingleton<SamlOAuthClient>();
            if (samlPlugin == null)
                throw new InvalidOperationException("Unable to load the SamlAuthentication plugin; saml logins are not supported in the current configuration");

            var requestId = "_" + Guid.NewGuid().ToString();
            var issuerUrl = Apis.Get<IUrl>().Absolute(Apis.Get<ICoreUrls>().Home());


            //if (samlPlugin.IdpBindingType == SamlBinding.SAML11_POST && (samlPlugin.IdpAuthRequestType != AuthnBinding.IDP_Initiated) || (samlPlugin.IdpAuthRequestType != AuthnBinding.WSFededation))
            //    throw new NotSupportedException("Only bare get requests (without querystring or signature) are supported by the SAML 11 AuthN handler at this time");


            switch(samlPlugin.IdpAuthRequestType)
            {
                case AuthnBinding.WSFededation:
                    context.Response.Redirect(string.Format(WsFederationSignInTemplate, samlPlugin.IdpUrl, HttpUtility.UrlEncode(Apis.Get<IUrl>().Absolute("~/")), HttpUtility.UrlEncode(Apis.Get<IUrl>().Absolute("~/samlresponse"))));
                    HttpContext.Current.ApplicationInstance.CompleteRequest();
                    break;

                case AuthnBinding.IDP_Initiated:
                    context.Response.Redirect(samlPlugin.IdpUrl, false);
                    HttpContext.Current.ApplicationInstance.CompleteRequest();
                    break;

                case AuthnBinding.Redirect: 
                    context.Response.Redirect(samlPlugin.IdpUrl + "?SAMLRequest=" + HttpUtility.UrlEncode(ZipStr(GetSamlAuthnBase64(requestId, samlPlugin.IdpUrl, issuerUrl))) + "&RelayState=" + HttpUtility.UrlEncode("/SamlLogin?ReturnUrl=" + returnUrl), false);
                    HttpContext.Current.ApplicationInstance.CompleteRequest();
                    break;

                case AuthnBinding.SignedRedirect:
                    var redirectThumbprint = samlPlugin.AuthNCertThumbprint;

                    if (string.IsNullOrEmpty(redirectThumbprint))
                        throw new ArgumentNullException("Invalid configuration, the SAML Plugin is set to sign AuthN requests, but no certificate thumbprint is configured", "samlPlugin.AuthNCertThumbrint");
                    
                    throw new NotImplementedException();
                    //break;

                case AuthnBinding.POST:
                    var authXML = GetSamlAuthnXml(requestId, samlPlugin.IdpUrl, issuerUrl);
                    ValidateXML(authXML);
                    POSTAuthNRequest(samlPlugin.IdpUrl, authXML);
                    break;

                case AuthnBinding.SignedPOST:
                    var postThumbprint = samlPlugin.AuthNCertThumbprint;

                    if (string.IsNullOrEmpty(postThumbprint))
                        throw new ArgumentNullException("Invalid configuration, the SAML Plugin is set to sign AuthN requests, but no certificate thumbprint is configured", "samlPlugin.AuthNCertThumbrint");


                    var signedAuthXML = GetSamlAuthnXml(requestId, samlPlugin.IdpUrl, issuerUrl, postThumbprint);
                    ValidateXML(signedAuthXML);
                    POSTAuthNRequest(samlPlugin.IdpUrl, signedAuthXML);
                    break;

            }
        }

        private void ValidateXML(string authNXml)
        {
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.LoadXml(authNXml);

            var signatureNode = xmlDoc.SelectSingleNode("//*[local-name()='Signature']");
            if (signatureNode != null)
            {
                //check the attribute of the SignatureMethod node if present, should have a property called Algorithm
                //<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>

                var signatureMethodNode = xmlDoc.SelectSingleNode("//*[local-name()='SignatureMethod']");
                if (signatureMethodNode.Attributes["Algorithm"] == null)
                    throw new NullReferenceException("The XML AuthN signature did not contain a valid SignatureMethod node");
            }
        }


        #endregion

        #region Helpers



        private string GetSamlAuthnXml(string requestId, string _identityProviderUrl, string _issuerUrl, string thumbprint = null)
        {
            var currentDateUtc = DateTime.SpecifyKind(DateTime.UtcNow, DateTimeKind.Utc);
            var authNXml = string.Format(
                    SamlRequestTemplate,
                    requestId,
                    currentDateUtc.ToString("o"),//DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss"), //DateTime.UtcNow.ToString("yyyy-MM-ddTHH:MM:ss.fffZ"),
                    _identityProviderUrl,
                    _issuerUrl);

            if(!string.IsNullOrEmpty(thumbprint))
            {
                var cert = GetSigningKey(thumbprint);

                authNXml = SignAuthN(authNXml, requestId, cert);
            }

            return authNXml;
        }

        private void POSTAuthNRequest(string idpUrl, string authXML)
        {
            // Redirect the request to the SAML STS
            string finalisedRedirectString = string.Format(
                SamlHandlerContent,
                idpUrl,
                ToBase64(authXML));

            HttpContext.Current.Response.Write(finalisedRedirectString);
            HttpContext.Current.ApplicationInstance.CompleteRequest();
        }

        private byte[] GetSamlAuthnBase64(string requestId, string _identityProviderUrl, string _issuerUrl, string thumbprint = null)
        {
            var samlXml = GetSamlAuthnXml(requestId, _identityProviderUrl, _issuerUrl, thumbprint);
            var bytes = System.Text.Encoding.UTF8.GetBytes(samlXml);
            return bytes;
        }

        private string ToBase64(string xml)
        {
            return System.Convert.ToBase64String(
                System.Text.Encoding.UTF8.GetBytes(xml));
        }

        public static string ZipStr(byte[] bytes)
        {
            string base64String;
            using (var output = new MemoryStream())
            {
                using (var gzip =
                    new DeflateStream(output, CompressionMode.Compress))
                {
                    gzip.Write(bytes,0,bytes.Length);
                }
                base64String = Convert.ToBase64String(output.ToArray());
            }

            return base64String;
        }

        public static string UnZipStr(byte[] input)
        {
            using (MemoryStream inputStream = new MemoryStream(input))
            {
                using (DeflateStream gzip =
                  new DeflateStream(inputStream, CompressionMode.Decompress))
                {
                    using (StreamReader reader =
                      new StreamReader(gzip, System.Text.Encoding.UTF8))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }
        }

        private X509Certificate2 GetSigningKey(string thumbprint)
        {
            X509Store store = new X509Store("MY", StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
            if (collection.Count < 1)
                throw new ArgumentException("Unable to locate any certificates in MY store on the local machine; unable to sign authnrequest", "thumbprint");

            X509Certificate2Collection fcollection = (X509Certificate2Collection)collection.Find(X509FindType.FindByThumbprint, thumbprint, false);

            if (fcollection.Count < 1)
                throw new ArgumentException(string.Format("Unable to locate certificate in MY store (local mahcine account) based on the thumbprint '{0}'; unable to sign authnrequest", thumbprint), "thumbprint");

            return fcollection[0];

        }

        private string SignAuthN(string authNXml, string requestId, X509Certificate2 requestSigningCert)
        {
            if (string.IsNullOrEmpty(authNXml))
                throw new ArgumentNullException("authNXml");

            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.LoadXml(authNXml);
            
            SignedXml signedXml = new SignedXml(xmlDoc);

            KeyInfo keyInfo = new KeyInfo();

            keyInfo.AddClause(new KeyInfoX509Data(requestSigningCert));

            signedXml.KeyInfo = keyInfo;

            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            RSACryptoServiceProvider rsaKey = (RSACryptoServiceProvider)requestSigningCert.PrivateKey;

            signedXml.SigningKey = rsaKey;

            // Create a reference to be signed.
            Reference reference = new Reference();
            reference.Uri = "#" + requestId;

            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            XmlDsigExcC14NTransform c16n = new XmlDsigExcC14NTransform();
            c16n.InclusiveNamespacesPrefixList = "#default samlp saml ds xs xsi";
            reference.AddTransform(c16n);

            signedXml.AddReference(reference);

            signedXml.ComputeSignature();

            XmlElement xmlDigitalSignature = signedXml.GetXml();

            xmlDoc.DocumentElement.InsertAfter(xmlDoc.ImportNode(xmlDigitalSignature, true), xmlDoc.DocumentElement.FirstChild);  //signature to be second node after saml:Issuer

            return xmlDoc.OuterXml;
        }

        private bool IsValidReturnUrl(string returnUrl)
        {
            var apiCoreUrls = Apis.Get<ICoreUrls>();
            if (!string.IsNullOrEmpty(returnUrl)
                && !(
                        returnUrl.IndexOf("MessageID") != -1
                        || returnUrl.IndexOf(apiCoreUrls.Banned()) != -1
                        || returnUrl.IndexOf(apiCoreUrls.NotFound()) != -1
                        || returnUrl.IndexOf("changepassword") != -1
                        || returnUrl.IndexOf("emailforgottenpassword") != -1
                        || returnUrl.IndexOf("/samlauthn") != -1
                        || returnUrl.IndexOf("/samlresponse") != -1
                        || returnUrl.IndexOf("/oauth") != -1
                        || returnUrl.IndexOf("/login") != -1
                        || returnUrl.IndexOf("/logout") != -1
                        || returnUrl.IndexOf("/samllogout") != -1
                    )
                )
                return true;

            return false;

        }


        #endregion
    }
}
