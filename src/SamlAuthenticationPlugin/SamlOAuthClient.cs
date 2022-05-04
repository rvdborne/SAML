using System;
using System.Collections.Generic;
using System.ServiceModel.Security;
using System.Web;
using System.Xml;
using Telligent.Evolution.Extensibility;
using Telligent.Evolution.Extensibility.Api.Version1;
using Telligent.Evolution.Extensibility.Authentication.Version1;
using Telligent.Evolution.Extensibility.Configuration.Version1;
using Telligent.Evolution.Extensibility.UI.Version1;
using Telligent.Evolution.Extensibility.Version1;
using Telligent.Evolution.Extensibility.Urls.Version1;
using Verint.Services.SamlAuthenticationPlugin.Components;
using Verint.Services.SamlAuthenticationPlugin.Extensibility.Events;
using IPluginConfiguration = Telligent.Evolution.Extensibility.Version2.IPluginConfiguration;
using IRequiredConfigurationPlugin = Telligent.Evolution.Extensibility.Version2.IRequiredConfigurationPlugin;

namespace Verint.Services.SamlAuthenticationPlugin  
{

    public class SamlOAuthClient : IScriptedContentFragmentFactoryDefaultProvider, IRequiredConfigurationPlugin, INavigable, ITokenProcessorConfiguration, IOAuthClient, IInstallablePlugin, ICategorizedPlugin, ISingletonPlugin
    {
        #region Defaults

        public static List<string> PluginCategories = new List<string> { "SAML", "OAuth" }; //leverage this for extensions to make them easier to find

        private const string _idpUrlDefault = "";
        private const SamlBinding _idpBindingTypeDefault = SamlBinding.SAML20_POST;
        private const string _issuerUrlDefault = "";
        private const string _issuerThumbprintDefault = "";
        private const X509CertificateValidationMode _issuerCertificateValidationModeDefault = X509CertificateValidationMode.None;
        private const AuthnBinding _idpAuthRequestTypeDefault = AuthnBinding.IDP_Initiated;
        private const string _authThumbprintDefault = "";
        private const string _usernameClaimDefault = "name";
        private const string _emailClaimDefault = "email";
        private const string _logoutUrlDefault = "";
        private const string _iconUrlDefault = "";
        private const LogoutUrlBehavior _logoutUrlBehaviorDefault = LogoutUrlBehavior.INTERNAL;
        private const SubjectRecipientValidationMode _subjectRecipientValidationModeDefault = SubjectRecipientValidationMode.ExactMatch;
        private const bool _allowTokenMatchingByEmailAddressDefault = true;
        private const bool _allowAutoUserRegistrationDefault = true;
        internal const string oauthTokeyQuerystringKey = "saml_data_token_key";

        #endregion

        #region IPlugin

        public string Name => "SAML Authentication OAuth Client";

        public string Description => "Allows single-sign-on by converting SAML Tokens into OAuth tokens.";

        public void Initialize()
        {
            var usersApi = Apis.Get<IUsers>();

            //hook the user created event to save SAML token data (from secure cookie if persist flag is set) for new users
            usersApi.Events.AfterCreate += Events_AfterUserCreate;

            //hook to create custom user authenticated event
            usersApi.Events.AfterIdentify += Events_AfterIdentify;

            //cleanup persistant storage when a user is deleted
            usersApi.Events.AfterDelete += Events_AfterUserDelete;

        }

        #endregion

        #region Configuration

        public bool IsConfigured
        {
            get
            {
                if (string.IsNullOrEmpty(UserNameAttributeName))
                    return false;

                if (string.IsNullOrEmpty(this.IdpUrl))
                    return false;

                if (string.IsNullOrEmpty(this.TrustedIssuerThumbprint))
                    return false;

                return true;
            }
        }

        protected IPluginConfiguration Configuration
        {
            get;
            private set;
        }
        
        public void Update(IPluginConfiguration configuration)
        {
            Configuration = configuration;
            //clientType = SamlCookieName;
            tokenProcessor = null; //reset the security token handler so we can regen it
        }

        public PropertyGroup[] ConfigurationOptions
        {
            get
            {
                var groups = new[]
                {
                    new PropertyGroup{Id = "issuer", LabelText = "Issuer", OrderNumber = 0},
                    new PropertyGroup{Id = "auth", LabelText = "AuthN", OrderNumber = 1},
                    new PropertyGroup{Id = "logout", LabelText = "Logout", OrderNumber = 2},
                    new PropertyGroup{Id = "options", LabelText = "Options", OrderNumber = 3}
                };

                #region Issuer

                var idpUrl = new Property { Id = "idpUrl", LabelText = "The SAML Identity Provider URL", DataType = "String", OrderNumber = 10, DefaultValue = _idpUrlDefault};
                idpUrl.Rules.Add(new PropertyRule{Name = "trim"});
                groups[0].Properties.Add(idpUrl);

                var idpBindingType = new Property
                {
                    Id = "idpBindingType", 
                    LabelText = "The SAML Binding Type Used by the Identity Provider", 
                    DataType = "String", 
                    OrderNumber = 20, 
                    DefaultValue = _idpBindingTypeDefault.ToString()
                };
                idpBindingType.SelectableValues.Add(new PropertyValue
                {
                    LabelText = SamlBinding.SAML11_POST.ToString(), 
                    Value = SamlBinding.SAML11_POST.ToString(), 
                    OrderNumber = 1
                });
                idpBindingType.SelectableValues.Add(new PropertyValue
                {
                    LabelText = SamlBinding.SAML20_POST.ToString(), 
                    Value = SamlBinding.SAML20_POST.ToString(), 
                    OrderNumber = 2
                });
                groups[0].Properties.Add(idpBindingType);

                var issuerThumbprint = new Property
                {
                    Id = "issuerThumbprint", 
                    LabelText = "Issuer Certificate Thumbprints", 
                    DataType = "String", 
                    OrderNumber = 30, 
                    DefaultValue = _issuerThumbprintDefault,
                    DescriptionText = "A comma seperated list of thumbprints used by the trusted issuer(s) (used to validate the SAML token)"
                };
                issuerThumbprint.Rules.Add(new PropertyRule{Name = "cleanthumbprint" });
                groups[0].Properties.Add(issuerThumbprint);

                var issuerCertificateValidationMode = new Property
                {
                    Id = "issuerCertificateValidationMode", 
                    LabelText = "Issuer Certificate Validation Mode", 
                    DataType = "String", 
                    OrderNumber = 40, 
                    DefaultValue = _issuerCertificateValidationModeDefault.ToString(),
                    DescriptionText = "Validation of the SAML signing certificate issuer"
                }; 
                issuerCertificateValidationMode.SelectableValues.Add(new PropertyValue
                {
                    LabelText = X509CertificateValidationMode.ChainTrust.ToString(), 
                    Value = X509CertificateValidationMode.ChainTrust.ToString(), 
                    OrderNumber = 1
                });
                issuerCertificateValidationMode.SelectableValues.Add(new PropertyValue
                {
                    LabelText = X509CertificateValidationMode.PeerOrChainTrust.ToString(),
                    Value = X509CertificateValidationMode.PeerOrChainTrust.ToString(),
                    OrderNumber = 2
                });
                issuerCertificateValidationMode.SelectableValues.Add(new PropertyValue
                {
                    LabelText = X509CertificateValidationMode.PeerTrust.ToString(),
                    Value = X509CertificateValidationMode.PeerTrust.ToString(),
                    OrderNumber = 3
                });
                issuerCertificateValidationMode.SelectableValues.Add(new PropertyValue
                {
                    LabelText = X509CertificateValidationMode.None.ToString(),
                    Value = X509CertificateValidationMode.None.ToString(),
                    OrderNumber = 4
                });
                groups[0].Properties.Add(issuerCertificateValidationMode);


                var subjectRecipientValidationMode = new Property
                {
                    Id = "subjectRecipientValidationMode", 
                    LabelText = "Token Subject Recipient Validation Mode",
                    DataType = "String",
                    OrderNumber = 50,
                    DefaultValue = _subjectRecipientValidationModeDefault.ToString(),
                    DescriptionText = "Rules to use for validation of SAML Token Subject Recipient clause"
                };
                subjectRecipientValidationMode.SelectableValues.Add(new PropertyValue
                {
                    LabelText = SubjectRecipientValidationMode.ExactMatch.ToString(),
                    Value = SubjectRecipientValidationMode.ExactMatch.ToString(),
                    OrderNumber = 1
                });
                subjectRecipientValidationMode.SelectableValues.Add(new PropertyValue
                {
                    LabelText = SubjectRecipientValidationMode.HostOnly.ToString(),
                    Value = SubjectRecipientValidationMode.HostOnly.ToString(),
                    OrderNumber = 2
                });
                subjectRecipientValidationMode.SelectableValues.Add(new PropertyValue
                {
                    LabelText = SubjectRecipientValidationMode.HostAndScheme.ToString(),
                    Value = SubjectRecipientValidationMode.HostAndScheme.ToString(),
                    OrderNumber = 3
                });
                subjectRecipientValidationMode.SelectableValues.Add(new PropertyValue
                {
                    LabelText = SubjectRecipientValidationMode.None.ToString(),
                    Value = SubjectRecipientValidationMode.None.ToString(),
                    OrderNumber = 4
                });
                groups[0].Properties.Add(subjectRecipientValidationMode);

                var usernameClaim = new Property
                {
                    Id = "usernameClaim",
                    LabelText = "User Name Attribute Name",
                    DataType = "String",
                    OrderNumber = 60,
                    DefaultValue = _usernameClaimDefault,
                    DescriptionText = "The name saml attribute containing the users name. (Must be present, must be unique, must be valid based on community settings.)"
                };
                usernameClaim.Rules.Add(new PropertyRule{Name = "trim"});
                groups[0].Properties.Add(usernameClaim);

                var emailClaim = new Property
                {
                    Id = "emailClaim",
                    LabelText = "Email Address Attribute name",
                    DataType = "String",
                    OrderNumber = 70,
                    DefaultValue = _emailClaimDefault,
                    DescriptionText = "The name saml attribute containing the users email address. (Must be present, must be unique.)"
                };
                emailClaim.Rules.Add(new PropertyRule{Name = "trim"});
                groups[0].Properties.Add(emailClaim);

                #endregion

                #region AuthN

                var idpAuthRequestType = new Property
                {
                    Id = "idpAuthRequestType",
                    LabelText = "AuthN Binding Type",
                    DataType = "String",
                    OrderNumber = 100,
                    DefaultValue = _idpAuthRequestTypeDefault.ToString(),
                    DescriptionText = "The AuthN request type to intiate the saml login (IDP_Initiated is a simple redirect without AuthN payload)"
                };
                idpAuthRequestType.SelectableValues.Add(new PropertyValue
                {
                    LabelText = AuthnBinding.IDP_Initiated.ToString(),
                    Value = AuthnBinding.IDP_Initiated.ToString(),
                    OrderNumber = 1
                });
                idpAuthRequestType.SelectableValues.Add(new PropertyValue
                {
                    LabelText = AuthnBinding.Redirect.ToString(),
                    Value = AuthnBinding.Redirect.ToString(),
                    OrderNumber = 2
                });
                //idpAuthRequestType.SelectableValues.Add(new PropertyValue
                //{
                //  LabelText = AuthnBinding.SignedRedirect.ToString(),
                //  Value = AuthnBinding.SignedRedirect.ToString(),
                //  OrderNumber = 3
                //});//not yet supported
                idpAuthRequestType.SelectableValues.Add(new PropertyValue
                {
                    LabelText = AuthnBinding.POST.ToString(),
                    Value = AuthnBinding.POST.ToString(),
                    OrderNumber = 4
                });
                idpAuthRequestType.SelectableValues.Add(new PropertyValue
                {
                    LabelText = AuthnBinding.SignedPOST.ToString(),
                    Value = AuthnBinding.SignedPOST.ToString(),
                    OrderNumber = 5
                });
                idpAuthRequestType.SelectableValues.Add(new PropertyValue
                {
                    LabelText = AuthnBinding.WSFededation.ToString(),
                    Value = AuthnBinding.WSFededation.ToString(),
                    OrderNumber = 6
                });
                groups[1].Properties.Add(idpAuthRequestType);

                var authThumbprint = new Property
                {
                    Id = "authThumbprint",
                    LabelText = "AuthN Certificate Thumbprint",
                    DataType = "String",
                    OrderNumber = 110,
                    DefaultValue = _authThumbprintDefault,
                    DescriptionText = "The Thumbprint of a private key located in the localmachine/personal store, for which the applicaiton pool user has been given permissions; required for signed AuthN request types"
                };
                authThumbprint.Rules.Add(new PropertyRule { Name = "cleanthumbprint" });
                groups[1].Properties.Add(authThumbprint);


                #endregion

                #region Logout

                var logoutUrlBehavior = new Property
                {
                    Id = "logoutUrlBehavior",
                    LabelText = "Logout Behavior",
                    DataType = "String",
                    OrderNumber = 200,
                    DefaultValue = "_logoutUrlBehaviorDefault.ToString()",
                    DescriptionText = "Controls how the site uses the logout Url (Internal the URL is not used or required; the default platform logout is used)"
                };
                logoutUrlBehavior.SelectableValues.Add(new PropertyValue
                {
                    LabelText = LogoutUrlBehavior.INTERNAL.ToString(),
                    Value = LogoutUrlBehavior.INTERNAL.ToString(),
                    OrderNumber = 1
                });
                logoutUrlBehavior.SelectableValues.Add(new PropertyValue
                {
                    LabelText = LogoutUrlBehavior.EXTERNAL.ToString(),
                    Value = LogoutUrlBehavior.EXTERNAL.ToString(),
                    OrderNumber = 2
                });
                logoutUrlBehavior.SelectableValues.Add(new PropertyValue
                {
                    LabelText = LogoutUrlBehavior.IFRAME.ToString(),
                    Value = LogoutUrlBehavior.IFRAME.ToString(),
                    OrderNumber = 3
                });
                groups[2].Properties.Add(logoutUrlBehavior);

                var logoutUrl = new Property
                {
                    Id = "logoutUrl",
                    LabelText = "Identity Provider Logout Url",
                    DataType = "String",
                    DefaultValue = _logoutUrlDefault,
                    DescriptionText = "Identity Provider Logout Url (used by Iframe or external options)"
                };
                logoutUrl.Rules.Add(new PropertyRule {Name = "trim"});
                groups[2].Properties.Add(logoutUrl);

                #endregion

                #region Options

                var allowTokenMatchingByEmailAddress = new Property
                {
                    Id = "allowTokenMatchingByEmailAddress",
                    LabelText = "Lookup Users By Email",
                    DataType = "Bool",
                    OrderNumber = 50,
                    DefaultValue = _allowTokenMatchingByEmailAddressDefault.ToString(),
                    DescriptionText = "Allow the email address to be used to locate an existing user account if the username does not match."
                };
                groups[3].Properties.Add(allowTokenMatchingByEmailAddress);

                var persistClaims = new Property
                {
                    Id = "persistClaims",
                    LabelText = "Persist Claims",
                    DataType = "Bool",
                    OrderNumber = 70,
                    DefaultValue = "false",
                    DescriptionText = "If checked, the claim collection will be stored in the database and be available during non login events."
                };
                groups[3].Properties.Add(persistClaims);

                var secureCookie = new Property
                {
                    Id = "secureCookie",
                    LabelText = "Force HTTPS",
                    DataType = "Bool",
                    OrderNumber = 80,
                    DefaultValue = "true",
                    DescriptionText = "If checked, saml token data will be passed using a secure only (https cookie) uncheck only if your site does not support HTTPS (less secure)."
                };
                groups[3].Properties.Add(secureCookie);

                var iconUrl = new Property
                {
                    Id = "iconUrl",
                    LabelText = "The URL for the OAuth image",
                    DataType = "String",
                    OrderNumber = 120,
                    DefaultValue = _iconUrlDefault,
                    DescriptionText = "Overrides the built in SAML oauth image"
                };
                iconUrl.Rules.Add(new PropertyRule{Name = "trim"});
                groups[3].Properties.Add(iconUrl);

                var cookieName = new Property
                {
                    Id = "samlCookieName",
                    LabelText = "SAML Cookie Name",
                    DataType = "String",
                    OrderNumber = 3,
                    DefaultValue = "saml"
                };
                groups[3].Properties.Add(cookieName);

                #endregion

                return groups;
            }
        }

        #endregion

        #region Lifecycle Events
        private void Events_AfterUserCreate(UserAfterCreateEventArgs e)
        {

            var afterCreatedCookie = CookieHelper.GetCookie(SamlCookieName);
            if (afterCreatedCookie == null) return;
            
            var samlTokenData = SamlTokenData.GetTokenDataFromDatabase(afterCreatedCookie.Value);
            if (samlTokenData == null) return; 

            //destroy secure cookie for new user if cookie is still present
            CookieHelper.DeleteCookie(afterCreatedCookie.Value);
            //also cleanup our afterCreatedCookie
            CookieHelper.DeleteCookie(afterCreatedCookie.Name);

            //update the samlTokenData now that we know the user ID and cleanup the cookie used by the login
            samlTokenData.UserId = e.Id.Value;

            //Update the cookie SAMLToken Data to have the UserId now that its an existing user to fire the after authenticated events (which also removes the cookie)
            var tokenKey = samlTokenData.SaveTokenDataToDatabase();
            var afterAuthenticatedCookie = new HttpCookie(clientType, tokenKey)
            {
                Expires = DateTime.Now.AddHours(8), 
                HttpOnly = true
            };
            CookieHelper.AddCookie(afterAuthenticatedCookie);

            if (PersistClaims)
            {
                SqlData.SaveSamlToken(samlTokenData);
            }

            var apiUser = Apis.Get<IUsers>().Get(new UsersGetOptions() { Id = e.Id.Value });

            //raise new SamlUserCreated Event
            try
            {
                SamlEvents.Instance.OnAfterUserCreate(apiUser, samlTokenData);
            }
            catch (Exception ex)
            {
                Apis.Get<IExceptions>().Log(ex);
                Apis.Get<IEventLog>().Write("SamlOAuthClient Error OnAfterUserCreate: " + ex.Message + " : " + ex.StackTrace, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 1, EventType = "Error"  });
            }

        }

        void Events_AfterIdentify(UserAfterIdentifyEventArgs e)
        {

            var context = HttpContext.Current;
            if (context == null) return;
            if (context.Request == null) return;
            if (!context.Request.IsAuthenticated) return;

            //filter some requests basic non UI requests
            if (context.Request.RawUrl.ToLower().StartsWith("/socket.ashx")) return;
            if (context.Request.RawUrl.ToLower().StartsWith("/webresource.axd")) return;
            if (context.Request.RawUrl.ToLower().StartsWith("/api.ashx")) return;
            if (context.Request.RawUrl.ToLower().StartsWith("/utility/")) return;
            if (context.Request.RawUrl.ToLower().StartsWith("/cfs-filesystemfile/")) return;
            if (context.Request.RawUrl.ToLower().StartsWith("/dynamic-style")) return;
            if (context.Request.RawUrl.ToLower().StartsWith("/favicon.ico")) return;
            if (context.Request.RawUrl.ToLower().EndsWith(".css")) return;

            //check to see if our Oauth ProcessLogin() cookie exists
            try
            {
                var afterAuthenticatedCookie = CookieHelper.GetCookie(clientType);
                if (afterAuthenticatedCookie == null) return;

                var samlTokenData = SamlTokenData.GetTokenDataFromDatabase(afterAuthenticatedCookie.Value);
                if (samlTokenData == null) return;

                if (!samlTokenData.IsExistingUser()) return;

                if (samlTokenData.UserId != e.Id.Value) return;  //check to see that the logged in user and ProcessLogin() user have the same ID;

                if (Guid.TryParse(afterAuthenticatedCookie.Value, out var tokenKey))
                    SamlTokenData.DeleteTokenDataFromDatabase(afterAuthenticatedCookie.Value);

                CookieHelper.DeleteCookie(afterAuthenticatedCookie.Value);
                CookieHelper.DeleteCookie(afterAuthenticatedCookie.Name);

                //Get the API user and the last SAML token to keep things API friendly
                var apiUser = Apis.Get<IUsers>().Get(new UsersGetOptions() { Id = e.Id.Value });

                SamlEvents.Instance.OnAfterAuthenticate(apiUser, samlTokenData);
            }
            catch (Exception ex)
            {
                Apis.Get<IExceptions>().Log(ex);
                Apis.Get<IEventLog>().Write("SamlOAuthClient Error OnAfterAuthenticate: " + ex.Message + " : " + ex.StackTrace, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 1, EventType = "Error" });
            }

        }

        private void Events_AfterUserDelete(UserAfterDeleteEventArgs e)
        {
            try
            {
                SqlData.DeleteSamlTokenData(e.Id.Value);
            }
            catch (Exception ex)
            {
                Apis.Get<IExceptions>().Log(ex);
                Apis.Get<IEventLog>().Write("SamlOAuthClient Error AfterUserDelete: " + ex.Message + " : " + ex.StackTrace, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 1, EventType = "Error" });
            }
        }

        #endregion

        #region Properties

        public string LoginUrl => SecureCookie ? Apis.Get<IUrl>().Absolute("~/samlauthn").Replace("http:", "https:") : Apis.Get<IUrl>().Absolute("~/samlauthn");
        public string IdpUrl => Configuration.GetString("idpUrl");
        public SamlBinding IdpBindingType => Enum.TryParse(Configuration.GetString("idpBindingType"), true, out SamlBinding configuredBinding) ? configuredBinding : _idpBindingTypeDefault;
        public AuthnBinding IdpAuthRequestType => Enum.TryParse<AuthnBinding>(Configuration.GetString("idpAuthRequestType"), true, out var configuredBinding) ? configuredBinding : _idpAuthRequestTypeDefault;
        public LogoutUrlBehavior LogoutUrlBehavior => Enum.TryParse<LogoutUrlBehavior>(Configuration.GetString("logoutUrlBehavior"), true, out var configuredBehavior) ? configuredBehavior : _logoutUrlBehaviorDefault;
        public string LogoutUrl => LogoutUrlBehavior == LogoutUrlBehavior.EXTERNAL ? IdpLogoutUrl : string.Empty;
        public string IdpLogoutUrl => IdpAuthRequestType == AuthnBinding.WSFededation ? $"{IdpUrl}?wa=wsignout1.0" : Configuration.GetString("logoutUrl");
        public string AuthNCertThumbprint => Configuration.GetString("authThumbprint");
        public string SamlCookieName => Configuration.GetString("samlCookieName");
        public string clientType => string.IsNullOrEmpty(Configuration.GetString("samlCookieName")) ? "saml" : Configuration.GetString("samlCookieName");


        /// <summary>
        /// This property is used by the platform to store the current url the user was on when they clicked login or register
        /// The platform code does not ever redirect the user to this URL, its up to the AuthenticationPlugin to handle redirection
        /// In our case its important that our AuthN handler packages this return url in a way that will persist though saml auth for use
        /// at the end of our AuthenticateRequest() method.
        /// </summary>
        public string ReturnUrlParameter => SamlHelpers.ReturnUrlParameterName;
        public bool AllowTokenMatchingByEmailAddress => Configuration.GetBool("allowTokenMatchingByEmailAddress").Value;
        //required by IAuthenticationPlugin
        public bool UseHttpContextUser => true;
        public string UserNameAttributeName => Configuration.GetString("usernameClaim");
        public string EmailAttributeName => Configuration.GetString("emailClaim");
        public bool PersistClaims => Configuration.GetBool("persistClaims").Value;
        public bool SecureCookie => Configuration.GetBool("secureCookie").Value;
        public X509CertificateValidationMode CertificateValidationMode => Enum.TryParse<X509CertificateValidationMode>(Configuration.GetString("issuerCertificateValidationMode"), true, out var configuredValidationMode) ? configuredValidationMode : _issuerCertificateValidationModeDefault;
        public SubjectRecipientValidationMode SubjectRecipientValidationMode => Enum.TryParse<SubjectRecipientValidationMode>(Configuration.GetString("subjectRecipientValidationMode"), true, out var configuredValidationMode) ? configuredValidationMode : _subjectRecipientValidationModeDefault;
        public string TrustedIssuerThumbprint => Configuration.GetString("issuerThumbprint");
        public int ProfileRefreshInterval => 1;
        
        object _lock = new object();

        private TokenProcessor tokenProcessor = null;
        public TokenProcessor TokenProcessor
        {
            get
            {
                if (tokenProcessor == null)
                {
                    lock (_lock)
                    {
                        if (tokenProcessor == null)
                        {
                            tokenProcessor = new TokenProcessor(this);
                        }
                    }
                }
                return tokenProcessor;
            }
        }

        #endregion

        #region INavigable

        public void RegisterUrls(IUrlController controller)
        {
            controller.AddRaw("samlresponse", "samlresponse", null, new { handlerHeader = new RequestTypeHandlerMethodConstraint("GET", "POST") },
               (c, p) =>
               {
                   var handler = new SamlResponseHandler();
                   handler.ProcessRequest(c.ApplicationInstance.Context);
               },
               new RawDefinitionOptions()
           );

            controller.AddRaw("samlauthn", "samlauthn", null, new { handlerHeader = new RequestTypeHandlerMethodConstraint("GET", "POST") },
               (c, p) =>
               {
                   var handler = new SamlAuthnHandler();
                   handler.ProcessRequest(c.ApplicationInstance.Context);
               },
               new RawDefinitionOptions()
           );

            controller.AddPage("saml-logout", "samllogout", null, null, "saml-logout", new PageDefinitionOptions() { DefaultPageXml = LoadPageXml("SamlLogout-Social-Site-Page") });



        }

        private static string LoadPageXml(string pageName)
        {
            var xml = new XmlDocument();
            xml.LoadXml(EmbeddedResources.GetString("Verint.Services.SamlAuthenticationPlugin.Resources.Pages." + pageName + ".xml"));
            var xmlNode = xml.SelectSingleNode("theme/contentFragmentPages/contentFragmentPage");
            return xmlNode != null ? xmlNode.OuterXml : string.Empty;
        }

        #endregion

        #region Authentication
        
        protected virtual void ProcessReturnUrl()
        {
            var apiCoreUrls = Apis.Get<ICoreUrls>();
            var returnUrl = SamlHelpers.GetCookieReturnUrl();

            SamlHelpers.ClearCookieReturnUrl();

            if (string.IsNullOrEmpty(returnUrl))
            {
                returnUrl = apiCoreUrls.Home();
            }

            if (!string.IsNullOrEmpty(returnUrl) && SamlHelpers.IsPathOnSameServer(returnUrl, HttpContext.Current.Request.Url))
                HttpContext.Current.Response.Redirect(returnUrl, true);

            HttpContext.Current.Response.Redirect(apiCoreUrls.Home(), true);
        }
        
        #endregion

        #region IOAuthClient

        /// <summary>
        /// Used if no returnurl is present on the querystring, its important that any return url points back to the login page
        /// For OAuth processing to work properly, any further reuturn url must be encoded
        /// </summary>
        public string CallbackUrl
        {
            get => Apis.Get<ICoreUrls>().LogIn(new CoreUrlLoginOptions() { ReturnToCurrentUrl = false }) + "?oauth_data_token_key=TOKEN";
            set
            {

            }
        }

        public string ClientLogoutScript
        {
            get
            {
                //Identity server (wsfed?wa=signout1.0) sends request "samlresponse/wa=wsignoutcleanup1.0"(passive logout) and after that we should just reload page
                if (LogoutUrlBehavior == LogoutUrlBehavior.IFRAME && IdpAuthRequestType == AuthnBinding.WSFededation)
                    return
                        $@"<div style=""display:none""><iframe id=""saml-logout"" width=""0"" height=""0"" src=""{IdpLogoutUrl}"" onload=""window.location.reload();""></iframe></div>";

                if (LogoutUrlBehavior == LogoutUrlBehavior.IFRAME)
                    return
                        $@"<div style=""display:none""><iframe id=""saml-logout"" width=""0"" height=""0"" src=""{IdpLogoutUrl}"" onload=""jQuery(document).trigger('oauthsignout');""></iframe></div>";

                if (LogoutUrlBehavior == LogoutUrlBehavior.EXTERNAL && IdpAuthRequestType == AuthnBinding.WSFededation && !string.IsNullOrWhiteSpace(IdpLogoutUrl))
                    return
                        $@"<script type='text/javascript'>window.location='{IdpLogoutUrl}&wreply={Apis.Get<IUrl>().Absolute("~/logout")}';</script>";

                return string.Empty;
            }
        }

        public string ClientName => Name;

        public string ClientType => clientType;

        public string ConsumerKey => string.Empty;

        public string ConsumerSecret => string.Empty;

        public bool Enabled => true;

        public string GetAuthorizationLink()
        {
            //append the current querystring to the login url
            try
            {
                if (HttpContext.Current != null && HttpContext.Current.Request != null)
                {
                    var currentUrlParts = HttpContext.Current.Request.RawUrl.Split('?');
                    if (currentUrlParts.Length > 0) //we have a querstring
                    {
                        if (LoginUrl.Contains("?"))
                            return string.Concat(LoginUrl, "&", currentUrlParts[1]);

                        return string.Concat(LoginUrl, "?", currentUrlParts[1]);
                    }
                }
            }
            catch { }
            return LoginUrl;
        }

        public string IconUrl
        {
            get
            {
                try
                {
                    var configuredIconUrl = Configuration.GetString("iconUrl");
                    if (!string.IsNullOrEmpty(configuredIconUrl))
                        return configuredIconUrl;

                    return SamlHelpers.GetWebResourceUrl(this.GetType(), "Verint.Services.SamlAuthenticationPlugin.Resources.Images.saml.png");
                }
                catch
                {
                    return SamlHelpers.GetWebResourceUrl(this.GetType(), "Verint.Services.SamlAuthenticationPlugin.Resources.Images.saml.png");
                }
            }
        }

        public string Privacy => string.Empty;


        public OAuthData ProcessLogin(HttpContextBase context)
        {
            var apiExceptions = Apis.Get<IExceptions>();
            if (!Enabled)
                return null;

            //should have a SamlOAuthClient.oauthTokeyQuerystringKey which corresponds to the current cookie to decrypt
            var tokenKey = HttpContext.Current.Request[oauthTokeyQuerystringKey];
            if (!string.IsNullOrEmpty(tokenKey))
            {
                var samlTokenData = SamlTokenData.GetTokenDataFromDatabase(tokenKey);
                if (samlTokenData == null)
                {
                    apiExceptions.Log(new ArgumentException(
                        "The SAML token was not found in the HttpContext.Current.Request, or could not be extracted. Please ensure the db_SamlTempTokenData table exist and try again."));

                    ProcessReturnUrl();
                }

                //Store our token key so we can retrieve it later to raise the SamlUserCreated and SamlAuthenticated events and delete it
                var afterAuthenticatedCookie = new HttpCookie(clientType, tokenKey) {HttpOnly = true, Expires = DateTime.Now.AddHours(8)};
                CookieHelper.AddCookie(afterAuthenticatedCookie);
                
                //this object is stored in temporary storage by the oauth handler, its guid is placed into the return url into the "TOKEN" placeholder.
                //the expectation of this processing is the return url at this time is to the login page, and that any login based return url should be double encoded
                return samlTokenData.GetOAuthData();
            }

            //if this is not a sign-in response, we should probably redirect to login.aspx
            apiExceptions.Log(new ArgumentException("The SAML token was not found in the HttpContext.Current.Request, please check the configuration and try again"));
            return null;
        }
        
        public string ThemeColor => "006699";

        #endregion

        #region IScriptedContentFragmentFactoryDefaultProvider Members

        public Guid ScriptedContentFragmentFactoryDefaultIdentifier => new Guid("a699e912b5654ef98d195877c8f9eb41");

        #endregion

        #region IInstallablePlugin Members

        object lockObject = new object();

        private void InitializeSchema()
        {
            if (PersistClaims)
            {
                lock (lockObject)
                {
                    try
                    {
                        //Ensure SAML SQL tables are present
                        if (!SqlData.IsInstalled())
                            SqlData.Install();
                        else if (SqlData.NeedsUpgrade())
                            SqlData.Upgrade();
                    }
                    catch (Exception ex)
                    {
                        Apis.Get<IExceptions>().Log(ex);
                        Apis.Get<IEventLog>().Write("SamlOAuthClient Error InitializeSchema (you may need to manually run the sql install script): " + ex.Message + " : " + ex.StackTrace, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 1, EventType = "Error" });
                    }
                }
            }
        }

        //notes on guids
        //evolutionGuid = "aa8056256ecb481bae92f2db9f87e893";
        //fijiGuid = "7e987e474b714b01ba29b4336720c446";
        //socialGuid = "3fc3f82483d14ec485ef92e206116d49";
        //enterpriseGuid = "424eb7d9138d417b994b64bff44bf274";

        //blogThemeTypeID = new Guid("a3b17ab0-af5f-11dd-a350-1fcf55d89593");
        //groupThemeTypeID = new Guid("c6108064-af65-11dd-b074-de1a56d89593");
        //siteThemeTypeID = new Guid("0c647246-6735-42f9-875d-c8b991fe739b");
        void IInstallablePlugin.Install(Version lastInstalledVersion)
        {
            #region Install Widgets

            FactoryDefaultScriptedContentFragmentProviderFiles.DeleteAllFiles(this);

            //install default widgets and supplementary files
            var definitionFiles = new string[] {
                "SamlLoginAutoSelect-Widget.xml"
                ,"SamlLogout-Widget.xml"
            };

            foreach (var definitionFile in definitionFiles)
                using (var stream = EmbeddedResources.GetStream("Verint.Services.SamlAuthenticationPlugin.Resources.Widgets." + definitionFile))
                    FactoryDefaultScriptedContentFragmentProviderFiles.AddUpdateDefinitionFile(this, definitionFile, stream);

            ContentFragments.Enable(ThemeTypes.Site, ContentFragments.GetScriptedContentFragmentTypeString(new Guid("63b5fbf0d2db41eaa165c27ac43ee0f7"))); //Login Auto Select
            ContentFragments.Enable(ThemeTypes.Site, ContentFragments.GetScriptedContentFragmentTypeString(new Guid("31728beb334e420e84200cc6f81d109c"))); //Logout

            #endregion

            #region Insert Widgets Into existing themes and pages

            foreach (var theme in Themes.List(ThemeTypes.Site))
            {

                //add the saml auto select widget to the login page

                if (theme.Name == "3fc3f82483d14ec485ef92e206116d49")
                {
                    //Add CaseList to User profile page after Activity List
                    InsertWidget(theme
                        , "common-login"
                        , false
                        , "Telligent.Evolution.ScriptedContentFragments.ScriptedContentFragment, Telligent.Evolution.ScriptedContentFragments::b1db6b71c0be43b58925e469eb6315a4"
                        , ContentFragmentPlacement.Before
                        , "content"
                        , "Telligent.Evolution.ScriptedContentFragments.ScriptedContentFragment, Telligent.Evolution.ScriptedContentFragments::63b5fbf0d2db41eaa165c27ac43ee0f7"
                        , ""
                        , "no-wrapper responsive-1");
                }
            }


            #endregion

            #region Create Database Table if required
            InitializeSchema();
            #endregion
        }

        void InsertWidget(Theme theme, string pageName, bool isCustom, string existingContentFragmentType, ContentFragmentPlacement placement, string regionName, string contentFragmentType, string contentFragmentConfiguration, string contentFragmentWrappingFormat)
        {
            ThemePageContentFragments.RemoveFromDefault(theme, pageName, isCustom, contentFragmentType);
            ThemePageContentFragments.InsertInDefault(theme, pageName, isCustom, existingContentFragmentType, placement, regionName, contentFragmentType, contentFragmentConfiguration, contentFragmentWrappingFormat);
        }

        void IInstallablePlugin.Uninstall()
        {

            #region Remove Widget Files

            FactoryDefaultScriptedContentFragmentProviderFiles.DeleteAllFiles(this);

            #endregion

        }

        Version IInstallablePlugin.Version => GetType().Assembly.GetName().Version;

        #endregion

        public string[] Categories => PluginCategories.ToArray();
    }
}

