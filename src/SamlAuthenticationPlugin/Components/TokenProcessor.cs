using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Claims;
using System.ServiceModel.Security;
using System.Xml;
using Telligent.Evolution.Extensibility;
using Telligent.Evolution.Extensibility.Api.Version1;
using Telligent.Evolution.Extensibility.Version1;
using Verint.Services.SamlAuthenticationPlugin.Extensibility;

namespace Verint.Services.SamlAuthenticationPlugin.Components
{
    public class TokenProcessor
    {

        private ITokenProcessorConfiguration tokenProcessorConfiguration;

        public TokenProcessor(ITokenProcessorConfiguration config)
        {
            tokenProcessorConfiguration = config;
            TokenHandler = GetSecurityTokenHandler();
        }

        //At the moment this class is the only thing that consumes uses the SecurityTokenHandler
        protected virtual SecurityTokenHandler TokenHandler { get; set; }


        public virtual SamlTokenData GetSamlTokenData()
        {
            var samlUserLookup = PluginManager.GetSingleton<ISamlUserLookup>();
            var displayNameGenerator = PluginManager.GetSingleton<ISamlDisplayNameGenerator>();
            var usernameGenerator = PluginManager.GetSingleton<ISamlUsernameGenerator>();
            var samlTokenValidator = PluginManager.GetSingleton<ISamlTokenDataValidator>();
            var apiUsers = Apis.Get<IUsers>();

            //Extracts, validates and returns the assertion nodes from the current context samlResponse
            SecurityToken samlToken = GetAssertion();

            var samlTokenData = new SamlTokenData { Attributes = GetClaims(samlToken), ResponseDate = DateTime.Now, UserId = 0 };


            samlTokenData.NameId = samlTokenData.ClientId = GetNameId(samlToken);
            samlTokenData.Email = samlTokenData.GetAttribute(tokenProcessorConfiguration.EmailAttributeName, null);

            //fall back to a known claim if the nameid wasnt found in the saml token
            if(samlTokenData.ClientId == null)
                samlTokenData.NameId = samlTokenData.ClientId = samlTokenData.UserName;

            //see if we have a ISamlUserLookup to check for existing OauthLinks
            if (samlUserLookup != null && samlUserLookup.Enabled)
                samlTokenData = samlUserLookup.GetUser(samlTokenData);

            //check if we have a custom user name plugin and execute it now to populate the UserName attribue
            if (usernameGenerator != null && usernameGenerator.Enabled)
                samlTokenData = usernameGenerator.GenerateUsername(samlTokenData);
            else
                samlTokenData.UserName = samlTokenData.GetAttribute(tokenProcessorConfiguration.UserNameAttributeName);

            //check if we have a custom display name plugin and execute it now to populate the commonname attribue
            if (displayNameGenerator != null && displayNameGenerator.Enabled)
                samlTokenData = displayNameGenerator.GenerateDisplayName(samlTokenData);


            if (!samlTokenData.IsExistingUser()) //only run if the ISamlUserLookup didnt already give us the UserId
            {
                // Get the UserID 
                int userID = 0;


                //look up the user by username.
                var user = apiUsers.Get(new UsersGetOptions() { Username = samlTokenData.UserName });
                if (user != null && !user.HasErrors() && user.Id.HasValue)
                    userID = user.Id.Value;

                if (userID == 0 && tokenProcessorConfiguration.AllowTokenMatchingByEmailAddress)
                {
                    // look up the user by email address
                    user = apiUsers.Get(new UsersGetOptions() { Email = samlTokenData.Email.ToLower() });
                    if (user != null && !user.HasErrors() && user.Id.HasValue)
                        userID = user.Id.Value;
                }

                if (userID > 0)
                    samlTokenData.UserId = userID;
            }

            if (samlTokenValidator != null && samlTokenValidator.Enabled)
                samlTokenValidator.Validate(samlToken, samlTokenData);

            samlTokenData.Validate();  //validate the token data before we make any db changes

            //Tuck this in context items for later use in this request
            SamlHelpers.SamlTokenDataContextItem = samlTokenData;

            return samlTokenData;
        }


        #region SecurityTokenHandler Configuration

        protected virtual SecurityTokenHandler GetSecurityTokenHandler()
        {

            var authPlugin = PluginManager.GetSingleton<SamlOAuthClient>();


            //var config = System.IdentityModel.Services.Configuration..FederationConfiguration..;
            SecurityTokenHandler handler = null;
            var securityRequirements = new SamlSecurityTokenRequirement();
            var securityTokenHandlerConfig = new SecurityTokenHandlerConfiguration();

            switch (authPlugin.IdpBindingType)
            {
                case SamlBinding.SAML11_POST:
                    handler = new SamlSecurityTokenHandler(securityRequirements) { Configuration = securityTokenHandlerConfig };
                    break;

                case SamlBinding.SAML20_POST:
                    handler = new SubjectConfirmationDataSaml2SecurityTokenHandler(securityRequirements, authPlugin.SubjectRecipientValidationMode) { Configuration = securityTokenHandlerConfig };
                    break;
            }

            if (handler == null)
                throw new InvalidOperationException(
                    string.Format("No suitable token handler was loaded for the SAML binding type : {0}",
                                  tokenProcessorConfiguration.IdpBindingType));


            handler.Configuration.IssuerNameRegistry = new CodeBasedIssuerNameRegistry(tokenProcessorConfiguration.TrustedIssuerThumbprint.Split(','));

            handler.Configuration.CertificateValidationMode = tokenProcessorConfiguration.CertificateValidationMode;

            if (typeof(SamlSecurityTokenHandler).IsAssignableFrom(handler.GetType()))
                ((SamlSecurityTokenHandler)handler).CertificateValidator = GetCertificateValidator(handler.Configuration.CertificateValidationMode);

            if (typeof(Saml2SecurityTokenHandler).IsAssignableFrom(handler.GetType()))
                ((Saml2SecurityTokenHandler)handler).CertificateValidator = GetCertificateValidator(handler.Configuration.CertificateValidationMode);


            handler.Configuration.AudienceRestriction.AudienceMode = System.IdentityModel.Selectors.AudienceUriMode.Never;

            return handler;
        }

        protected virtual X509CertificateValidator GetCertificateValidator(X509CertificateValidationMode x509CertificateValidationMode)
        {
            //setup the right validator (only validates the credential of the certificate used to sign, not the certificate itself or the signature)
            switch (x509CertificateValidationMode)
            {

                case X509CertificateValidationMode.ChainTrust:
                    return X509CertificateValidator.ChainTrust;

                case X509CertificateValidationMode.PeerTrust:
                    return X509CertificateValidator.PeerTrust;

                case X509CertificateValidationMode.PeerOrChainTrust:
                    return X509CertificateValidator.PeerOrChainTrust;

                case X509CertificateValidationMode.None:
                    return X509CertificateValidator.None;

                case X509CertificateValidationMode.Custom:
                    throw new ArgumentException("Custom Certificate Validation Mode is not supported by the SAML Plugin");
                //we could expose a custom plugin type and try to load it here

            }
            throw new ArgumentException("Selected Certificate Validation Mode is not supported by the SAML Plugin");

        }

        #endregion

        #region SamlTokenData Helpers

        /// <summary>
        /// Extracts, validates and returns the assertion nodes from the current context samlResponse
        /// </summary>
        /// <returns></returns>
        protected virtual SecurityToken GetAssertion()
        {
            var signInResponse = SamlHelpers.SignInResponse;

            if (signInResponse == null)
                throw new ArgumentNullException("No valid SAML response could be found in the current request");

            //only adfs wif tokens come with  "Assertion" real saml tokens are saml:Assertion
            XmlNodeList assertionList = signInResponse.GetElementsByTagName("Assertion");

            //saml:Assertion
            if (assertionList.Count == 0) assertionList = signInResponse.GetElementsByTagName("saml:Assertion");
            //samlp:Assertion
            if (assertionList.Count == 0) assertionList = signInResponse.GetElementsByTagName("samlp:Assertion");
            //saml2:Assertion
            if (assertionList.Count == 0) assertionList = signInResponse.GetElementsByTagName("saml2:Assertion");

            if (assertionList.Count == 0) throw new ArgumentException("Invalid SAML response, failed to detect a valid assertion");

            XmlNode assertionNode = assertionList[0];

            XmlReader reader = XmlReader.Create(new StringReader(assertionNode.OuterXml));


            //This expects to be on the assertion node
            var samlToken = TokenHandler.ReadToken(reader);

            //validate the Assertions
            var claimsIdentity = TokenHandler.ValidateToken(samlToken);

            //Store the claimsIdentity in ContextItems in case we want to use it later in this request
            SamlHelpers.ClaimsPrincipalContextItem = new ClaimsPrincipal(claimsIdentity);

            return samlToken;
        }

        #region Get Claims

        public virtual List<SamlAttribute> GetClaims(SecurityToken samlToken)
        {
            //switch between Saml2SecurityToken and SamlSecurityToken

            if (typeof(SamlSecurityToken).IsAssignableFrom(samlToken.GetType()))
                return GetClaims((SamlSecurityToken)samlToken);

            if (typeof(Saml2SecurityToken).IsAssignableFrom(samlToken.GetType()))
                return GetClaims((Saml2SecurityToken)samlToken);

            throw new ArgumentException("Cannot GetClaims from the current passed SecurityToken type", "samlToken");
        }

        private static List<SamlAttribute> GetClaims(SamlSecurityToken samlToken)
        {

            IList<System.IdentityModel.Tokens.SamlAttribute> attributes = GetTokenAttributes(samlToken);
            if (attributes == null)
                return null;

            var claims = new List<SamlAttribute>();
            foreach (System.IdentityModel.Tokens.SamlAttribute attribute in attributes)
            {
                claims.AddRange(
                    SamlAttribute.SamlAttributeFromToken(attribute));
            }

            return claims;

        }
        
        private static List<SamlAttribute> GetClaims(Saml2SecurityToken samlToken)
        {

            IList<Saml2Attribute> attributes = GetTokenAttributes(samlToken);
            if (attributes == null)
                return null;

            var claims = new List<SamlAttribute>();
            foreach (Saml2Attribute attribute in attributes)
            {
                claims.AddRange(
                    SamlAttribute.SamlAttributeFromToken(attribute));
            }

            return claims;

        }

        private static IList<System.IdentityModel.Tokens.SamlAttribute> GetTokenAttributes(SamlSecurityToken samlToken)
        {

            IList<System.IdentityModel.Tokens.SamlAttribute> attributes = null;
            foreach (SamlStatement statement in samlToken.Assertion.Statements)
                if (statement.GetType() == typeof(SamlAttributeStatement))
                    attributes = ((SamlAttributeStatement)statement).Attributes;

            return attributes;
        }

        private static IList<Saml2Attribute> GetTokenAttributes(Saml2SecurityToken samlToken)
        {

            IList<Saml2Attribute> attributes = null;
            foreach (Saml2Statement statement in samlToken.Assertion.Statements)
                if (statement.GetType() == typeof(Saml2AttributeStatement))
                    attributes = ((Saml2AttributeStatement)statement).Attributes;

            return attributes;
        }

        #endregion


        public virtual string GetNameId(SecurityToken samlToken)
        {
            //switch between Saml2SecurityToken and SamlSecurityToken
            if (typeof(SamlSecurityToken).IsAssignableFrom(samlToken.GetType()))
            {
                foreach (SamlStatement statement in ((SamlSecurityToken)samlToken).Assertion.Statements)
                    if (statement.GetType() == typeof(SamlSubjectStatement))
                        return ((SamlSubjectStatement)statement).SamlSubject.Name;

                return null;

            }

            if (typeof(Saml2SecurityToken).IsAssignableFrom(samlToken.GetType()))
                return ((Saml2SecurityToken)samlToken).Assertion.Subject.NameId.Value;

            throw new ArgumentException("Cannot Get NameId from the current passed SecurityToken type", "samlToken");
        }



        #endregion

    }

    public interface ITokenProcessorConfiguration
    {
        string IdpUrl { get; }

        SamlBinding IdpBindingType {get;}

        X509CertificateValidationMode CertificateValidationMode { get; }

        string TrustedIssuerThumbprint { get; }

        string UserNameAttributeName { get; }

        string EmailAttributeName { get; }

        bool AllowTokenMatchingByEmailAddress { get; }


    }

}
