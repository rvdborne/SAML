using System;
using System.Collections.Generic;
using System.Web;
using Telligent.Evolution.Extensibility.Authentication.Version1;
using System.Xml.Serialization;
using Telligent.Evolution.Extensibility;
using Telligent.Evolution.Extensibility.Version1;
using Telligent.Evolution.Extensibility.Api.Version1;

namespace Telligent.Services.SamlAuthenticationPlugin.Components
{
    [Serializable]
    [XmlInclude(typeof(SamlAttribute))]
    public class SamlTokenData
    {

        public SamlTokenData()
        {
            UserId = 0;
        }

        public string AvatarUrl { get; set; }
        public string NameId { get; set; }
        public string CommonName { get; set; }
        public string Email { get; set; }
        public string UserName { get; set; }


        public int UserId { get; set; }
        public DateTime ResponseDate { get; set; }
        public bool IsExistingUser()
        {
            return UserId > 0;
        }

        public string ClientType
        {
            get { return SamlOAuthClient.clientType; }
        }

        public string ClientId { get; set; }

        public List<SamlAttribute> Attributes { get; set; }

        #region GetClaims

        /// <summary>
        /// Returns the requested Attribute Value or throws a not found exception
        /// </summary>
        /// <param name="attributeName"></param>
        /// <returns></returns>
        public virtual string GetAttribute(string attributeName)
        {
            foreach (SamlAttribute attribute in Attributes)
                if (attribute.ClaimType.Equals(attributeName, StringComparison.InvariantCultureIgnoreCase))
                    return attribute.Value;

            throw new InvalidOperationException(string.Format("The authentication token did not contain the attribute : {0}", attributeName));
        }

        /// <summary>
        /// Returns the requested Attribute Values when multiple entries of the same name are expected
        /// </summary>
        /// <param name="attributeName"></param>
        /// <returns></returns>
        public virtual string[] GetAttributes(string attributeName)
        {
            List<string> values = null;
            foreach (SamlAttribute attribute in Attributes)
                if (attribute.ClaimType.Equals(attributeName, StringComparison.InvariantCultureIgnoreCase))
                {
                    if (values == null)
                        values = new List<string>();

                    values.Add(attribute.Value);
                }
            if (values != null)
                return values.ToArray();

            return null;

        }

        /// <summary>
        /// Returns the requested Attribute Value or the default value if the Attribute is not found in the collection
        /// </summary>
        /// <param name="attributeName"></param>
        /// <param name="defaultValue"></param>
        /// <returns></returns>
        public virtual string GetAttribute(string attributeName, string defaultValue)
        {
            foreach (SamlAttribute attribute in Attributes)
                if (attribute.ClaimType.Equals(attributeName, StringComparison.InvariantCultureIgnoreCase))
                    return attribute.Value;

            return defaultValue;
        }

        public string GetAttributes(string delimiter, string attributeName)
        {
            string[] attributeValues = GetAttributes(attributeName);

            if (attributeValues == null)
                return null;

            return string.Join(delimiter, attributeValues);
        }

        /// <summary>
        /// Iterate through the passed attributes and validate they meet the configuration requirements for user processing
        /// </summary>
        public bool Validate(bool throwExceptions = true)
        {
            if (Attributes == null || Attributes.Count == 0) return false;

            if (string.IsNullOrEmpty(UserName)) return false;

            var samlPlugin = PluginManager.GetSingleton<SamlOAuthClient>();

            if (samlPlugin == null) return false;


            bool userNameValid = false;
            bool emailValid = false;
            bool timezoneValid = true; //only validate if present
            //validate UserMapping
            foreach (SamlAttribute attribute in Attributes)
            {
                if (attribute.ClaimType.Equals(samlPlugin.UserNameAttributeName, StringComparison.InvariantCultureIgnoreCase))
                    userNameValid = !string.IsNullOrEmpty(attribute.Value);

                if (attribute.ClaimType.Equals(samlPlugin.EmailAttributeName, StringComparison.InvariantCultureIgnoreCase))
                    emailValid = !string.IsNullOrEmpty(attribute.Value);
            }

            if(throwExceptions)
            {
                if (!userNameValid)
                    throw new InvalidOperationException("The saml token did not contain a valid username"); 
                if (!emailValid)
                    throw new InvalidOperationException("The saml token did not contain a valid user email");
                if (!timezoneValid)
                    throw new InvalidOperationException("The saml token did not contain a valid user timezone");
            }
            
            if(!userNameValid || !emailValid || !timezoneValid) return false;

            return true;
        }

        #endregion


        public OAuthData GetOAuthData()
        {
            var oAuthData = new OAuthData();

            oAuthData.ClientId = this.ClientId;  //note: by default this is the NameId from the saml token
            oAuthData.ClientType = SamlOAuthClient.clientType;
            oAuthData.CommonName = this.CommonName;
            oAuthData.Email = this.Email;
            oAuthData.UserName = this.UserName;

            return oAuthData;
        
        }


        internal string SaveToSecureCookie()
        {
            var tokenKey = Guid.NewGuid();
            string samlXml = SamlHelpers.ConvertToString(this);
            var encryptedToken = SamlHelpers.Protect(samlXml, this.GetType().Name);

            HttpCookie cookie = new HttpCookie(tokenKey.ToString(), encryptedToken);
            cookie.HttpOnly = true;
            cookie.Secure = HttpContext.Current.Request.IsSecureConnection;
            
            CookieHelper.AddCookie(cookie);

            return tokenKey.ToString();
        }

        internal static SamlTokenData GetFromSecureCookie(string tokenKey)
        {
            try
            {
                HttpCookie secureCookie = CookieHelper.GetCookie(tokenKey);
                var samlXml = SamlHelpers.Unprotect(secureCookie.Value, typeof(SamlTokenData).Name);
                var samlTokenData = SamlHelpers.Deserialize<SamlTokenData>(samlXml);
                return samlTokenData;
            }
            catch(Exception ex)
            {
                Apis.Get<IEventLog>().Write("Error Extracting SAML token from cookie:" + ex, new EventLogEntryWriteOptions { Category = "SAML", EventType = "Error", EventId = 1001 });
            }
            return null;
        }
    }

}
