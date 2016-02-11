using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.ServiceModel.Security;
using System.Text;
using System.Web;

namespace Telligent.Services.SamlAuthenticationPlugin.Components
{
    public class SubjectConfirmationDataSaml2SecurityTokenHandler : Saml2SecurityTokenHandler
    {
        public SubjectConfirmationDataSaml2SecurityTokenHandler():base(){}
        public SubjectConfirmationDataSaml2SecurityTokenHandler(SamlSecurityTokenRequirement samlSecurityTokenRequirement) : base(samlSecurityTokenRequirement) { }
        public SubjectConfirmationDataSaml2SecurityTokenHandler(SamlSecurityTokenRequirement samlSecurityTokenRequirement, SubjectRecipientValidationMode subjectRecipientValidationMode) : base(samlSecurityTokenRequirement) 
        {
            _subjectRecipientValidationMode = subjectRecipientValidationMode;
        }

        protected SubjectRecipientValidationMode _subjectRecipientValidationMode = SubjectRecipientValidationMode.ExactMatch;

        protected override void ValidateConfirmationData(Saml2SubjectConfirmationData confirmationData)
        {
            if (confirmationData == null)
            {
                throw new ArgumentNullException("confirmationData");
            }
            if (confirmationData.Address != null)
            {
                throw new NotSupportedException("Token 'Address' confirmation is not currently supported");
            }
            if (confirmationData.InResponseTo != null)  //ignore in response to (this is present when issuing an authen request but would require persisting state to track)
            {
                //throw new SecurityTokenException("ID4154: confirmationData.InResponseTo not supperted");
            }
            if (null != confirmationData.Recipient && _subjectRecipientValidationMode != SubjectRecipientValidationMode.None)
            {
                switch(_subjectRecipientValidationMode)
                {
                    case SubjectRecipientValidationMode.ExactMatch:
                        if(HttpContext.Current.Request.Url != confirmationData.Recipient)
                        {
                            //handle the special case where we redirected from the old oauth.ashx patterns..
                            if (HttpContext.Current.Request.Url.ToString().Replace("samlresponse","oauth.ashx").ToLower() != confirmationData.Recipient.ToString().ToLower())
                            {
                                throw new ArgumentException(string.Format("Token 'Recipient' value {0} does not match the current URL requirement of {1}", confirmationData.Recipient, HttpContext.Current.Request.Url));
                            }
                        }
                        break;

                    case SubjectRecipientValidationMode.HostAndScheme:
                        if(HttpContext.Current.Request.Url.Host != confirmationData.Recipient.Host || HttpContext.Current.Request.Url.Scheme != confirmationData.Recipient.Scheme)
                        {
                            throw new ArgumentException(string.Format("Token 'Recipient' value {0} does not match the current host and or scheme requirement of {1}", confirmationData.Recipient, HttpContext.Current.Request.Url));
                        }
                        break;

                    case SubjectRecipientValidationMode.HostOnly:
                        if(HttpContext.Current.Request.Url.Host != confirmationData.Recipient.Host)
                        {
                            throw new ArgumentException(string.Format("Token 'Recipient' value {0} does not match the current host requirement of {1}", confirmationData.Recipient, HttpContext.Current.Request.Url));
                        }
                        break;
                }
            }
            DateTime utcNow = DateTime.UtcNow;
            if (confirmationData.NotBefore.HasValue && (AddTimespan(utcNow, base.Configuration.MaxClockSkew) < confirmationData.NotBefore.Value))
            {
                throw new ArgumentOutOfRangeException(string.Format("The token is not valid before {0} and the current time is {1}", confirmationData.NotBefore.Value, utcNow ));
            }
            if (confirmationData.NotOnOrAfter.HasValue && (AddTimespan(utcNow, base.Configuration.MaxClockSkew.Negate()) >= confirmationData.NotOnOrAfter.Value))
            {
                throw new ArgumentOutOfRangeException(string.Format("The token is not valid after {0} and the current time is {1}", confirmationData.NotOnOrAfter.Value, utcNow));
            }

        }

        private static DateTime AddTimespan(DateTime time, TimeSpan timespan)
        {
            if ((timespan >= TimeSpan.Zero) && ((DateTime.MaxValue - time) <= timespan))
            {
                return new DateTime(DateTime.MaxValue.Ticks, time.Kind);
            }
            if ((timespan <= TimeSpan.Zero) && ((DateTime.MinValue - time) >= timespan))
            {
                return new DateTime(DateTime.MinValue.Ticks, time.Kind);
            }
            return (time + timespan);
        }

    }
}
