# SAML Authentication Plugin

Plugin Version 4.10.x compatible with Telligent Community 10.x and Up (see branch Telligent7 for older version support)

#### What is the SAML Authentication Plugin

This plugin allows your community to receive a SAML tokens via HTTP POST at a new endpoint / route ( ~/samlresponse ).
will receive, validate and unpackage the SAML token and repackages it in a way compatible with the out of the box IOAuthClient extensibility features.  It supports 
SAML 1.1 HTTP POST and SAML 2.0 HTTP POST bindings, configurable AuthN request scenarios, has several options for handling logout scenarios.

SAML Binding Support
- SAML 1.1 HTTP POST
- SAML 2.0 HTTP Post

SAML AuthN support
- IDP Initiated
- Redirect / HTTP GET (XML signatures not supported in current code)
- HTTP POST (with optional XML signature)
- WSFederation

Logout
- Internal (local forms authentication logout)
- External (logout preformed by external URL; must destroy the forms auth cookie or call ~/samllogout)
- IFrame (logout form calls into remote url to log out of IDP)
- WSFederation signout requests are supported (requires a custom IPlatformLogout extension)

To use this plugin, your SAML token must support the following claims (exact claim paths can be configured  in the plugin)
- Username (must be unique)
- Email Address (must be unique)
- Display Name (optional)

There are also extensibility points for custom username and display name handling during the authentication  lifecycle.

#### Documentation:

Please refer to the [Wiki](/Telligent/SAML/wiki) in this repository for additional documentation.

#### A note on existing users:
If you have existing users in your database or create users outside of the SAML workflow (e.g., via the Administration area or REST) those Users will need to know the username and password used to create the account so they are able to link their Telligent user with their SAML user identity.  (To support this ability users need a custom ISamlOAuthLinkManager extension)

#### Version History
Version 3.0 - Initial GitHub Release

Version 4.0 - Add support for WSFederation AuthN and Logout

Version 4.7 - Minor version made to indicate that the code was built from the Telligent7 branch and will be maintained there going forward

Version 4.10 - Add minor build number to indicate the break in the backward compatibility of the assembly (note the configuration is backward compatible with all prior versions of this assembly)