# SAML Authentication Plugin

Version 3.0 compatible with Telligent Community 7.x and Up

#### What is the SAML Authentication Plugin

This plugin allows your community to receive a SAML tokens via HTTP POST at a new endpoint / route ( ~/samlresponse ).
will receive, validate and unpackage the SAML token and repackages it in a way compatible with the out of the box IOAuthClient extensibility features.  It supports 
SAML 1.1 HTTP POST and SAML 2.0 HTTP POST bindings, configurable AuthN request scenarios, has several options for handling logout scenarios.

SAML Binding Support
- SAML 1.1 HTTP POST
- SAML 2.0 HTTP Post

SAML AuthN support
- IDP Initiated
- Redirect (XML signatures not supported)
- HTTP POST (with optional XML signature)

Logout
- Internal (local forms authentication logout)
- External (logout preformed by external URL; must destroy the forms auth cookie or call ~/samllogout)
- IFrame (logout form calls into remote url to log out of IDP)

To use this plugin, your SAML token must support the following claims (exact claim paths can be configured  in the plugin)
- Username (must be unique)
- Email Address (must be unique)
- Display Name (optional)

There are also extensibility points for custom username and display name handling during the authentication  lifecycle.



#### Dependencies

Please copy your local Community library files to the **References** folder. 

- Telligent.Common.dll
- Telligent.DynamicConfiguration.dll
- Telligent.Evolution.Api.dll
- Telligent.Evolution.Components.dll
- Telligent.Evolution.Controls.dll
- Telligent.Evolution.Core.dll
- Telligent.Evolution.ScriptedContentFragments.dll
- Telligent.Evolution.SecurityModules.dll
- Telligent.Evolution.VelocityExtensions.dll

### Install and configure the Telligent SAML Authentication Plugin

#### In this Article

- [Installing Web files](#installing-web-files)
- [Installing SQL files](#installing-sql-files)
- [Installing tasks](#installing-tasks)

#### Installing Web files

> It is recommended that you back up your entire Web directory before performing any installs.

1. Copy the contents of /Web to your Web installation directory.  The /Web folder contents of the installation package mirrors the Telligent Evolution Web structure.


#### Installing SQL files

> It is recommended that you do a full database backup before installing SQL.

The installation package will self install the required schema updates, only manually run the sql script if your website does not have permission to change your sql schema.  
If you are required to manually run the sql schema updates, be sure to use a version of the sql files which matches the build number of your 'Telligent.Services.SamlAuthenticationPlugin.dll'

#### Enabling SAML plugin

1. Go to the Web site's Control Panel page. Browse to the Manage Plugins page (**System Administration > Site Administration > Site Configuration > Manage Plugins**).
2. Place a check mark next to the **SAML Authentication OAuth Client** plugin, and click **Save**.
3. Click Configure.  

[//]: # (TODO Configuration Information)

> Enabling the "SAML Authentication OAuth Client" plugin updates the database schema (if required) and adds the SAML Authentication OAuth Client widgets to site’s pages and Adds the SAML Authentication OAuth Client Widgets to the site. Server and/or browser caching may prevent these changes from being seen immediately. After enabling the plugin, restarting the Web site and/or clearing the browser cache should make the SAML Authentication OAuth Client functionality appear immediately.

#### Installing tasks

1. Stop your Job Scheduler Service.
2. You will need to copy the following files from the installation package to their respective places in the installation directory or the Job Scheduler service:(note: * means all, e.g., *.dll means all files with the extension of .dll)
  - Copy **Web/bin/&#42;.dll** to the root of the Job Scheduler installation (same location as the .exefile).
  - Copy all files and folders from Web/Languages to the same folder in the Job Scheduler installation.
3. Restart your Job Scheduler Service.


