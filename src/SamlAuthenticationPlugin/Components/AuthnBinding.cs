namespace Verint.Services.SamlAuthenticationPlugin.Components
{
    public enum AuthnBinding
    {
        IDP_Initiated = 1,
        Redirect = 2,
        POST = 4,
        SignedRedirect = 8,
        SignedPOST = 16,
        WSFededation = 32
    }
}
