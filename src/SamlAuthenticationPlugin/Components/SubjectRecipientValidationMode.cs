namespace Verint.Services.SamlAuthenticationPlugin.Components
{
    public enum SubjectRecipientValidationMode
    {
        ExactMatch = 1,
        HostOnly = 2,
        HostAndScheme = 4,
        None = 8,

    }
}
