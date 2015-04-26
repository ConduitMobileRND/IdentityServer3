namespace Thinktecture.IdentityServer.Core.Validation
{
    public interface IRequestValidatorHelper
    {
        string CallServiceGet(string token, string baseAddress, string uri);
    }
}