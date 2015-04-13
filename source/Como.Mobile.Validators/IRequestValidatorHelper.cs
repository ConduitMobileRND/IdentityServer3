namespace Como.Mobile.Validators
{
    public interface IRequestValidatorHelper
    {
        string CallServiceGet(string token, string baseAddress, string uri);
    }
}