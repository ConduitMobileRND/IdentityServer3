using System;

namespace Como.Mobile.Idsrv.Providers
{
    public interface IIdentityEmailProvider
    {
        bool SendPasswordRecoveryEmail(string email, string token, Guid? userId);
    }
}