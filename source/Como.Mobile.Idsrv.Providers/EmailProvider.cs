using System;
using System.Collections.Generic;
using System.Configuration;
using Conduit;
using Conduit.Mobile.Mail.Client;
using Conduit.Mobile.Mail.Contracts;

namespace Como.Mobile.Idsrv.Providers
{
   
    public class IdentityEmailProvider : IIdentityEmailProvider
    {
        //static readonly ILog Logger = LogProvider.GetCurrentClassLogger();
        private readonly MailClient _mailClient;

        public IdentityEmailProvider()
        {
            _mailClient = new MailClient(ConfigurationManager.AppSettings["Mail.Client.Environment"].NoNull(ServiceEnvironment.PROD));
        }

        public bool SendPasswordRecoveryEmail(string email, string token, Guid? userId)
        {
            try
            {
                var msg = CreateMail(email, token,userId);

                return _mailClient.SendMail(msg);
            }
            catch (Exception ex)
            {
                //Logger.ErrorFormat("Failed to send password recovery email. Email: {1}", ex, email);
                return false;
            }
        }

        private Email CreateMail(string email, string token, Guid? userId)
        {
            var template = ConfigurationManager.AppSettings["ForgotPassword_EmailTemplate"];

            var recipient = new Recipient
            {
                Name = email,
                Id = userId,
                Address = email,
                RecipientMergeParams = new List<MergeParam>
                {
                    new MergeParam {Name = "token", Content = token},
                    new MergeParam {Name = "to", Content = email}
                }
            };

            var msg = new Email
            {
                ExternalTemplate = template,
                From = new Sender { Address = ConfigurationManager.AppSettings["mandrillfrom"] },
                To = new[] { recipient }
            };
            return msg;
        }
    }
}
