using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Thinktecture.IdentityModel;
using Thinktecture.IdentityServer.Core;
using Thinktecture.IdentityServer.Core.Configuration;
using Thinktecture.IdentityServer.Core.Logging;
using Thinktecture.IdentityServer.Core.Models;
using Thinktecture.IdentityServer.Core.Services;
using Thinktecture.IdentityServer.Core.Validation;

namespace Como.Mobile.Validators
{
    public class ComoRequestValidator : IComoRequestValidator
    {
        private static readonly ILog Logger = LogProvider.GetCurrentClassLogger();
        private readonly IRequestValidatorHelper _requestValidatorHelper;
        private readonly IdentityServerOptions _options;
        private readonly ITokenSigningService _signingService;

        public ComoRequestValidator(IRequestValidatorHelper requestValidatorHelper, IdentityServerOptions options, ITokenSigningService signingService)
        {
            if (requestValidatorHelper == null) throw new ArgumentNullException("requestValidatorHelper");
            if (options == null) throw new ArgumentNullException("options");
            if (signingService == null) throw new ArgumentNullException("signingService");
            _requestValidatorHelper = requestValidatorHelper;
            _options = options;
            _signingService = signingService;
        }


        public async Task<ValidationResult> Validate(NameValueCollection parameters, Client client)
        {
            Logger.Info("Start token request validation for appid with CPMS.");
            string appId = parameters.Get(Constants.TokenRequest.AppId);
            string publisherid = parameters.Get(Constants.TokenRequest.PublisherId);
            if (appId != null)
            {
                var outputClaims = new List<Claim>
                {
                    new Claim(Constants.ClaimTypes.ClientId, client.ClientId),
                };

                // add scope
                outputClaims.Add(new Claim(Constants.ClaimTypes.Scope, Constants.StandardScopes.application));
                outputClaims.Add(new Claim(Constants.ClaimTypes.Scope, "add"));


                //add appid
                outputClaims.Add(new Claim(Constants.ClaimTypes.Appid, appId));
                var token = new Token(Constants.TokenTypes.AccessToken)
                {
                    Audience = string.Format(Constants.AccessTokenAudience, _options.IssuerUri.EnsureTrailingSlash()),
                    Issuer = _options.IssuerUri,
                    Lifetime = client.AccessTokenLifetime,
                    Claims = outputClaims.Distinct(new ClaimComparer()).ToList(),
                    Client = client
                };

                string signedToken = await _signingService.SignTokenAsync(token);

                string servicePublisherId = _requestValidatorHelper.CallServiceGet(signedToken, ConfigurationManager.AppSettings["cpmsuri"],
                    "publisher");

                //if publisher id returned from CPMS is null then application
                //doesn't belongs to specific user (just created application),or
                //if publisher id returned from CPMS equals to parameter one
                //which means application belongs to this specific user
                if (servicePublisherId == null || servicePublisherId.Equals(publisherid, StringComparison.Ordinal))
                {
                    return Valid();
                }
                return Invalid("Application Id is not valid");
            }
            return Valid();
        }


        private ValidationResult Valid()
        {
            return new ValidationResult
            {
                IsError = false
            };
        }

        private ValidationResult Invalid(string error)
        {
            return new ValidationResult
            {
                IsError = true,
                ErrorType = ErrorTypes.Client,
                Error = error
            };
        }
    }
}
