/*
 * Copyright 2014, 2015 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Thinktecture.IdentityModel;
using Thinktecture.IdentityModel.Http;
using Thinktecture.IdentityServer.Core.Configuration;
using Thinktecture.IdentityServer.Core.Extensions;
using Thinktecture.IdentityServer.Core.Logging;
using Thinktecture.IdentityServer.Core.Models;
using Thinktecture.IdentityServer.Core.Services;

namespace Thinktecture.IdentityServer.Core.Validation
{
    internal class TokenRequestValidator
    {
        private static readonly ILog Logger = LogProvider.GetCurrentClassLogger();

        private readonly IAuthorizationCodeStore _authorizationCodes;
        private readonly ICustomGrantValidator _customGrantValidator;
        private readonly ICustomRequestValidator _customRequestValidator;
        private readonly IEventService _events;
        private readonly IdentityServerOptions _options;
        private readonly IRefreshTokenStore _refreshTokens;
        private readonly ScopeValidator _scopeValidator;
        private readonly ITokenSigningService _signingService;
        private readonly IRequestValidatorHelper _requestValidatorHelper;
        private readonly IUserService _users;

        private ValidatedTokenRequest _validatedRequest;

        public TokenRequestValidator(IdentityServerOptions options, IAuthorizationCodeStore authorizationCodes,
            IRefreshTokenStore refreshTokens, IUserService users, ICustomGrantValidator customGrantValidator,
            ICustomRequestValidator customRequestValidator, ScopeValidator scopeValidator, IEventService events,
            ITokenSigningService signingService,IRequestValidatorHelper requestValidatorHelper )
        {
            _options = options;
            _authorizationCodes = authorizationCodes;
            _refreshTokens = refreshTokens;
            _users = users;
            _customGrantValidator = customGrantValidator;
            _customRequestValidator = customRequestValidator;
            _scopeValidator = scopeValidator;
            _events = events;
            _signingService = signingService;
            _requestValidatorHelper = requestValidatorHelper;
        }

        public ValidatedTokenRequest ValidatedRequest
        {
            get { return _validatedRequest; }
        }


        public async Task<ValidationResult> ValidateRequestForAppIdAsync(NameValueCollection parameters, Client client)
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
                    "publisherid");

                //TODO:merge if and extract to diff class
                if (servicePublisherId == null)
                {
                    return Valid();
                }
                if (servicePublisherId.Equals(publisherid, StringComparison.Ordinal))
                {
                    return Valid();
                }

                return Invalid("Application Id is not valid");
            }
            return Valid();
        }


        public async Task<ValidationResult> ValidateRequestAsync(NameValueCollection parameters, Client client)
        {
            Logger.Info("Start token request validation");

            _validatedRequest = new ValidatedTokenRequest();

            if (client == null)
            {
                throw new ArgumentNullException("client");
            }

            if (parameters == null)
            {
                throw new ArgumentNullException("parameters");
            }

            _validatedRequest.Raw = parameters;
            _validatedRequest.Client = client;
            _validatedRequest.Options = _options;

            /////////////////////////////////////////////
            // check grant type
            /////////////////////////////////////////////
            string grantType = parameters.Get(Constants.TokenRequest.GrantType);
            if (grantType.IsMissing())
            {
                LogError("Grant type is missing.");
                return Invalid(Constants.TokenErrors.UnsupportedGrantType);
            }

            if (grantType.Length > Constants.MaxGrantTypeLength)
            {
                LogError("Grant type is too long.");
                return Invalid(Constants.TokenErrors.UnsupportedGrantType);
            }

            _validatedRequest.GrantType = grantType;

            // standard grant types
            switch (grantType)
            {
                case Constants.GrantTypes.AuthorizationCode:
                    return await RunValidationAsync(ValidateAuthorizationCodeRequestAsync, parameters);
                case Constants.GrantTypes.ClientCredentials:
                    return await RunValidationAsync(ValidateClientCredentialsRequestAsync, parameters);
                case Constants.GrantTypes.Password:
                    return await RunValidationAsync(ValidateResourceOwnerCredentialRequestAsync, parameters);
                case Constants.GrantTypes.RefreshToken:
                    return await RunValidationAsync(ValidateRefreshTokenRequestAsync, parameters);
            }

            // custom grant type
            ValidationResult result = await RunValidationAsync(ValidateCustomGrantRequestAsync, parameters);

            if (result.IsError)
            {
                if (result.Error.IsPresent())
                {
                    return result;
                }

                LogError("Unsupported grant_type: " + grantType);
                return Invalid(Constants.TokenErrors.UnsupportedGrantType);
            }

            return result;
        }

        private async Task<ValidationResult> RunValidationAsync(
            Func<NameValueCollection, Task<ValidationResult>> validationFunc, NameValueCollection parameters)
        {
            // run standard validation
            ValidationResult result = await validationFunc(parameters);
            if (result.IsError)
            {
                return result;
            }

            // run custom validation
            ValidationResult customResult = await _customRequestValidator.ValidateTokenRequestAsync(_validatedRequest);

            if (customResult.IsError)
            {
                string message = "Custom token request validator error";

                if (customResult.Error.IsPresent())
                {
                    message += ": " + customResult.Error;
                }

                LogError(message);
                return customResult;
            }

            LogSuccess();
            return customResult;
        }

        private async Task<ValidationResult> ValidateAuthorizationCodeRequestAsync(NameValueCollection parameters)
        {
            Logger.Info("Start validation of authorization code token request");

            /////////////////////////////////////////////
            // check if client is authorized for grant type
            /////////////////////////////////////////////
            if (_validatedRequest.Client.Flow != Flows.AuthorizationCode &&
                _validatedRequest.Client.Flow != Flows.Hybrid)
            {
                LogError("Client not authorized for code flow");
                return Invalid(Constants.TokenErrors.UnauthorizedClient);
            }

            /////////////////////////////////////////////
            // validate authorization code
            /////////////////////////////////////////////
            string code = parameters.Get(Constants.TokenRequest.Code);
            if (code.IsMissing())
            {
                string error = "Authorization code is missing.";
                LogError(error);
                RaiseFailedAuthorizationCodeRedeemedEvent(null, error);

                return Invalid(Constants.TokenErrors.InvalidGrant);
            }

            _validatedRequest.AuthorizationCodeHandle = code;

            AuthorizationCode authZcode = await _authorizationCodes.GetAsync(code);
            if (authZcode == null)
            {
                LogError("Invalid authorization code: " + code);
                RaiseFailedAuthorizationCodeRedeemedEvent(code, "Invalid handle");

                return Invalid(Constants.TokenErrors.InvalidGrant);
            }

            await _authorizationCodes.RemoveAsync(code);

            /////////////////////////////////////////////
            // validate client binding
            /////////////////////////////////////////////
            if (authZcode.Client.ClientId != _validatedRequest.Client.ClientId)
            {
                LogError(string.Format("Client {0} is trying to use a code from client {1}",
                    _validatedRequest.Client.ClientId, authZcode.Client.ClientId));
                RaiseFailedAuthorizationCodeRedeemedEvent(code, "Invalid client binding");

                return Invalid(Constants.TokenErrors.InvalidGrant);
            }

            /////////////////////////////////////////////
            // validate code expiration
            /////////////////////////////////////////////
            if (authZcode.CreationTime.HasExceeded(_validatedRequest.Client.AuthorizationCodeLifetime))
            {
                string error = "Authorization code is expired";
                LogError(error);
                RaiseFailedAuthorizationCodeRedeemedEvent(code, error);

                return Invalid(Constants.TokenErrors.InvalidGrant);
            }

            _validatedRequest.AuthorizationCode = authZcode;

            /////////////////////////////////////////////
            // validate redirect_uri
            /////////////////////////////////////////////
            string redirectUri = parameters.Get(Constants.TokenRequest.RedirectUri);
            if (redirectUri.IsMissing())
            {
                string error = "Redirect URI is missing.";
                LogError(error);
                RaiseFailedAuthorizationCodeRedeemedEvent(code, error);

                return Invalid(Constants.TokenErrors.UnauthorizedClient);
            }

            if (redirectUri.Equals(_validatedRequest.AuthorizationCode.RedirectUri, StringComparison.Ordinal) == false)
            {
                string error = "Invalid redirect_uri: " + redirectUri;
                LogError(error);
                RaiseFailedAuthorizationCodeRedeemedEvent(code, error);

                return Invalid(Constants.TokenErrors.UnauthorizedClient);
            }

            /////////////////////////////////////////////
            // validate scopes are present
            /////////////////////////////////////////////
            if (_validatedRequest.AuthorizationCode.RequestedScopes == null ||
                !_validatedRequest.AuthorizationCode.RequestedScopes.Any())
            {
                string error = "Authorization code has no associated scopes.";
                LogError(error);
                RaiseFailedAuthorizationCodeRedeemedEvent(code, error);

                return Invalid(Constants.TokenErrors.InvalidRequest);
            }


            /////////////////////////////////////////////
            // make sure user is enabled
            /////////////////////////////////////////////
            if (await _users.IsActiveAsync(_validatedRequest.AuthorizationCode.Subject) == false)
            {
                string error = "User has been disabled: " + _validatedRequest.AuthorizationCode.Subject;
                LogError(error);
                RaiseFailedAuthorizationCodeRedeemedEvent(code, error);

                return Invalid(Constants.TokenErrors.InvalidRequest);
            }

            Logger.Info("Validation of authorization code token request success");
            RaiseSuccessfulAuthorizationCodeRedeemedEvent();

            return Valid();
        }

        private async Task<ValidationResult> ValidateClientCredentialsRequestAsync(NameValueCollection parameters)
        {
            Logger.Info("Start client credentials token request validation");

            /////////////////////////////////////////////
            // check if client is authorized for grant type
            /////////////////////////////////////////////
            if (_validatedRequest.Client.Flow != Flows.ClientCredentials)
            {
                if (_validatedRequest.Client.AllowClientCredentialsOnly == false)
                {
                    LogError("Client not authorized for client credentials flow");
                    return Invalid(Constants.TokenErrors.UnauthorizedClient);
                }
            }

            /////////////////////////////////////////////
            // check if client is allowed to request scopes
            /////////////////////////////////////////////
            if (!(await ValidateRequestedScopesAsync(parameters)))
            {
                LogError("Invalid scopes.");
                return Invalid(Constants.TokenErrors.InvalidScope);
            }

            if (_validatedRequest.ValidatedScopes.ContainsOpenIdScopes)
            {
                LogError("Client cannot request OpenID scopes in client credentials flow");
                return Invalid(Constants.TokenErrors.InvalidScope);
            }

            if (_validatedRequest.ValidatedScopes.ContainsOfflineAccessScope)
            {
                LogError("Client cannot request a refresh token in client credentials flow");
                return Invalid(Constants.TokenErrors.InvalidScope);
            }

            Logger.Info("Client credentials token request validation success");
            return Valid();
        }

        private async Task<ValidationResult> ValidateResourceOwnerCredentialRequestAsync(NameValueCollection parameters)
        {
            Logger.Info("Start password token request validation");

            // if we've disabled local authentication, then fail
            if (_options.AuthenticationOptions.EnableLocalLogin == false ||
                _validatedRequest.Client.EnableLocalLogin == false)
            {
                LogError("EnableLocalLogin is disabled, failing with UnsupportedGrantType");
                return Invalid(Constants.TokenErrors.UnsupportedGrantType);
            }

            /////////////////////////////////////////////
            // check if client is authorized for grant type
            /////////////////////////////////////////////
            if (_validatedRequest.Client.Flow != Flows.ResourceOwner)
            {
                LogError("Client not authorized for resource owner flow");
                return Invalid(Constants.TokenErrors.UnauthorizedClient);
            }

            /////////////////////////////////////////////
            // check if client is allowed to request scopes
            /////////////////////////////////////////////
            if (!(await ValidateRequestedScopesAsync(parameters)))
            {
                LogError("Invalid scopes.");
                return Invalid(Constants.TokenErrors.InvalidScope);
            }

            /////////////////////////////////////////////
            // check resource owner credentials
            /////////////////////////////////////////////
            string userName = parameters.Get(Constants.TokenRequest.UserName);
            string password = parameters.Get(Constants.TokenRequest.Password);

            if (userName.IsMissing() || password.IsMissing())
            {
                LogError("Username or password missing.");
                return Invalid(Constants.TokenErrors.InvalidGrant);
            }

            if (userName.Length > Constants.MaxUserNameLength ||
                password.Length > Constants.MaxPasswordLength)
            {
                LogError("Username or password too long.");
                return Invalid(Constants.TokenErrors.InvalidGrant);
            }

            _validatedRequest.UserName = userName;

            /////////////////////////////////////////////
            // check optional parameters and populate SignInMessage
            /////////////////////////////////////////////
            var signInMessage = new SignInMessage();

            // pass through client_id
            signInMessage.ClientId = _validatedRequest.Client.ClientId;

            // process acr values
            string acr = parameters.Get(Constants.AuthorizeRequest.AcrValues);
            if (acr.IsPresent())
            {
                if (acr.Length > Constants.MaxAcrValuesLength)
                {
                    LogError("Acr values too long.");
                    return Invalid(Constants.TokenErrors.InvalidRequest);
                }

                List<string> acrValues = acr.FromSpaceSeparatedString().Distinct().ToList();

                // look for well-known acr value -- idp
                string idp = acrValues.FirstOrDefault(x => x.StartsWith(Constants.KnownAcrValues.HomeRealm));
                if (idp.IsPresent())
                {
                    signInMessage.IdP = idp.Substring(Constants.KnownAcrValues.HomeRealm.Length);
                    acrValues.Remove(idp);
                }

                // look for well-known acr value -- tenant
                string tenant = acrValues.FirstOrDefault(x => x.StartsWith(Constants.KnownAcrValues.Tenant));
                if (tenant.IsPresent())
                {
                    signInMessage.Tenant = tenant.Substring(Constants.KnownAcrValues.Tenant.Length);
                    acrValues.Remove(tenant);
                }

                // pass through any remaining acr values
                if (acrValues.Any())
                {
                    signInMessage.AcrValues = acrValues;
                }
            }

            _validatedRequest.SignInMessage = signInMessage;

            /////////////////////////////////////////////
            // authenticate user
            /////////////////////////////////////////////
            AuthenticateResult authnResult = await _users.AuthenticateLocalAsync(userName, password, signInMessage);
            if (authnResult == null || authnResult.IsError || authnResult.IsPartialSignIn)
            {
                LogError("User authentication failed");
                RaiseFailedResourceOwnerAuthenticationEvent(userName, signInMessage);

                return Invalid(Constants.TokenErrors.InvalidGrant);
            }

            _validatedRequest.UserName = userName;
            _validatedRequest.Subject = authnResult.User;

            RaiseSuccessfulResourceOwnerAuthenticationEvent(userName, authnResult.User.GetSubjectId(), signInMessage);
            Logger.Info("Password token request validation success.");
            return Valid();
        }

        private async Task<ValidationResult> ValidateRefreshTokenRequestAsync(NameValueCollection parameters)
        {
            Logger.Info("Start validation of refresh token request");

            string refreshTokenHandle = parameters.Get(Constants.TokenRequest.RefreshToken);
            if (refreshTokenHandle.IsMissing())
            {
                string error = "Refresh token is missing";
                LogError(error);
                RaiseRefreshTokenRefreshFailureEvent(null, error);

                return Invalid(Constants.TokenErrors.InvalidRequest);
            }

            _validatedRequest.RefreshTokenHandle = refreshTokenHandle;

            /////////////////////////////////////////////
            // check if refresh token is valid
            /////////////////////////////////////////////
            RefreshToken refreshToken = await _refreshTokens.GetAsync(refreshTokenHandle);
            if (refreshToken == null)
            {
                string error = "Refresh token is invalid";
                LogWarn(error);
                RaiseRefreshTokenRefreshFailureEvent(refreshTokenHandle, error);

                return Invalid(Constants.TokenErrors.InvalidGrant);
            }

            /////////////////////////////////////////////
            // check if refresh token has expired
            /////////////////////////////////////////////
            if (refreshToken.CreationTime.HasExceeded(refreshToken.LifeTime))
            {
                string error = "Refresh token has expired";
                LogWarn(error);
                RaiseRefreshTokenRefreshFailureEvent(refreshTokenHandle, error);

                await _refreshTokens.RemoveAsync(refreshTokenHandle);
                return Invalid(Constants.TokenErrors.InvalidGrant);
            }

            /////////////////////////////////////////////
            // check if client belongs to requested refresh token
            /////////////////////////////////////////////
            if (_validatedRequest.Client.ClientId != refreshToken.ClientId)
            {
                LogError(string.Format("Client {0} tries to refresh token belonging to client {1}",
                    _validatedRequest.Client.ClientId, refreshToken.ClientId));
                RaiseRefreshTokenRefreshFailureEvent(refreshTokenHandle, "Invalid client binding");

                return Invalid(Constants.TokenErrors.InvalidGrant);
            }

            /////////////////////////////////////////////
            // check if client still has offline_access scope
            /////////////////////////////////////////////
            if (_validatedRequest.Client.ScopeRestrictions != null &&
                _validatedRequest.Client.ScopeRestrictions.Count != 0)
            {
                if (!_validatedRequest.Client.ScopeRestrictions.Contains(Constants.StandardScopes.OfflineAccess))
                {
                    string error = "Client does not have access to offline_access scope anymore";
                    LogError(error);
                    RaiseRefreshTokenRefreshFailureEvent(refreshTokenHandle, error);

                    return Invalid(Constants.TokenErrors.InvalidGrant);
                }
            }

            _validatedRequest.RefreshToken = refreshToken;

            /////////////////////////////////////////////
            // make sure user is enabled
            /////////////////////////////////////////////
            ClaimsPrincipal principal = IdentityServerPrincipal.FromSubjectId(_validatedRequest.RefreshToken.SubjectId,
                refreshToken.AccessToken.Claims);

            if (await _users.IsActiveAsync(principal) == false)
            {
                string error = "User has been disabled: " + _validatedRequest.RefreshToken.SubjectId;
                LogError(error);
                RaiseRefreshTokenRefreshFailureEvent(refreshTokenHandle, error);

                return Invalid(Constants.TokenErrors.InvalidRequest);
            }

            Logger.Info("Validation of refresh token request success");
            return Valid();
        }

        private async Task<ValidationResult> ValidateCustomGrantRequestAsync(NameValueCollection parameters)
        {
            Logger.Info("Start validation of custom grant token request");

            /////////////////////////////////////////////
            // check if client is authorized for custom grant type
            /////////////////////////////////////////////
            if (_validatedRequest.Client.Flow != Flows.Custom)
            {
                LogError("Client not registered for custom grant type");
                return Invalid(Constants.TokenErrors.UnsupportedGrantType);
            }

            /////////////////////////////////////////////
            // check if client has grant type restrictions
            /////////////////////////////////////////////
            if (_validatedRequest.Client.CustomGrantTypeRestrictions.Any())
            {
                if (!_validatedRequest.Client.CustomGrantTypeRestrictions.Contains(_validatedRequest.GrantType))
                {
                    LogError("Client has configured grant type restrictions. Requested grant is not allowed.");
                    return Invalid(Constants.TokenErrors.UnsupportedGrantType);
                }
            }

            /////////////////////////////////////////////
            // check if client is allowed to request scopes
            /////////////////////////////////////////////
            if (!(await ValidateRequestedScopesAsync(parameters)))
            {
                LogError("Invalid scopes.");
                return Invalid(Constants.TokenErrors.InvalidScope);
            }

            /////////////////////////////////////////////
            // validate custom grant type
            /////////////////////////////////////////////
            CustomGrantValidationResult result = await _customGrantValidator.ValidateAsync(_validatedRequest);

            if (result == null)
            {
                LogError("Invalid custom grant.");
                return Invalid(Constants.TokenErrors.InvalidGrant);
            }

            if (result.ErrorMessage.IsPresent())
            {
                LogError("Invalid custom grant: " + result.ErrorMessage);
                return Invalid(result.ErrorMessage);
            }

            if (result.Principal != null)
            {
                _validatedRequest.Subject = result.Principal;
            }

            Logger.Info("Validation of custom grant token request success");
            return Valid();
        }

        private async Task<bool> ValidateRequestedScopesAsync(NameValueCollection parameters)
        {
            string scopes = parameters.Get(Constants.TokenRequest.Scope);
            if (scopes.IsMissingOrTooLong(Constants.MaxScopeLength))
            {
                Logger.Warn("Scopes missing or too long");
                return false;
            }

            List<string> requestedScopes = ScopeValidator.ParseScopesString(scopes);

            if (requestedScopes == null)
            {
                return false;
            }

            if (!_scopeValidator.AreScopesAllowed(_validatedRequest.Client, requestedScopes))
            {
                return false;
            }

            if (!await _scopeValidator.AreScopesValidAsync(requestedScopes))
            {
                return false;
            }

            _validatedRequest.Scopes = requestedScopes;
            _validatedRequest.ValidatedScopes = _scopeValidator;
            return true;
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

        private void LogError(string message)
        {
            var validationLog = new TokenRequestValidationLog(_validatedRequest);
            string json = LogSerializer.Serialize(validationLog);

            Logger.ErrorFormat("{0}\n {1}", message, json);
        }

        private void LogWarn(string message)
        {
            var validationLog = new TokenRequestValidationLog(_validatedRequest);
            string json = LogSerializer.Serialize(validationLog);

            Logger.WarnFormat("{0}\n {1}", message, json);
        }

        private void LogSuccess()
        {
            var validationLog = new TokenRequestValidationLog(_validatedRequest);
            string json = LogSerializer.Serialize(validationLog);

            Logger.InfoFormat("{0}\n {1}", "Token request validation success", json);
        }

        private void RaiseSuccessfulResourceOwnerAuthenticationEvent(string userName, string subjectId,
            SignInMessage signInMessage)
        {
            _events.RaiseSuccessfulResourceOwnerFlowAuthenticationEvent(userName, subjectId, signInMessage);
        }

        private void RaiseFailedResourceOwnerAuthenticationEvent(string userName, SignInMessage signInMessage)
        {
            _events.RaiseFailedResourceOwnerFlowAuthenticationEvent(userName, signInMessage);
        }

        private void RaiseFailedAuthorizationCodeRedeemedEvent(string handle, string error)
        {
            _events.RaiseFailedAuthorizationCodeRedeemedEvent(_validatedRequest.Client, handle, error);
        }

        private void RaiseSuccessfulAuthorizationCodeRedeemedEvent()
        {
            _events.RaiseSuccessAuthorizationCodeRedeemedEvent(_validatedRequest.Client,
                _validatedRequest.AuthorizationCodeHandle);
        }

        private void RaiseRefreshTokenRefreshFailureEvent(string handle, string error)
        {
            _events.RaiseFailedRefreshTokenRefreshEvent(_validatedRequest.Client, handle, error);
        }

       
    }
}