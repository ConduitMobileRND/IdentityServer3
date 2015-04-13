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

using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Thinktecture.IdentityServer.Core.Models;
using Thinktecture.IdentityServer.Core.Validation;

namespace Thinktecture.IdentityServer.Core.Services.Default
{
    /// <summary>
    ///     Default claims provider implementation
    /// </summary>
    public class ComoClaimsProvider : DefaultClaimsProvider
    {
        /// <summary>
        ///     Initializes a new instance of the <see cref="ComoClaimsProvider" /> class.
        /// </summary>
        /// <param name="users">The users service</param>
        public ComoClaimsProvider(IUserService users)
            : base(users)
        {
        }


        /// <summary>
        ///     Returns claims for an identity token.
        /// </summary>
        /// <param name="subject">The subject.</param>
        /// <param name="client">The client.</param>
        /// <param name="scopes">The requested scopes.</param>
        /// <param name="request">The raw request.</param>
        /// <returns>
        ///     Claims for the access token
        /// </returns>
        public override async Task<IEnumerable<Claim>> GetAccessTokenClaimsAsync(ClaimsPrincipal subject, Client client,
            IEnumerable<Scope> scopes, ValidatedRequest request)
        {
            // add client_id
            var outputClaims = new List<Claim>
            {
                new Claim(Constants.ClaimTypes.ClientId, client.ClientId),
            };
            if (request.Raw.Get(Constants.ClaimTypes.Appid) != null)
            {
                outputClaims.Add(new Claim(Constants.ClaimTypes.Appid, request.Raw.Get(Constants.ClaimTypes.Appid)));
            }
            if (request.Raw.Get(Constants.ClaimTypes.PublisherId) != null)
            {
                outputClaims.Add(new Claim(Constants.ClaimTypes.PublisherId,
                    request.Raw.Get(Constants.ClaimTypes.PublisherId)));
            }

            return await ConstructOutputClaims(subject, client, scopes, outputClaims);
        }
    }
}