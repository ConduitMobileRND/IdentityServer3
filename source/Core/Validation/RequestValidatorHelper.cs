﻿using System;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using Thinktecture.IdentityModel.Http;

namespace Thinktecture.IdentityServer.Core.Validation
{
    public class RequestValidatorHelper : IRequestValidatorHelper
    {
        public string CallServiceGet(string token, string baseAddress, string uri)
        {
            var client = new HttpClient
            {
                BaseAddress = new Uri(baseAddress)
            };

            client.SetBearerToken(token);
            Task<string> result = client.GetStringAsync(uri);
            dynamic rawResult = JObject.Parse(result.Result);
            if (rawResult.result == null)
            {
                return null;
            }
            var dresult = Guid.Parse(rawResult.result.ToString());
            return dresult.ToString();
        }
    }
}