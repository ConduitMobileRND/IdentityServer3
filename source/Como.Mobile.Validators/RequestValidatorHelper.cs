using System;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Thinktecture.IdentityModel.Http;

namespace Como.Mobile.Validators
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
            var dresult = JsonConvert.DeserializeObject<string>(result.Result);

            return dresult;
        }
    }
}