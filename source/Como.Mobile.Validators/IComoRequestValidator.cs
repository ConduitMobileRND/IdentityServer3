using System.Collections.Specialized;
using System.Threading.Tasks;
using Thinktecture.IdentityServer.Core.Models;
using Thinktecture.IdentityServer.Core.Validation;

namespace Como.Mobile.Validators
{
    public interface IComoRequestValidator
    {
        Task<ValidationResult> Validate(NameValueCollection parameters, Client client);
    }
}