using System.Collections.Specialized;
using System.Threading.Tasks;
using Thinktecture.IdentityServer.Core.Models;

namespace Thinktecture.IdentityServer.Core.Validation
{
    public interface IComoRequestValidator
    {
        Task<ValidationResult> Validate(NameValueCollection parameters, Client client);
    }
}