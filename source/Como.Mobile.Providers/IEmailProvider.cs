using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Como.Mobile.Providers
{
    public interface IEmailProvider
    {
        Task<bool> Send();
    }
}
