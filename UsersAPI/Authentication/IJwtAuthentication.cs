using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace UsersAPI.Authentication
{
    public interface IJwtAuthentication
    {
        (string, DateTime) GetToken(string userName, IEnumerable<string> roles);
    }
}
