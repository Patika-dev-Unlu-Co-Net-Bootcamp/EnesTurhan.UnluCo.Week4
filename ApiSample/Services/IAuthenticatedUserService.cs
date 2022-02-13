using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ApiSample.Services
{
    public class AuthenticatedUser
    {
        public string Email { get; set; }
        public string Id { get; set; }

    }

    public interface IAuthenticatedUserService
    {
        AuthenticatedUser GetUser { get; }
    }
}
