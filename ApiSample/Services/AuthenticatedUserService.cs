using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ApiSample.Services
{
    public class AuthenticatedUserService : IAuthenticatedUserService
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuthenticatedUserService(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        public AuthenticatedUser GetUser
        {
            get
            {
                return new AuthenticatedUser
                {
                    Email = _httpContextAccessor.HttpContext.User.Claims.First(x => x.Type == ClaimTypes.Name).Value,
                    Id = _httpContextAccessor.HttpContext.User.Claims.First(x => x.Type == "id").Value
                };

            }
        }
        
        
    }
}
