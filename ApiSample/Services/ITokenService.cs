using ApiSample.Dtos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ApiSample.Services
{
    public interface ITokenService
    {
        /// <summary>
        /// TokenDto Response dönecek olan method
        /// </summary>
        /// <returns></returns>
        Task<TokenDto> GenerateToken(IEnumerable<Claim> Claims);
    }
}
