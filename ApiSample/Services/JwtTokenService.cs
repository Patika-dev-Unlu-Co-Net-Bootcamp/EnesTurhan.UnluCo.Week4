using ApiSample.Dtos;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace ApiSample.Services
{
    public class JwtTokenService : ITokenService
    {

        private readonly IConfiguration _configuration;

        public JwtTokenService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        // Json Web Token libraty kullanacağız
        /// <summary>
        /// JWT ile Token oluştururuz.
        /// // Auth2.0 (Open Authorization 2.0) ve ODIC (Open Id Connect Protokolü)
        /// </summary>
        /// <returns></returns>
        public async Task<TokenDto> GenerateToken(IEnumerable<Claim> Claims)
        {
            // kullanıcı ile alakalı bilgilerin üzerinde tutulduğu nesne claimType ve claimValue olarak key-value pair bir şekilde tutulur.

            var token = new JwtSecurityToken
               (
                   issuer: _configuration["JWT:issuer"],
                   audience: _configuration["JWT:audience"],
                   claims: Claims,
                   expires: DateTime.UtcNow.AddSeconds(TokenExpireDateHelper.GetExpireDateMinutes),
                   notBefore: DateTime.UtcNow,
                   signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:signingKey"])),
                           SecurityAlgorithms.HmacSha512)

                  
               );

            var model = new TokenDto
            {
                AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
                RefreshToken = TokenHelper.GetToken()
            };

            return await Task.FromResult(model);
        }
    }
}
