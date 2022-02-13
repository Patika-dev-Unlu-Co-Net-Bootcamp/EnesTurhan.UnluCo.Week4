using ApiSample.Dtos;
using ApiSample.Identity;
using ApiSample.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ApiSample.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TokensController : ControllerBase
    {
        private readonly ITokenService _tokenService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signManager;


        public TokensController(ITokenService tokenService, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            _tokenService = tokenService;
            _userManager = userManager;
            _signManager = signInManager;


        }

        [HttpPost]
        public async Task<IActionResult> Token([FromBody] AuthDto model)
        {


            if((model.UserName == "enes" || model.UserName =="ahmet") && model.Password == "1234" && model.GrantType == GrantTypes.Password)
            {
                // access token da saklanacak bilgiler.
                var claims = new List<Claim>
                {
                    new Claim("id",model.UserName == "enes" ? "1":"2"),
                    new Claim(ClaimTypes.Name,model.UserName)
                };

                var response = await _tokenService.GenerateToken(claims);

                RefreshTokenStore.Tokens.Add(response.RefreshToken);

                return Ok(response);
            }

            // eğer sistemde kayıtlı bir kullanıcı değilsek 401 hatası döndür.
            return Unauthorized();
        }


        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDto model)
        {


            if(RefreshTokenStore.Tokens.Any(x => x == model.RefreshToken))
            {
                // refresh token sistemde varsa access token
                // fakat acess token biz mi oluşturduk kontrol etmeliyiz.

               var principle =  TokenHelper.ValidateAccessToken(model.AccessToken);

                // veritabanına gitmeden adamın oturum açarken kullandığı claim bilgilerini tekrar validateaccesstoken ile aldık. zaten eğer yanlış bir bilgiyse principle null gelicektir. jwt bu kodu çözemeyecektir.

                if(principle != null)
                {
                    var response = await _tokenService.GenerateToken(principle.Claims);

                    return Ok(response);
                }
                return Unauthorized();
            }
            // eğer sistemde kayıtlı bir kullanıcı değilsek 401 hatası döndür.
            return Unauthorized();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginInputModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            var checkPassword = await _userManager.CheckPasswordAsync(user, model.Password);


            if (user != null && checkPassword)
            {
                // email confirmed olup olmasını kontrol eder. 
                // signInManager signInAsync bu kontrolü yapmaz.
                await _signManager.PasswordSignInAsync(user, model.Password, model.RememberMe, false);

                return Redirect("/Admin");
            }

            return Ok();
        }
    }
}
