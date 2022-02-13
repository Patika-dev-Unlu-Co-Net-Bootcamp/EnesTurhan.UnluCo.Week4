using ApiSample.Dtos;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ApiSample.Controllers
{
    // mvc route döndürdük.
    //[Route("api/[controller]/[action]/{id?}")]
    [Route("api/[controller]")]
    [ApiController]

    //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    // Access Token ile kimlik doğrulamadan bu controller'a erişemeyiz. protected resource halinegelimiş oldu
    public class ProductsController : ControllerBase
    {
        [HttpGet("v2")]
        // attribute routing ile her bir route birbirinden ayırdık
        public IActionResult GetProducts2()
        {
            // saveToken yapınca accessToken uygulama genelinde erişebiliyoruz. HttpContext.GetTokenAsync(JwtBearerDefaults.AuthenticationScheme);

            var model = new List<ProductDto>
            {
               new ProductDto
               {
                   Id = Guid.NewGuid().ToString(),
                   Name = "P-1",
                   Price = 10,
                   Stock = 20
               },
               new ProductDto
               {
                   Id = Guid.NewGuid().ToString(),
                   Name = "P-2",
                   Price = 13,
                   Stock = 24
               }
            };


            return Ok(model);
        }

        [HttpGet("v1")][Authorize]
        public IActionResult GetProducts()
        {
            // actionları IActionResult tipinde genelde işaretleriz.
            // eğer bir get isteği ise ok result ile 200 status code döneriz.
            var model = new List<ProductDto>
            {
               new ProductDto
               {
                   Id = Guid.NewGuid().ToString(),
                   Name = "P-1",
                   Price = 10,
                   Stock = 20
               },
               new ProductDto
               {
                   Id = Guid.NewGuid().ToString(),
                   Name = "P-2",
                   Price = 13,
                   Stock = 24
               }
            };

            return Ok(model);
        }

        // id değerini dışarıdan dinamik yakalayacak şekilde ayarladık.
        // attribute routing kullandık
        [HttpGet("v1/{id?}")]
        public IActionResult GetProductById(string id)
        {
            if (string.IsNullOrEmpty(id))
                return NotFound(); // 404 kaynak bulunamadı hatası döndür

            return Ok(new ProductDto {
                Id = id, 
                Name = "Deneme", 
                Price = 10, 
                Stock = 12 
            });

        }

        // querystring ile yakaladık
        [HttpGet("v3")]
        public IActionResult GetProductById2(string id)
        {
            if (string.IsNullOrEmpty(id))
                return NotFound(); // 404 kaynak bulunamadı hatası döndür

            return Ok(new ProductDto
            {
                Id = id,
                Name = "Deneme",
                Price = 10,
                Stock = 12
            });

        }

        // 415 sunucuya istenilen formatta veri taşınmadı anlamına gelen status code 415 Unsupported Media Type
        [HttpPost("create-v1")][Authorize]
        public IActionResult CreateProduct([FromBody] ProductDto model)
        {
            // [FromBody] attribute ile api ya gönderilen dosyayı application-json formatında alırız.
            // eğer www.urlformencoded şeklinde alıcak isek FromForm kullanırız.
            // Farklı şekillerde post ile veri taşınabilir.
            // FromHeader, FromQuery, FromRoute, FromBody, FromForm vs.

            // api da olmayan yeni bir kayanğı açmak için created 201 result döndürürüz.

            return Created($"api/products/v1/{model.Id}", model);
        }


        [HttpPost("create-v2")]
        public IActionResult CreateProduct2([FromForm] ProductDto model)
        {
            // yani burada bilgi x-www-form-urlencoded

            return Created($"api/products/v1/{model.Id}", model);
        }


        [HttpPost("{barcode}")]
        public IActionResult GetProductByCode([FromRoute] string barcode)
        {
            return Ok(new ProductDto { Id = "1", Name = "Product1", Price = 10, Stock=20 });
        }

        [HttpPost("changeName")]
        public IActionResult ChangeProductName([FromBody] string value)
        {
            // genelde body üzerinden object göndeririz fakat bazı ektrem durumlarda tek bir veri value type gönderebiliriz.
            return Ok();

        }









    }
}
