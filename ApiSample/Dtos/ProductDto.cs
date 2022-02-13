using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ApiSample.Dtos
{
    /// <summary>
    /// Dtolar data transfer objeleri olduğu için anemic model olarak yazılır sadece propertylerden oluşur. Data annotations ile validasyon işlemleri yapılabilir.
    /// </summary>
    public class ProductDto
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public decimal  Price { get; set; }

        public int Stock { get; set; }

    }
}
