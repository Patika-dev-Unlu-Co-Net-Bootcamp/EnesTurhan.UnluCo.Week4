using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ApiSample.Dtos
{
    /// <summary>
    /// Enduserdan authenticate olurken alıcağımız değerler
    /// GrantType izin tipi yani username ve password ile resource owner bazlı izin default olarak set ettik.
    /// </summary>
    public class AuthDto
    {
        public string UserName { get; set; }
        public string Password { get; set; }

        public string GrantType { get; set; } 

    }

    public static class GrantTypes
    {
        public const string Password = "password";
        public const string ClientCredentials = "client_credentials";
    }
}
