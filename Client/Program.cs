using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace Client
{
    class Program
    {
        private static string PublicKeyLocation = @"C:\Users\BRUNO BRITO\source\repos\AsymetricEncryptionDemo\AsymetricEncryptionDemo\bin\Debug\net5.0\publickey.json";
        private static HttpClient client = new HttpClient();
        static async Task Main(string[] args)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = await Loadkey();

            var enc = new EncryptingCredentials(key, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes128CbcHmacSha256);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = "me",
                Audience = "you",
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim("cc", "4000-0000-0000-0002"),
                }),
                EncryptingCredentials = enc
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);


            Console.WriteLine(tokenHandler.WriteToken(token));
        }


        private static async Task<SecurityKey> Loadkey()
        {
            var publicKey = await client.GetStringAsync("https://localhost:5001/jwks_e");
            var key = JsonWebKeySet.Create(publicKey);
            return key.Keys.FirstOrDefault();
        }
        

    }
}
