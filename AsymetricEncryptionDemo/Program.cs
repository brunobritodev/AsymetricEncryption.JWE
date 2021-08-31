using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace PrivateKey
{
    class Program
    {
        private static readonly string PrivateJwkLocation = Path.Combine(Environment.CurrentDirectory, "mysupersecretkey.json");
        private static readonly string PublicJwkLocation = Path.Combine(Environment.CurrentDirectory, "publickey.json");
        private static RandomNumberGenerator Rng = RandomNumberGenerator.Create();
        static void Main()
        {
            var key = Loadkey();

            var jwe = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJ0eXAiOiJKV1QifQ.K4-rhbkRn8CrGmLLQb_uucH23QUC1dLkJ2-lVPJ3ZhE2epWi8U6IFBFFJoGZBIeJf8sP47cD2Us54uo8RDlhLw9R_cWpnRhZ_N1uwJgrIgxdx_ldnS-WkEkHFEn3iy7-23yYVi-NfzTNwjlJF0MvGyM-nMNR_HBblHmbfT2PGjfdpS7qxN75mxr0RSeh6OExq68pvItuL2fnNljnI1ZpawDzJI3wRB3Ge0xRe7AAphV6BpEFKhcdVMcOq-vaCKWjcWSw-CBQ2hpv243lR7fN3ontvnxo5FsAY8yDgfSwEwKj4SmQ3KAa8wyGMZoFY4IugdAwEszvQ3tBL0vUu7DsOQ.X9fCTCsPKB49tiwADcc1FQ.FnMDAbr96Dy3lwR_OCMYM2390WSIv_5tl8gb9J8tl4fYXSPpH9t6kYxAmYn36hX0ySnporK7-gjYvCIDuK4Y72f9wC8P4x-jAFdJQkvgWHIZlf6yspMdyXL9YZeCL2ZGZSAs5Xp5ncvOnuRB9na6Z64qtGiJ-3iALK2uxcUAXCrojSYR8OYLeujF2wKC1422.uWTs_yH1mee7gAhKvI5t1w";

            var encryptingCredentials = new EncryptingCredentials(key, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes128CbcHmacSha256);

            var handler = new JsonWebTokenHandler();
            var result = handler.ValidateToken(jwe,
                new TokenValidationParameters
                {
                    RequireSignedTokens = false,
                    TokenDecryptionKey = encryptingCredentials.Key,
                    ValidateAudience = false,
                    ValidateIssuer = false
                });

            
        }
        

        private static byte[] GenerateKey(int bytes)
        {
            var data = new byte[bytes];
            Rng.GetBytes(data);
            return data;
        }

        private static SecurityKey Loadkey()
        {
            if (File.Exists(PrivateJwkLocation))
                return JsonSerializer.Deserialize<JsonWebKey>(File.ReadAllText(PrivateJwkLocation));

            var key = new RsaSecurityKey(RSA.Create(2048))
            {
                KeyId = Guid.NewGuid().ToString()
            };
            var privateKey = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
            privateKey.KeyId = Base64UrlEncoder.Encode(GenerateKey(16));
            File.WriteAllText(PrivateJwkLocation, JsonSerializer.Serialize(privateKey, new JsonSerializerOptions() { IgnoreNullValues = true }));


            var rsaPublic = new RsaSecurityKey(RSA.Create(key.Rsa.ExportParameters(false)));
            var publicKey = JsonWebKeyConverter.ConvertFromRSASecurityKey(rsaPublic);
            File.WriteAllText(PublicJwkLocation, JsonSerializer.Serialize(publicKey, new JsonSerializerOptions() { IgnoreNullValues = true }));
            
            return key;
        }

        private static JsonWebKey CreateJWK()
        {
            var key = new RsaSecurityKey(RSA.Create(2048))
            {
                KeyId = Guid.NewGuid().ToString()
            };
            var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
            jwk.KeyId = Base64UrlEncoder.Encode(GenerateKey(16));


            

            return jwk;
        }

        private static void DemoRodando()
        {
            //lets take a new CSP with a new 2048 bit rsa key pair
            var csp = new RSACryptoServiceProvider(2048);

            //how to get the private key
            var privKey = csp.ExportParameters(true);

            //and the public key ...
            var pubKey = csp.ExportParameters(false);


            //converting the public key into a string representation
            string pubKeyString = JsonSerializer.Serialize(pubKey);

            //converting it back
            pubKey = JsonSerializer.Deserialize<RSAParameters>(pubKeyString);

            //conversion for the private key is no black magic either ... omitted

            //we have a public key ... let's get a new csp and load that key
            csp = new RSACryptoServiceProvider();
            csp.ImportParameters(pubKey);

            //we need some data to encrypt
            var plainTextData = "foobar";

            //for encryption, always handle bytes...
            var bytesPlainTextData = System.Text.Encoding.Unicode.GetBytes(plainTextData);

            //apply pkcs#1.5 padding and encrypt our data 
            var bytesCypherText = csp.Encrypt(bytesPlainTextData, false);

            //we might want a string representation of our cypher text... base64 will do
            var cypherText = Convert.ToBase64String(bytesCypherText);


            /*
             * some transmission / storage / retrieval
             * 
             * and we want to decrypt our cypherText
             */

            //first, get our bytes back from the base64 string ...
            bytesCypherText = Convert.FromBase64String(cypherText);

            //we want to decrypt, therefore we need a csp and load our private key
            csp = new RSACryptoServiceProvider();
            csp.ImportParameters(privKey);

            //decrypt and strip pkcs#1.5 padding
            bytesPlainTextData = csp.Decrypt(bytesCypherText, false);

            //get our original plainText back...
            plainTextData = System.Text.Encoding.Unicode.GetString(bytesPlainTextData);
        }
    }
}
