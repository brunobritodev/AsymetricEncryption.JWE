using System;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace PrivateKey
{
    internal static class CryptoService
    {
        private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();
        /// <summary>
        /// Creates a new RSA security key.
        /// Key size recommendations: https://www.keylength.com/en/compare/
        /// </summary>
        /// <returns></returns>
        public static RsaSecurityKey CreateRsaSecurityKey(int keySize = 2048)
        {
            return new RsaSecurityKey(RSA.Create(keySize))
            {
                KeyId = CreateUniqueId()
            };
        }

        internal static string CreateUniqueId(int length = 16)
        {
            return Base64UrlEncoder.Encode(CreateRandomKey(length));
        }

        /// <summary>Creates a random key byte array.</summary>
        /// <param name="length">The length.</param>
        /// <returns></returns>
        internal static byte[] CreateRandomKey(int length)
        {
            byte[] data = new byte[length];
            Rng.GetBytes(data);
            return data;
        }
    }
}