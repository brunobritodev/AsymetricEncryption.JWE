using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Interfaces;

namespace ServerApi.Controllers
{
    [ApiController]
    [Route("teste")]
    public class TesteController : ControllerBase
    {
        private readonly ILogger<TesteController> _logger;
        private readonly IJsonWebKeySetService _jwksService;

        public TesteController(ILogger<TesteController> logger, IJsonWebKeySetService jsonWebKeySetService)
        {
            _logger = logger;
            _jwksService = jsonWebKeySetService;
        }

        [HttpGet]
        public IActionResult Get(string jwe)
        {
            var handler = new JsonWebTokenHandler();
            var encryptingCredentials = _jwksService.GetCurrentEncryptingCredentials();
            var result = handler.ValidateToken(jwe,
                new TokenValidationParameters
                {
                    ValidIssuer = "me",
                    ValidAudience = "you",
                    RequireSignedTokens = false,
                    TokenDecryptionKey = encryptingCredentials.Key,
                });
            if (!result.IsValid)
                BadRequest();

            return Ok(result.Claims);
        }
    }

}
