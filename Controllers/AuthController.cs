using Microsoft.AspNetCore.Mvc;
using NSwag.Annotations;
using UmCalendar.Services;

namespace UmCalendar.Controllers
{
    [ApiController]
    [Route("auth")]
    [OpenApiTag("Authorisation")]
    public class AuthController : ControllerBase
    {
        private readonly IJwtTokenService _jwtTokenService;

        public AuthController(IJwtTokenService jwtTokenService)
        {
            _jwtTokenService = jwtTokenService;
        }
        public class TokenRequest
        {
            public string? Username { get; set; }
            public string? Role { get; set; }
        }
        [HttpOptions("generate-token")]
        public IActionResult HandlePreflight()
        {
            return NoContent(); // 204 No Content
        }
        [HttpPost("generate-token")]
        public IActionResult GenerateToken([FromBody] TokenRequest request)
        {
            if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Role))
            {
                return BadRequest("Username and Role are required.");
            }
            var token = _jwtTokenService.GenerateToken(request.Username, request.Role);
            return Ok(new { token });

        }

    }
}