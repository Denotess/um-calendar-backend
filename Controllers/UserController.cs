using Microsoft.AspNetCore.Mvc;
using UmCalendar.DTOs;
using UmCalendar.Models;
using UmCalendar.Services;
using NSwag.Annotations;
namespace UmCalendar.Controllers
{
    [ApiController]
    [Route("user")]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IJwtTokenService _jwtTokenService;
        public UserController(IUserService userService, IJwtTokenService jwtTokenService)
        {
            _userService = userService;
            _jwtTokenService = jwtTokenService;
        }
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto dto)
        {
            var success = await _userService.RegisterAsync(dto);
            if (!success) return BadRequest("User already exists or error occured.");
            return Ok(new {message = "Registration successful."});
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto dto)
        {
            var user = await _userService.AuthenticateAsync(dto);
            if (user == null) return Unauthorized("Invalid credentials.");

            var token = _jwtTokenService.GenerateToken(user.Email, user.Name);
            return Ok(new { token, user = new { user.Id, user.Email, user.Name } });
        }
    }
}