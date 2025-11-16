using Microsoft.AspNetCore.Mvc;
using UmCalendar.DTOs;
using UmCalendar.Models;
using UmCalendar.Services;
using NSwag.Annotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace UmCalendar.Controllers
{
    [ApiController]
    [Route("user")]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IJwtTokenService _jwtTokenService;
        private readonly AppDbContext _db;

        public UserController(IUserService userService, IJwtTokenService jwtTokenService, AppDbContext db)
        {
            _userService = userService;
            _jwtTokenService = jwtTokenService;
            _db = db;
        }
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto dto)
        {
            var result = await _userService.RegisterAsync(dto);
            if (!result.Success)
                return BadRequest(new { message = result.Error ?? "User already exists or error occured." });
            return Ok(new { message = "Registration successful." });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto dto)
        {
            var user = await _userService.AuthenticateAsync(dto);
            if (user == null) return Unauthorized("Invalid credentials.");

            var token = _jwtTokenService.GenerateToken(user.Email, user.Name);
            return Ok(new { token, user = new { user.Id, user.Email, user.Name } });
        }

        [Authorize]
        [HttpGet("profile")]
        public async Task<IActionResult> Profile(){
            var email = User.FindFirst(ClaimTypes.Name)?.Value;
            if (email == null) return Unauthorized();

            var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null) return NotFound();

            return Ok(new { name = user.Name, email = user.Email, createdAt = user.CreatedAt });
        }
    }
}