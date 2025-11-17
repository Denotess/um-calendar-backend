using Microsoft.AspNetCore.Mvc;
using UmCalendar.DTOs;
using UmCalendar.Models;
using UmCalendar.Services;
using NSwag.Annotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;

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
        public async Task<IActionResult> Profile()
        {
            var email = User.FindFirst(ClaimTypes.Name)?.Value;
            if (email == null) return Unauthorized();

            var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null) return NotFound();

            return Ok(new { name = user.Name, email = user.Email, createdAt = user.CreatedAt });
        }
        [HttpGet("signin-google")]
        public IActionResult ExternalLogin([FromQuery] string provider = "Google", string returnUrl = null)
        {
            var redirectUrl = Url.Action("ExternalLoginCallback", "User", new { ReturnUrl = returnUrl });
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            return Challenge(properties, provider);
        }

        [HttpGet("signin-google-callback")]
        public async Task<IActionResult> ExternalLoginCallback()
        {
            var authenticateResult = await HttpContext.AuthenticateAsync("Google");
            if (authenticateResult == null) return RedirectToAction("Login");

            var email = authenticateResult.Principal.FindFirstValue(ClaimTypes.Email) ?? "";
            var name = authenticateResult.Principal.FindFirstValue(ClaimTypes.Name) ?? "";

            var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
            {
                user = new User { 
                    Email = email ?? "", 
                    Name = name ?? "", 
                    CreatedAt = DateTime.UtcNow,
                    PasswordHash = "",
                    PasswordSalt = ""
                    };
                _db.Users.Add(user);
                await _db.SaveChangesAsync();
            }

            var claims = new List<Claim>{
                new Claim(ClaimTypes.Name, user.Name),
                new Claim(ClaimTypes.Email, user.Email)
            };
            var claimsIdentity = new ClaimsIdentity(claims, "Cookies");
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
            await HttpContext.SignInAsync("Cookies", claimsPrincipal);
            var token = _jwtTokenService.GenerateToken(user.Email ?? "", user.Name ?? "");
            return Redirect($"http://localhost:5173/login?token={token}");
        }
    }
}