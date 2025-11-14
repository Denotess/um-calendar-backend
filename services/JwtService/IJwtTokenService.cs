using Microsoft.AspNetCore.Mvc;
namespace UmCalendar.Services
{
    public interface IJwtTokenService
    {
        string GenerateToken(string username, string role);
    }
}