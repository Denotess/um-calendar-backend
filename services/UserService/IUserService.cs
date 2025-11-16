using UmCalendar.DTOs;
using UmCalendar.Models;
namespace UmCalendar.Services
{
    public interface IUserService
    {
        Task<(bool Success, string Error)> RegisterAsync(RegisterDto dto);
        Task<User> AuthenticateAsync(LoginDto dto);
    }
}