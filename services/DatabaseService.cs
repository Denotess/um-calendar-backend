using Npgsql;
using System.Threading.Tasks;

namespace um_calendar_backend.services
{
    public class DatabaseService
    {
        private readonly string _connectionString;
        public DatabaseService(string connectionString)
        {
            _connectionString = connectionString;
        }
        public async Task<bool> UserExists(string email)
        {
            try
            {

                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                using var cmd = new NpgsqlCommand("SELECT COUNT(*) FROM users WHERE email = @email", conn);
                cmd.Parameters.AddWithValue("email", email);
                var count = (long)await cmd.ExecuteScalarAsync();
                return count > 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"UserExists error: {ex.Message}");
                return false;
            }
        }

        public async Task CreateUser(string email, string name, string passwordHash, string passwordSalt)
        {
            try

            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                using var cmd = new NpgsqlCommand(
                    "INSERT INTO users (email, name, password_hash, password_salt) VALUES (@email, @name, @password_hash, @password_salt)", conn);
                cmd.Parameters.AddWithValue("email", email);
                cmd.Parameters.AddWithValue("name", name);
                cmd.Parameters.AddWithValue("password_hash", passwordHash);
                cmd.Parameters.AddWithValue("password_salt", passwordSalt);
                await cmd.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"CreatUser error: {ex.Message}");
                return;
            }
        }
        public async Task<User?> GetUserByEmail(string email)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                await conn.OpenAsync();
                using var cmd = new NpgsqlCommand(
                    "SELECT email, name, password_hash, password_salt FROM users WHERE email = @email", conn);
                cmd.Parameters.AddWithValue("email", email);
                using var reader = await cmd.ExecuteReaderAsync();
                if (await reader.ReadAsync())
                {
                    return new User
                    {
                        Email = reader.GetString(0),
                        Name = reader.GetString(1),
                        PasswordHash = reader.GetString(2),
                        PasswordSalt = reader.GetString(3)
                    };
                }
                return null;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"GetUserByEmail error: {ex.Message}");
                return null;
            }
        }
        public class User
        {
            public string Email { get; set; } = string.Empty;
            public string Name { get; set; } = string.Empty;

            public string PasswordHash { get; set; } = string.Empty;
            public string PasswordSalt { get; set; } = string.Empty;
        }
    }

}