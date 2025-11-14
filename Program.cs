using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Extensions.FileSystemGlobbing;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Win32;
using System.Security.Authentication.ExtendedProtection;
using um_calendar_backend.services;

DotNetEnv.Env.Load();

var builder = WebApplication.CreateBuilder();

var connectionString = Environment.GetEnvironmentVariable("DefaultConnection") ?? "";
var dbService = new DatabaseService(connectionString);


var jwtKey = builder.Configuration["Jwt:Key"]!;
var jwtIssuer = builder.Configuration["Jwt:Issuer"]!;
var jwtAudience = builder.Configuration["Jwt:Audience"]!;
var apiKey = builder.Configuration["Jwt:ApiKey"];

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApiDocument(config =>
{
    config.DocumentName = "calendar-api";
    config.Title = "Calendar Api";
    config.Version = "v1";
});
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
.AddJwtBearer(jwtOptions =>
{
    jwtOptions.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidAudience = jwtAudience,
        ValidIssuer = jwtIssuer,
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(jwtKey)
        )
    };
});

builder.Services.AddAuthorization();
builder.Services.AddCors(FileOptions =>
{
    FileOptions.AddDefaultPolicy(policy =>
    {
        policy
        .AllowAnyOrigin()
        .AllowAnyMethod()
        .AllowAnyHeader();
    });
});

var app = builder.Build();
app.UseOpenApi();
app.UseSwaggerUi();

app.UseAuthentication();
app.UseCors();
app.UseAuthorization();

app.Use(async (context, next) =>
{
    if (context.Request.Path == "/")
    {
        context.Response.Redirect("/swagger");
        return;
    }
    await next();
});


var rootPath = Directory.GetCurrentDirectory();
var calendarPath = Path.Combine(rootPath, "calendars");
Directory.CreateDirectory(calendarPath);
string[] icsFiles = Directory.GetFiles(calendarPath, "*.ics");

app.MapGet("/health", () =>
{
    return new { status = "healthy" };
})
.WithTags("System");

app.MapGet("/names", () =>
{
    var names = icsFiles
    .Select(f => Path.GetFileNameWithoutExtension(f))
    .OrderBy(n => n)
    .ToArray();

    return names;
})
.WithTags("Calendars")
.RequireAuthorization();

app.MapGet("/cal/{name}", (string name) =>
{
    var filePath = Path.Combine(calendarPath, name + ".ics");
    if (!File.Exists(filePath))
    {
        return Results.NotFound();
    }
    var fileContent = File.ReadAllText(filePath);
    return Results.Content(fileContent, "text/calendar; charset=utf-8");
})
.WithTags("Calendars")
.RequireAuthorization();

app.MapPost("/register", async (string email, string name, string password) =>
{
    if (await dbService.UserExists(email))
    {
        return Results.BadRequest(new { message = "User already exists. " });
    }

    byte[] saltBytes = new byte[16];
    using (var rng = RandomNumberGenerator.Create())
    {
        rng.GetBytes(saltBytes);
    }
    string salt = Convert.ToBase64String(saltBytes);

    string passwordHash;
    using (var deriveBytes = new Rfc2898DeriveBytes(password, saltBytes, 100_000, HashAlgorithmName.SHA256))
    {
        byte[] hashBytes = deriveBytes.GetBytes(32);
        passwordHash = Convert.ToBase64String(hashBytes);
    }
    await dbService.CreateUser(email, name, passwordHash, salt);

    return Results.Ok(new { message = "User registrated succesfully." });
})
.WithTags("Authorisation");

app.MapPost("/login", async (string email, string password) =>
{
    var user = await dbService.GetUserByEmail(email);
    if (user == null)
        return Results.BadRequest(new { message = "invalid email or password." });

    string storedSalt = user.PasswordSalt;
    string storedHash = user.PasswordHash;

    byte[] saltBytes = Convert.FromBase64String(storedSalt);
    string passwordHash;
    using (var deriveBytes = new Rfc2898DeriveBytes(password, saltBytes, 100_000, HashAlgorithmName.SHA256))
    {
        byte[] hashBytes = deriveBytes.GetBytes(32);
        passwordHash = Convert.ToBase64String(hashBytes);
    }

    if (passwordHash != storedHash)
    {
        return Results.BadRequest(new { message = "Invalid email or password" });
    }

    var claims = new[]
    {
        new Claim(ClaimTypes.Name, user.Email),
        new Claim(ClaimTypes.Role, "user")
    };
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
    var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var token = new JwtSecurityToken(
        issuer: jwtIssuer,
        audience: jwtAudience,
        claims: claims,
        expires: DateTime.Now.AddHours(24),
        signingCredentials: credentials
    );
    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

    return Results.Ok(new { token = tokenString });

})
.WithTags("Authorisation");

app.MapGet("/generate-token/", () =>
{
    var claims = new[]
    {
        new Claim(ClaimTypes.Name, "public"),
        new Claim(ClaimTypes.Role, "viewer")
    };

    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
    var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
        issuer: jwtIssuer,
        audience: jwtAudience,
        claims: claims,
        expires: DateTime.Now.AddHours(24),
        signingCredentials: credentials
    );

    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
    return Results.Ok(new { token = tokenString });
})
.WithTags("Authorisation");

app.MapPost("auth/neon", async (string neonToken) =>
{
    var neonSecretKey = Environment.GetEnvironmentVariable("STACK_SECRET_SERVER_KEY");
    var tokenHandler = new JwtSecurityTokenHandler();
    var validationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(neonSecretKey)),
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true
    };

    try
    {
        var principal = tokenHandler.ValidateToken(neonToken, validationParameters, out var validatedToken);

        var email = principal.FindFirst(ClaimTypes.Email)?.Value ?? principal.FindFirst("email")?.Value;
        var name = principal.FindFirst(ClaimTypes.Name)?.Value ?? principal.FindFirst("name")?.Value;

        if (string.IsNullOrEmpty(email))
        {
            return Results.BadRequest(new { message = "Email not found in token." });
        }

        if (!await dbService.UserExists(email))
        {
            await dbService.CreateUser(email, name ?? "", "", "");
        }
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, email),
            new Claim(ClaimTypes.Role, "user")
        };
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: jwtIssuer,
            audience: jwtAudience,
            claims: claims,
            expires: DateTime.Now.AddHours(24),
            signingCredentials: credentials
        );
        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

        return Results.Ok(new { token = tokenString });
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Neon Auth token validation error: {ex.Message}");
        return Results.BadRequest(new { message = "Invalid Neon Auth token." });
    }

})
.WithTags("Authorisation");

app.MapGet("/me", async (ClaimsPrincipal userPrincipal) =>
{
    var email = userPrincipal.FindFirst(ClaimTypes.Name)?.Value;
    if (string.IsNullOrEmpty(email)){
        return Results.BadRequest(new {message = "User not found in token."});
    }

    var user = await dbService.GetUserByEmail(email);
    if (user == null)
        return Results.NotFound(new {message = "User not found."});
    
    return Results.Ok(new {
        email = user.Email,
        name = user.Name
    });
})
.RequireAuthorization()
.WithTags("User");

app.UseHttpsRedirection();
app.Run();

record LoginRequest(string ApiKey);
