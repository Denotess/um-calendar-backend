using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Extensions.FileSystemGlobbing;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Win32;
using System.Security.Authentication.ExtendedProtection;

DotNetEnv.Env.Load();

var builder = WebApplication.CreateBuilder();

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

app.MapGet("/generate-token/", (HttpContext context) => 
{
    if (!context.Request.Headers.TryGetValue("X-API-Key", out var recievedKey))
    {
        return Results.Unauthorized();
    }
    if (recievedKey != apiKey) {
        return Results.Unauthorized();
    }

    var claims = new[]
    {
        new Claim(ClaimTypes.Name, "admin"),
        new Claim(ClaimTypes.Role, "owner")
    };
    
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
    var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    
    var token = new JwtSecurityToken(
        issuer: jwtIssuer,
        audience: jwtAudience,
        claims: claims,
        expires: DateTime.Now.AddYears(1),
        signingCredentials: credentials
    );
    
    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
    return Results.Ok(new { token = tokenString });
})
.WithTags("Authorisation");

app.Run();

record LoginRequest(string ApiKey);
