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
using UmCalendar.Services;
using UmCalendar.Controllers;

DotNetEnv.Env.Load();
var builder = WebApplication.CreateBuilder();

var jwtKey = builder.Configuration["Jwt:Key"]!;
var jwtIssuer = builder.Configuration["Jwt:Issuer"]!;
var jwtAudience = builder.Configuration["Jwt:Audience"]!;
var apiKey = builder.Configuration["Jwt:ApiKey"];

var rootPath = Directory.GetCurrentDirectory();
var calendarPath = Path.Combine(rootPath, "calendars");
builder.Services.AddSingleton(calendarPath);

// Add services
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApiDocument(config =>
{
    config.DocumentName = "calendar-api";
    config.Title = "Calendar Api";
    config.Version = "v1";
    config.AddSecurity("JWT", Enumerable.Empty<string>(), new NSwag.OpenApiSecurityScheme
    {
        Type = NSwag.OpenApiSecuritySchemeType.ApiKey,
        Name = "Authorization",
        In = NSwag.OpenApiSecurityApiKeyLocation.Header,
        Description = "Type: Bearer {your JWT token}."
    });
});

// Authentication
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
// Authorisation
builder.Services.AddAuthorization();

// Services
builder.Services.AddScoped<IJwtTokenService, JwtTokenService>();

// Cors
builder.Services.AddCors(options => options.AddPolicy(name: "UmPolicy",
    policy =>
    {
        policy.SetIsOriginAllowed(origin =>
        {
            if (string.IsNullOrEmpty(origin)) return true;
            try
            {
                var uri = new Uri(origin);
                var host = uri.Host.ToLowerInvariant();
                // production front end
                if (uri.Scheme == "https" && host == "um-calendar-frontend.pages.dev") return true;
    
                // subdomains
                if (uri.Scheme == "https" && host.EndsWith(".um-calendar-frontend.pages.dev")) return true;
                if (host.StartsWith("um-calendar")) return true;

                // localhost
                if (builder.Environment.IsDevelopment() && host == "localhost") return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"EXCEPTION_CORS:\nOrigin:{origin}\nException:{ex.Message}");
                return false;
            }
            return false;
        })
        .AllowAnyMethod()
        .AllowAnyHeader()
        .AllowCredentials();
    }));

var app = builder.Build();
// Middleware
app.UseCors("UmPolicy");

app.UseOpenApi();
app.UseSwaggerUi();

// Auth
app.UseAuthentication();
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


app.MapControllers();
app.Run();

record LoginRequest(string ApiKey);
