using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;


namespace AlvaServer.Services;

public static class AuthUtils
{
    // KEEP THIS SECRET THE SAME for Generation and Validation!
    // Ideally move this to appsettings.json for production.
    private const string SecretKey = "THIS_IS_A_SECRET_CHANGE_ME_TO_256_BITS"; 

    // === Argon2id password hashing (Same as before) ===
    public static (string hash, byte[] salt) HashPassword(string password, string username)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var key = DeriveKey(password, username, salt);
        var hash = Convert.ToBase64String(key);
        return (hash, salt);
    }

    public static bool VerifyPassword(string password, string username, string storedHash, byte[] storedSalt)
    {
        var key = DeriveKey(password, username, storedSalt);
        var hash = Convert.ToBase64String(key);
        return hash == storedHash;
    }

    private static byte[] DeriveKey(string password, string username, byte[] salt)
    {
        byte[] pwd = Encoding.UTF8.GetBytes(password + username.ToLowerInvariant());
        var argon = new Argon2id(pwd)
        {
            Salt = salt,
            Iterations = 3,
            MemorySize = 32768,
            DegreeOfParallelism = 1
        };
        return argon.GetBytes(32);
    }

    // === JWT Generation (Same as before) ===
    public static string GenerateJwt(string username)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: "AlvaServer",
            audience: "AlvaClient",
            claims: new[] { new Claim(ClaimTypes.Name, username) }, // This maps to context.User.Identity.Name
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    // === NEW: Encapsulated Configuration Logic ===
    public static void RegisterJwtServices(WebApplicationBuilder builder)
    {
        builder.Services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = "AlvaServer",
                ValidAudience = "AlvaClient",
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey))
            };
        });

        builder.Services.AddAuthorization();
    }
}