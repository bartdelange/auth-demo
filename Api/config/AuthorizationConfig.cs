using System.Text;
using Api.repositories;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace Api.config;

public static class AuthorizationConfig
{
    public static TokenValidationParameters GetTokenValidationParameters(string key, string issuer, string audience)
    {
        var keyBytes = Encoding.UTF8.GetBytes(key);
        return new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = issuer,
            ValidAudience = audience,
            IssuerSigningKey = new SymmetricSecurityKey(keyBytes)
        };
    }

    public static void ConfigureAuthorization(this WebApplicationBuilder builder)
    {
        builder.Services.AddAuthorization();
        builder.Services.AddAuthentication(
                x =>
                {
                    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                }
            )
            .AddJwtBearer(
                o =>
                {
                    o.SaveToken = true;
                    o.TokenValidationParameters = GetTokenValidationParameters(builder.Configuration["JWT:Key"], builder.Configuration["JWT:Issuer"], builder.Configuration["JWT:Audience"]);
                }
            );

        builder.Services.AddSingleton<IJwtManagerRepository, JwtManagerRepository>();
    }

    public static void ConfigureAuthorization(this WebApplication app)
    {
        app.UseAuthentication();
        app.UseAuthorization();
    }
}
