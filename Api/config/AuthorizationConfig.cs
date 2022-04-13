using System.Text;
using Api.repositories;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace Api.config;

public static class AuthorizationConfig
{
    public static void ConfigureAuthorization(this WebApplicationBuilder builder)
    {
        builder.Services.AddAuthorization();
        builder.Services.AddAuthentication(x =>
        {
            x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(o =>
        {
            var key = Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"]);
            o.SaveToken = true;
            o.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = builder.Configuration["JWT:Issuer"],
                ValidAudience = builder.Configuration["JWT:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(key)
            };
        });

        builder.Services.AddSingleton<IJwtManagerRepository, JwtManagerRepository>();
    }

    public static void ConfigureAuthorization(this WebApplication app)
    {
        app.UseAuthentication();
        app.UseAuthorization();
    }
}
