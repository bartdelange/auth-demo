using System.Text;
using Api.repositories;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

namespace Api.config;

public static class SwaggerConfig
{
    public static void ConfigureSwagger(this WebApplicationBuilder builder)
    {
        var securityScheme = new OpenApiSecurityScheme()
        {
            Name = "Authorization",
            Type = SecuritySchemeType.ApiKey,
            Scheme = "Bearer",
            BearerFormat = "JWT",
            In = ParameterLocation.Header,
            Description = "JSON Web Token based security",
        };

        var securityReq = new OpenApiSecurityRequirement()
        {
            {
                new OpenApiSecurityScheme
                {
                    Reference = new OpenApiReference
                    {
                        Type = ReferenceType.SecurityScheme,
                        Id = "Bearer"
                    }
                },
                Array.Empty<string>()
            }
        };

        
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen(
            o =>
            {
                o.AddSecurityDefinition("Bearer", securityScheme);
                o.AddSecurityRequirement(securityReq);
            });
    }

    public static void ConfigureSwagger(this WebApplication app)
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }
}
