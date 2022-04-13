using Api.attributes;
using Api.config;
using Api.models;
using Api.repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);
builder.ConfigureAuthorization();
builder.ConfigureSwagger();

var app = builder.Build();
app.ConfigureAuthorization();
app.ConfigureSwagger();

app.MapGet("/", [RoleAuthorization("role10")]() => "Hello World!")
    .Produces<string>()
    .RequireAuthorization();

app.MapPost(
        "/login", [AllowAnonymous]([FromServices] IJwtManagerRepository jwtManager, [FromBody] User user, HttpResponse response) =>
        {
            var token = jwtManager.Authenticate(user);

            if (token == null)
            {
                response.StatusCode = 401;
                return null;
            }

            response.StatusCode = 200;
            return token;
        }
    )
    .Accepts<User>("application/json")
    .Produces<JwtToken>()
    .Produces(StatusCodes.Status401Unauthorized);


app.Run("https://localhost:3000");
