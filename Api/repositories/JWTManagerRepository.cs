using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Api.config;
using Api.models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Api.repositories;

public interface IJwtManagerRepository
{
    JwtToken? Authenticate(User users);
    JwtSecurityToken? ValidateRefresh(string refreshToken);
    JwtToken? AuthenticateRefresh(JwtSecurityToken refreshToken);
}

public class JwtManagerRepository : IJwtManagerRepository
{
    private readonly List<User> _usersRecords = new()
    {
        new User { UserName = "user1", Password = "password1", Roles = new List<Role> { new() { Name = "Role1" }, new() { Name = "Role11" } } },
        new User { UserName = "user2", Password = "password2", Roles = new List<Role> { new() { Name = "Role2" }, new() { Name = "Role21" } } },
        new User { UserName = "user3", Password = "password3", Roles = new List<Role> { new() { Name = "Role3" }, new() { Name = "Role31" } } },
    };

    private readonly IConfiguration _configuration;

    public JwtManagerRepository(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    private JwtToken _CreateToken(User user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenKey = Encoding.UTF8.GetBytes(_configuration["JWT:Key"]);
        var claims = user.Roles.Select(role => new Claim(ClaimTypes.Role, role.Name)).ToList();

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature),
            Issuer = _configuration["JWT:Issuer"],
            Audience = _configuration["JWT:Audience"]
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);

        var refreshTokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new []{new Claim("id", user.UserName)}),
            Expires = DateTime.UtcNow.AddMinutes(60),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature),
            Issuer = _configuration["JWT:Issuer"],
            Audience = _configuration["JWT:Audience"]
        };
        var refreshToken = tokenHandler.CreateToken(refreshTokenDescriptor);
        return new JwtToken { Token = tokenHandler.WriteToken(token), RefreshToken = tokenHandler.WriteToken(refreshToken) };
    }

    public JwtToken? Authenticate(User user)
    {
        var userData = _usersRecords.FirstOrDefault((u) => u.UserName == user.UserName && u.Password == user.Password);

        return userData == null ? null : _CreateToken(userData);
    }

    public JwtSecurityToken? ValidateRefresh(string refreshToken)
    {
        var validationParameters = AuthorizationConfig.GetTokenValidationParameters(_configuration["JWT:Key"], _configuration["JWT:Issuer"], _configuration["JWT:Audience"]);

        JwtSecurityTokenHandler jwtSecurityTokenHandler = new();

        try
        {
            jwtSecurityTokenHandler.ValidateToken(refreshToken, validationParameters, out var validatedToken);
            return (JwtSecurityToken?)validatedToken;
        }
        catch (Exception e)
        {
            return null;
        }
    }
    public JwtToken? AuthenticateRefresh(JwtSecurityToken refreshToken)
    {
        var userId = refreshToken.Claims.FirstOrDefault(x => x.Type == "id")?.Value;
        var userData = _usersRecords.FirstOrDefault((u) => u.UserName == userId);
        return userData == null ? null : _CreateToken(userData);
    }
}
