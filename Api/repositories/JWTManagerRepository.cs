using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Api.models;
using Microsoft.IdentityModel.Tokens;

namespace Api.repositories;

public interface IJwtManagerRepository
{
    JwtToken? Authenticate(User users);
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
    
    public JwtToken? Authenticate(User user)
    {
        var userData = _usersRecords.FirstOrDefault((u) => u.UserName == user.UserName && u.Password == user.Password);
        if (userData == null)
        {
            return null;
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenKey = Encoding.UTF8.GetBytes(_configuration["JWT:Key"]);
        var claims = userData.Roles.Select(role => new Claim(ClaimTypes.Role, role.Name)).ToList();

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(10),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return new JwtToken { Token = tokenHandler.WriteToken(token) };
    }
}
