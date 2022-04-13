using System.ComponentModel.DataAnnotations;

namespace Api.models;

public record UserDto(string UserName, string Password);

public record User
{
    [Required]
    public string UserName { get; set; }
    [Required]
    public string Password { get; set; }
    public List<Role> Roles { get; set; }
}
