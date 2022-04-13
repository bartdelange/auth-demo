using System.ComponentModel.DataAnnotations;

namespace Api.models;

public class Role
{
    [Required]
    public string Name { get; set; }
}
