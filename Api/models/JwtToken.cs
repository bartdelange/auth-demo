namespace Api.models;

public record JwtToken
{
    public string Token { get; set; }
    public string RefreshToken { get; set; }
}
