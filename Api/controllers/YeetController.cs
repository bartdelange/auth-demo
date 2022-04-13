using Api.attributes;
using Api.models;
using Api.repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Api.controllers;

[ApiController]
[Route("api")]
public class YeetController : Controller
{
    private readonly IJwtManagerRepository _jwtManager;

    public YeetController(IJwtManagerRepository jwtManagerRepository)
    {
        _jwtManager = jwtManagerRepository;
    }
    // GET
    [Route("")]
    [HttpGet]
    [RoleAuthorization("Role1")]
    public ActionResult<string> Index()
    {
        return "Hello authorized person";
    }
    
    // GET
    [Route("login")]
    [HttpPost]
    [AllowAnonymous]
    public ActionResult<JwtToken> Login([FromBody] User user)
    {
             var token = _jwtManager.Authenticate(user);
             if (token == null)
             {
                 return Unauthorized();
             }

             return token;
    }
    
    // GET
    [Route("refresh")]
    [HttpPost]
    [AllowAnonymous]
    public ActionResult<JwtToken> Refresh([FromBody] string refreshToken)
    {
             var parsedToken = _jwtManager.ValidateRefresh(refreshToken);
             if (parsedToken == null)
             {
                 return Unauthorized();
             }

             var newToken = _jwtManager.AuthenticateRefresh(parsedToken);
             if (newToken == null)
             {
                 return Unauthorized();
             }

             return newToken;
    }
}
