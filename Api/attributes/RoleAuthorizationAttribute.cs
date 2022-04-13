using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Api.attributes;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public class RoleAuthorizationAttribute : Attribute, IAuthorizationFilter
{
    public string[] Roles { get; }

    public RoleAuthorizationAttribute(params string[] roles)
    {
        Roles = roles;
    }
    
    public void OnAuthorization(AuthorizationFilterContext context)  
    {
        if (context.ActionDescriptor.EndpointMetadata.Any(em => em.GetType() == typeof(AllowAnonymousAttribute)))
        {
            return;
        }

        if (context.HttpContext.User.Identity is { IsAuthenticated: false })
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        if (!context.HttpContext.User.Claims.Any(x => x.Type == ClaimTypes.Role && Roles.Contains(x.Value)))
        {
            context.Result = new UnauthorizedResult();
        }
    }
}
