using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace EvaluacionEduardoGomezMVC.Helpers
{
    public class PermissionRequirement : IAuthorizationRequirement
    {
        public string Permission { get; }

        public PermissionRequirement(string permission)
        {
            Permission = permission;
        }
    }

    public class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
        {
            if (context.User.HasClaim(c =>
                (c.Type == ClaimTypes.Role && c.Value == "Global Administrator") ||
                (c.Type == "Permiso" && c.Value == requirement.Permission)))
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }

}
