using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Darius
{
    class AuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        //
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            // Aqui o token é validado no cache do OAuth, a cada requisição. O OAuth gerencia.
            // Não há hit no banco
            context.Validated();
            // Se o token não é valido, vai para o proximo método
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origen", new[] { "*" });

            try
            {
                var user = context.UserName;
                var password = context.Password;

                if(user != "wiliam" || password != "buzatto")
                {
                    context.SetError("invalid_grant", "Usuário ou senha inválidos");
                    return;
                }

                var identity = new ClaimsIdentity(context.Options.AuthenticationType);

                identity.AddClaim(new Claim(ClaimTypes.Name, user));

                var roles = new List<string>();
                //roles.Add("Admin");
                roles.Add("User");

                foreach (var role in roles)
                {
                    identity.AddClaim(new Claim(ClaimTypes.Role, role));
                }

                GenericPrincipal principal = new GenericPrincipal(identity, roles.ToArray());
                Thread.CurrentPrincipal = principal;

                context.Validated(identity);

            }
            catch (Exception)
            {
                context.SetError("invalid_grant", "Falha ao autenticar");
            }
        }


    }
}
