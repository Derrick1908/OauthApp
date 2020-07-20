using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using OauthApp.Models;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Http.Cors;
using System.Data.SqlClient;
using System.Configuration;
using Microsoft.AspNet.Identity;
using OauthApp.Repository;

namespace OauthApp.Provider
{
    [EnableCors(origins: "*", headers: "*", methods: "*")]
    public class ApplicationAuthProvider : OAuthAuthorizationServerProvider
    {
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            await Task.Run(() => context.Validated());
        }
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var identity = new ClaimsIdentity(context.Options.AuthenticationType);

            using (var db = new DataContextt())
            {
                if (db != null)
                {
                    var user = db.ApiUsers.Where(o => o.UserName == context.UserName && o.UserPasswd == context.Password).FirstOrDefault();
                    if (user != null)
                    {
                        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()));
                        identity.AddClaim(new Claim(ClaimTypes.Role, user.UserRole));
                        identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));
                        identity.AddClaim(new Claim("LoggedOn", DateTime.Now.ToString()));
                        await Task.Run(() => context.Validated(identity));  //Calls th Internal structure to issue Token
                    }
                    else
                    {
                        context.SetError("Wrong Crendtials", "Provided username and password is incorrect");
                    }
                }
                else
                {
                    context.SetError("Wrong Crendtials", "Provided username and password is incorrect");
                }
                return;
            }
        }

        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            return Task.FromResult<object>(null);
        }

        public override Task TokenEndpointResponse(OAuthTokenEndpointResponseContext context)
        {

            try
            {

                using (var connection = new SqlConnection(ConfigurationManager.ConnectionStrings["DefaultConnectionn"].ConnectionString))
                {
                    ValidUser validUser = new ValidUser();
                    int id = Int32.Parse(context.Identity.GetUserId());
                    if (validUser.UserExists(id))
                    {
                        validUser.DeleteUser(id);
                    }
                    connection.Open();
                    string query = "insert into TokenInformation (userid, username, token) values (@useridd, @usernamee, @tokenn);";
                    using (SqlCommand myCommand = new SqlCommand(query, connection))
                    {
                        myCommand.Parameters.AddWithValue("@useridd", context.Identity.GetUserId());
                        myCommand.Parameters.AddWithValue("@usernamee", context.Identity.Name);
                        myCommand.Parameters.AddWithValue("@tokenn", context.AccessToken);
                        myCommand.ExecuteNonQuery();
                    }
                    
                }
            }
            catch(Exception)
            {
                return base.TokenEndpointResponse(context);
            }
            //System.Diagnostics.Debug.WriteLine(context.AccessToken);
            //System.Diagnostics.Debug.WriteLine(context.Identity.Name);
            //System.Diagnostics.Debug.WriteLine(context.AdditionalResponseParameters[".expires"]);
            return base.TokenEndpointResponse(context);
           
        }
    }
}