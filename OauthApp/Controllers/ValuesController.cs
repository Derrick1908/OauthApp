using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data.SqlClient;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web;
using System.Web.Http;
using OauthApp.Repository;

namespace OauthApp.Controllers
{
    public class ValuesController : ApiController
    {
        // GET api/values
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }

        // GET api/values/5
        public string Get(int id)
        {
            return "value";
        }

        // POST api/values
        public void Post([FromBody] string value)
        {
        }

        // PUT api/values/5
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE api/values/5
        public void Delete(int id)
        {
        }

        //This method is For all types of role.
        //This controller returns Okay for all valid Tokens according to Owin
        //even though the user may have logged out.
        [Authorize(Roles = "SuperAdmin, Admin, User")]
        [HttpGet]
        [Route("api/values/getvalues")]
        public IHttpActionResult GetValues()
        {
            var identity = (ClaimsIdentity)User.Identity;
            var roles = identity.Claims
                        .Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value);
            var LogTime = identity.Claims
                        .FirstOrDefault(c => c.Type == "LoggedOn").Value;
            return Ok("Hello: " + identity.Name + ", " +
                "Your Role(s) are: " + string.Join(",", roles.ToList()) +
                "Your Login time is :" + LogTime);
        }


        // This Controller is called on Logout.
        // It deletes the user Information from the Table (separately created) along with its token. 
        [Authorize]
        [HttpPost]
        [Route("api/values/Logout")]
        public IHttpActionResult Logout()
        {
            ValidUser validUser = new ValidUser();
            var identity = (ClaimsIdentity)User.Identity;
            try
            { 
                int id = Int32.Parse(identity.GetUserId());
                if (validUser.UserExists(id))
                {
                    validUser.DeleteUser(id);
                }
                else
                    throw new Exception();
            }
            catch (Exception)
            {
                System.Diagnostics.Debug.WriteLine("No user exists. Unauthorized Access");
                return BadRequest("Unauthorized Access"); 
            }

            //System.Web.HttpContext.Current.GetOwinContext().Authentication.SignOut(Microsoft.AspNet.Identity.DefaultAuthenticationTypes.ApplicationCookie);
            return Ok(identity.Name + " Has successfuly Logged Out");

        }

        //Though Auhtorize may validate a valid token according to it, we check in our
        //Table if that token is still present, then only do we allow it access
        [Authorize]
        [HttpGet]
        [Route("api/values/CheckValidity")]
        public IHttpActionResult CheckValidity()
        { 
            HttpContext httpContext = HttpContext.Current;                  //Retrieves the Token from the Authorization Header
            string authHeader = httpContext.Request.Headers["Authorization"];     //send along with the Get Request
            string token = authHeader.Substring("Bearer ".Length).Trim();        

            ValidUser validUser = new ValidUser();
            var identity = (ClaimsIdentity)User.Identity;         
            int id = Int32.Parse(identity.GetUserId());
            if(validUser.UnauthorisedUser(id, token))
                return BadRequest("Unauthorized User");
            else
               return Ok("Hello: " + identity.Name);
        }
    }
}
