using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using UsersAPI.Model.Headers.Generics;
using UsersAPI.Model.Headers;
using UsersAPI.DAL;
using UsersAPI.DAO;
using UsersAPI.Authentication;
using UsersAPI.Exceptions;
using System.Security.Claims;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860
namespace UsersAPI.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly ILogger<UsersController> logger;
        private readonly IUsersService usersService;

        public UsersController(ILogger<UsersController> logger, IUsersService usersService)
        {
            this.logger = logger;
            this.usersService = usersService;
        }

        [AllowAnonymous]
        [HttpPost("authentication")]
        public IActionResult Authentication([FromBody] UserLogin userLogin)
        {
            var (token, validTo) = this.usersService.Authenticate(userLogin.UserName, userLogin.Password);
            if (string.IsNullOrWhiteSpace(token))
                return Unauthorized(new Response<object>(OperationResultEnum.ERROR, null, "The user name or password are incorrect", "The user name or password are incorrect"));
            else
                return Ok(new Response<object>(OperationResultEnum.OK, new { Token = token, ValidTo = validTo }));
        }

        [HttpPut("changepass")]
        public IActionResult ChangePassword([FromBody] UserLogin newLogin)
        {
            if (!this.User.Identity.Name.Equals(newLogin.UserName) && !this.User.HasClaim(ClaimTypes.Role, UserRoles.Admin))
                return Unauthorized(new Response<int>(OperationResultEnum.ERROR, 0,
                    "User is not authorized for performing this operationr", "User is not authorized for performing this operationr"));

            return Ok(new Response<int>(OperationResultEnum.OK, this.usersService.ChangePaassword(newLogin.UserName, newLogin.Password)));
        }

        // GET: api/<UsersController>
        [HttpGet]
        public Response<IEnumerable<User>> Get([FromQuery] string name = "") =>
            new Response<IEnumerable<User>>(OperationResultEnum.OK, this.usersService.GetUsers(name));

        // GET api/<UsersController>/5
        [HttpGet("{userId}")]
        public Response<User> Get(long userId) =>
            new Response<User>(OperationResultEnum.OK, this.usersService.GetUserById(userId));

        // POST api/<UsersController>
        [Authorize(Roles = UserRoles.Admin + "," + UserRoles.Assist)]
        [HttpPost]
        public Response<long> Post([FromBody] User user)
        {
            try
            {
                return new Response<long>(OperationResultEnum.OK, this.usersService.InsertUser(user));
            }
            catch (AppException ex)
            {
                return new Response<long>(OperationResultEnum.ERROR, -1, ex.Message, ex.UserMessage);
            }
            catch (Exception ex)
            {
                return new Response<long>(OperationResultEnum.ERROR, -1, ex.Message, "An unexpected error occurred.");
            }
        }

        // PUT api/<UsersController>/5
        [Authorize(Roles = UserRoles.Admin + "," + UserRoles.Assist)]
        [HttpPut]
        public Response<int> Put([FromQuery] long userId, [FromBody] User user)
        {
            try
            {
                user.UserId = userId;
                return new Response<int>(OperationResultEnum.OK, this.usersService.UpdateUser(user));
            }
            catch (AppException ex)
            {
                return new Response<int>(OperationResultEnum.ERROR, 0, ex.Message, ex.UserMessage);
            }
            catch (Exception ex)
            {
                return new Response<int>(OperationResultEnum.ERROR, 0, ex.Message, "An unexpected error occurred.");
            }
        }

        // DELETE api/<UsersController>/5
        [Authorize(Roles = UserRoles.Admin)]
        [HttpDelete("{userId}")]
        public Response<int> Delete(long userId)
        {
            try
            {
                return new Response<int>(OperationResultEnum.OK, this.usersService.DeleteUser(userId));
            }
            catch (AppException ex)
            {
                return new Response<int>(OperationResultEnum.ERROR, 0, ex.Message, ex.UserMessage);
            }
            catch (Exception ex)
            {
                return new Response<int>(OperationResultEnum.ERROR, 0, ex.Message, "An unexpected error occurred.");
            }
        }
    }
}
