using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace UsersAPI.Authentication
{
    public class JwtAuthentication : IJwtAuthentication
    {
        private readonly IConfiguration configuration;

        public JwtAuthentication(IConfiguration configuration)
        {
            this.configuration = configuration;
        }
        public (string, DateTime) GetToken(string userName, IEnumerable<string> roles)
        {
            var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, userName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

            foreach (var userRole in roles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(this.configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: this.configuration["JWT:ValidIssuer"],
                audience: this.configuration["JWT:ValidAudience"],
                expires: DateTime.UtcNow.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return (new JwtSecurityTokenHandler().WriteToken(token), token.ValidTo);

            //// 1. Create Security Token Handler
            //var tokenHandler = new JwtSecurityTokenHandler();

            //// 2. Create Private Key to Encrypted
            //var tokenKey = Encoding.ASCII.GetBytes(this.configuration["JWT:Secret"]);

            ////3. Create JETdescriptor
            //var tokenDescriptor = new SecurityTokenDescriptor()
            //{
            //    Subject = new ClaimsIdentity(
            //        new Claim[]
            //        {
            //            new Claim(ClaimTypes.Name, userName),
            //            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            //            new Claim(ClaimTypes.Role, "Administrator")
            //        }),
            //    Issuer = this.configuration["JWT:ValidIssuer"],
            //    Audience = this.configuration["JWT:ValidAudience"],
            //    Expires = DateTime.UtcNow.AddHours(1),
            //    SigningCredentials = new SigningCredentials(
            //        new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256)
            //};
            ////4. Create Token
            //var token = tokenHandler.CreateToken(tokenDescriptor);

            //// 5. Return Token from method
            //return (tokenHandler.WriteToken(token), token.ValidTo);
        }
    }
}
