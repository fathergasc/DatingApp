using API.Entities;
using API.Interfaces;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace API.Services
{
    public class TokenService(IConfiguration config) : ITokenService
    {
        /// <summary>
        /// Creates a JWT token for the specified user.
        /// </summary>
        /// <param name="user">The user for whom the token is being created.</param>
        /// <returns>A JWT token as a string.</returns>
        /// <exception cref="Exception">
        /// Thrown when the token key cannot be accessed from the configuration or if the token key length is less than 64 characters.
        /// </exception>
        public string CreateToken(AppUser user)
        {
            var tokenKey = config["TokenKey"] ?? throw new Exception("Cannot access tokenKey from appsettings");
            if (tokenKey.Length < 64)
            {
                throw new Exception("Your tokenKey needs to be longer");
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenKey));

            var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, user.UserName)
                };

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = creds
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }
    }
}
