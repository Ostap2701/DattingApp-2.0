
using API.Data;
using Microsoft.AspNetCore.Mvc;
using API.Entities;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using API.DTOs;
using API.Services;
using API.Interfaces;
using API.Extensions;

namespace API.Controllers
{
    public class AccountController(AppDbContext context, ITokenService tokenService) : BaseAPIController
    {
        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDtos)
        {
            if (await EmailExists(registerDtos.Email))
            {
                return BadRequest("Email is already in use");
            }
            using var hmac = new HMACSHA512();
            var user = new AppUser
            {
                DisplayName = registerDtos.DisplayName,
                Email = registerDtos.Email,
                PasswordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(registerDtos.Password)),
                PasswordSalt = hmac.Key
            };
            context.Users.Add(user);
            await context.SaveChangesAsync();

            return user.ToDTO(tokenService);
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
            var user = await context.Users.SingleOrDefaultAsync(x => x.Email.ToLower() == loginDto.Email.ToLower());
            if (user == null) return Unauthorized("Invalid email");
            using var hmac = new HMACSHA512(user.PasswordSalt);
            var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(loginDto.Password));
            for (int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid email or password");
            }
           return user.ToDTO(tokenService);
        }

        private async Task<bool> EmailExists(string email)
        {
            return await context.Users.AnyAsync(x => x.Email.ToLower() == email.ToLower());
        }
    }
}
