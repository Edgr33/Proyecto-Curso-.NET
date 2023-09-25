using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.Operations;
using Microsoft.EntityFrameworkCore;
using System.Data;
using System.Security.Claims;
using EvaluacionEduardoGomezMVC.Models;
using EvaluacionEduardoGomezMVC.Helpers;
using Newtonsoft.Json;

namespace MiEcommApp.Controllers
{
    public class LoginController : Controller
    {
        private readonly AdventureWorksLt2019Context _context;
        private readonly ILogger<LoginController> _logger;

        public LoginController(AdventureWorksLt2019Context context, ILogger<LoginController> logger)
        {
            _context = context;
            _logger = logger;
        }


        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(string cEmail, string cPassword)
        {
            var userInfo = await (from emp in _context.Customers
                                  where emp.EmailAddress == cEmail
                                  select new
                                  {
                                      IDEmployee = emp.CustomerId,
                                      Nombre = emp.FirstName,
                                      Apellido = emp.LastName,
                                      Email = emp.EmailAddress,
                                      Password = emp.PasswordHash

                                  }).SingleOrDefaultAsync();

            if (userInfo != null)
            {
                if (userInfo != null && Argon2PasswordHasher.VerifyHashedPassword(userInfo.Email, cPassword))
                {
                    var claims = new List<Claim>();

                    var claimsIdentity = new ClaimsIdentity(claims, "CookieAuth");

                    await HttpContext.SignInAsync(
                        "CookieAuth",
                        new ClaimsPrincipal(claimsIdentity));

                    _logger.LogInformation("User: {} successfully logged in", userInfo.Email);

                    return RedirectToAction("Index", "Home");
                }
                return RedirectToAction("Index", "Home");
            }
            return RedirectToAction("Index", "Home");
        }

        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync("CookieAuth");
            return RedirectToAction("Index", "Home");
        }


    }
}


