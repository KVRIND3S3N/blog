using AspNetCoreHero.ToastNotification.Abstractions;
using FineBlog.Models;
using FineBlog.Utilites;
using FineBlog.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace FineBlog.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class UserController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        public INotyfService _notification { get; }
        public UserController(UserManager<ApplicationUser> userManager, 
                                    SignInManager<ApplicationUser> signInManager, 
                                    INotyfService notyfService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _notification = notyfService;
        }

        [Authorize(Roles = "Admin")]
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var users = await _userManager.Users.ToListAsync();

            var vm = users.Select(x => new UserVM()
            {
                Id = x.Id,
                FirstName = x.FirstName,
                LastName = x.LastName,
                UserName = x.UserName,
                Email = x.Email,
            }).ToList();
            //assinging role
            foreach(var user in vm)
            {
                var singleUser = await _userManager.FindByIdAsync(user.Id);
                var role = await _userManager.GetRolesAsync(singleUser);
                user.Role = role.FirstOrDefault();
            }

            return View(vm);
        }

        [Authorize(Roles = "Admin")]
        [HttpGet]
        public async Task<IActionResult> ResetPassword(string id)
        {
            var existingUser = await _userManager.FindByIdAsync(id);
            if (existingUser == null)
            {
                _notification.Error("Kullanıcı mevcut değil");
                return View();
            }
            var vm = new ResetPasswordVM()
            {
                Id = existingUser.Id,
                UserName = existingUser.UserName
            };
            return View(vm);
        }

        [Authorize(Roles = "Admin")]
        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordVM vm)
        {
            if (!ModelState.IsValid) { return View(vm); }

            var existingUser = await _userManager.FindByIdAsync(vm.Id);
            if (existingUser == null)
            {
                _notification.Error("Kullanıcı mevcut değil");
                return View(vm);
            }

            // Şifre sıfırlama token'ı oluşturuluyor
            var token = await _userManager.GeneratePasswordResetTokenAsync(existingUser);
            var result = await _userManager.ResetPasswordAsync(existingUser, token, vm.NewPassword);

            if (result.Succeeded)
            {
                _notification.Success("Şifre sıfırlama başarılı");
                return RedirectToAction(nameof(Index));
            }

            // Hata mesajlarını kullanıcıya gösterelim
            foreach (var error in result.Errors)
            {
                _notification.Error(error.Description);
            }

            return View(vm);
        }



        [Authorize(Roles ="Admin")]
        [HttpGet]
        public IActionResult Register()
        {
            return View(new RegisterVM());
        }

        [Authorize(Roles = "Admin")]
        [HttpPost]
        public async Task<IActionResult> Register(RegisterVM vm)
        {
            // Model doğrulaması
            if (!ModelState.IsValid)
            {
                return View(vm);
            }

            // E-posta kontrolü
            var checkUserByEmail = await _userManager.FindByEmailAsync(vm.Email);
            if (checkUserByEmail != null)
            {
                _notification.Error("Email zaten kullanılıyor");
                return View(vm);
            }

            // Kullanıcı adı kontrolü
            var checkUserByUsername = await _userManager.FindByNameAsync(vm.UserName);
            if (checkUserByUsername != null)
            {
                _notification.Error("Kullanıcı adı kullanılıyor");
                return View(vm);
            }

            // Yeni kullanıcıyı oluşturma
            var applicationUser = new ApplicationUser()
            {
                Email = vm.Email,
                UserName = vm.UserName,
                FirstName = vm.FirstName,
                LastName = vm.LastName
            };

            // Kullanıcıyı kaydetme
            var result = await _userManager.CreateAsync(applicationUser, vm.Password);

            if (result.Succeeded)
            {
                // Eğer kullanıcı admin olarak kaydediliyorsa, role ekle
                if (vm.IsAdmin)
                {
                    await _userManager.AddToRoleAsync(applicationUser, WebsiteRoles.WebsiteAdmin);
                }
                else
                {
                    await _userManager.AddToRoleAsync(applicationUser, WebsiteRoles.WebsiteAuthor);
                }

                // Başarı mesajı
                _notification.Success("Kullanıcı oluşturuldu");
                return RedirectToAction("Index", "User", new { area = "Admin" });
            }

            // Hata mesajlarını kullanıcıya göster
            foreach (var error in result.Errors)
            {
                _notification.Error(error.Description);
            }

            return View(vm);
        }



        [HttpGet("Login")]
        public IActionResult Login()
        {
            if (!HttpContext.User.Identity!.IsAuthenticated)
            {
                return View(new LoginVM());
            }
            return RedirectToAction("Index", "Post", new { area = "Admin" });
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginVM vm)
        {
            if (!ModelState.IsValid) { return View(vm); }
            var existingUser = await _userManager.Users.FirstOrDefaultAsync(x => x.UserName == vm.Username);
            if (existingUser == null)
            {
                _notification.Error("Kullanıcı adı eşleşmiyor!");
                return View(vm);
            }
            var verifyPassword = await _userManager.CheckPasswordAsync(existingUser, vm.Password);
            if (!verifyPassword)
            {
                _notification.Error("Şifreniz Eşleşmiyor!");
                return View(vm);
            }
            await _signInManager.PasswordSignInAsync(vm.Username, vm.Password, vm.RememberMe, true);
            _notification.Success("Giriş Başarılı!");
            return RedirectToAction("Index", "Post", new { area = "Admin" });
        }


        [HttpPost]
        [Authorize]
        public IActionResult Logout()
        {
            _signInManager.SignOutAsync();
            _notification.Success("Çıkış başarılı");
            return RedirectToAction("Index", "Home" , new {area = ""});
        }

        [HttpGet("AccessDenied")]
        [Authorize]
        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}
