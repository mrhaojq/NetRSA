using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using RSA_WebLogin.Utils;

// For more information on enabling MVC for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace RSA_WebLogin.Controllers
{
    public class AccountController : Controller
    {
        // GET: /<controller>/
        public IActionResult Index()
        {
            RSAKey rsaKey = RSAHelper.CreateRsaKey();
            ViewData["publicKey"]= rsaKey.PublicKey;
            HttpContext.Session.SetString("privateKey", rsaKey.PrivateKey);

            return View();
        }

        [HttpPost]
        public IActionResult Index(string na,string pw)
        {
            string privateKey = HttpContext.Session.GetString("privateKey");
            string pwd = RSAHelper.RSADecrypt(pw, privateKey);
            ViewData["publicKey"] = $"解密的密码是：{pwd}";
            return View();
        }
    }
}
