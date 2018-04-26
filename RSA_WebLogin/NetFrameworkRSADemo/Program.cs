using NetFrameworkRSADemo.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Console;

namespace NetFrameworkRSADemo
{
    class Program
    {
        static void Main(string[] args)
        {
            string content = "Mr@1234_$%!";
            RSAKey rsaKey = RsaHelper.CreateRsaKey();
            WriteLine($"PrivateKey:{rsaKey.PrivateKey}");
            WriteLine();
            WriteLine($"PublicKey;{rsaKey.PublicKey}");
            WriteLine();

            WriteLine($"{content} 加密后：");
            string e = RsaHelper.RSAEncrypt(content, rsaKey.PublicKey);
            WriteLine(e);

            WriteLine($"解密后：{RsaHelper.RSADecrypt(e, rsaKey.PrivateKey)}");

            ReadKey();
        }
    }
}
