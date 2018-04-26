using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using NetCoreRSADemo.Utils;
using static System.Console;
using System.Text;

namespace NetCoreRSADemo
{
    public class Program
    {
        public static void Main(string[] args)
        {
            try
            {

                string data = "rAb2GPvdYSH4lFrDHpeAVVd4opZt05vEOeHZ8wtljFvmnh0sywwqHSg/6XFPwREJKOkw7U1nVy357b9nO8MmVXZeHeSYEpvqbOwnN9kSQRJx2O1/yIJA4MOkj0pZV3zUhByj9W3gxGh2vqgGg7Tc2NxdAvRvKj0A0tqFHyxuHm4=";

                StringBuilder privateKey = new StringBuilder();
                privateKey.Append("-----BEGIN RSA PRIVATE KEY-----");
                privateKey.Append("MIICXQIBAAKBgQDM1ycX6VaBbSbL5BPUTcSN6k0ETJPO9AJyO5dFqhPAXcFSTXhk");
                privateKey.Append("N6QiWfpoT4N33uueQ3I241aX8d7N36FPcGr7xAH+jpLTQfV/INoc3wOEzKoOrCRG");
                privateKey.Append("tyEfl7rbE3kDpA6sXOhGDEOw3zkMH5XvoKq4KDcdYrG8PQkDeBtiNL/6GQIDAQAB");
                privateKey.Append("AoGAEQVTvJs+p+naTm447kGOspLPLCtHdkE1BCmgIUFyULVkVKLBUo/ZC02vZAQv");
                privateKey.Append("aBeAO+9eHzd2wOYaiGrWVukqynNV3PLV0P6JX5hh9cRsfZhURkRuB/XZSXAHBnAM");
                privateKey.Append("ACR8EopTx0/jVJsPDKYOKH8kcxcET8P4nCDFbwnXTUFfXfECQQD0CeFqSmn4HR3b");
                privateKey.Append("7zuWkmUJ0G6UNnN+kzPJoGjjN6JKk1f4GRpyJ90sfzvG6dj5u1DNdteTH5Q85mdc");
                privateKey.Append("WjQNr+ktAkEA1uFtEpo/bt8oqkam4PIGMjz96F9R4wQjLwANOT65IB6gA4vqilSH");
                privateKey.Append("agiRsWeRtbLkIMjiv23MHBRj8zdTwpbQHQJBAPDMixORh8zeFid9gQPLQk2T0HkI");
                privateKey.Append("3Z+o6nHqiXSi4c3KZAQX6SN5OGF+zmIxPvr0nP+QY5j1kRUimBzlmPVkfaUCQGok");
                privateKey.Append("vpFC2nS1DUxXTBWv1/m3ASFo/HUsVQjheKa/YgkIt7goxDmCmcV56CX+6A4eCOxc");
                privateKey.Append("7wzqermgJOM+gESN5M0CQQDTRmYt9KGIxPRsiOnEK0c6QcccOXGe8KDokSOv5zhh");
                privateKey.Append("JyYYXv8qATPDZ5ASNvxZ85IoOH+ukj1LxSfL9vUJU2o+");
                privateKey.Append("-----END RSA PRIVATE KEY-----");

                StringBuilder publicKey = new StringBuilder();
                publicKey.Append("-----BEGIN PUBLIC KEY-----");
                publicKey.Append("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDM1ycX6VaBbSbL5BPUTcSN6k0E");
                publicKey.Append("TJPO9AJyO5dFqhPAXcFSTXhkN6QiWfpoT4N33uueQ3I241aX8d7N36FPcGr7xAH+");
                publicKey.Append("jpLTQfV/INoc3wOEzKoOrCRGtyEfl7rbE3kDpA6sXOhGDEOw3zkMH5XvoKq4KDcd");
                publicKey.Append("YrG8PQkDeBtiNL/6GQIDAQAB");
                publicKey.Append("-----END PUBLIC KEY-----");

                //string content = "Mr@1234_$%!";
                //RSAKey rsaKey = RsaHelper.CreateRsaKey();
                //WriteLine($"PrivateKey:{rsaKey.PrivateKey}");
                //WriteLine();
                //WriteLine($"PublicKey;{rsaKey.PublicKey}");
                //WriteLine();

                //WriteLine($"{content} 加密后：");
                //string e = RsaHelper.RSAEncrypt(content, rsaKey.PublicKey);
                //WriteLine(e);

                //WriteLine($"解密后：{RsaHelper.RSADecrypt(e, rsaKey.PrivateKey)}");


                string d = RsaHelper.RSADecrypt(data, privateKey.ToString());
                Console.WriteLine(d);
                ReadKey();
            }
            catch (Exception ex)
            {
                throw;
            }

        }
    }
}
