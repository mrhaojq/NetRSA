using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.OpenSsl;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace RSA_WebLogin.Utils
{
    public class RSAHelper
    {
        const int KEYSIZE = 1024;

        public static RSAKey CreateRsaKey()
        {
            var key = new RSAKey();

            RsaKeyPairGenerator generator = new RsaKeyPairGenerator();
            generator.Init(new KeyGenerationParameters(new SecureRandom(), KEYSIZE));
            var pair = generator.GenerateKeyPair();

            TextWriter textWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(pair.Private);
            pemWriter.Writer.Flush();
            key.PrivateKey = textWriter.ToString();

            textWriter = new StringWriter();
            pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(pair.Public);
            pemWriter.Writer.Flush();
            key.PublicKey = textWriter.ToString();

            return key;
        }

        //RSA加密
        public static string RSAEncrypt(string context, string publicKey)
        {
            UTF8Encoding ByteConverter = new UTF8Encoding();
            byte[] DataToEncrypt = ByteConverter.GetBytes(context);
            try
            {
                var rsa = RSA.Create();
                rsa.ImportParameters(CreateRsaFromPublicKey(publicKey));

                byte[] bytes = rsa.Encrypt(DataToEncrypt, RSAEncryptionPadding.Pkcs1);
                string str = Convert.ToBase64String(bytes);
                return str;
            }
            catch (CryptographicException e)
            {
                throw e;
            }
        }

        //RSA解密
        public static string RSADecrypt(string context, string privateKey)
        {
            byte[] DataToDecrypt = Convert.FromBase64String(context);
            try
            {
                var rsa = RSA.Create();
                rsa.ImportParameters(CreateRsaFromPrivateKey(privateKey));

                byte[] bytes = rsa.Decrypt(DataToDecrypt, RSAEncryptionPadding.Pkcs1);
                UTF8Encoding ByteConverter = new UTF8Encoding();
                string str = ByteConverter.GetString(bytes);
                return str;
            }
            catch (CryptographicException e)
            {
                return null;
                throw e;
            }
        }

        private static RSAParameters CreateRsaFromPrivateKey(string privateKey)
        {
            string tmp = privateKey.Replace("\r\n", "")
                .Replace("-----END RSA PRIVATE KEY-----", "")
                .Replace("-----BEGIN RSA PRIVATE KEY-----", "");

            var privateKeyBits = System.Convert.FromBase64String(tmp);
            var RSAparams = new RSAParameters();

            using (var binr = new BinaryReader(new MemoryStream(privateKeyBits)))
            {
                byte bt = 0;
                ushort twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130)
                    binr.ReadByte();
                else if (twobytes == 0x8230)
                    binr.ReadInt16();
                else
                    throw new Exception("Unexpected value read binr.ReadUInt16()");

                twobytes = binr.ReadUInt16();
                if (twobytes != 0x0102)
                    throw new Exception("Unexpected version");

                bt = binr.ReadByte();
                if (bt != 0x00)
                    throw new Exception("Unexpected value read binr.ReadByte()");

                RSAparams.Modulus = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.Exponent = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.D = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.P = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.Q = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.DP = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.DQ = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.InverseQ = binr.ReadBytes(GetIntegerSize(binr));
            }
            return RSAparams;
        }

        private static int GetIntegerSize(BinaryReader binr)
        {
            byte bt = 0;
            byte lowbyte = 0x00;
            byte highbyte = 0x00;
            int count = 0;
            bt = binr.ReadByte();
            if (bt != 0x02)
                return 0;
            bt = binr.ReadByte();

            if (bt == 0x81)
                count = binr.ReadByte();
            else
                if (bt == 0x82)
            {
                highbyte = binr.ReadByte();
                lowbyte = binr.ReadByte();
                byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                count = BitConverter.ToInt32(modint, 0);
            }
            else
            {
                count = bt;
            }

            while (binr.ReadByte() == 0x00)
            {
                count -= 1;
            }
            binr.BaseStream.Seek(-1, SeekOrigin.Current);
            return count;
        }

        private static RSAParameters CreateRsaFromPublicKey(string publicKeyString)
        {
            byte[] SeqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            byte[] x509key;
            byte[] seq = new byte[15];
            int x509size;

            var tmp = publicKeyString.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Replace("\r\n", "");

            x509key = Convert.FromBase64String(tmp);
            x509size = x509key.Length;

            using (var mem = new MemoryStream(x509key))
            {
                using (var binr = new BinaryReader(mem))
                {
                    byte bt = 0;
                    ushort twobytes = 0;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130)
                        binr.ReadByte();
                    else if (twobytes == 0x8230)
                        binr.ReadInt16();
                    else
                        return new RSAParameters();

                    seq = binr.ReadBytes(15);
                    if (!CompareBytearrays(seq, SeqOID))
                        return new RSAParameters();

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8103)
                        binr.ReadByte();
                    else if (twobytes == 0x8203)
                        binr.ReadInt16();
                    else
                        return new RSAParameters();

                    bt = binr.ReadByte();
                    if (bt != 0x00)
                        return new RSAParameters();

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130)
                        binr.ReadByte();
                    else if (twobytes == 0x8230)
                        binr.ReadInt16();
                    else
                        return new RSAParameters();

                    twobytes = binr.ReadUInt16();
                    byte lowbyte = 0x00;
                    byte highbyte = 0x00;

                    if (twobytes == 0x8102)
                        lowbyte = binr.ReadByte();
                    else if (twobytes == 0x8202)
                    {
                        highbyte = binr.ReadByte();
                        lowbyte = binr.ReadByte();
                    }
                    else
                        return new RSAParameters();
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                    int modsize = BitConverter.ToInt32(modint, 0);

                    int firstbyte = binr.PeekChar();
                    if (firstbyte == 0x00)
                    {
                        binr.ReadByte();
                        modsize -= 1;
                    }

                    byte[] modulus = binr.ReadBytes(modsize);

                    if (binr.ReadByte() != 0x02)
                        return new RSAParameters();
                    int expbytes = (int)binr.ReadByte();
                    byte[] exponent = binr.ReadBytes(expbytes);
                    var rsaKeyInfo = new RSAParameters
                    {
                        Modulus = modulus,
                        Exponent = exponent
                    };
                    return rsaKeyInfo;
                }
            }
        }

        private static bool CompareBytearrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;
            int i = 0;
            foreach (byte c in a)
            {
                if (c != b[i])
                    return false;
                i++;
            }
            return true;
        }
    }

    public struct RSAKey
    {
        public string PrivateKey { get; set; }
        public string PublicKey { get; set; }
    }
}
