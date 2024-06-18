using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace CryptoAPI.Controllers
{
    [RoutePrefix("cryptoAES")]
    public class CryptoAESController : Controller
    {
        [HttpGet]
        [Route("api/generate-keys")]
        public JsonResult GenerateKeys()
        {
            try
            {
                byte[] key;
                byte[] iv;
                using (Aes aes = Aes.Create())
                {
                    aes.GenerateKey();
                    aes.GenerateIV();
                    key = aes.Key;
                    iv = aes.IV;
                }

                string keyBase64 = Convert.ToBase64String(key);
                string ivBase64 = Convert.ToBase64String(iv);

                return Json(new { Success = true, Key = keyBase64, IV = ivBase64 }, JsonRequestBehavior.AllowGet);
                
            }
            catch (Exception ex)
            {
                return Json(new { Success = false, Message = ex.Message }, JsonRequestBehavior.AllowGet);
            }
        }

        [HttpPost]
        [Route("api/encrypt")]
        public JsonResult Encrypt(string dataToEncrypt, byte[] Key, byte[] IV)
        {
            try
            {
                byte[] encryptedData = EncryptData(Encoding.UTF8.GetBytes(dataToEncrypt), Key, IV);
                return Json(new { Success = true, EncryptedData = Convert.ToBase64String(encryptedData) });
            }
            catch (Exception ex)
            {
                return Json(new { Success = false, Message = ex.Message });
            }
        }

        [HttpPost]
        [Route("api/decrypt")]
        public JsonResult Decrypt(string dataToDecrypt, byte[] Key, byte[] IV)
        {
            try
            {
                byte[] decryptedData = DecryptData(Convert.FromBase64String(dataToDecrypt), Key, IV);
                return Json(new { Success = true, DecryptedData = Encoding.UTF8.GetString(decryptedData) });
            }
            catch (Exception ex)
            {
                return Json(new { Success = false, Message = ex.Message });
            }
        }

        private byte[] EncryptData(byte[] dataToEncrypt, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                        cryptoStream.FlushFinalBlock();
                        return memoryStream.ToArray();
                    }
                }
            }
        }

        private byte[] DecryptData(byte[] dataToDecrypt, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(dataToDecrypt, 0, dataToDecrypt.Length);
                        cryptoStream.FlushFinalBlock();
                        return memoryStream.ToArray();
                    }
                }
            }
        }
    }
}