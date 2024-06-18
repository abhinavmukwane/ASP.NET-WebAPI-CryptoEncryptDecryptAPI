using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace CryptoAPI.Controllers
{
    [RoutePrefix("cryptoRSA")]
    public class CryptoController : Controller
    {
        [HttpGet]
        [Route("api/generate-keys")]
        public JsonResult GenerateKeys()
        {
            try
            {
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
                {
                    RSAParameters rsaParameters = rsa.ExportParameters(true);
                    string publicKey = Convert.ToBase64String(rsaParameters.Modulus);
                    string privateKey = Convert.ToBase64String(rsa.ExportCspBlob(true));

                    return Json(new { Success = true, PublicKey = publicKey, PrivateKey = privateKey }, JsonRequestBehavior.AllowGet);
                }
            }
            catch (Exception ex)
            {
                return Json(new { Success = false, Message = ex.Message }, JsonRequestBehavior.AllowGet);
            }
        }

        [HttpPost]
        [Route("api/encrypt")]
        public JsonResult Encrypt(string publicKey, string dataToEncrypt)
        {
            try
            {
                byte[] encryptedData = EncryptData(Encoding.UTF8.GetBytes(dataToEncrypt), publicKey);
                return Json(new { Success = true, EncryptedData = Convert.ToBase64String(encryptedData) });
            }
            catch (Exception ex)
            {
                return Json(new { Success = false, Message = ex.Message });
            }
        }

        [HttpPost]
        [Route("api/decrypt")]
        public JsonResult Decrypt(string privateKey, string dataToDecrypt)
        {
            try
            {
                byte[] decryptedData = DecryptData(Convert.FromBase64String(dataToDecrypt), privateKey);
                return Json(new { Success = true, DecryptedData = Encoding.UTF8.GetString(decryptedData) });
            }
            catch (Exception ex)
            {
                return Json(new { Success = false, Message = ex.Message });
            }
        }

        private byte[] EncryptData(byte[] dataToEncrypt, string publicKeyString)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                RSAParameters rsaParameters = new RSAParameters
                {
                    Modulus = Convert.FromBase64String(publicKeyString),
                    Exponent = new byte[] { 1, 0, 1 } // 65537 in decimal
                };
                rsa.ImportParameters(rsaParameters);
                return rsa.Encrypt(dataToEncrypt, false);
            }
        }

        private byte[] DecryptData(byte[] dataToDecrypt, string privateKeyString)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportCspBlob(Convert.FromBase64String(privateKeyString));
                return rsa.Decrypt(dataToDecrypt, false);
            }
        }
    }
}