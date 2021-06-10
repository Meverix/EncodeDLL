using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RSAEncoder
{   
    [Guid("243B90B1-FC0A-4D62-87A8-AC1AE3E4756F")]
    interface IRSAEncodeManager
    {
        string Encode(string textToEncode, string openKey);
    }

    [Guid("70DD7E62-7D82-4301-993C-B7D919430990"), InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
    interface IRSAEncoderEvents
    {
    }

    [Guid("69EE0677-884A-4eeb-A3BD-D407844C0C70"), ClassInterface(ClassInterfaceType.None), ComSourceInterfaces(typeof(IRSAEncoderEvents))]
    public class RSAEncodeManager :IRSAEncodeManager
    {

        public string Encode(string textToEncode, string openKey)
        {
            RSAParameters rpm = ConvertFromPemPublicKey(openKey);

            RSACryptoServiceProvider rsab = new RSACryptoServiceProvider(2048, new CspParameters() { });
            rsab.ImportParameters(rpm);

            byte[] sample = rsab.Encrypt(Encoding.UTF8.GetBytes(textToEncode), true);
            return Convert.ToBase64String(sample);
        }

        private RSAParameters ConvertFromPemPublicKey(string pemFileConent)
        {
            if (string.IsNullOrEmpty(pemFileConent))
            {
                throw new ArgumentNullException("pemFileConent", "This arg cann't be empty.");
            }
            pemFileConent = pemFileConent.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Replace("\n", "").Replace("\r", "");
            byte[] keyData = Convert.FromBase64String(pemFileConent);
            bool keySize1024 = (keyData.Length == 162);
            bool keySize2048 = (keyData.Length == 294);
            if (!(keySize1024 || keySize2048))
            {
                throw new ArgumentException("pem file content is incorrect, Only support the key size is 1024 or 2048");
            }
            byte[] pemModulus = (keySize1024 ? new byte[128] : new byte[256]);
            var pemPublicExponent = new byte[3];
            Array.Copy(keyData, (keySize1024 ? 29 : 33), pemModulus, 0, (keySize1024 ? 128 : 256));
            Array.Copy(keyData, (keySize1024 ? 159 : 291), pemPublicExponent, 0, 3);
            var para = new RSAParameters { Modulus = pemModulus, Exponent = pemPublicExponent };
            return para;
        }
    }
}
