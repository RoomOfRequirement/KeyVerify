using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace KeyVerify
{
    static class Helper
    {
        public static PhysicalAddress? GetMacAddress()
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .OrderByDescending(n => n.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                .Select(n => n.GetPhysicalAddress())
                .FirstOrDefault();
        }

        public static string GetOSInfo()
        {
            return $"{RuntimeInformation.OSDescription}.{RuntimeInformation.OSArchitecture}";
        }

        public static DateTime GetBuildDateTime()
        {
            return File.GetCreationTimeUtc(Assembly.GetExecutingAssembly()!.Location);
        }

        public static bool VerifyExpiration()
        {
            return DateTime.UtcNow < GetBuildDateTime().AddMonths(1);
        }

        public static string? GenerateLicense(string priv_key)
        {
            // data consist of `mac address + os platform + os version + os arch`
            var data = Encoding.UTF8.GetBytes($"{GetMacAddress()}.{GetOSInfo()}");
            PemReader reader = new(new StringReader(priv_key));
            var pem_obj = reader.ReadPemObject();
            Ed25519PrivateKeyParameters parameters = (Ed25519PrivateKeyParameters)PrivateKeyFactory.CreateKey(pem_obj.Content);
            ISigner signer = new Ed25519Signer();
            signer.Init(true, parameters);
            signer.BlockUpdate(data, 0, data.Length);
            return Convert.ToBase64String(signer.GenerateSignature());
        }

        public static bool VerifyLicense(string pub_key, string sig)
        {
            var data = Encoding.UTF8.GetBytes($"{GetMacAddress()}.{GetOSInfo()}");
            PemReader reader = new(new StringReader(pub_key));
            var pem_obj = reader.ReadPemObject();
            Ed25519PublicKeyParameters parameters = (Ed25519PublicKeyParameters)PublicKeyFactory.CreateKey(pem_obj.Content);
            ISigner verifier = new Ed25519Signer();
            verifier.Init(false, parameters);
            verifier.BlockUpdate(data, 0, data.Length);
            return verifier.VerifySignature(Convert.FromBase64String(sig));
        }
    }

    internal class Program
    {
        static void Main(string[] args)
        {
            // using pkg `BouncyCastle.Cryptography`: `Install-Package BouncyCastle.Cryptography`
            // generate key pair with openssl
            // private key: `openssl genpkey -algorithm ed25519 -out private.pem`
            // public key: `openssl pkey -in private.pem -pubout -out public.pem`
            string priv_key = "", pub_key = "";
            try
            {
                using (StreamReader sr = new("private.pem"))
                {
                    priv_key = sr.ReadToEnd();
                }
            }
            catch (IOException e)
            {
                Console.WriteLine("private.pem could not be read:");
                Console.WriteLine(e.Message);
                return;
            }
            try
            {
                using (StreamReader sr = new("public.pem"))
                {
                    pub_key = sr.ReadToEnd();
                }
            }
            catch (IOException e)
            {
                Console.WriteLine("public.pem could not be read:");
                Console.WriteLine(e.Message);
                return;
            }

            var license = Helper.GenerateLicense(priv_key);
            if (license == null)
            {
                Console.WriteLine("failed to generate the license");
                return;
            }
            Console.WriteLine($"license: {license}");

            var path = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!, "license.txt");
            try
            {
                using StreamWriter outputFile = new(path);
                outputFile.WriteLine(license);
            }
            catch (IOException e)
            {
                Console.WriteLine("license file could not be written:");
                Console.WriteLine(e.Message);
                return;
            }
            Console.WriteLine($"write license to {path}");
            
            if (Helper.VerifyLicense(pub_key, license))
                Console.WriteLine("succeed to verify license");
            else Console.WriteLine("fail to verify license");

            if (!Helper.VerifyExpiration()) Console.WriteLine("license expired");
            Console.WriteLine($"{DateTime.UtcNow} - {Helper.GetBuildDateTime()}");
        }
    }
}