using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Timers;

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

    class RunningTimer
    {
        public const double m_1_min = 1000 * 60;  // 1 min
        private static string m_clock_file_name = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!, "clock.dat");
        private double m_timer_interval;
        private double m_total_running_time_limit;
        private double m_total_running_time;
        private System.Timers.Timer? m_timer;
        private Stopwatch m_stop_watch = Stopwatch.StartNew();

        public static void CreateClock(string clock_file_name)
        {
            m_clock_file_name = clock_file_name;
            using (var stream = File.Open(m_clock_file_name, FileMode.Create))
            {
                using (var writer = new BinaryWriter(stream, Encoding.UTF8, false))
                {
                    writer.Write(0.0);
                }
            }
        }

        public RunningTimer(double timer_interval = 1 * m_1_min, double total_running_time_limit = 2 * m_1_min)
        {
            m_timer_interval = timer_interval;
            m_total_running_time_limit = total_running_time_limit;

            if (File.Exists(m_clock_file_name))
            {
                using (var stream = File.Open(m_clock_file_name, FileMode.Open))
                {
                    using (var reader = new BinaryReader(stream, Encoding.UTF8, false))
                    {
                        m_total_running_time = reader.ReadDouble();
                    }
                }

                Console.WriteLine($"app has been running: {m_total_running_time / 1000}s");
                if (m_total_running_time >= m_total_running_time_limit)
                    OnTimeout();
            }
            else
                OnMissingAsset();

            m_timer = new System.Timers.Timer(m_timer_interval);
            m_timer.Elapsed += OnTimedEvent;
            m_timer.AutoReset = true;
            m_timer.Enabled = true;
        }

        // destructor will only be called if instance collected by GC
        // https://learn.microsoft.com/en-us/dotnet/csharp/programming-guide/classes-and-structs/finalizers
        ~RunningTimer()
        {
            Dispose();
        }

        public void Dispose()
        {
            m_timer?.Stop();
            m_timer?.Dispose();

            m_total_running_time += m_stop_watch.ElapsedMilliseconds;
            using (var stream = File.Open(m_clock_file_name, FileMode.Open))
            {
                using (var writer = new BinaryWriter(stream, Encoding.UTF8, false))
                {
                    writer.Write(m_total_running_time);
                }
            }
            m_stop_watch.Stop();
            //Console.WriteLine("dispose");
        }

        private void OnTimedEvent(Object? source, ElapsedEventArgs e)
        {
            Console.WriteLine("The Elapsed event was raised at {0:HH:mm:ss.fff}",
                              e.SignalTime);
            m_total_running_time += m_timer_interval;
            if (m_total_running_time >= m_total_running_time_limit)
                OnTimeout();
            m_stop_watch = Stopwatch.StartNew();
        }

        private void OnTimeout()
        {
            Dispose();
            Environment.FailFast("app runs out of time");  // Environment.Exit(1);
        }

        private void OnMissingAsset()
        {
            Dispose();
            Environment.FailFast("app misses asset");
        }
    }

    internal class Program
    {
        static void Main(string[] args)
        {
            string app_folder_path = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!;
            string clock_file_path = Path.Combine(app_folder_path, "clock.dat");
            if (!File.Exists(clock_file_path))
                RunningTimer.CreateClock(clock_file_path);

            RunningTimer rt = new(RunningTimer.m_1_min, 2 * RunningTimer.m_1_min);

            // using pkg `BouncyCastle.Cryptography`: `Install-Package BouncyCastle.Cryptography`
            // generate key pair with openssl
            // private key: `openssl genpkey -algorithm ed25519 -out private.pem`
            // public key: `openssl pkey -in private.pem -pubout -out public.pem`
            string priv_key = "", pub_key = "";
            try
            {
                using (StreamReader sr = new(Path.Combine(app_folder_path, "private.pem")))
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
                using (StreamReader sr = new(Path.Combine(app_folder_path, "public.pem")))
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

            var path = Path.Combine(app_folder_path, "license.txt");
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

            Thread.Sleep(1000 * 60);
            rt.Dispose();  // need explicitly call it here
        }
    }
}