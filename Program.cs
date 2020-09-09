using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.IO;

namespace MicrosoftGraphToken
{
    public class Program
    {
        static async Task Main(string[] args)
        {
            string clientId = args[0];
            string secrets = args[1];
            string tenant = args[2];
            double u = double.Parse(args[3]);
            double x0 = double.Parse(args[4]);

            string json = File.ReadAllText("./Token.txt");
            string reflashToken = Decode(JObject.Parse(json)["reflash_token"].ToString(), u, x0);
            // string reflashToken = JObject.Parse(json)["reflash_token"].ToString();

            var tokens = await ReflashTokenAsync(clientId, secrets, tenant,reflashToken);

            string access_token = tokens.Item1;
            string reflash_token = Encode(tokens.Item2, u, x0);
            DateTime reflash_time = DateTime.UtcNow;

            var tokenObject = new { access_token, reflash_token, reflash_time };
            json = JsonConvert.SerializeObject(tokenObject, Formatting.Indented);
            File.WriteAllText("./Token.txt", json);
        }

        static async Task<(string, string)> ReflashTokenAsync(string clientId, string secrets, string tenant, string reflash_token)
        {
            HttpClient httpClient = new HttpClient();
            string appurl = "https://msgraphauthorization.azurewebsites.net/authcode/";
            string scope = "offline_access user.read Mail.Read Mail.ReadWrite Mail.Send Files.Read Files.ReadWrite Files.Read.All Files.ReadWrite.All";

            Dictionary<string, string> body = new Dictionary<string, string>()
            {
                { "client_id", clientId },
                { "scope", scope },
                { "refresh_token", reflash_token },
                { "redirect_uri", appurl },
                { "grant_type", "refresh_token" },
                { "client_secret", secrets }
            };

            var formData = new FormUrlEncodedContent(body);
            Uri url = new Uri($"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
            var buffer = await httpClient.PostAsync(url, formData);

            string json = await buffer.Content.ReadAsStringAsync();
            JObject jObject = JObject.Parse(json);
            if (jObject.Property("access_token") != null)
                return (jObject["access_token"].ToString(), jObject["refresh_token"].ToString());

            throw new InvalidOperationException("獲取 Token 失敗");
        }

        private static string Encode(string data, double u, double x0)
        {
            return Convert.ToBase64String(Encrypt(Encoding.UTF8.GetBytes(data), u, x0));
        }

        private static string Decode(string data, double u, double x0)
        {
            return Encoding.UTF8.GetString(Encrypt(Convert.FromBase64String(data), u, x0));
        }

        private static byte[] Encrypt(byte[] data, double u, double x0)
        {
            byte[] res = new byte[data.Length];
            double x = Logistic(u, x0, 2000);

            for (int i = 0; i < data.Length; i++)
            {
                x = Logistic(u, x, 5);
                res[i] = Convert.ToByte(Convert.ToInt32(Math.Floor(x * 1000))
                    % 256 ^ data[i]);
            }

            return res;
        }

        private static double Logistic(double u, double x, int n)
        {
            for (int i = 0; i < n; i++)
            {
                x = u * x * (1 - x);
            }
            return x;
        }
    }
}
