using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace HIBPSecurePassCheck
{
    class Program
    {
        
        static void Main(string[] args)
        {
            string passWd = string.Empty;
            do
            {
                Console.WriteLine("Please enter password to be securely checked against the Have I Been Pwned database: ");
                bool globalMatch = false;
                bool match = false;
                passWd = GetPwFromConsole();
                Console.WriteLine("Creating Hash value for the given password");
                string hashResult = Hash(passWd);
                string hashPrefix = hashResult.Substring(0, 5);
                string[] hashesToCompare = SendHIBPRequest(hashPrefix);
                string[] originalHashListResponse = new string[hashesToCompare.Length];
                hashesToCompare.CopyTo(originalHashListResponse, 0);
                hashesToCompare = ClearHashList(hashesToCompare);
                int counter = 0;
                Console.WriteLine(hashesToCompare.Length + " Hash values returned by HIBP");
                foreach (string hashVal in hashesToCompare)
                {
                    match = (hashPrefix + hashVal).Equals(hashResult);
                    if (match)
                    {
                        string hashOccur = originalHashListResponse[counter];
                        string[] parts = hashOccur.Split(':');
                        Console.WriteLine("Match found at position " + counter + " - Please change PW!");
                        Console.WriteLine("The database contains " + parts[1] + " occurrences of this PW");
                        globalMatch = true;
                    }
                    counter++;
                }
                Console.WriteLine("Hash value for given PW is: " + hashResult + "\n");
                
                if (!globalMatch)
                {
                    Console.WriteLine("No match found - Lucky bastard. Nevertheless - Change your PW regularly\n");
                }
                Console.WriteLine("----------------------------------------");
            } while (passWd != "ex");
        }

        static string[] ClearHashList(string[] hashListFromResponse)
        {
            int length = hashListFromResponse.Length;
            for(int i = 0; i < length; i++)
            {
                string hash = hashListFromResponse[i];
                string clearedHash = hash.Remove(hash.IndexOf(":"));
                hashListFromResponse[i] = clearedHash;
            }

            return hashListFromResponse;
            
        }

        static string Hash(string input)
        {
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
                var sb = new StringBuilder(hash.Length * 2);

                foreach (byte b in hash)
                {
                    sb.Append(b.ToString("X2"));
                }

                return sb.ToString();
            }
        }

        static string[] SendHIBPRequest(string hashFragment)
        {
            Console.WriteLine("Sending Request to HIBP with Hash fragment: " + hashFragment);
            Uri reqUri = new Uri("https://api.pwnedpasswords.com/range/" + hashFragment);
            Console.WriteLine("Request sent to HIBP is: " + reqUri.ToString());
            string[] hashListResponse = null;
            try
            {
                WebRequest request = WebRequest.CreateHttp(reqUri);
                request.Method = "GET";
                WebResponse response = request.GetResponse();
                Console.WriteLine("Response from Server: " +((HttpWebResponse)response).StatusDescription);
                Stream dataStream = response.GetResponseStream();
                StreamReader reader = new StreamReader(dataStream);
                  
                string responseFromServer = reader.ReadToEnd();
                hashListResponse = responseFromServer.Split(new string[] { "\n", "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                reader.Close();
                dataStream.Close();
                response.Close();                
            } catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            return hashListResponse;
        }

        static string GetPwFromConsole()
        {
            string pass = "";
            do
            {
                ConsoleKeyInfo key = Console.ReadKey(true);
                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    pass += key.KeyChar;
                    Console.Write("*");
                }
                else
                {
                    if (key.Key == ConsoleKey.Backspace && pass.Length > 0)
                    {
                        pass = pass.Substring(0, (pass.Length - 1));
                        Console.Write("\b \b");
                    }
                    else if (key.Key == ConsoleKey.Enter)
                    {
                        break;
                    }
                }
            } while (true);
            Console.WriteLine("\n");
            return pass;
        }
    }
}
