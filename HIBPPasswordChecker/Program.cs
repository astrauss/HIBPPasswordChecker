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
            bool exitFlag = false;
            do
            {
                Console.WriteLine("Please enter password to be securely checked against the Have I Been Pwned database (exit by entering 'ex'): ");
                bool globalMatch = false;                
                passWd = GetPwFromConsole();
                if(passWd == "ex")
                {
                    exitFlag = true;
                }
                Console.WriteLine("Creating Hash value for the given password");
                string hashResult = Hash(passWd);
                //Getting rid of clear text password asap
                passWd = string.Empty;
                string hashPrefix = hashResult.Substring(0, 5);
                //Create and populate an array with hash values returned by the HIBP service
                string[] hashesToCompare = SendHIBPRequest(hashPrefix);
                int counter = 0;
                Console.WriteLine(hashesToCompare.Length + " Hash values returned by HIBP");
                //Rebuild the complete hash values and compare it with our actual password hash
                foreach (string hashVal in hashesToCompare)
                {                    
                    string[] parts = hashVal.Split(':');                    
                    if (hashResult.Equals((hashPrefix + parts[0])))
                    {                       
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
                
            } while (!exitFlag);
        }
        
        static string Hash(string input)
        {
            //Create SHA-1 hash from password
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
            //Contact the HIBP API using an HTTP GET appending the k anonymized hash fragment to the URL
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
                //Read HIBP APIresponse and populate hash array
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
            //Get password to check from conole replacing the chars typed with star characters
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
