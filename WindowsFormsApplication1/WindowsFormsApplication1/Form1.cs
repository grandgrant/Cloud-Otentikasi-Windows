
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Management;
using System.Collections.Specialized;
using System.IO;
using System.Net;
using MySql.Data.MySqlClient;
using System.Collections;
using System.Net.Mail;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;
using System.Net.Sockets;
using Newtonsoft.Json;
using System.Text.RegularExpressions;

namespace WindowsFormsApplication1
{
    public partial class Form1 : Form
    {
        string email;
        string kodeperangkat;
        string lastkodeperangkat;
        string cpuid;
        string motherboardsn;
        string biossn;
        string access_token;
        string expired_time;
        string refresh_token;
        string recordtime;
        int Intexpiredtime;
        int Intrecordtime;
        string temp_reftoken;
        string datainfoResult;
        string temp_acctoken;
        string temp_expiredtime;
        string[] hasilfile;
        bool hasilotentikasipertama;
        bool hasilotentikasikedua;
        const string clientIDG = "995506483560-59ovq8jugbmbcsjcl7h0mj74dttprkga.apps.googleusercontent.com";
        const string clientSecretG = "NUpKdjLPH3LN0d_E7hhK-DwD";
        const string clientIDC = "995506483560-kkj1ncu4cfrki10vvtsm6cmpotjfdv87.apps.googleusercontent.com";
        const string clientSecretC = "fKfx339y79fc86ykd5aqV6Ap";
        const string endpointGPlus = "https://www.googleapis.com/oauth2/v1/userinfo";
        const string endpointCloud = "https://cloudresourcemanager.googleapis.com/v1/projects";
        const string scopeGPlus = "openid%20email";
        const string scopeCloud = "https://www.googleapis.com/auth/cloud-platform";
        const string authorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
        const string tokenEndpoint = "https://www.googleapis.com/oauth2/v4/token";


        public Form1()
        {
            InitializeComponent();
        }


        private async void button1_Click(object sender, EventArgs e)
        {
            hasilotentikasipertama = await OtentikasiPengguna();
            if (hasilotentikasipertama == true)
            {
                hasilotentikasikedua = OtentikasiPerangkat();
                if (hasilotentikasikedua == true)
                {
                    if (File.Exists(@"C:\Users\Public\token.txt"))
                    {

                        hasilfile = System.IO.File.ReadAllLines(@"C:\Users\Public\token.txt");
                        hasilfile[0] = temp_acctoken;
                        hasilfile[1] = temp_expiredtime;
                        hasilfile[2] = temp_reftoken;
                        hasilfile[3] = recordtime;
                        int timenow = unixTimestamp();
                        Intexpiredtime = Convert.ToInt32(temp_expiredtime);
                        Intrecordtime = Convert.ToInt32(recordtime);
                        int diff = timenow - Intrecordtime;

                        if (temp_acctoken != null && temp_acctoken != "")
                        {
                            if (diff < Intexpiredtime)
                            {
                                await datainfoCall(temp_acctoken, endpointCloud);
                                parseResultCloud(datainfoResult);
                            }
                            else
                            {
                                await getnewaccesstoken(temp_reftoken, clientIDC, clientSecretC);
                                parseResultCloud(datainfoResult);
                            }
                        }
                        else
                        {
                            await Oauth2Google(scopeCloud, clientIDC, clientSecretC, endpointCloud);
                            parseResultCloud(datainfoResult);
                        }
                    }
                    else
                    {
                        await Oauth2Google(scopeCloud, clientIDC, clientSecretC, endpointCloud);
                        parseResultCloud(datainfoResult);
                    }
                }
                else
                {
                    lastkodeperangkat = Kirimperangkatbaru();
                    KirimEmail(email, lastkodeperangkat);
                    MessageBox.Show("Anda mengakses dari perangkat baru. Silahkan cek di email Anda.");
                }
            }
            else
            {
                MessageBox.Show("alamat email dan password yang diisikan salah.");
            }

        }

        public void parseResultCloud(string dataAPI)
        {
            string[] projectNumber;
            string[] projectId;
            string[] lifecycleState;
            string[] projectName;
            string[] createTime;

            JObject objects = JObject.Parse(dataAPI);
            JArray array = JArray.FromObject(objects["projects"]);
            projectNumber = new string[array.Count];
            projectId = new string[array.Count];
            lifecycleState = new string[array.Count];
            projectName = new string[array.Count];
            createTime = new string[array.Count];
            for (int i = 0; i < array.Count; i++)
            {
                projectNumber[i] = (string)array[i]["projectNumber"];
                projectId[i] = (string)array[i]["projectId"];
                lifecycleState[i] = (string)array[i]["lifecycleState"];
                projectName[i] = (string)array[i]["name"];
                createTime[i] = (string)array[i]["createTime"];
            }
            FormIntent(projectNumber, projectId, lifecycleState, projectName, createTime);
        }
        public string parseResultGPlus(string dataAPI)
        {
            JObject objects = JObject.Parse(dataAPI);
            string returnEmail = (string)objects["email"];
            return returnEmail;
        }
        public void FormIntent(string[] data1, string[] data2, string[] data3, string[] data4, string[] data5)
        {
            Form2 frm = new Form2(data1,data2,data3,data4,data5);
            frm.Show();
            this.Hide();
            
        }
        public string getProcessorId()
        {
            string processorId = "";
            ManagementObjectSearcher objectSearcherProcessor = new ManagementObjectSearcher("SELECT * FROM Win32_Processor");

            foreach (ManagementObject processor in objectSearcherProcessor.Get())
            {
                processorId = (string)processor["ProcessorId"];

            }
            return processorId;
        }
        public string getMotherboardSN()
        {
            string motherboardSN = "";
            ManagementObjectSearcher objectSearcherMotherboard = new ManagementObjectSearcher("SELECT * FROM Win32_BaseBoard");

            foreach (ManagementObject motherboard in objectSearcherMotherboard.Get())
            {
                motherboardSN = (string)motherboard["SerialNumber"];
            }
            return motherboardSN;
        }
        public string getBiosSN()
        {
            string BIOSsn = "";
            ManagementObjectSearcher objectSearcherBIOS = new ManagementObjectSearcher("SELECT * FROM Win32_BIOS");
            foreach (ManagementObject BIOS in objectSearcherBIOS.Get())
            {
                BIOSsn = (string)BIOS["SerialNumber"];
            }
            return BIOSsn;
        }
        public string Kirimperangkatbaru()
        {
            cpuid = getProcessorId();
            motherboardsn = getMotherboardSN();
            biossn = getBiosSN();
            WebClient client = new WebClient();
            byte[] response = client.UploadValues("http://aprihadiperdana.web.id/TA/tambahperangkatilegal.php", new NameValueCollection()
            {
                {"email", email },
                {"cpuid", cpuid },
                {"motherboardsn", motherboardsn },
                {"biossn", biossn }
            });
            string result = System.Text.Encoding.UTF8.GetString(response);

            JArray array = JArray.Parse(result);
            lastkodeperangkat = (string)array[0]["kode_perangkat_baru"];
            return lastkodeperangkat;
        }
        public void KirimEmail(string inputpengguna,string inputkode)
        {
            try
            {
                string linkperangkat = "http://aprihadiperdana.web.id/TA/tambahperangkat.php?png=" + MD5link(inputpengguna) + "&kde=" + MD5link(inputkode);
                string linkgantipassword = "http://aprihadiperdana.web.id/TA/ubahpassword.php?png=" + MD5link(inputpengguna);
                MailMessage message = new MailMessage();
                SmtpClient smtp = new SmtpClient();

                message.From = new MailAddress("eb14854@gmail.com","Skripsi");
                message.To.Add(new MailAddress("eril.ilkom@gmail.com"));
                message.Subject = "Akses dari Perangkat Ilegal";
                message.Body = "Akun ada diakses oleh perangkat yang tidak dikenal sistem. Jika Anda mengenali perangkat ini silahkan klik link " + linkperangkat + ". Jika Anda tidak mengenali perangkat ini silahkan untuk mengganti password Anda menggunakan link " + linkgantipassword;
                smtp.Port = 587;
                smtp.Host = "smtp.gmail.com";
                smtp.EnableSsl = true;
                smtp.UseDefaultCredentials = false;
                smtp.Credentials = new NetworkCredential("eb14854@gmail.com", "14854papa");
                smtp.DeliveryMethod = SmtpDeliveryMethod.Network;
                smtp.Send(message);
            }
            catch (Exception ex)
            {
                MessageBox.Show("err: " + ex.Message);

            }
        }
        public bool OtentikasiPerangkat()
        {
            bool hasilotentikasi;
            cpuid = getProcessorId();
            motherboardsn = getMotherboardSN();
            biossn = getBiosSN();

            WebClient client = new WebClient();

            byte[] response = client.UploadValues("http://aprihadiperdana.web.id/TA/getperangkatwindows.php", new NameValueCollection()
            {
                {"email", email},
                {"cpu", cpuid},
                {"motherboard", motherboardsn},
                {"bios", biossn}
            });
            string result = Encoding.Default.GetString(response);
            int panjangstring = result.Length;
            result = result.Substring(1,panjangstring-6);
            Console.WriteLine(result.Length);
            if (result.Equals("ok"))
            {
                hasilotentikasi = true;
            }
            else
            {
                hasilotentikasi = false;
            }
            return hasilotentikasi;
        }
        public async Task<bool> OtentikasiPengguna()
        {
            await Oauth2Google(scopeGPlus, clientIDG, clientSecretG, endpointGPlus);
            email = parseResultGPlus(datainfoResult);
            if (email != null) return true;    
            else return false;
        }
        public string MD5link(string input)
        {
            MD5 md5hash = MD5.Create();
            // Convert the input string to a byte array and compute the hash.
            byte[] data = md5hash.ComputeHash(Encoding.UTF8.GetBytes(input));

            // Create a new Stringbuilder to collect the bytes
            // and create a string.
            StringBuilder sBuilder = new StringBuilder();

            // Loop through each byte of the hashed data 
            // and format each one as a hexadecimal string.
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Return the hexadecimal string.
            return sBuilder.ToString();

        }
        //get data from google cloud
        public async Task Oauth2Google(string scope, string clientID, string clientSecret, string endpoint)
        {
            string state = randomDataBase64url(32);
            string code_verifier = randomDataBase64url(32);
            string code_challenge = base64urlencodeNoPadding(sha256(code_verifier));
            const string code_challenge_method = "S256";

            // Creates a redirect URI using an available port on the loopback address.
            string redirectURI = string.Format("http://{0}:{1}/", IPAddress.Loopback, GetRandomUnusedPort());
            Console.WriteLine("redirect URI: " + redirectURI);

            // Creates an HttpListener to listen for requests on that redirect URI.
            var http = new HttpListener();
            http.Prefixes.Add(redirectURI);
            Console.WriteLine("Listening..");
            http.Start();

            // Creates the OAuth 2.0 authorization request.
            string authorizationRequest = string.Format("{0}?response_type=code&scope={1}&redirect_uri={2}&client_id={3}&state={4}&code_challenge={5}&code_challenge_method={6}",
                authorizationEndpoint,
                scope,
                System.Uri.EscapeDataString(redirectURI),
                clientID,
                state,
                code_challenge,
                code_challenge_method);

            // Opens request in the browser.
            System.Diagnostics.Process.Start(authorizationRequest);

            // Waits for the OAuth authorization response.
            var context = await http.GetContextAsync();

            // Brings this app back to the foreground.
            this.Activate();

            // Sends an HTTP response to the browser.
            var response = context.Response;
            string responseString = string.Format("<html><head><meta http-equiv='refresh' content='10;url=https://google.com'></head><body>Please return to the app.</body></html>");
            var buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
            response.ContentLength64 = buffer.Length;
            var responseOutput = response.OutputStream;
            Task responseTask = responseOutput.WriteAsync(buffer, 0, buffer.Length).ContinueWith((task) =>
            {
                responseOutput.Close();
                http.Stop();
                Console.WriteLine("HTTP server stopped.");
            });

            // Checks for errors.
            if (context.Request.QueryString.Get("error") != null)
            {
                Console.WriteLine(String.Format("OAuth authorization error: {0}.", context.Request.QueryString.Get("error")));
                return;
            }
            if (context.Request.QueryString.Get("code") == null
                || context.Request.QueryString.Get("state") == null)
            {
                Console.WriteLine("Malformed authorization response. " + context.Request.QueryString);
                return;
            }

            // extracts the code
            var code = context.Request.QueryString.Get("code");
            var incoming_state = context.Request.QueryString.Get("state");

            // Compares the receieved state to the expected value, to ensure that
            // this app made the request which resulted in authorization.
            if (incoming_state != state)
            {
                Console.WriteLine(String.Format("Received request with invalid state ({0})", incoming_state));
                return;
            }
            Console.WriteLine("Authorization code: " + code);

            // Starts the code exchange at the Token Endpoint.
            await performCodeExchange(code, code_verifier, redirectURI,clientID,clientSecret,scope,endpoint);
        }
        public static int GetRandomUnusedPort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        public async Task getnewaccesstoken(string refreshtoken, string clientID, string clientSecret)
        {
            string tokenRequestURI = "https://www.googleapis.com/oauth2/v4/token";
            string tokenRequestBody = string.Format("client_id={0}&client_secret={1}&refresh_token={2}&grant_type=refresh_token",
                clientID,
                clientSecret,
                refreshtoken
                );
            HttpWebRequest tokenRequest = (HttpWebRequest)WebRequest.Create(tokenRequestURI);
            tokenRequest.Method = "POST";
            tokenRequest.ContentType = "application/x-www-form-urlencoded";
            tokenRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            byte[] _byteVersion = Encoding.ASCII.GetBytes(tokenRequestBody);
            tokenRequest.ContentLength = _byteVersion.Length;
            Stream stream = tokenRequest.GetRequestStream();
            await stream.WriteAsync(_byteVersion, 0, _byteVersion.Length);
            stream.Close();

            try
            {
                WebResponse tokenResponse = await tokenRequest.GetResponseAsync();
                using (StreamReader reader = new StreamReader(tokenResponse.GetResponseStream()))
                {
                    string responseText = await reader.ReadToEndAsync();
                    Console.WriteLine(responseText);
                    Dictionary<string, string> tokenEndpointDecoded = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseText);
                    access_token = tokenEndpointDecoded["access_token"];
                    expired_time = tokenEndpointDecoded["expires_in"];
                    int gettime = unixTimestamp();
                    string[] lines = { access_token, expired_time, refreshtoken, gettime.ToString() };
                    File.WriteAllLines(@"C:\Users\Public\Token.txt", lines);
                    await datainfoCall(access_token, endpointCloud);
                }
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;
                    if (response != null)
                    {
                        Console.WriteLine("HTTP: " + response.StatusCode);
                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            // reads response body
                            string responseText = await reader.ReadToEndAsync();
                        }
                    }
                }
            }
        }

        async Task performCodeExchange(string code, string code_verifier, string redirectURI, string clientID, string clientSecret,string scope,string endpoint)
        {
            Console.WriteLine("Exchanging code for tokens...");

            // builds the  request
            string tokenRequestURI = "https://www.googleapis.com/oauth2/v4/token";
            string tokenRequestBody = string.Format("code={0}&redirect_uri={1}&client_id={2}&code_verifier={3}&client_secret={4}&scope=&grant_type=authorization_code",
                code,
                System.Uri.EscapeDataString(redirectURI),
                clientID,
                code_verifier,
                clientSecret
                );

            // sends the request
            HttpWebRequest tokenRequest = (HttpWebRequest)WebRequest.Create(tokenRequestURI);
            tokenRequest.Method = "POST";
            tokenRequest.ContentType = "application/x-www-form-urlencoded";
            tokenRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            byte[] _byteVersion = Encoding.ASCII.GetBytes(tokenRequestBody);
            tokenRequest.ContentLength = _byteVersion.Length;
            Stream stream = tokenRequest.GetRequestStream();
            await stream.WriteAsync(_byteVersion, 0, _byteVersion.Length);
            stream.Close();

            try
            {
                // gets the response
                WebResponse tokenResponse = await tokenRequest.GetResponseAsync();
                using (StreamReader reader = new StreamReader(tokenResponse.GetResponseStream()))
                {
                    // reads response body
                    string responseText = await reader.ReadToEndAsync();
                    Console.WriteLine(responseText);

                    // converts to dictionary
                    Dictionary<string, string> tokenEndpointDecoded = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseText);

                    access_token = tokenEndpointDecoded["access_token"];
                    if (scope == "https://www.googleapis.com/auth/cloud-platform")
                    {
                        expired_time = tokenEndpointDecoded["expires_in"];
                        refresh_token = tokenEndpointDecoded["refresh_token"];
                        int gettime = unixTimestamp();
                        string[] lines = { access_token, expired_time, refresh_token, gettime.ToString()};
                        File.WriteAllLines(@"C:\Users\Public\Token.txt",lines);
                    }
                    await datainfoCall(access_token,endpoint);
                }
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;
                    if (response != null)
                    {
                        Console.WriteLine("HTTP: " + response.StatusCode);
                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            // reads response body
                            string responseText = await reader.ReadToEndAsync();
                            Console.WriteLine(responseText);
                        }
                    }

                }
            }
        }

        async Task datainfoCall(string access_token, string endpoint)
        {
            //Console.WriteLine("Making API Call to Projectinfo...");

            // builds the  request
            string datainfoRequestURI = endpoint;

            // sends the request
            HttpWebRequest datainfoRequest = (HttpWebRequest)WebRequest.Create(datainfoRequestURI);
            datainfoRequest.Method = "GET";
            datainfoRequest.Headers.Add(string.Format("Authorization: Bearer {0}", access_token));
            datainfoRequest.ContentType = "application/x-www-form-urlencoded";
            datainfoRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

            // gets the response
            WebResponse datainfoResponse = await datainfoRequest.GetResponseAsync();
            StreamReader datainfoResponseReader = new StreamReader(datainfoResponse.GetResponseStream());
            
            // reads response body
            string datainfoResponseText = await datainfoResponseReader.ReadToEndAsync();
            datainfoResult = datainfoResponseText;
            Console.WriteLine(datainfoResult);
        }

        /// <summary>
        /// Base64url no-padding encodes the given input buffer.
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public static string base64urlencodeNoPadding(byte[] buffer)
        {
            string base64 = Convert.ToBase64String(buffer);

            // Converts base64 to base64url.
            base64 = base64.Replace("+", "-");
            base64 = base64.Replace("/", "_");
            // Strips padding.
            base64 = base64.Replace("=", "");

            return base64;
        }

        /// <summary>
        /// Returns URI-safe data with a given input length.
        /// </summary>
        /// <param name="length">Input length (nb. output will be longer)</param>
        /// <returns></returns>
        public static string randomDataBase64url(uint length)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[length];
            rng.GetBytes(bytes);
            return base64urlencodeNoPadding(bytes);
        }

        /// <summary>
        /// Returns the SHA256 hash of the input string.
        /// </summary>
        /// <param name="inputStirng"></param>
        /// <returns></returns>
        public static byte[] sha256(string inputStirng)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(inputStirng);
            SHA256Managed sha256 = new SHA256Managed();
            return sha256.ComputeHash(bytes);
        }

        public int unixTimestamp()
        {
            var dateTime = DateTime.Now.AddHours(7);
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Local);
            int unixDateTime = (int) (dateTime.ToUniversalTime() - epoch).TotalSeconds;
            return unixDateTime;
        }

        private void label1_Click(object sender, EventArgs e)
        {

        }
    }
}
