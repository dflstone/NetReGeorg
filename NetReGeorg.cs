using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;

public class NetReGeorg
{
    /// <summary>
    /// 服务启动，开始监听
    /// </summary>
    /// <returns></returns>
    public static async Task Start()
    {
        const string BASICCHECKSTRING = "Georg says, 'All seems fine'";

        const int READBUFSIZE = 1024;
        const int SOCKTIMEOUT = 5000;//超时时间5000毫秒

        async Task<bool> AskGeorgAsync(string url)
        {
            try
            {
                HttpClient httpClient = new HttpClient();
                string result = await httpClient.GetStringAsync(url);
                if (BASICCHECKSTRING.Equals(result.Trim()))
                    return true;
            }
            catch { }
            return false;
        }

        string listen_on = "127.0.0.1";
        int listen_port = 8888;
        string url = "http://192.168.70.82:8080/August/tunnel.jsp";
        Console.WriteLine($"Starting socks server [{listen_on}:{listen_port}], tunnel at [{url}]");
        Console.WriteLine("Checking if Georg is ready");
        if (!await AskGeorgAsync(url))
        {
            Console.WriteLine("Georg is not ready, please check url");
            return;
        }
        Socket servSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);//启动tcp socket
        servSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);//SO_REUSEADDR是让端口释放后立即就可以被再次使用
        servSocket.Bind(new IPEndPoint(IPAddress.Parse(listen_on), listen_port));
        servSocket.Listen(1000);

        while (true)
        {
            try
            {
                Socket socket = servSocket.Accept();//这里等待socket连接
                socket.SendTimeout = SOCKTIMEOUT;
                socket.ReceiveTimeout = SOCKTIMEOUT;
                Task.Run(new Session(socket, url).Run);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.StackTrace);
            }
        }
        servSocket.Close();
    }


    class Session
    {
        const byte VER = 5;
        const byte METHOD = 0;
        const byte SUCCESS = 0;
        const byte SOCKFAIL = 1;
        const byte NETWORKFAIL = 2;
        const byte HOSTFAIL = 4;
        const byte REFUSED = 5;
        const byte TTLEXPIRED = 6;
        const byte UNSUPPORTCMD = 7;
        const byte ADDRTYPEUNSPPORT = 8;
        const byte UNASSIGNED = 9;

        const int READBUFSIZE = 1024;

        private string? target = null;
        private int targetPort = 0;
        private readonly Socket pSocket;
        private readonly string ConnectString;
        private readonly HttpClient Client;
        public Session(Socket socket, string connectString)
        {

            pSocket = socket;
            ConnectString = connectString;

            Client = new HttpClient();
        }
        private async Task<bool> ParseSocks5(Socket socket)
        {
            Console.WriteLine("SocksVersion5 detected");
            byte[] data1 = new byte[1];
            byte[] data2 = new byte[2];
            byte[] data3 = new byte[3];
            byte[] data4 = new byte[4];
            socket.Receive(data1);
            socket.Receive(data1);
            socket.Send(new byte[] { VER, METHOD });
            socket.Receive(data1);
            byte ver, cmd, rsv, atyp;
            if (data1[0] == 2)//this is a hack for proxychains
            {
                socket.Receive(data4);
                ver = data4[0];
                cmd = data4[1];
                rsv = data4[2];
                atyp = data4[3];
            }
            else
            {
                socket.Receive(data3);
                cmd = data3[0];
                rsv = data3[1];
                atyp = data3[2];
            }
            if (atyp == 1)
            {
                //Reading 6 bytes for the IP and Port
                socket.Receive(data4);
                target = string.Join('.', data4);
                socket.Receive(data2);
                targetPort = data2[0] * 256 + data2[1];
            }
            else if (atyp == 3)
            {
                // hostname length (1 byte) www.baidu.com:80
                socket.Receive(data1);
                int targetLen = data1[0];//ord(sock.recv(1));
                byte[] temp = new byte[targetLen];
                socket.Receive(temp);
                target = Encoding.UTF8.GetString(temp);
                socket.Receive(data2);
                targetPort = data2[0] * 256 + data2[1];
            }
            else if (atyp == 4)
            {
                // ipv6
                byte[] data16 = new byte[16];
                socket.Receive(data16);
                string[] temp = new string[8];
                for (int i = 0; i < 8; i++)
                {
                    // x 为16进制 2 为强制2字符显示
                    temp[i] = data16[i * 2].ToString("x2") + data16[i * 2 + 1].ToString("x2");
                }
                target = string.Join(":", temp);
                socket.Receive(data2);
                targetPort = data2[0] * 256 + data2[1];
            }
            if (cmd == 2) throw new Exception("Socks5 - BIND not implemented");
            else if (cmd == 3) throw new Exception("Socks5 - UDP  not implemented");
            else if (cmd == 1)// CONNECT
            {
                string serverIp = target;
                try
                {
                    serverIp = Dns.GetHostEntry(target).AddressList[0].ToString();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("oeps");
                }
                byte[] ip4 = new byte[4];
                int i = 0;
                foreach (string s in serverIp.Split('.'))
                {
                    ip4[i++] = (byte)int.Parse(s);
                }

                bool sucess = await SetupRemoteSessionAsync(target, targetPort);
                if (sucess)
                {
                    socket.Send(new byte[] { VER, SUCCESS, 0, 1, ip4[0], ip4[1], ip4[2], ip4[3], (byte)(targetPort / 256), (byte)(targetPort % 256) });
                    return true;
                }
                else
                {
                    socket.Send(new byte[] { VER, REFUSED, 0, 1, ip4[0], ip4[1], ip4[2], ip4[3], (byte)(targetPort / 256), (byte)(targetPort % 256) });
                    throw new Exception($"[{target}:{targetPort}] Remote failed");
                }
            }

            throw new Exception("Socks5 - Unknown CMD");
        }
        private bool ParseSocks4(Socket socket)
        {
            return false;
        }
        /// <summary>
        /// 设置socket连接，根据接收的第一个字节，决定采用socket5还是socket4进行连接
        /// </summary>
        /// <param name="socket"></param>
        /// <returns></returns>
        private async Task<bool> HandleSocks(Socket socket)
        {
            byte[] data = new byte[1];
            socket.Receive(data);
            if (data[0] == 5)// socket5
            {
                return await ParseSocks5(socket);
            }
            else if (data[0] == 4)// socket4
            {
                return ParseSocks4(socket);
            }
            return false;
        }

        private async Task<bool> SetupRemoteSessionAsync(string target, int port)
        {
            HttpContent content = new StringContent("");
            content.Headers.Add("X-CMD", "CONNECT");
            content.Headers.Add("X-TARGET", target);
            content.Headers.Add("X-PORT", port.ToString());
            HttpResponseMessage httpResponseMessage = await Client.PostAsync(ConnectString + $"?cmd=connect&target={target}&port={targetPort}", content);
            if (httpResponseMessage.StatusCode == HttpStatusCode.OK)
            {
                var status = httpResponseMessage.Headers.GetValues("X-status");
                if (((string[])status)[0] == "OK")
                {
                    //var cookie = httpResponseMessage.Headers.GetValues("set-cookie");
                    //return ((string[])cookie)[0];
                    return true;
                }
                else
                {
                    var error = httpResponseMessage.Headers.GetValues("X-ERROR");
                    Console.WriteLine(error);
                }
            }

            return false;
        }
        private async Task CloseRemoteSession()
        {
            HttpContent content = new StringContent("");
            content.Headers.Add("X-CMD", "DISCONNECT");
            HttpResponseMessage httpResponseMessage = await Client.PostAsync(ConnectString + "?cmd=disconnect", content);
            if (httpResponseMessage.StatusCode == HttpStatusCode.OK)
            {
                Console.WriteLine($"[{target}:{targetPort}] Connection Terminated");
            }
        }

        private async Task Reader()
        {
            byte[]? data;
            while (true)
            {
                try
                {
                    if (pSocket == null) break;
                    HttpContent content = new StringContent("");
                    content.Headers.Add("X-CMD", "READ");
                    HttpResponseMessage httpResponseMessage = await Client.PostAsync(ConnectString + "?cmd=read", content);
                    if (httpResponseMessage.StatusCode == HttpStatusCode.OK)
                    {
                        var status = (string[])httpResponseMessage.Headers.GetValues("X-status");

                        if (status.Length > 0 && status[0] == "OK")
                        {
                            //var cookie = httpResponseMessage.Headers.GetValues("set-cookie");
                            data = await httpResponseMessage.Content.ReadAsByteArrayAsync();
                            try
                            {
                                var server = (string[])httpResponseMessage.Headers.GetValues("server");
                                //if (server[0].Contains("Apache-Coyote/1.1"))
                                //{
                                //    Array.Resize(ref data, data.Length - 1);
                                //}
                            }
                            catch { }
                        }
                        else
                        {
                            data = null;
                            var error = (string[])httpResponseMessage.Headers.GetValues("X-ERROR");
                            Console.WriteLine($"[{target}:{targetPort}] HTTP [{httpResponseMessage.StatusCode}]: Status: [{status[0]}]: Message [{error[0]}] Shutting down");
                        }
                    }
                    else
                    {
                        data = null;
                        Console.WriteLine($"[{target}:{targetPort}] HTTP [{httpResponseMessage.StatusCode}]: Shutting down");
                    }
                    if (data == null)//Remote socket closed
                        break;
                    if (data.Length == 0)
                    {
                        Thread.Sleep(100);
                        continue;
                    }
                    Console.WriteLine($"[{target}:{targetPort}] <<<< [{data.Length}]");
                    string temp = Encoding.UTF8.GetString(data);
                    pSocket.Send(data);
                }
                catch (Exception)
                {
                    throw;
                }
            }
            CloseRemoteSession();
            Console.WriteLine($"[{target}:{targetPort}] Closing localsocket");
            try
            {
                pSocket?.Close();
            }
            catch (Exception)
            {
                Console.WriteLine($"[{target}:{targetPort}] Localsocket already closed");
            }
        }
        private async Task Writer()
        {
            byte[] data = new byte[READBUFSIZE];
            while (true)
            {
                try
                {
                    pSocket.ReceiveTimeout = 1000;
                    pSocket.SendTimeout = 1000;
                    int len = pSocket.Receive(data);
                    if (len == 0) break;
                    string tem = Encoding.UTF8.GetString(data, 0, len);
                    //HttpContent content = new FormUrlEncodedContent( new[] {new KeyValuePair<string, string>("cmd","forward")});
                    //content.Headers.Add("X-CMD", "FORWARD");
                    //content.Headers.Add("Connection", "Keep-Alive");
                    var content = new ByteArrayContent(data, 0, len);
                    content.Headers.Add("X-CMD", "FORWARD");
                    content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                    HttpResponseMessage httpResponseMessage = await Client.PostAsync(ConnectString + "?cmd=forward", content);
                    if (httpResponseMessage.StatusCode == HttpStatusCode.OK)
                    {
                        var status = (string[])httpResponseMessage.Headers.GetValues("X-status");

                        if (status.Length > 0 && status[0] == "OK")
                        {
                            //var cookie = httpResponseMessage.Headers.GetValues("set-cookie");                        
                        }
                        else
                        {
                            var error = (string[])httpResponseMessage.Headers.GetValues("X-ERROR");
                            Console.WriteLine($"[{target}:{targetPort}] HTTP [{httpResponseMessage.StatusCode}]: Status: [{status[0]}]: Message [{error[0]}] Shutting down");
                            break;
                        }
                    }
                    else
                    {
                        Console.WriteLine($"[{target}:{targetPort}] HTTP [{httpResponseMessage.StatusCode}]: Shutting down");
                        break;
                    }
                    Console.WriteLine($"[{target}:{targetPort}] >>>> [{len}]");
                }
                catch (TimeoutException)
                {
                    continue;
                }
                catch (Exception)
                {
                    break;
                    throw;
                }
            }
            CloseRemoteSession();
            Console.WriteLine("Closing localsocket");
            try
            {
                pSocket.Close();
            }
            catch (Exception)
            {
                Console.WriteLine("Localsocket already closed");
            }
        }
        public async Task Run()
        {
            try
            {
                if (await HandleSocks(pSocket))
                {
                    var readerTask = Task.Run(Reader);
                    var writerTask = Task.Run(Writer);
                    Task.WaitAll(readerTask, writerTask);
                }
            }
            catch (Exception)
            {
                pSocket.Close();
            }
        }
    }
}

