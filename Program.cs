using System.Net;

Task.Run(NetReGeorg.Start);

var proxy = new WebProxy();
proxy.Address = new Uri("socks5://127.0.0.1:8888");
var handler = new HttpClientHandler
{
    Proxy = proxy
};
HttpClient httpClient = new HttpClient(handler);
string response = await httpClient.GetStringAsync("https://www.t66y.com");
Console.WriteLine(response);


