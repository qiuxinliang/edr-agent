// Test-only TLS 1.2 server. Runs on a CLR thread without a PowerShell runspace.
using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

public sealed class InstallTlsFixture : IDisposable
{
    private readonly TcpListener listener;
    private readonly X509Certificate2 certificate;
    private readonly Thread thread;
    private TcpClient client;
    public readonly int Port;
    public string Error;
    public InstallTlsFixture(X509Certificate2 certificate)
    {
        this.certificate = certificate;
        listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        thread = new Thread(Serve);
        thread.IsBackground = true;
        thread.Start();
    }
    private void Serve()
    {
        try
        {
            using (client = listener.AcceptTcpClient())
            using (SslStream ssl = new SslStream(client.GetStream(), false))
            {
                client.ReceiveTimeout = 5000;
                client.SendTimeout = 5000;
                ssl.ReadTimeout = 5000;
                ssl.WriteTimeout = 5000;
                ssl.AuthenticateAsServer(certificate, false, SslProtocols.Tls12, false);
                // Transport-only GET fixture: bounded headers, no request body.
                int end = 0;
                for (int count = 0; count < 16384 && end != 4; count++)
                {
                    int b = ssl.ReadByte();
                    if (b < 0) throw new IOException("request closed before headers");
                    if ((end == 0 || end == 2) && b == 13) end++;
                    else if ((end == 1 || end == 3) && b == 10) end++;
                    else end = 0;
                }
                if (end != 4) throw new IOException("headers too long");
                byte[] response = Encoding.ASCII.GetBytes(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}");
                ssl.Write(response, 0, response.Length);
                ssl.Flush();
            }
        }
        catch (Exception error) { Error = error.GetType().Name + ": " + error.Message; }
    }
    public void Dispose()
    {
        listener.Stop();
        if (client != null) client.Close();
        if (!thread.Join(6000)) throw new TimeoutException("test TLS server did not stop");
    }
}
