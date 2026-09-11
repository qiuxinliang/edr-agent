// Test-only TLS 1.2 server. Runs on a CLR thread without a PowerShell runspace.
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

// Test certificate owner backed by a uniquely named current-user CNG key.
// The persistent key lets Windows Schannel use the private key reliably while
// keeping the certificate itself out of CurrentUser/LocalMachine stores.
public sealed class InstallCertificateFixtureMaterial : IDisposable
{
    private readonly string keyName;
    private readonly CngProvider provider;
    private CngKey key;
    private RSACng rsa;

    public X509Certificate2 Certificate { get; private set; }

    internal InstallCertificateFixtureMaterial(
        string keyName,
        CngProvider provider,
        CngKey key,
        RSACng rsa,
        X509Certificate2 certificate)
    {
        this.keyName = keyName;
        this.provider = provider;
        this.key = key;
        this.rsa = rsa;
        Certificate = certificate;
    }

    public void Dispose()
    {
        List<Exception> failures = new List<Exception>();
        if (Certificate != null)
        {
            try { Certificate.Dispose(); }
            catch (Exception error) { failures.Add(error); }
            finally { Certificate = null; }
        }
        if (rsa != null)
        {
            try { rsa.Dispose(); }
            catch (Exception error) { failures.Add(error); }
            finally { rsa = null; }
        }
        if (key != null)
        {
            try { key.Dispose(); }
            catch (Exception error) { failures.Add(error); }
            finally { key = null; }
        }
        CngKey cleanupKey = null;
        try
        {
            if (CngKey.Exists(keyName, provider))
            {
                cleanupKey = CngKey.Open(keyName, provider);
                cleanupKey.Delete();
            }
        }
        catch (Exception error) { failures.Add(error); }
        finally
        {
            if (cleanupKey != null)
            {
                try { cleanupKey.Dispose(); }
                catch (Exception error) { failures.Add(error); }
            }
        }
        if (failures.Count != 0)
            throw new AggregateException("Test certificate fixture cleanup failed.", failures);
    }
}

public static class InstallCertificateFixtureFactory
{
    private static readonly CngProvider Provider =
        new CngProvider("Microsoft Software Key Storage Provider");

    private static InstallCertificateFixtureMaterial Create(
        InstallCertificateFixtureMaterial issuer,
        string commonName,
        bool certificateAuthority,
        string ekuOid,
        string dnsName,
        string ipAddress,
        int notBeforeDays,
        int notAfterDays)
    {
        string keyName = "FDS-Compat-TLS-" + Guid.NewGuid().ToString("N");
        CngKey key = null;
        RSACng rsa = null;
        X509Certificate2 certificate = null;
        try
        {
            CngKeyCreationParameters creation = new CngKeyCreationParameters();
            creation.Provider = Provider;
            creation.ExportPolicy = CngExportPolicies.None;
            creation.KeyUsage = CngKeyUsages.Signing | CngKeyUsages.Decryption;
            creation.Parameters.Add(new CngProperty(
                "Length", BitConverter.GetBytes(2048), CngPropertyOptions.None));
            key = CngKey.Create(CngAlgorithm.Rsa, keyName, creation);
            rsa = new RSACng(key);

            CertificateRequest request = new CertificateRequest(
                new X500DistinguishedName("CN=" + commonName),
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
                certificateAuthority, false, 0, true));
            X509KeyUsageFlags usage = certificateAuthority
                ? X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature
                : X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment;
            request.CertificateExtensions.Add(new X509KeyUsageExtension(usage, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            if (!String.IsNullOrEmpty(ekuOid))
            {
                OidCollection usages = new OidCollection();
                usages.Add(new Oid(ekuOid));
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, true));
            }
            if (!String.IsNullOrEmpty(dnsName) || !String.IsNullOrEmpty(ipAddress))
            {
                SubjectAlternativeNameBuilder san = new SubjectAlternativeNameBuilder();
                if (!String.IsNullOrEmpty(dnsName)) san.AddDnsName(dnsName);
                if (!String.IsNullOrEmpty(ipAddress)) san.AddIpAddress(IPAddress.Parse(ipAddress));
                request.CertificateExtensions.Add(san.Build());
            }

            DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(notBeforeDays);
            DateTimeOffset notAfter = DateTimeOffset.UtcNow.AddDays(notAfterDays);
            if (issuer == null)
            {
                certificate = request.CreateSelfSigned(notBefore, notAfter);
            }
            else
            {
                byte[] serialNumber = Guid.NewGuid().ToByteArray();
                serialNumber[0] = (byte)(serialNumber[0] & 0x7f);
                if (serialNumber[0] == 0) serialNumber[0] = 1;
                X509Certificate2 publicCertificate = request.Create(
                    issuer.Certificate, notBefore, notAfter, serialNumber);
                try
                {
                    certificate = RSACertificateExtensions.CopyWithPrivateKey(publicCertificate, rsa);
                }
                finally { publicCertificate.Dispose(); }
            }
            InstallCertificateFixtureMaterial result = new InstallCertificateFixtureMaterial(
                keyName, Provider, key, rsa, certificate);
            key = null;
            rsa = null;
            certificate = null;
            return result;
        }
        catch (Exception creationError)
        {
            List<Exception> failures = new List<Exception>();
            failures.Add(creationError);
            if (certificate != null)
            {
                try { certificate.Dispose(); }
                catch (Exception error) { failures.Add(error); }
            }
            if (rsa != null)
            {
                try { rsa.Dispose(); }
                catch (Exception error) { failures.Add(error); }
            }
            if (key != null)
            {
                try { key.Dispose(); }
                catch (Exception error) { failures.Add(error); }
            }
            CngKey cleanupKey = null;
            try
            {
                if (CngKey.Exists(keyName, Provider))
                {
                    cleanupKey = CngKey.Open(keyName, Provider);
                    cleanupKey.Delete();
                }
            }
            catch (Exception error) { failures.Add(error); }
            finally
            {
                if (cleanupKey != null)
                {
                    try { cleanupKey.Dispose(); }
                    catch (Exception error) { failures.Add(error); }
                }
            }
            if (failures.Count == 1) throw;
            throw new AggregateException(
                "Test certificate fixture creation failed and cleanup also failed.", failures);
        }
    }

    public static InstallCertificateFixtureMaterial CreateRoot(string commonName)
    {
        return Create(null, commonName, true, null, null, null, -10, 365);
    }

    public static InstallCertificateFixtureMaterial CreateIssued(
        InstallCertificateFixtureMaterial issuer,
        string commonName,
        bool certificateAuthority,
        string ekuOid,
        string dnsName,
        string ipAddress,
        int notBeforeDays,
        int notAfterDays)
    {
        if (issuer == null) throw new ArgumentNullException("issuer");
        return Create(issuer, commonName, certificateAuthority, ekuOid, dnsName, ipAddress,
            notBeforeDays, notAfterDays);
    }
}

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
