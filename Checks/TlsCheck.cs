using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace ProdMonitor.Checks;

/// <summary>
/// Reads each host's TLS certificate over a raw connection and fails if it is
/// within two weeks of expiry, turning a silent outage into an early warning.
/// </summary>
public static class TlsCheck
{
    public static async Task<List<CheckResult>> RunAsync(string[] hosts)
    {
        var results = new List<CheckResult>();
        foreach (var host in hosts)
        {
            var name = $"TLS certificate for {host} is valid for 14+ days";
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(host, 443).WaitAsync(TimeSpan.FromSeconds(15));

                await using var ssl = new SslStream(
                    client.GetStream(), leaveInnerStreamOpen: false,
                    userCertificateValidationCallback: (_, _, _, _) => true);
                await ssl.AuthenticateAsClientAsync(host);

                var cert = ssl.RemoteCertificate as X509Certificate2
                           ?? new X509Certificate2(ssl.RemoteCertificate!);
                var daysLeft = (cert.NotAfter.ToUniversalTime() - DateTime.UtcNow).TotalDays;

                results.Add(daysLeft > 14
                    ? new(name, true, $"{daysLeft:F0}d left")
                    : new(name, false, $"expires in {daysLeft:F0}d"));
            }
            catch (Exception ex)
            {
                results.Add(new(name, false, ex.Message));
            }
        }
        return results;
    }
}
