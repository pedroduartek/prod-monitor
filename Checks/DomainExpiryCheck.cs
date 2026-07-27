using System.Globalization;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ProdMonitor.Checks;

/// <summary>
/// Domain registration expiry, so a forgotten renewal is caught weeks early.
/// .com and other gTLDs are read over RDAP (JSON/HTTPS); .pt has no public RDAP,
/// so it is read from the DNS.PT WHOIS server over TCP 43.
/// </summary>
public static class DomainExpiryCheck
{
    private const int WarnDays = 30;
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(20) };

    public static async Task<List<CheckResult>> RunAsync(string[] domains)
    {
        var results = new List<CheckResult>();
        foreach (var domain in domains)
        {
            var name = $"Domain {domain} registration is valid for {WarnDays}+ days";
            try
            {
                var expiry = domain.EndsWith(".pt", StringComparison.OrdinalIgnoreCase)
                    ? await PtWhoisExpiryAsync(domain)
                    : await RdapExpiryAsync(domain);

                if (expiry is null)
                {
                    results.Add(new(name, false, "could not determine expiry date"));
                    continue;
                }

                var daysLeft = (expiry.Value.ToUniversalTime() - DateTime.UtcNow).TotalDays;
                var stamp = expiry.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
                results.Add(daysLeft > WarnDays
                    ? new(name, true, $"{daysLeft:F0}d left (expires {stamp})")
                    : new(name, false, $"expires in {daysLeft:F0}d ({stamp})"));
            }
            catch (Exception ex)
            {
                results.Add(new(name, false, ex.Message));
            }
        }
        return results;
    }

    // gTLDs (.com, ...): RDAP JSON over HTTPS. rdap.org bootstraps to the registry.
    private static async Task<DateTime?> RdapExpiryAsync(string domain)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, $"https://rdap.org/domain/{domain}");
        req.Headers.Add("Accept", "application/rdap+json");
        using var resp = await Http.SendAsync(req);
        resp.EnsureSuccessStatusCode();

        await using var stream = await resp.Content.ReadAsStreamAsync();
        using var doc = await JsonDocument.ParseAsync(stream);
        if (!doc.RootElement.TryGetProperty("events", out var events)) return null;

        foreach (var e in events.EnumerateArray())
        {
            if (e.TryGetProperty("eventAction", out var action)
                && action.GetString() == "expiration"
                && e.TryGetProperty("eventDate", out var date)
                && DateTime.TryParse(date.GetString(), CultureInfo.InvariantCulture,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var parsed))
            {
                return parsed;
            }
        }
        return null;
    }

    // .pt: DNS.PT WHOIS over TCP 43. Line format: "Expiration Date: DD/MM/YYYY HH:MM:SS".
    private static async Task<DateTime?> PtWhoisExpiryAsync(string domain)
    {
        // The DNS.PT WHOIS server returns the record but may keep the connection
        // open (no EOF), so read with a hard timeout and stop as soon as the
        // expiry line arrives instead of waiting for the stream to close.
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(12));
        using var client = new TcpClient();
        await client.ConnectAsync("whois.dns.pt", 43, cts.Token);

        var stream = client.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes(domain + "\r\n"), cts.Token);

        var sb = new StringBuilder();
        var buffer = new byte[4096];
        try
        {
            int read;
            while ((read = await stream.ReadAsync(buffer, cts.Token)) > 0)
            {
                sb.Append(Encoding.UTF8.GetString(buffer, 0, read));
                if (sb.ToString().Contains("Expiration Date", StringComparison.Ordinal))
                    break;
            }
        }
        catch (OperationCanceledException)
        {
            // Timed out waiting for more data; parse whatever arrived.
        }

        var m = Regex.Match(sb.ToString(), @"Expiration Date:\s*(\d{2})/(\d{2})/(\d{4})");
        if (!m.Success) return null;

        return new DateTime(
            int.Parse(m.Groups[3].Value), // year
            int.Parse(m.Groups[2].Value), // month
            int.Parse(m.Groups[1].Value), // day
            0, 0, 0, DateTimeKind.Utc);
    }
}
