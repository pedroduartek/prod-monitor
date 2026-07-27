using System.Globalization;
using System.Text.Json;

namespace ProdMonitor.Checks;

/// <summary>
/// Domain registration expiry via authoritative registry RDAP (JSON over HTTPS),
/// so a forgotten renewal is caught weeks early. Only gTLDs are covered: .pt has
/// no RDAP at all and its WHOIS (whois.dns.pt) times out for datacenter/CI IPs
/// and even third-party proxies, so .pt renewals are tracked manually.
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
                var expiry = await RdapExpiryAsync(domain);
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

    private static async Task<DateTime?> RdapExpiryAsync(string domain)
    {
        // Query the authoritative registry RDAP directly. The rdap.org proxy
        // returns 403 to CI/datacenter IPs, so it is only a last-resort fallback.
        var tld = domain[(domain.LastIndexOf('.') + 1)..].ToLowerInvariant();
        var baseUrl = tld switch
        {
            "com" or "net" => $"https://rdap.verisign.com/{tld}/v1/domain/",
            "org" => "https://rdap.publicinterestregistry.org/rdap/domain/",
            _ => "https://rdap.org/domain/",
        };

        using var req = new HttpRequestMessage(HttpMethod.Get, baseUrl + domain);
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
}
