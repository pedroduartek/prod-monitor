using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ProdMonitor.Checks;

/// <summary>
/// Domain registration expiry, so a forgotten renewal is caught weeks early.
/// gTLDs (.com, ...) use the free authoritative registry RDAP over HTTPS. .pt has
/// no RDAP and its WHOIS blocks datacenter/CI IPs, so .pt goes through the
/// WhoisXML API (WHOISXML_API_KEY), which maintains its own WHOIS access.
/// </summary>
public static class DomainExpiryCheck
{
    private const int WarnDays = 30;
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(25) };

    public static async Task<List<CheckResult>> RunAsync(string[] domains)
    {
        var results = new List<CheckResult>();
        foreach (var domain in domains)
        {
            var name = $"Domain {domain} registration is valid for {WarnDays}+ days";
            try
            {
                var expiry = domain.EndsWith(".pt", StringComparison.OrdinalIgnoreCase)
                    ? await WhoisXmlExpiryAsync(domain)
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

    // gTLDs: authoritative registry RDAP. The rdap.org proxy 403s CI/datacenter
    // IPs, so hit the registry directly.
    private static async Task<DateTime?> RdapExpiryAsync(string domain)
    {
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
                && e.TryGetProperty("eventDate", out var date))
            {
                return ParseExpiry(date.GetString());
            }
        }
        return null;
    }

    // .pt (and any TLD without usable RDAP): WhoisXML API over HTTPS.
    private static async Task<DateTime?> WhoisXmlExpiryAsync(string domain)
    {
        var key = Environment.GetEnvironmentVariable("WHOISXML_API_KEY")
            ?? throw new InvalidOperationException("WHOISXML_API_KEY is not set");

        var url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
            + $"?apiKey={Uri.EscapeDataString(key)}&outputFormat=JSON&domainName={Uri.EscapeDataString(domain)}";

        using var resp = await Http.GetAsync(url);
        resp.EnsureSuccessStatusCode();

        await using var stream = await resp.Content.ReadAsStreamAsync();
        using var doc = await JsonDocument.ParseAsync(stream);
        if (!doc.RootElement.TryGetProperty("WhoisRecord", out var record)) return null;

        // Prefer the top-level expiry; fall back to the registry sub-record.
        var raw = ReadString(record, "expiresDate")
            ?? (record.TryGetProperty("registryData", out var reg) ? ReadString(reg, "expiresDate") : null);
        return ParseExpiry(raw);
    }

    private static string? ReadString(JsonElement obj, string prop) =>
        obj.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    // Handles both ISO 8601 (gTLD/.com) and the .pt native "DD/MM/YYYY HH:MM:SS".
    private static DateTime? ParseExpiry(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;

        // .pt uses slashes and is day-first, so parse it explicitly to avoid
        // month/day ambiguity; ISO strings have no slashes and skip this.
        var m = Regex.Match(raw, @"(\d{2})/(\d{2})/(\d{4})");
        if (m.Success)
        {
            return new DateTime(
                int.Parse(m.Groups[3].Value),
                int.Parse(m.Groups[2].Value),
                int.Parse(m.Groups[1].Value),
                0, 0, 0, DateTimeKind.Utc);
        }

        return DateTime.TryParse(raw, CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var iso)
            ? iso
            : null;
    }
}
