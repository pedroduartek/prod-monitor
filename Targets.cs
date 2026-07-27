namespace ProdMonitor;

/// <summary>
/// Production targets checked every day. Keep the <c>MustMatch</c> anchors to
/// words that are effectively permanent, so copy changes never trigger false
/// alarms.
/// </summary>
public static class Targets
{
    public sealed record Site(string Name, string Url, string MustMatch);

    public static readonly Site[] Sites =
    [
        new("DUARTEK", "https://www.duartek.pt/", "casa"),
        new("Ourivesaria Rinchoa", "https://www.ourivesariarinchoa.pt/", "ourivesaria"),
        new("pedroduartek.com", "https://pedroduartek.com/", "pedro"),
    ];

    public static readonly string[] TlsHosts =
    [
        "www.duartek.pt",
        "www.ourivesariarinchoa.pt",
        "pedroduartek.com",
        "api.pedroduartek.com",
    ];

    // The ai-chat-api is checked indirectly via this site's chat launcher, which
    // only mounts once the browser reaches the API health endpoint. This sidesteps
    // Cloudflare's Bot Fight Mode, which challenges direct requests from CI IPs.
    public const string ChatSiteUrl = "https://pedroduartek.com/";

    // Domain registration expiry, distinct from the TLS cert check. gTLDs use
    // free authoritative RDAP; .pt goes through the WhoisXML API (see the check,
    // since .pt has no RDAP and its WHOIS blocks datacenter/CI access).
    public static readonly string[] Domains =
    [
        "pedroduartek.pt",
        "pedroduartek.com",
        "duartek.pt",
        "ourivesariarinchoa.pt",
    ];
}
