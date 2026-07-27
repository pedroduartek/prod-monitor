using System.Text;
using ProdMonitor;
using ProdMonitor.Checks;
using ProdMonitor.Reporting;

// Emojis in the console output render correctly on every platform.
Console.OutputEncoding = Encoding.UTF8;

var results = new List<CheckResult>();

// Browser-based checks (Playwright): sites render, og:image, chat launcher.
results.AddRange(await BrowserChecks.RunAsync());

// TLS certificate expiry.
results.AddRange(await TlsCheck.RunAsync(Targets.TlsHosts));

// Domain registration expiry (WHOIS/RDAP).
results.AddRange(await DomainExpiryCheck.RunAsync(Targets.Domains));

foreach (var r in results)
{
    var status = r.Ok ? "PASS" : "FAIL";
    var detail = r.Detail is null ? "" : $"  ({r.Detail})";
    Console.WriteLine($"{status}  {r.Name}{detail}");
}

// Emails on failure immediately, otherwise only weekly; returns the exit code
// (non-zero when any check failed, so the CI run is marked red).
var reporter = new EmailReporter();
return await reporter.ReportAsync(results);
