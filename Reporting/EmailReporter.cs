using System.Net;
using System.Text;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace ProdMonitor.Reporting;

/// <summary>
/// Sends the run report via Brevo SMTP. Rule: on ANY failure email immediately;
/// if all pass, email only once a week (Monday). Manual runs can force the email
/// with FORCE_EMAIL=1.
/// </summary>
public sealed class EmailReporter
{
    private const DayOfWeek WeeklyDay = DayOfWeek.Monday;

    public async Task<int> ReportAsync(IReadOnlyList<CheckResult> results)
    {
        var failed = results.Count(r => !r.Ok);
        var anyFail = failed > 0;
        var force = Environment.GetEnvironmentVariable("FORCE_EMAIL") is "1" or "true";
        var isWeeklyDay = DateTime.UtcNow.DayOfWeek == WeeklyDay;

        string? subject = anyFail
            ? $"\U0001F534 Production monitor: {failed} check(s) failing"
            : isWeeklyDay || force
                ? "\U0001F7E2 Weekly production monitor: all checks passing"
                : null;

        Console.WriteLine(
            $"checks={results.Count} failed={failed} weeklyDay={isWeeklyDay} force={force} -> "
            + (subject is null ? "no email" : $"sending \"{subject}\""));

        if (subject is not null)
            await SendAsync(subject, BuildHtml(subject, results, failed));

        return anyFail ? 1 : 0;
    }

    private static async Task SendAsync(string subject, string html)
    {
        var host = Require("SMTP_HOST");
        var port = int.Parse(Optional("SMTP_PORT") ?? "587");
        var user = Require("SMTP_USER");
        var key = Require("SMTP_KEY");
        var from = Require("MAIL_FROM");
        var to = Require("MAIL_TO");

        var message = new MimeMessage();
        message.From.Add(MailboxAddress.Parse(from));
        message.To.Add(MailboxAddress.Parse(to));
        message.Subject = subject;
        message.Body = new BodyBuilder { HtmlBody = html }.ToMessageBody();

        using var smtp = new SmtpClient();
        await smtp.ConnectAsync(host, port, SecureSocketOptions.StartTls);
        await smtp.AuthenticateAsync(user, key);
        await smtp.SendAsync(message);
        await smtp.DisconnectAsync(quit: true);

        Console.WriteLine($"email sent: \"{subject}\" -> {to}");
    }

    private static string BuildHtml(
        string subject, IReadOnlyList<CheckResult> results, int failed)
    {
        var rows = new StringBuilder();
        foreach (var r in results)
        {
            var icon = r.Ok ? "✅" : "❌";
            var detail = r.Detail is null
                ? ""
                : $" <span style=\"color:#888\">({WebUtility.HtmlEncode(r.Detail)})</span>";
            rows.Append(
                $"<tr><td style=\"padding:4px 10px\">{icon}</td>"
                + $"<td style=\"padding:4px 10px\">{WebUtility.HtmlEncode(r.Name)}{detail}</td></tr>");
        }

        var passed = results.Count - failed;
        return $"""
            <h2>{WebUtility.HtmlEncode(subject)}</h2>
            <p>{passed}/{results.Count} checks passed &middot; {DateTime.UtcNow:yyyy-MM-ddTHH:mm:ssZ}</p>
            <table style="border-collapse:collapse;font-family:system-ui,Arial,sans-serif;font-size:14px">{rows}</table>
            <p style="color:#888;font-size:12px">Automated report from the prod-monitor repository.</p>
            """;
    }

    private static string? Optional(string name) => Environment.GetEnvironmentVariable(name);

    private static string Require(string name) =>
        Environment.GetEnvironmentVariable(name)
        ?? throw new InvalidOperationException($"Missing required environment variable {name}");
}
