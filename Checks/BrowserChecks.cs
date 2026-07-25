using System.Text.RegularExpressions;
using Microsoft.Playwright;

namespace ProdMonitor.Checks;

/// <summary>
/// Real-browser checks. Retries absorb transient network blips so alerts stay
/// trustworthy, and using a genuine Chromium context is what lets the chat
/// launcher check pass Cloudflare's Bot Fight Mode.
/// </summary>
public static class BrowserChecks
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(20) };

    public static async Task<List<CheckResult>> RunAsync()
    {
        var results = new List<CheckResult>();

        using var playwright = await Playwright.CreateAsync();
        // Channel "chromium" runs the full Chromium in new-headless mode (not the
        // lighter chrome-headless-shell), giving a real-browser fingerprint that
        // passes Cloudflare's Bot Fight Mode, which the chat launcher check needs.
        await using var browser = await playwright.Chromium.LaunchAsync(
            new BrowserTypeLaunchOptions { Headless = true, Channel = "chromium" });
        // A realistic desktop Chrome fingerprint (no "HeadlessChrome" tell) keeps
        // Cloudflare's Bot Fight Mode from challenging the chat widget's health fetch.
        var context = await browser.NewContextAsync(new BrowserNewContextOptions
        {
            UserAgent =
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                + "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
            ViewportSize = new ViewportSize { Width = 1280, Height = 800 },
            Locale = "en-US",
        });

        foreach (var site in Targets.Sites)
        {
            results.Add(await Retry($"{site.Name} is up and renders",
                () => CheckSiteRendersAsync(context, site)));
            results.Add(await Retry($"{site.Name} og:image resolves",
                () => CheckOgImageAsync(context, site)));
        }

        results.Add(await Retry(
            "ai-chat-api is healthy (chat launcher on pedroduartek.com)",
            () => CheckChatLauncherAsync(context)));

        await context.CloseAsync();
        return results;
    }

    private static async Task<CheckResult> CheckSiteRendersAsync(
        IBrowserContext context, Targets.Site site)
    {
        var name = $"{site.Name} is up and renders";
        var page = await context.NewPageAsync();
        try
        {
            var resp = await page.GotoAsync(site.Url, new PageGotoOptions
            {
                WaitUntil = WaitUntilState.DOMContentLoaded,
                Timeout = 25_000,
            });
            if (resp is null) return new(name, false, "no response");
            if (resp.Status >= 400) return new(name, false, $"HTTP {resp.Status}");

            var title = await page.TitleAsync();
            if (string.IsNullOrWhiteSpace(title)) return new(name, false, "empty title");

            var body = await page.InnerTextAsync("body", new() { Timeout = 20_000 });
            if (!Regex.IsMatch(body, site.MustMatch, RegexOptions.IgnoreCase))
                return new(name, false, $"missing /{site.MustMatch}/i");

            return new(name, true);
        }
        catch (Exception ex) { return new(name, false, ex.Message); }
        finally { await page.CloseAsync(); }
    }

    private static async Task<CheckResult> CheckOgImageAsync(
        IBrowserContext context, Targets.Site site)
    {
        var name = $"{site.Name} og:image resolves";
        var page = await context.NewPageAsync();
        try
        {
            await page.GotoAsync(site.Url, new PageGotoOptions
            {
                WaitUntil = WaitUntilState.DOMContentLoaded,
                Timeout = 25_000,
            });

            var metas = page.Locator("meta[property='og:image']");
            if (await metas.CountAsync() == 0)
                return new(name, true, "no og:image (skipped)");

            var url = await metas.First.GetAttributeAsync("content");
            if (string.IsNullOrWhiteSpace(url))
                return new(name, true, "empty og:image (skipped)");

            using var r = await Http.GetAsync(url);
            return (int)r.StatusCode == 200
                ? new(name, true)
                : new(name, false, $"og:image HTTP {(int)r.StatusCode}");
        }
        catch (Exception ex) { return new(name, false, ex.Message); }
        finally { await page.CloseAsync(); }
    }

    private static async Task<CheckResult> CheckChatLauncherAsync(IBrowserContext context)
    {
        var name = "ai-chat-api is healthy (chat launcher on pedroduartek.com)";
        var page = await context.NewPageAsync();
        try
        {
            await page.GotoAsync(Targets.ChatSiteUrl, new PageGotoOptions
            {
                WaitUntil = WaitUntilState.DOMContentLoaded,
                Timeout = 25_000,
            });

            var launcher = page.GetByRole(AriaRole.Button,
                new PageGetByRoleOptions { Name = "Open chat" });
            await launcher.WaitForAsync(new LocatorWaitForOptions
            {
                State = WaitForSelectorState.Visible,
                Timeout = 30_000,
            });
            return new(name, true);
        }
        catch (Exception ex) { return new(name, false, ex.Message); }
        finally { await page.CloseAsync(); }
    }

    private static async Task<CheckResult> Retry(
        string name, Func<Task<CheckResult>> check, int attempts = 3)
    {
        CheckResult last = new(name, false, "not run");
        for (var i = 1; i <= attempts; i++)
        {
            last = await check();
            if (last.Ok) return last;
            if (i < attempts) await Task.Delay(2_000);
        }
        return last;
    }
}
