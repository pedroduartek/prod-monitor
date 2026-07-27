# prod-monitor

Daily synthetic monitoring for the production apps, with email reports. A small
.NET 10 console app that GitHub Actions runs on a cron.

## What it checks (every day at ~07:00 Lisbon)

- **Sites** (`www.duartek.pt`, `www.ourivesariarinchoa.pt`, `pedroduartek.com`):
  the page loads (HTTP < 400) in a real browser, has a title, actually renders
  content, and its `og:image` resolves.
- **ai-chat-api**: checked indirectly on `pedroduartek.com`, where the chat
  launcher only appears once the browser reaches the API health endpoint
  (Cloudflare's Bot Fight Mode blocks direct requests from CI/datacenter IPs).
- **TLS**: every host's certificate is valid for at least 14 more days.
- **Domain registration**: `pedroduartek.com` is registered for at least 30 more
  days (authoritative registry RDAP over HTTPS). `.pt` domains are not checked
  here: `.pt` has no RDAP and its WHOIS blocks datacenter/CI access, so their
  renewal is tracked manually.

Browser checks use [Playwright for .NET](https://playwright.dev/dotnet/); the
TLS check uses a raw `SslStream`.

## Email logic

- **Any failure → email immediately** (that run), and the process exits non-zero
  so the CI run is marked red.
- **All passing → email only once a week** (Monday).
- A manual run (`workflow_dispatch`) can force the digest with the `force_email`
  input.

Delivery uses Brevo SMTP via MailKit, reusing the same account as `ai-chat-api`.

## Run locally

```bash
dotnet build -c Release
pwsh bin/Release/net10.0/playwright.ps1 install --with-deps chromium
# provide SMTP_* / MAIL_* env vars (FORCE_EMAIL=1 to always send)
dotnet run -c Release --no-build
```

## Required GitHub Actions secrets

`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `BREVO_SMTP_KEY`, `MAIL_FROM`, `MAIL_TO`.
