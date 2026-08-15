# shild

An IRC channel guardian bot for Limnoria: an ML classifier + real host
reputation evidence (DNSBL, AbuseIPDB, Scamalytics) for join/message
analysis, plus a deterministic spam-template kick+ban plugin (SpamGuard),
a read-only web dashboard, weather, and GitHub push/issue/PR announcements.
No classifier model ships -- train your own from your own shadow-mode data
once you have some (see docs/SHILD.md).

## Install

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Csurlee/shild/main/install.sh)"
```

See [`docs/INSTALL.md`](docs/INSTALL.md) for what this does, what it asks,
and the manual steps (registering the bot with IRC services, getting it
opped) it can't do for you.

## Plugin reference

- [`docs/SHILD.md`](docs/SHILD.md) -- the classifier + evidence gate + enforcement
- [`docs/SPAMGUARD.md`](docs/SPAMGUARD.md) -- deterministic content-match kick+ban
- [`docs/WEBPANEL.md`](docs/WEBPANEL.md) -- the read-only LAN web dashboard
- [`docs/GITHUBWATCH.md`](docs/GITHUBWATCH.md) -- GitHub push/issue/PR announcements
- [`docs/WEATHER.md`](docs/WEATHER.md) -- current conditions, forecast, air quality
- [`docs/UNDERNETX.md`](docs/UNDERNETX.md) -- X login, manual X moderation commands

## Version

1.2 -- see [`CHANGELOG.md`](CHANGELOG.md).

## License

MIT -- see [LICENSE](LICENSE).
