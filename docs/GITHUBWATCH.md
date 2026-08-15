# GitHubWatch

Polls configured GitHub repos and announces new pushes, opened issues, and opened/merged pull
requests to a channel. Independent of Shild — no ML/threat-analysis logic, just a presentation
layer over GitHub's Events API.

## Status / prerequisites

Ships inert by default: `plugins.GitHubWatch.repos` defaults to empty, so the poll loop runs but
announces nothing until configured. Two values must both be set before anything is announced:

1. `plugins.GitHubWatch.repos` — space-separated `owner/repo` list (**global**)
2. the **network-scoped** channel value — easy to miss, since `repos` itself is global:
   ```
   @config network libera plugins.GitHubWatch.channel #yourrelay
   @config network undernet plugins.GitHubWatch.channel #yourrelay
   ```

**A private repo needs a token, not just for rate limits.** The Events API returns
`repo_not_found` (not a 403) for a private repo when unauthenticated — public repos work fine
without a token. Put a token in `secrets.json`'s `github_token` key (or the
`SHILD_GITHUB_TOKEN` env var) to watch a private repo, and to raise the rate limit from
60 to 5000 requests/hour.

Keep `repos × (3600 / pollIntervalSecs)` comfortably under 60 requests/hour unless a token is
configured.

## Commands

### `githubwatchstatus`

```
takes no arguments
```

Reports which repos are being polled, the worker thread's health, and the last poll result per
repo. Read-only. **Unlike every other plugin in this repo, this command has no capability
requirement** — any user may run it, subject only to Limnoria's standard defaults.

```
<anyone> githubwatchstatus
<Shild> GitHubWatch: worker=running pollInterval=120s | repos: Csurlee/shild=ok
```

If no repos are configured: `GitHubWatch: no repos configured (plugins.GitHubWatch.repos is
empty).`

There are no commands to change `repos`/`channel` state — those are `@config`-only.

## Configuration

| Value | Scope | Type | Default | Description |
|---|---|---|---|---|
| `plugins.GitHubWatch.repos` | global | Space-separated list | `[]` | `owner/repo` pairs to poll. Not op-settable — repointing the bot at an arbitrary repo is an admin decision. |
| `plugins.GitHubWatch.channel` | **network** | String | `""` | Channel to announce to on this network. Empty means no announcements on that network even if `repos` is set. |
| `plugins.GitHubWatch.pollIntervalSecs` | global | Positive integer | `120` | How often to poll each configured repo's events feed. |
| `plugins.GitHubWatch.announcePushes` | global | Boolean | `True` | Whether to announce new pushes. |
| `plugins.GitHubWatch.announceIssues` | global | Boolean | `True` | Whether to announce newly opened issues. |
| `plugins.GitHubWatch.announcePullRequests` | global | Boolean | `True` | Whether to announce newly opened **and** merged pull requests. |
| `plugins.GitHubWatch.maxCommitsShown` | global | Positive integer | `3` | Max individual commit messages shown per push before collapsing the rest into `(+N more)`. |
| `plugins.GitHubWatch.statePath` | global | String | `github_watch_state.json` | Persisted per-repo polling cursor (last announced event id) — survives restarts. |
| `plugins.GitHubWatch.secretsPath` | global | String | `secrets.json` | Path to the gitignored secrets file. `github_token` key (or `SHILD_GITHUB_TOKEN` env var) raises the rate limit and is required for private repos. |

> `statePath` and `secretsPath` are resolved relative to the bot's own working directory
> (`runtime/`) — never prefix them with `runtime/`.

## When changes take effect

`repos`, `channel`, `pollIntervalSecs`, `maxCommitsShown`, the three `announce*` flags, and
`secretsPath` are all re-read on every poll cycle — no reload needed. `statePath` is read once at
plugin startup and needs `@reload GitHubWatch` to change.

## Files it reads/writes

| File | Purpose |
|---|---|
| `github_watch_state.json` | Last-announced event id per repo, so nothing is re-announced or silently skipped across a restart. |
| `secrets.json` | Optional `github_token` key. |
