"""Config registry for GitHubWatch.

`repos` and `channel` are opSettable=False, same discipline as Shild's
own config: a channel op should never be able to repoint the bot at an
arbitrary repo or make it start posting into a different channel --
that's a deliberate admin decision, not something to flip on a whim.
"""
from __future__ import annotations

from supybot import conf, registry

try:
    from supybot.i18n import PluginInternationalization
    _ = PluginInternationalization("GitHubWatch")
except ImportError:
    _ = lambda x: x  # noqa: E731


def configure(advanced):
    conf.registerPlugin("GitHubWatch", True)


GitHubWatch = conf.registerPlugin("GitHubWatch")

conf.registerGlobalValue(
    GitHubWatch, "repos",
    registry.SpaceSeparatedListOfStrings([], _(
        """Space-separated "owner/repo" list to poll for new pushes/issues/
        pull requests. Empty by default -- inert until configured.""")),
)

# Network-specific, same reasoning as Shild's relayChannel: a repo
# announcement made for one network's bot instance must never leak to a
# channel on a different network by accident. Global (not per-channel),
# so there's no channel-op-vs-admin distinction to make -- only
# registerChannelValue takes opSettable.
conf.registerNetworkValue(
    GitHubWatch, "channel",
    registry.String("", _(
        """Channel to announce new pushes/issues/pull requests to. Empty
        means no announcements on this network even if "repos" is set.""")),
)

conf.registerGlobalValue(
    GitHubWatch, "pollIntervalSecs",
    registry.PositiveInteger(120, _(
        """How often (seconds) to poll each configured repo's events feed.
        GitHub's unauthenticated rate limit is 60 requests/hour/IP -- one
        request per repo per poll, so keep repos * (3600 / this) comfortably
        under 60 unless "secretsPath" provides a token (5000/hour
        authenticated).""")),
)

conf.registerGlobalValue(
    GitHubWatch, "announcePushes",
    registry.Boolean(True, _("""Whether to announce new pushes.""")),
)
conf.registerGlobalValue(
    GitHubWatch, "announceIssues",
    registry.Boolean(True, _("""Whether to announce newly opened issues.""")),
)
conf.registerGlobalValue(
    GitHubWatch, "announcePullRequests",
    registry.Boolean(True, _(
        """Whether to announce newly opened and merged pull requests.""")),
)

conf.registerGlobalValue(
    GitHubWatch, "maxCommitsShown",
    registry.PositiveInteger(3, _(
        """Maximum individual commit messages summarized in a single push
        announcement before collapsing the rest into "(+N more)".""")),
)

conf.registerGlobalValue(
    GitHubWatch, "statePath",
    registry.String("github_watch_state.json", _(
        """Path to the persisted per-repo polling cursor (last announced
        event id) -- survives restarts so nothing gets re-announced or
        silently skipped. Resolved relative to the bot's own working
        directory (runtime/) -- found 2026-08-10 defaulting to
        "runtime/github_watch_state.json", the identical mistake already
        fixed once for Shild.secretsPath, which silently wrote into a
        nested runtime/runtime/ instead. Fixed at the source; the live
        conf value still needs a one-time manual correction -- see
        CLAUDE.md.""")),
)

conf.registerGlobalValue(
    GitHubWatch, "secretsPath",
    registry.String("secrets.json", _(
        """Path to the gitignored local secrets file, resolved relative to
        the bot's own working directory (runtime/, since it's started via
        `cd runtime && supybot shildpy.conf`) -- NOT relative to the repo
        root, so this must be "secrets.json", not "runtime/secrets.json"
        (that was a real bug, shared with Shild.secretsPath's identical
        mistake, fixed 2026-08-02: the file silently never loaded, which
        fails open/looks like "no key configured" rather than erroring,
        so it went unnoticed). A "github_token" key (or the
        SHILD_GITHUB_TOKEN env var, which takes precedence) raises the
        GitHub API rate limit from 60 to 5000 requests/hour, AND is
        required (not just rate-limit-optional) to watch a PRIVATE repo at
        all -- confirmed live 2026-08-02: the Events API returns
        repo_not_found for a private repo when unauthenticated, not a
        403/rate-limit error. Public repos work fine without a token.""")),
)
