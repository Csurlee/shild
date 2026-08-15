"""Drift test for scripts/install_catalog.py -- the anti-rot mechanism for
the public installer (see that file's own module docstring for the full
reasoning: a written reminder to "keep the installer updated" has failed
repeatedly in this project's history; this makes forgetting impossible
instead of merely discouraged).

Ground truth is the REAL Limnoria registry, not a second hand-maintained
list: this test imports every catalog-covered plugin's config.py (which
is what actually calls conf.registerGlobalValue/registerChannelValue/
registerNetworkValue) and walks the resulting registry tree under
supybot.plugins.<Name>, asserting every registered leaf value is
classified Ask or Skip in the catalog. Adding a plugin's config value
without updating install_catalog.py fails this test.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "plugins"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import supybot.conf as conf  # noqa: E402
import supybot.registry as registry  # noqa: E402

import install_catalog  # noqa: E402


def _import_plugin_config(name: str) -> None:
    """Mirrors bootstrap_runtime.py's own per-plugin config imports --
    each one registers conf.supybot.plugins.<name>.* as a side effect."""
    __import__(f"{name}.config")


def _walk_registered_paths(node, prefix: str = "") -> list[str]:
    """Every registered leaf Value's path relative to `node`, plus every
    intermediate Group's own children recursively. `_children` is a
    private attribute (registry.Group.__slots__), but this is exactly
    the same structure registry.close()/getValues() already walk
    internally -- there is no public enumeration API for "everything
    registered, whether or not it was ever set", only for "everything
    that currently has a non-default value" (getValues()), which is not
    what a drift check needs.
    """
    paths = []
    for name, child in node._children.items():
        child_path = f"{prefix}{name}" if not prefix else f"{prefix}.{name}"
        if isinstance(child, registry.Value):
            paths.append(child_path)
        # Recurse regardless (a Value is also a Group, e.g. Shild.enabled
        # is itself a Value with per-channel Group children) -- but right
        # after a fresh import, nothing has set a specific override yet,
        # so this only surfaces genuinely-registered sub-values (e.g.
        # thresholds.classifierAct under the `thresholds` group), not
        # phantom network/channel overrides.
        paths.extend(_walk_registered_paths(child, child_path))
    return paths


def _plugin_root(name: str):
    return conf.supybot.plugins.get(name)


@pytest.fixture(scope="module", autouse=True)
def _import_all_catalog_plugins():
    for plugin_name in install_catalog.CATALOG:
        _import_plugin_config(plugin_name)


@pytest.mark.parametrize("plugin_name", sorted(install_catalog.CATALOG.keys()))
def test_every_registered_value_is_classified(plugin_name):
    entries = install_catalog.CATALOG[plugin_name]
    # Secret entries (Ask(..., secret=True)) deliberately have NO registry
    # path at all -- they're written to runtime/secrets.json, never the
    # Limnoria registry (same discipline every credential in this repo
    # follows, so an admin's `@config` dump can never leak one). Excluded
    # from both directions of this comparison; real registry paths only.
    classified = {e.path for e in entries if not (isinstance(e, install_catalog.Ask) and e.secret)}
    registered = set(_walk_registered_paths(_plugin_root(plugin_name)))
    # "public" is auto-registered by conf.registerPlugin() for every
    # plugin (visibility in `list`, not a deployment decision) -- not
    # something any plugin's own config.py declares, so it's excluded
    # here rather than needing a Skip entry duplicated in every plugin.
    registered.discard("public")

    unclassified = registered - classified
    assert not unclassified, (
        f"{plugin_name}: registry value(s) {sorted(unclassified)} exist but "
        f"are not classified Ask or Skip in scripts/install_catalog.py. "
        f"Add an entry for each (see that file's module docstring)."
    )

    stale = classified - registered
    assert not stale, (
        f"{plugin_name}: scripts/install_catalog.py classifies "
        f"{sorted(stale)}, which no longer exists in the registry -- "
        f"the value was removed/renamed; update the catalog to match."
    )


@pytest.mark.parametrize("plugin_name,entry", install_catalog.all_ask_entries())
def test_ask_default_matches_registry_default(plugin_name, entry):
    if entry.secret:
        pytest.skip("secret values live in runtime/secrets.json, not the registry")
    root = _plugin_root(plugin_name)
    node = root
    for part in entry.path.split("."):
        node = node.get(part)
    assert node() == entry.default, (
        f"{plugin_name}.{entry.path}: catalog default {entry.default!r} != "
        f"registry default {node()!r} -- config.py's default changed without "
        f"updating scripts/install_catalog.py's Ask entry."
    )


def test_every_plugin_directory_with_a_config_is_covered():
    plugins_dir = REPO_ROOT / "plugins"
    covered = set(install_catalog.CATALOG) | set(install_catalog.BASELINE_PLUGINS)
    on_disk = {
        p.name for p in plugins_dir.iterdir()
        if p.is_dir() and (p / "config.py").exists()
    }
    uncovered = on_disk - covered
    assert not uncovered, (
        f"plugins/ contains {sorted(uncovered)} with a config.py, but "
        f"scripts/install_catalog.py doesn't classify it as either a "
        f"cataloged plugin or a BASELINE_PLUGINS entry. A new plugin needs "
        f"catalog entries for its user-facing config (or an explicit, "
        f"reasoned addition to BASELINE_PLUGINS if it truly has none)."
    )
