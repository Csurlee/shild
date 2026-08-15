"""Active open-proxy port probe -- the Tier 3 evidence check.

Modeled on what HOPM/BOPM (the standard IRC-network proxy scanners; see
docs/DOCUMENTATION.md for the research) do: connect back to a joining
host on the classic open-proxy ports and see if anything answers. A
confirmed open proxy corroborates a ban; a clean scan is real evidence
*against* "this is a drone", which is exactly the false-positive case
this whole phase exists to address.

**Ships disabled by default** (plugins/Shild/config.py:
proxyscan.enabled=False) per user decision: this is qualitatively
different from every other check here, because it actively opens a
connection to a third party's machine rather than passively querying a
public list about them. It's also largely redundant on Libera, which
already runs its own connect-time proxy scan (the "ozone"/ex-BOPM
lineage referenced during planning) before a client is even allowed to
connect. It exists here for completeness, for Undernet (which has no
equivalent), and for a network operator who wants it.

Never called for a trusted cloak or an unresolvable host -- same rule as
Tier 1/2 in reputation.py, enforced by the caller (plugin.py), not
re-checked here.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

# Classic open-proxy ports (SOCKS4/5, HTTP CONNECT, WinGate). A bare TCP
# connect is enough signal for evidence purposes -- we are not attempting
# to actually drive a proxy handshake and loop back through it (what
# HOPM/BOPM do to *confirm* an open relay), just checking whether
# something is listening on a port that legitimate residential/office
# connections essentially never have open. That keeps this simple, fast,
# and unable to be mistaken for actually using the proxy.
PROXY_PORTS = (1080, 3128, 8080, 8118, 23)


@dataclass
class ProxyScanConfig:
    enabled: bool = False
    connect_timeout: float = 2.0
    overall_timeout: float = 6.0
    max_concurrent_ports: int = 5


async def _probe_port(host: str, port: int, timeout: float) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout,
        )
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True


async def scan(ip: str, config: ProxyScanConfig) -> list[int]:
    """Returns the list of PROXY_PORTS found open, or [] if the whole scan
    ran clean. Bounded by `overall_timeout` regardless of how many ports
    are configured, so a flood of joins can never pile up slow scans.
    """
    sem = asyncio.Semaphore(config.max_concurrent_ports)

    async def bounded(port: int) -> tuple[int, bool]:
        async with sem:
            return port, await _probe_port(ip, port, config.connect_timeout)

    try:
        results = await asyncio.wait_for(
            asyncio.gather(*(bounded(p) for p in PROXY_PORTS)),
            timeout=config.overall_timeout,
        )
    except asyncio.TimeoutError:
        return []  # inconclusive scan is not evidence of anything -- see evidence.py
    return sorted(port for port, is_open in results if is_open)
