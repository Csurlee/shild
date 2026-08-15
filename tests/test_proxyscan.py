import asyncio

import pytest

from plugins.Shild import proxyscan
from plugins.Shild.proxyscan import ProxyScanConfig, _probe_port, scan


def test_probe_port_detects_open_listener():
    async def run():
        server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            assert await _probe_port("127.0.0.1", port, timeout=2.0) is True
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run())


def test_probe_port_reports_closed_port_as_false():
    async def run():
        # Port 1 is a reserved/unlikely-to-be-listening port on loopback.
        assert await _probe_port("127.0.0.1", 1, timeout=1.0) is False

    asyncio.run(run())


def test_scan_reports_clean_when_all_probes_negative(monkeypatch):
    async def fake_probe(host, port, timeout):
        return False

    monkeypatch.setattr(proxyscan, "_probe_port", fake_probe)

    async def run():
        return await scan("127.0.0.1", ProxyScanConfig())

    assert asyncio.run(run()) == []


def test_scan_reports_open_ports_sorted(monkeypatch):
    async def fake_probe(host, port, timeout):
        return port in (8080, 1080)

    monkeypatch.setattr(proxyscan, "_probe_port", fake_probe)

    async def run():
        return await scan("127.0.0.1", ProxyScanConfig())

    assert asyncio.run(run()) == [1080, 8080]


def test_scan_timeout_returns_empty_not_a_false_clean_claim(monkeypatch):
    """An inconclusive (timed-out) scan must return [] as a neutral 'not
    scanned successfully', distinguishable upstream from checks_run
    including 'proxyscan' with an empty open_proxy_ports list -- see
    plugin.py wiring, which only marks the check as run on a real result.
    """
    async def slow_probe(host, port, timeout):
        await asyncio.sleep(10)
        return False

    monkeypatch.setattr(proxyscan, "_probe_port", slow_probe)

    async def run():
        return await scan("127.0.0.1", ProxyScanConfig(overall_timeout=0.05))

    assert asyncio.run(run()) == []
