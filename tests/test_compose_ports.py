"""Every port the test stack publishes is bound to loopback (#867).

Tier 0: reads `test/compose.yaml` and opens no socket.

The stack's credentials are in the repository: the Vault dev root token and the
Oracle and PostgreSQL passwords. A port published without a host address
listens on every interface, so anyone on the same network could log in as Vault
root or SYS. A new service, or an edit that drops the host address, would do
that again without any test noticing. This test is the one that notices.

Each port is published on `127.0.0.1` and on `::1`. `localhost` resolves to
`::1` first on Windows, and with the IPv4 binding alone every connection to it
waited about two seconds before it fell back.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

COMPOSE = Path(__file__).resolve().parents[1] / "test" / "compose.yaml"

IPV4 = "127.0.0.1:"
IPV6 = "[::1]:"


def _ports() -> dict[str, list[str]]:
    """Each service that publishes ports, with its port entries as written."""
    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    return {
        name: [str(port) for port in service["ports"]]
        for name, service in document["services"].items()
        if "ports" in service
    }


def test_the_stack_publishes_ports() -> None:
    """Guards the tests below against passing on an empty list."""
    assert _ports()


@pytest.mark.parametrize("service", sorted(_ports()))
def test_every_port_is_published_on_loopback_only(service: str) -> None:
    for port in _ports()[service]:
        assert port.startswith((IPV4, IPV6)), (
            f"{service} publishes {port!r} on every interface; bind it to 127.0.0.1 and [::1]"
        )


@pytest.mark.parametrize("service", sorted(_ports()))
def test_every_port_is_published_on_both_loopback_addresses(service: str) -> None:
    ports = _ports()[service]
    on_ipv4 = {port.removeprefix(IPV4) for port in ports if port.startswith(IPV4)}
    on_ipv6 = {port.removeprefix(IPV6) for port in ports if port.startswith(IPV6)}

    assert on_ipv4 == on_ipv6, f"{service} must publish the same ports on both: {ports}"
