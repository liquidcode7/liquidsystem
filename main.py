"""pihole-audit — entry point."""

from __future__ import annotations

import asyncio

from rich.console import Console
from rich.table import Table

import traffic
from client import PiholeClient

console = Console()


async def _run() -> None:
    async with PiholeClient() as client:
        console.print("[bold cyan]pihole-audit[/] — fetching traffic data…")
        data = await traffic.fetch(client)

    # Summary
    s = data.summary
    console.print(f"\n[bold]Traffic Summary[/]")
    console.print(f"  Total queries  : {s.total:,}")
    console.print(f"  Blocked        : {s.blocked:,}  ({s.percent_blocked:.1f}%)")
    console.print(f"  Allowed        : {s.allowed:,}")
    console.print(f"  Cached         : {s.cached:,}")
    console.print(f"  Forwarded      : {s.forwarded:,}")
    console.print(f"  Unique domains : {s.unique_domains:,}")
    console.print(f"  Active clients : {s.active_clients} / {s.total_clients} total")
    console.print(f"  Gravity list   : {s.gravity_domains:,} domains blocked")

    # Top allowed domains
    _print_table(
        "Top Allowed Domains",
        ["Domain", "Queries"],
        [(d.domain, str(d.count)) for d in data.top_allowed[:15]],
    )

    # Top blocked domains
    _print_table(
        "Top Blocked Domains",
        ["Domain", "Queries"],
        [(d.domain, str(d.count)) for d in data.top_blocked[:15]],
    )

    # Top clients
    _print_table(
        "Top Clients",
        ["IP", "Name", "Queries"],
        [(c.client, c.name, str(c.count)) for c in data.top_clients[:15]],
    )


def _print_table(title: str, headers: list[str], rows: list[tuple[str, ...]]) -> None:
    t = Table(title=title, show_lines=False)
    for h in headers:
        t.add_column(h)
    for row in rows:
        t.add_row(*row)
    console.print()
    console.print(t)


def main() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    main()
