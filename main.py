#!/usr/bin/env python3
"""
IP Address Information Finder
=============================
CLI tool for IP / hostname reconnaissance:

  * Target parsing (IPv4, IPv6, hostname w/ DNS resolution, or your own public IP)
  * Geolocation + ASN/ISP + proxy/hosting indicators (ip-api.com)
  * Reverse DNS (PTR) lookup
  * Local network interface listing
  * Rich terminal output, JSON/CSV export, interactive mode

Only use against targets you are authorised to investigate.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

try:
    import requests  # type: ignore[import-not-found]
    from rich import box
    from rich.console import Console, Group
    from rich.markup import escape
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table
    from rich.text import Text
except ImportError as exc:  # pragma: no cover
    sys.exit(f"Missing dependency ({exc.name}). Run: pip install -r requirements.txt")

try:
    import psutil  # type: ignore[import-not-found]  # optional, richer interface data
except ImportError:  # pragma: no cover
    psutil = None

__version__ = "1.0.0"

console = Console(emoji=False)  # emoji=False: MAC addresses like ':ab:' must not become emoji
err_console = Console(stderr=True, emoji=False)

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
FREE_ENDPOINT = "http://ip-api.com/json/{query}"          # free tier: HTTP only
PRO_ENDPOINT = "https://pro.ip-api.com/json/{query}"      # requires API key (HTTPS)
API_FIELDS = ",".join([
    "status", "message", "query", "continent", "continentCode", "country",
    "countryCode", "regionName", "city", "district", "zip", "lat", "lon",
    "timezone", "offset", "currency", "isp", "org", "as", "asname",
    "mobile", "proxy", "hosting",
])
USER_AGENT = f"ip-address-info-finder/{__version__}"
HOST_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
RFC1918_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
ULA_NET = ipaddress.ip_network("fc00::/7")


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #
class InvalidTargetError(ValueError):
    """Target is neither a valid IP nor a valid hostname."""


class ResolutionError(RuntimeError):
    """Hostname could not be resolved."""


class ApiError(RuntimeError):
    """Geolocation API error (network, HTTP, or API-reported failure)."""


class RateLimitError(ApiError):
    def __init__(self, ttl: int | None):
        self.ttl = ttl
        msg = "ip-api.com rate limit reached (HTTP 429)."
        if ttl is not None:
            msg += f" Retry in about {ttl}s."
        super().__init__(msg)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def run_with_timeout(fn, timeout: float, *args):
    """Run a blocking call (e.g. DNS) in a daemon thread with a hard timeout."""
    box: dict[str, Any] = {}

    def worker() -> None:
        try:
            box["value"] = fn(*args)
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            box["error"] = exc

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise TimeoutError(f"operation timed out after {timeout:g}s")
    if "error" in box:
        raise box["error"]
    return box["value"]


def flatten(data: dict[str, Any], parent: str = "") -> dict[str, Any]:
    """Flatten nested dicts to dotted keys (for CSV)."""
    out: dict[str, Any] = {}
    for key, value in data.items():
        name = f"{parent}.{key}" if parent else key
        if isinstance(value, dict):
            out.update(flatten(value, name))
        elif isinstance(value, (list, tuple)):
            out[name] = "; ".join(str(v) for v in value)
        else:
            out[name] = value
    return out


# --------------------------------------------------------------------------- #
# Target parsing / validation
# --------------------------------------------------------------------------- #
def classify_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[str, bool]:
    """Return (human-readable category, is_public_routable)."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_unspecified:
        return "Unspecified address", False
    if ip.is_loopback:
        return "Loopback", False
    if ip.is_link_local:
        return "Link-local", False
    if ip.is_multicast:
        return "Multicast", False
    if isinstance(ip, ipaddress.IPv4Address):
        if any(ip in net for net in RFC1918_NETS):
            return "Private (RFC 1918)", False
        if ip in CGNAT_NET:
            return "Carrier-grade NAT (RFC 6598)", False
    elif ip in ULA_NET:
        return "Unique local (RFC 4193)", False
    if ip.is_global:
        return "Public (globally routable)", True
    if ip.is_reserved or ip.is_private:
        return "Reserved / special-use", False
    return "Non-routable", False


def parse_target(raw: str) -> tuple[str, str]:
    """
    Validate and sanitise user input.
    Returns (kind, normalised_value) where kind is 'ip' or 'hostname'.
    """
    value = (raw or "").strip()
    if not value:
        raise InvalidTargetError("empty target")
    if any(ch.isspace() or ord(ch) < 32 for ch in value):
        raise InvalidTargetError("target contains whitespace or control characters")

    # Accept URLs by extracting the host part (http://example.com/path -> example.com)
    if "://" in value:
        host = urlparse(value).hostname
        if not host:
            raise InvalidTargetError("could not extract a host from the URL")
        value = host
    value = value.strip("[]").rstrip(".")

    try:
        return "ip", str(ipaddress.ip_address(value))
    except ValueError:
        pass

    try:
        ascii_host = value.encode("idna").decode("ascii")
    except UnicodeError:
        raise InvalidTargetError("invalid internationalised hostname") from None
    if len(ascii_host) > 253:
        raise InvalidTargetError("hostname longer than 253 characters")
    labels = ascii_host.split(".")
    if not all(HOST_LABEL_RE.match(label) for label in labels):
        raise InvalidTargetError("not a valid IP address or hostname")
    if labels[-1].isdigit():
        raise InvalidTargetError("not a valid IP address (malformed numeric host)")
    return "hostname", ascii_host.lower()


def resolve_hostname(host: str, timeout: float) -> list[str]:
    """Resolve host to unique IPs (IPv4 first)."""
    try:
        infos = run_with_timeout(socket.getaddrinfo, timeout, host, None, 0, socket.SOCK_STREAM)
    except TimeoutError:
        raise ResolutionError(f"DNS resolution for '{host}' timed out") from None
    except socket.gaierror as exc:
        raise ResolutionError(f"could not resolve '{host}': {exc.strerror or exc}") from None
    seen: list[str] = []
    for info in infos:
        addr = info[4][0].split("%")[0]
        if addr not in seen:
            seen.append(addr)
    seen.sort(key=lambda a: ipaddress.ip_address(a).version)
    if not seen:
        raise ResolutionError(f"no addresses found for '{host}'")
    return seen


def reverse_dns(ip: str, timeout: float) -> dict[str, Any]:
    """PTR lookup via socket.gethostbyaddr."""
    try:
        name, aliases, _ = run_with_timeout(socket.gethostbyaddr, timeout, ip)
        return {"hostname": name, "aliases": aliases, "error": None}
    except TimeoutError:
        return {"hostname": None, "aliases": [], "error": "lookup timed out"}
    except (socket.herror, socket.gaierror):
        return {"hostname": None, "aliases": [], "error": "no PTR record found"}
    except OSError as exc:
        return {"hostname": None, "aliases": [], "error": str(exc)}


# --------------------------------------------------------------------------- #
# Geolocation client (ip-api.com)
# --------------------------------------------------------------------------- #
class IpApiClient:
    """Thin ip-api.com client honouring the documented X-Rl / X-Ttl headers."""

    def __init__(self, timeout: float = 8.0, api_key: str | None = None,
                 wait_on_limit: bool = True, retries: int = 2):
        self.timeout = timeout
        self.api_key = api_key
        self.wait_on_limit = wait_on_limit
        self.retries = retries
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self._remaining: int | None = None
        self._reset_at = 0.0

    def _url(self, query: str | None) -> str:
        template = PRO_ENDPOINT if self.api_key else FREE_ENDPOINT
        return template.format(query=query or "")

    def _params(self) -> dict[str, str]:
        params = {"fields": API_FIELDS}
        if self.api_key:
            params["key"] = self.api_key
        return params

    def _pause_for_limit(self, seconds: float) -> None:
        seconds = max(0.0, min(seconds, 90.0))
        with err_console.status(f"[yellow]Rate limit reached - waiting {seconds:.0f}s..."):
            time.sleep(seconds + 1)

    def _track_headers(self, resp: requests.Response) -> None:
        rl, ttl = resp.headers.get("X-Rl"), resp.headers.get("X-Ttl")
        try:
            self._remaining = int(rl) if rl is not None else self._remaining
            if ttl is not None:
                self._reset_at = time.monotonic() + int(ttl)
        except ValueError:
            pass

    def lookup(self, query: str | None = None) -> dict[str, Any]:
        """Query the API. `query=None` returns data for the caller's public IP."""
        # ip-api docs: if X-Rl is 0, do not send more requests until X-Ttl elapses.
        if self._remaining == 0 and time.monotonic() < self._reset_at:
            wait = self._reset_at - time.monotonic()
            if not self.wait_on_limit:
                raise RateLimitError(int(wait) + 1)
            self._pause_for_limit(wait)

        last_error: Exception | None = None
        rate_limited_once = False
        attempt = 0
        while attempt <= self.retries:
            try:
                resp = self.session.get(self._url(query), params=self._params(),
                                        timeout=self.timeout)
            except requests.exceptions.Timeout as exc:
                last_error = ApiError(f"request timed out after {self.timeout:g}s")
                last_error.__cause__ = exc
            except requests.exceptions.ConnectionError as exc:
                last_error = ApiError("network connection error (check your internet/DNS/firewall)")
                last_error.__cause__ = exc
            except requests.exceptions.RequestException as exc:
                raise ApiError(f"request failed: {exc}") from exc
            else:
                self._track_headers(resp)
                if resp.status_code == 429:
                    ttl = resp.headers.get("X-Ttl")
                    ttl_i = int(ttl) if ttl and ttl.isdigit() else None
                    if self.wait_on_limit and not rate_limited_once and ttl_i is not None:
                        rate_limited_once = True
                        self._pause_for_limit(ttl_i)
                        continue  # retry once without consuming an attempt
                    raise RateLimitError(ttl_i)
                if resp.status_code == 403:
                    raise ApiError("access denied (HTTP 403) - possible causes: your IP was banned by "
                                   "ip-api.com for exceeding limits, an invalid API key, or a "
                                   "proxy/firewall blocking the request")
                if resp.status_code >= 500:
                    last_error = ApiError(f"server error (HTTP {resp.status_code})")
                elif resp.status_code != 200:
                    raise ApiError(f"unexpected HTTP status {resp.status_code}")
                else:
                    try:
                        data = resp.json()
                    except ValueError:
                        raise ApiError("API returned invalid JSON") from None
                    if data.get("status") != "success":
                        raise ApiError(f"lookup failed: {data.get('message', 'unknown reason')}")
                    return data
            attempt += 1
            if attempt <= self.retries:
                time.sleep(0.75 * 2 ** (attempt - 1))  # exponential backoff
        raise last_error or ApiError("lookup failed")


# --------------------------------------------------------------------------- #
# Analysis pipeline
# --------------------------------------------------------------------------- #
def shape_geo(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "geo": {
            "continent": data.get("continent"),
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "district": data.get("district") or None,
            "zip": data.get("zip") or None,
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "timezone": data.get("timezone"),
            "utc_offset_seconds": data.get("offset"),
            "currency": data.get("currency"),
        },
        "network": {
            "isp": data.get("isp"),
            "organization": data.get("org"),
            "asn": data.get("as"),
            "as_name": data.get("asname"),
            "mobile": data.get("mobile"),
        },
        "security": {
            "proxy_vpn_tor_flag": data.get("proxy"),
            "hosting_flag": data.get("hosting"),
        },
    }


def analyze(raw_target: str | None, client: IpApiClient, timeout: float,
            do_rdns: bool = True) -> dict[str, Any]:
    """Full pipeline for one target. Raises on invalid/unresolvable input."""
    result: dict[str, Any] = {
        "input": raw_target if raw_target else "(auto: own public IP)",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": "ip-api.com",
    }
    other_ips: list[str] = []

    if raw_target is None:
        kind, ip_str = "self", None
    else:
        kind, value = parse_target(raw_target)
        if kind == "ip":
            ip_str = value
        else:
            resolved = resolve_hostname(value, timeout)
            ip_str, other_ips = resolved[0], resolved[1:]
            result["hostname"] = value
    result["kind"] = kind

    if kind == "self":
        data = client.lookup(None)
        ip_str = data["query"]

    ip_obj = ipaddress.ip_address(ip_str)
    category, is_public = classify_ip(ip_obj)
    result.update({
        "ip": ip_str,
        "ip_version": ip_obj.version,
        "classification": category,
        "is_public": is_public,
        "other_resolved_ips": other_ips,
    })

    if do_rdns:
        result["reverse_dns"] = reverse_dns(ip_str, timeout)

    if not is_public:
        result["note"] = (f"{category} address: public geolocation is not available for "
                          "private, loopback, link-local or otherwise non-routable ranges. "
                          "No external API call was made.")
        return result

    if kind != "self":
        data = client.lookup(ip_str)
    result.update(shape_geo(data))
    return result


# --------------------------------------------------------------------------- #
# Local interfaces
# --------------------------------------------------------------------------- #
def get_local_interfaces() -> list[dict[str, Any]]:
    """List local adapters: IPv4/IPv6, netmask, MAC. Uses psutil when installed."""
    interfaces: list[dict[str, Any]] = []
    if psutil is not None:
        stats = psutil.net_if_stats()
        for name, addrs in psutil.net_if_addrs().items():
            entry: dict[str, Any] = {"name": name, "ipv4": [], "ipv6": [], "mac": None,
                                     "is_up": None, "mtu": None, "speed_mbps": None}
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    entry["ipv4"].append({"address": addr.address, "netmask": addr.netmask})
                elif addr.family == socket.AF_INET6:
                    entry["ipv6"].append({"address": addr.address.split("%")[0],
                                          "netmask": addr.netmask})
                elif addr.family == getattr(psutil, "AF_LINK", -1):
                    entry["mac"] = addr.address
            st = stats.get(name)
            if st:
                entry.update(is_up=st.isup, mtu=st.mtu, speed_mbps=st.speed or None)
            interfaces.append(entry)
        return interfaces

    # Fallback without psutil: limited data (no netmask/MAC per adapter).
    mac_int = uuid.getnode()
    mac = ":".join(f"{(mac_int >> s) & 0xff:02x}" for s in range(40, -1, -8))
    ips: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except socket.gaierror:
        pass
    interfaces.append({"name": "(psutil not installed - limited info)",
                       "ipv4": [{"address": ip, "netmask": None} for ip in sorted(ips)],
                       "ipv6": [], "mac": mac, "is_up": None, "mtu": None, "speed_mbps": None})
    return interfaces


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _kv_table(rows: list[tuple[str, Any]]) -> Table:
    table = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    table.add_column(style="bold cyan", no_wrap=True)
    table.add_column(overflow="fold")
    for key, value in rows:
        if value in (None, "", []):
            value = Text("-", style="dim")
        table.add_row(key, value if isinstance(value, Text) else str(value))
    return table


def _flag(value: Any, bad_when_true: bool = True) -> Text:
    if value is None:
        return Text("Unknown", style="dim")
    if bool(value) == bad_when_true:
        return Text("YES", style="bold red") if value else Text("NO", style="bold green")
    return Text("YES", style="bold yellow") if value else Text("NO", style="bold green")


def render_result(res: dict[str, Any]) -> None:
    pub = res["is_public"]
    overview_rows: list[tuple[str, Any]] = [("Input", res["input"])]
    if res.get("hostname"):
        overview_rows.append(("Resolved host", res["hostname"]))
    overview_rows += [
        ("IP address", Text(res["ip"], style="bold white")),
        ("Version", f"IPv{res['ip_version']}"),
        ("Classification", Text(res["classification"], style="green" if pub else "yellow")),
    ]
    if res.get("other_resolved_ips"):
        overview_rows.append(("Other A/AAAA records", ", ".join(res["other_resolved_ips"])))
    panels: list[Any] = [Panel(_kv_table(overview_rows), title="[bold]Target[/bold]",
                               border_style="blue", box=box.ROUNDED)]

    rdns = res.get("reverse_dns")
    if rdns is not None:
        if rdns["hostname"]:
            rows = [("PTR hostname", rdns["hostname"]),
                    ("Aliases", ", ".join(rdns["aliases"]))]
        else:
            rows = [("PTR hostname", Text(rdns["error"], style="dim"))]
        panels.append(Panel(_kv_table(rows), title="[bold]Reverse DNS[/bold]",
                            border_style="magenta", box=box.ROUNDED))

    if not pub:
        panels.append(Panel(res["note"], title="[bold yellow]Notice[/bold yellow]",
                            border_style="yellow", box=box.ROUNDED))
        console.print(Group(*panels))
        return

    g, n, s = res["geo"], res["network"], res["security"]
    offset = g.get("utc_offset_seconds")
    tz = g.get("timezone")
    if tz and offset is not None:
        sign = "+" if offset >= 0 else "-"
        tz = f"{tz} (UTC{sign}{abs(offset) // 3600:02d}:{abs(offset) % 3600 // 60:02d})"
    coords = None
    if g.get("latitude") is not None:
        coords = f"{g['latitude']}, {g['longitude']}"
    panels.append(Panel(_kv_table([
        ("Country", f"{g.get('country')} ({g.get('country_code')})" if g.get("country") else None),
        ("Continent", g.get("continent")),
        ("Region", g.get("region")), ("City", g.get("city")),
        ("District", g.get("district")), ("ZIP", g.get("zip")),
        ("Coordinates", coords), ("Timezone", tz), ("Currency", g.get("currency")),
    ]), title="[bold]Geolocation (approximate)[/bold]", border_style="green", box=box.ROUNDED))

    panels.append(Panel(_kv_table([
        ("ISP", n.get("isp")), ("Organization", n.get("organization")),
        ("ASN", n.get("asn")), ("AS name", n.get("as_name")),
        ("Mobile network", _flag(n.get("mobile"), bad_when_true=False)),
    ]), title="[bold]ISP / Autonomous System[/bold]", border_style="cyan", box=box.ROUNDED))

    flagged = bool(s.get("proxy_vpn_tor_flag")) or bool(s.get("hosting_flag"))
    panels.append(Panel(_kv_table([
        ("Proxy / VPN / Tor flag", _flag(s.get("proxy_vpn_tor_flag"))),
        ("Hosting / datacenter flag", _flag(s.get("hosting_flag"))),
    ]), title="[bold]Risk indicators (as reported by ip-api.com)[/bold]",
        border_style="red" if flagged else "green", box=box.ROUNDED))
    console.print(Group(*panels))


def render_interfaces(interfaces: list[dict[str, Any]]) -> None:
    table = Table(title="Local Network Interfaces", box=box.ROUNDED, header_style="bold cyan",
                  show_lines=True)
    for col in ("Interface", "Status", "IPv4 (netmask)", "IPv6", "MAC", "MTU"):
        table.add_column(col, overflow="fold")
    for i in interfaces:
        status = {True: Text("UP", style="green"), False: Text("DOWN", style="red"),
                  None: Text("-", style="dim")}[i["is_up"]]
        v4 = "\n".join(f"{a['address']} ({a['netmask'] or '?'})" for a in i["ipv4"]) or "-"
        v6 = "\n".join(a["address"] for a in i["ipv6"]) or "-"
        table.add_row(i["name"], status, v4, v6, i["mac"] or "-",
                      str(i["mtu"]) if i["mtu"] else "-")
    console.print(table)


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #
def export_results(records: list[dict[str, Any]], path: str, fmt: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(records, fh, indent=2, ensure_ascii=False)
    else:
        rows = [flatten(r) for r in records]
        fields: list[str] = []
        for row in rows:
            for key in row:
                if key not in fields:
                    fields.append(key)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
    console.print(f"[green]Exported {len(records)} record(s) to[/green] {path}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="main.py",
        description="IP Address Information Finder - geolocation, ASN, reverse DNS and "
                    "risk indicators for IPs and hostnames.",
        epilog="Examples:\n  python main.py 8.8.8.8\n  python main.py example.com --json out.json\n"
               "  python main.py            (looks up your own public IP)\n"
               "  python main.py -l         (list local interfaces)\n  python main.py -i         (interactive mode)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("targets", nargs="*", help="IPv4/IPv6 address(es) or hostname(s). "
                   "Omit to look up your own public IP.")
    p.add_argument("-l", "--interfaces", action="store_true", help="list local network interfaces")
    p.add_argument("-i", "--interactive", action="store_true", help="interactive prompt mode")
    p.add_argument("--json", metavar="FILE", help="export results to a JSON file")
    p.add_argument("--csv", metavar="FILE", help="export results to a CSV file")
    p.add_argument("--no-rdns", action="store_true", help="skip reverse DNS lookup")
    p.add_argument("--timeout", type=float, default=8.0, help="network/DNS timeout in seconds (default 8)")
    p.add_argument("--no-wait", action="store_true",
                   help="fail immediately on rate limit instead of waiting for the window to reset")
    p.add_argument("--api-key", default=os.environ.get("IP_API_KEY"),
                   help="ip-api.com Pro key (or env IP_API_KEY); enables HTTPS via pro.ip-api.com")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def run_one(target: str | None, client: IpApiClient, args: argparse.Namespace) -> dict[str, Any] | None:
    label = target or "your public IP"
    try:
        with console.status(f"[cyan]Analysing {label}..."):
            res = analyze(target, client, args.timeout, do_rdns=not args.no_rdns)
    except (InvalidTargetError, ResolutionError, ApiError) as exc:
        title = {InvalidTargetError: "Invalid target", ResolutionError: "DNS error",
                 RateLimitError: "Rate limited"}.get(type(exc), "Error")
        err_console.print(Panel(f"[bold]{escape(label)}[/bold]\n{escape(str(exc))}", title=f"[red]{title}[/red]",
                                border_style="red", box=box.ROUNDED))
        return None
    render_result(res)
    return res


def interactive_loop(client: IpApiClient, args: argparse.Namespace) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    console.print(Panel("Enter an IP or hostname.  [bold]Blank[/bold] = your public IP · "
                        "[bold]l[/bold] = local interfaces · [bold]q[/bold] = quit",
                        title="Interactive mode", border_style="blue"))
    while True:
        try:
            raw = Prompt.ask("[bold cyan]target[/bold cyan]", default="", show_default=False).strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            break
        if raw.lower() in {"q", "quit", "exit"}:
            break
        if raw.lower() in {"l", "interfaces"}:
            render_interfaces(get_local_interfaces())
            continue
        res = run_one(raw or None, client, args)
        if res:
            records.append(res)
    return records


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout <= 0:
        err_console.print("[red]--timeout must be greater than 0[/red]")
        return 2

    client = IpApiClient(timeout=args.timeout, api_key=args.api_key,
                         wait_on_limit=not args.no_wait)
    if not args.api_key:
        err_console.print("[dim]Note: the free ip-api.com tier uses plain HTTP (unencrypted) and is "
                          "for non-commercial use.[/dim]")

    records: list[dict[str, Any]] = []
    failures = 0
    try:
        if args.interfaces:
            render_interfaces(get_local_interfaces())

        if args.interactive:
            records = interactive_loop(client, args)
        elif args.targets:
            for t in args.targets:
                res = run_one(t, client, args)
                if res:
                    records.append(res)
                else:
                    failures += 1
        elif not args.interfaces:
            res = run_one(None, client, args)
            if res:
                records.append(res)
            else:
                failures += 1
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Interrupted.[/yellow]")
        return 130

    for path, fmt in ((args.json, "json"), (args.csv, "csv")):
        if path:
            if not records:
                err_console.print(f"[yellow]Nothing to export to {path}.[/yellow]")
                continue
            try:
                export_results(records, path, fmt)
            except OSError as exc:
                err_console.print(f"[red]Export failed for {path}: {exc}[/red]")
                failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
