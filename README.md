# IP Address Information Finder

A CLI tool for IP / hostname reconnaissance: geolocation, ASN/ISP, reverse DNS,
proxy/hosting indicators, and local network interface listing, with `rich` terminal
output and JSON/CSV export.

> **Use responsibly.** Only investigate targets you are authorised to look up.
> Geolocation data is approximate and must not be treated as proof of identity or location.

---

## Features

| Feature | Details |
|---|---|
| Target parsing | IPv4, IPv6, hostnames (auto DNS resolution, IDN supported), URLs (host is extracted), or no argument → your own public IP |
| Input validation | Rejects whitespace/control chars, malformed hostnames and numeric junk (e.g. `999.1.1.1`) **before** any network call |
| Classification | Public vs RFC 1918 private, loopback, link-local, multicast, CGNAT (RFC 6598), IPv6 ULA (RFC 4193), reserved. Non-public IPs never trigger an external API call |
| Geolocation / ASN | Country, region, city, ZIP, coordinates, timezone, currency, ISP, organisation, ASN via ip-api.com |
| Risk indicators | `proxy` and `hosting` (and `mobile`) flags as returned by ip-api.com |
| Reverse DNS | PTR lookup with `socket.gethostbyaddr` (with hard timeout) |
| Local interfaces | Name, status, IPv4 + netmask, IPv6, MAC, MTU (via `psutil`; limited fallback without it) |
| Output | Colour panels/tables (`rich`), `--json`, `--csv`, interactive mode |
| Resilience | Timeouts, retries with exponential backoff, HTTP 429 handling, `X-Rl`/`X-Ttl` tracking, clear error panels |

## Setup

Requires **Python 3.10+**.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py --help
```

## Usage

```bash
python main.py                          # your own public IP
python main.py 8.8.8.8                  # single IP
python main.py 2606:4700:4700::1111     # IPv6
python main.py example.com              # hostname (DNS-resolved)
python main.py 8.8.8.8 1.1.1.1 github.com   # several targets
python main.py 192.168.1.10             # private IP -> friendly notice, no API call
python main.py -l                       # list local interfaces
python main.py 8.8.8.8 -l               # both
python main.py -i                       # interactive prompt
python main.py example.com --json out.json --csv out.csv
python main.py 8.8.8.8 --no-rdns --timeout 5 --no-wait
```

| Option | Description |
|---|---|
| `targets…` | IPs/hostnames; omit for your public IP |
| `-l, --interfaces` | List local network interfaces |
| `-i, --interactive` | Prompt loop (blank = own IP, `l` = interfaces, `q` = quit) |
| `--json FILE` / `--csv FILE` | Export all results from the run (CSV keys are flattened, e.g. `geo.city`) |
| `--no-rdns` | Skip reverse DNS |
| `--timeout N` | Network/DNS timeout in seconds (default 8) |
| `--no-wait` | On rate limit, fail immediately instead of waiting for the window to reset |
| `--api-key KEY` | ip-api.com Pro key (or env var `IP_API_KEY`) → uses `https://pro.ip-api.com` |

**Exit codes:** `0` success · `1` at least one target/export failed · `2` bad arguments · `130` interrupted.

## API & rate-limiting rules (ip-api.com)

Verified against ip-api.com's own pages on 2026-09-28:

- Free endpoints are limited to **45 HTTP requests per minute per IP address**; exceeding it throttles you with **HTTP 429** until the window resets. ([ip-api.com](https://ip-api.com/))
- The batch endpoint is limited to 15 requests/minute (not used by this tool). ([ip-api.com/docs/unban](https://ip-api.com/docs/unban))
- If you constantly exceed limits, your IP can be **permanently banned**. The docs say to check the `X-Rl` header, and if it is `0`, not to send more requests for `X-Ttl` seconds. ([ip-api.com/docs/unban](https://ip-api.com/docs/unban)) This tool implements exactly that: it tracks both headers and waits (or fails with `--no-wait`).
- The free service is **for non-commercial use** and needs no key. ([ip-api.com](https://ip-api.com/))
- The **free tier uses HTTP, not HTTPS** (queries are unencrypted). ([pkg.go.dev/ipapi](https://pkg.go.dev/github.com/tamnd/ipapi-cli/ipapi)) An API-key setup uses HTTPS via `pro.ip-api.com`. ([PyPI aioipapi](https://pypi.org/project/aioipapi))
- Fields used (`status, message, query, continent, country, regionName, city, district, zip, lat, lon, timezone, offset, currency, isp, org, as, asname, mobile, proxy, hosting`) are listed in the [JSON API docs](https://ip-api.com/docs/api:json). Failure messages can be `private range`, `reserved range` or `invalid query`.

**What I could not confirm:** the exact definition of the `proxy` flag (whether it covers all VPN, Tor and open-proxy sources) was not visible in the documentation excerpts I retrieved. Check the [official field table](https://ip-api.com/docs/api:json) before relying on it. The tool labels this row "Proxy / VPN / Tor flag" as a convenience; treat it as an indicator, not a verdict.

Other providers such as ipinfo.io could be substituted by editing `IpApiClient`; this project does not implement them.

## Reconnaissance concepts

*(General background, not tool-specific claims.)*

- **Public vs private addresses.** RFC 1918 reserves `10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/16` for private networks; they're not globally routable, so no public geolocation exists for them. Related non-public ranges handled here: loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`), CGNAT `100.64.0.0/10` (RFC 6598), IPv6 unique-local `fc00::/7` (RFC 4193).
- **Geolocation accuracy.** IP geolocation is inferred from registry and network data, so it is approximate (city-level at best, often just the ISP's hub). Third-party libraries for ip-api note the data is "likely not exact". ([docs.rs ip_api](https://docs.rs/crate/ip_api/latest/source/src/lib.rs))
- **ASN / ISP.** An Autonomous System Number identifies a network that announces routes via BGP. It tells you *who operates* the IP block, which is often more reliable than the location.
- **Reverse DNS (PTR).** Maps an IP back to a name via `in-addr.arpa` / `ip6.arpa`. PTR records are optional, set by the IP owner, and need not match forward DNS, so they're a hint, not proof. `socket.gethostbyaddr` uses your OS resolver (which may also consult the hosts file or local DNS).
- **Hosting / proxy indicators.** Traffic from datacenter, VPN, proxy or Tor addresses is commonly treated as higher risk in fraud and security triage, but many legitimate users also use them. Use as one signal among several.
- **Hostname → IP.** One hostname can have many A/AAAA records (CDNs, load balancers). The tool analyses the first (IPv4-preferred) and lists the others.

## Project layout

```
main.py            # the CLI
requirements.txt   # requests, rich, psutil
README.md
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `HTTP 429` / "rate limit" | Wait for the window to reset; avoid loops over many targets (>45/min) |
| `HTTP 403` | Possible ban (see unban docs), bad API key, or a proxy/firewall blocking `ip-api.com` |
| Timeouts / connection errors | Check connectivity; raise `--timeout` |
| Interface list is limited | `pip install psutil` |
| Corporate network blocks HTTP | The free tier is HTTP-only; use a Pro key (HTTPS) |

## Testing note

Offline logic (input validation, IP classification, private-range handling, interface listing, CSV/JSON export, rate-limit/timeout handling with mocked responses) was tested in a sandbox. **Live calls to ip-api.com were not possible there** (outbound access was blocked), so the real-API path was verified only against mocked responses shaped like the documented schema. Run `python main.py 8.8.8.8` on your machine to confirm.
