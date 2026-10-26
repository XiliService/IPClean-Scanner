# IPClean-Scanner

An interactive Bash utility for finding Cloudflare anycast IPv4 endpoints that can complete a real TLS request for a chosen SNI/hostname. It is designed for quick terminal use and displays scan results directly in the terminal; it does not create persistent result files.

> **Important limitation:** A scan running on one Internet connection can only verify that connection's route. It cannot prove that an IP works on Irancell, Hamrah-e Aval, or Iranian fixed broadband without test probes actually running on those networks. The table therefore reports those operator columns as `N/A`, rather than inferring or inventing cross-operator results. Use the scanner separately on each network, or add trusted remote probes before treating an IP as multi-operator verified.

## First run

Run this single command in Bash (it downloads and starts the installer from the `main` branch):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/XiliService/IPClean-Scanner/main/scanner.sh)
```

On first launch, the script attempts to install itself as `cf-scanner`. It uses `$PREFIX/bin` in Termux, `/usr/local/bin` when writable, or `~/.local/bin` otherwise. If `~/.local/bin` is not already in `PATH`, the installer adds it to common shell startup files; open a new terminal or run `source ~/.bashrc` (or the relevant shell startup file) if necessary.

After installation, launch it from anywhere:

```bash
cf-scanner
```

The updater may need write access to the selected installation directory. It uses `sudo` when needed and available.

## What it does

The main menu is numeric and guides the user through a known sequence of steps:

1. **Quick Auto Scan** — samples the embedded candidate ranges, tests the current network's latency/reachability, then checks TLS against the selected SNI on port 443.
2. **Custom Step-by-Step Scan** — choose the SNI and request path, candidate range source, Cloudflare HTTPS port(s), latency profile, and scan depth.
3. **Test Specific IP/CIDR** — test an IP or sample a CIDR using the same local connection.
4. **System Diagnostics** — inspect required commands, public IP/ISP lookup availability, and CLI installation status.
5. **Update Script** — check GitHub `main`; if its semantic version is newer, offer that update. If `main` is equal, older, or unavailable, enter a branch name (or supported GitHub branch URL) to fetch the latest script from that branch.
6. **Uninstall** — remove the installed `cf-scanner` command.

During a scan, the script:

- samples IPs from embedded candidate CIDRs (or the selected custom CIDR);
- measures ICMP replies when available, with a TCP-connect timing fallback when ICMP is blocked;
- sends an HTTPS request to the chosen hostname while pinning the connection to each candidate IP (`curl --resolve`), checks certificate verification, and records TLS/connect and response timing;
- identifies Cloudflare responses where available from the `CF-Ray` header or `/cdn-cgi/trace`;
- ranks locally tested IP:port results and prints a copy-friendly list in the terminal.

The quality score ranks the measurements from the current connection. It is not a guarantee of future performance or of service on another ISP. Cloudflare anycast routing, filtering, and latency may differ by location, operator, time, SNI, and port. The embedded “Iran Golden” label denotes a candidate set only; it is not a claim that every range is currently optimal or universally reachable.

## Requirements

- Bash 3.2 or newer
- `curl`, `awk`, `sed`, `grep`, `sort`, `head`, `tr`, `cut`, `wc`
- `ping` is optional; TCP-connect timing is used if it is missing or ICMP replies are unavailable.
- An Internet connection to the selected SNI and GitHub for the first-run download/update.

The script uses temporary files during a scan and removes its temporary workspace on exit. It does not save scan reports or candidate lists to the repository or a persistent results directory.

## Optional command-line usage

```bash
cf-scanner --help
cf-scanner --version
cf-scanner --quick [your.cloudflare-host.example]
cf-scanner --diagnostics
cf-scanner --update
```

`--quick` uses the default SNI `speed.cloudflare.com` when none is supplied. For the most meaningful test, choose a hostname that is proxied by Cloudflare and represents the SNI used by your actual configuration. The TLS check verifies the hostname's certificate and HTTP response; it does not test a particular tunnel protocol, WebSocket path, or origin unless you select a custom path in the menu.

## Updating

Choose **5** in the menu or run `cf-scanner --update`. The updater reads `SCRIPT_VERSION` from the raw script on GitHub. Branch names are interpreted as branches in this repository. It also accepts GitHub `/tree/<branch>` or `/blob/<branch>/scanner.sh` URLs, as well as a `raw.githubusercontent.com` script URL.

The script should only be installed from a repository/branch you trust. A branch update replaces the installed script.

## Security and accuracy notes

- A successful TLS request means that the current network reached Cloudflare at the candidate IP for the supplied SNI at scan time; it does not imply that the IP is “clean” for every user or every protocol.
- Ping is not required for TLS to work. Some networks block ICMP while allowing HTTPS.
- The scan only samples large CIDRs; it does not exhaustively scan every address.
- Avoid scanning custom ranges that you do not own or have permission to test. The default ranges are Cloudflare address space and each candidate is tested with a small number of requests.

## Repository contents

- `scanner.sh` — the English-only interactive scanner and self-installer.
- `README.md` — this guide.
