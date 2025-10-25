# nmapAutomator (Python + Flask Edition)

Modern recon automation for offensive security teams. Run the original nmap workflows from a polished Flask control center or drive them via a Python CLI—now with first-class support for target lists, CIDR blocks, and curated recon scanners.

---

## Highlights

- **Multi-target aware** – paste IP lists, ranges (e.g. `10.10.10.5-45`), or `/24` blocks and the UI will dedupe and march through each host automatically.
- **Structured evidence** – live dashboards stream logs, aggregate unique findings (target/port/service/detail), and offer instant clipboard copy or CSV export.
- **Scanner toggles** – opt-in helpers such as *nmap Vulners, sslscan, nikto, joomscan, wpscan, droopescan, smbmap, enum4linux, dnsrecon, odat, smtp-user-enum, snmp-check, snmpwalk,* and *ldapsearch*.
- **Original recon DNA** – leverages `nmap`’s Network/Port/Full/UDP/Vulns/Recon logic with script scans, vulners integration, and OS detection.
- **One codebase** – the Flask UI wraps the Python CLI, so behaviour stays identical whether you launch one host or dozens.

> ⚠️ **Legal reminder**: Only run nmapAutomator against systems you own or have explicit permission to test.

---

## Requirements

- Python 3.10 or newer
- `nmap` installed locally (Kali/Parrot already include it)
- Optional recon tools (ffuf, gobuster, sslscan, nikto, etc.) if you plan to toggle them on

---

## Installation (with virtual environment)

```bash
git clone https://github.com/21y4d/nmapAutomator.git
cd nmapAutomator

# Create and activate a virtual environment
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
.venv\Scripts\Activate.ps1

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

Deactivate the environment any time with `deactivate`. Re-activate before running new scans.

---

## Running the Python CLI

The CLI is ideal for scripting or remote shells where you need a single-host run.

```bash
# Basic port scan
python automator.py -H 10.10.10.10 -t Port

# Script scan with custom DNS
python automator.py -H academy.htb -t Script -d 1.1.1.1

# Full workflow plus recon suggestions
python automator.py -H 10.10.11.11 -t All --run-recon

# Add post-scan helpers (sslscan + nikto)
python automator.py -H 10.10.11.50 -t Port --scanners sslscan nikto
```

> The CLI accepts one host at a time. Use the web cockpit for multi-target batches.

---

## Running the Flask Web Control Center

```bash
# Ensure your virtual environment is activated
python app.py
# Visit http://localhost:5000
```

Default behaviour:

| Variable | Purpose | Default |
| --- | --- | --- |
| `NMAP_AUTOMATOR_SCRIPT` | Path to the CLI wrapper | `./automator.py` |
| `NMAP_AUTOMATOR_INTERPRETER` | Python executable for the CLI | current interpreter |
| `NMAP_AUTOMATOR_WEB_OUTPUT` | Web job artifacts directory | `./web_output` |
| `NMAP_AUTOMATOR_MAX_WORKERS` | Concurrent jobs allowed | `2` |
| `NMAP_AUTOMATOR_MAX_LOG_LINES` | Lines kept in memory per job | `4000` |
| `NMAP_AUTOMATOR_MAX_TARGETS` | Max targets expanded from input | `256` |

### UI workflow

1. Paste hosts, IP ranges, or CIDR blocks into the **Targets** box (comma, newline, or semicolon separated).
2. Choose the scan profile (Network/Port/Script/Full/UDP/Vulns/Recon/All).
3. Toggle optional DNS server, static nmap path, custom output folder, or extra CLI flags.
4. Flip on *Remote mode* only if you plan to port the script to limited POSIX shells (currently limited in the Python port).
5. Tick any recon helpers to run automatically after nmap finishes.
6. Launch the scan and monitor progress + structured results per target. Copy findings or download CSV straight from the dashboard.

---

## Repository Layout

```
.
├─ app.py                # Flask dashboard
├─ automator.py          # Python CLI wrapper (invokes automator package)
├─ automator/            # Core logic (scanner + CLI modules)
├─ static/, templates/   # Web assets
├─ requirements.txt
└─ README.md
```

The `automator` package contains:

- `scanner.py` – orchestrates nmap runs, parses outputs, builds recon commands, and executes optional scanners.
- `cli.py` – argument parsing + `ScanOptions`.
- `__init__.py` – exports convenient entrypoints.

---

## Tips & Troubleshooting

- **Missing tools** – If a selected recon helper (e.g. `nikto`) is absent, the scan continues and logs the omission.
- **Static nmap** – Pass `-s /path/to/nmap` (or set the UI field) when operating on remote shells that lack `nmap`.
- **Output folders** – Each job writes to `web_output/<job-id>/<target>/nmap/`, keeping artifacts separated per host.
- **Remote mode** – Placeholder flag for parity with the legacy shell script; full POSIX-only support is on the roadmap.

---

## Contributing

1. Fork + clone the repo.
2. Create a feature branch and keep changes focused.
3. Run linting/tests relevant to your edits.
4. Submit a PR describing the motivation and testing performed.

Issues and PRs are always welcome—let’s keep nmapAutomator sharp. 🚀
