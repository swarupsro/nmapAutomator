from __future__ import annotations

import ipaddress
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

LogFunc = Callable[[str], None]


class ScanError(RuntimeError):
    """Raised when a scan cannot be executed."""


@dataclass
class ScanOptions:
    host: str
    scan_type: str
    dns_server: Optional[str] = None
    output_dir: Path = field(default_factory=lambda: Path.cwd())
    static_nmap: Optional[str] = None
    remote_mode: bool = False
    custom_output_name: Optional[str] = None
    extra_args: Sequence[str] = field(default_factory=tuple)
    run_recon_commands: bool = False
    notes: Optional[str] = None
    selected_scanners: Sequence[str] = field(default_factory=tuple)


PORT_LINE = re.compile(r"^(\d+)/(tcp|udp)\s+open", re.IGNORECASE)
SERVICE_LINE = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(.*)$", re.IGNORECASE)


def default_logger(message: str = "") -> None:
    print(message)


def which(tool: str) -> Optional[str]:
    return shutil.which(tool)


def shell_join(parts: Sequence[str]) -> str:
    return " ".join(shlex.quote(part) for part in parts)


def detect_os_from_ttl(ttl: Optional[int]) -> str:
    if ttl is None:
        return "Unknown OS"
    if 254 <= ttl <= 255:
        return "OpenBSD/Cisco/Oracle"
    if 126 <= ttl <= 128:
        return "Windows"
    if 63 <= ttl <= 64:
        return "Linux"
    return "Unknown OS"


def ping_host(host: str) -> Tuple[bool, Optional[int]]:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", host]
        ttl_pattern = re.compile(r"TTL=(\d+)", re.IGNORECASE)
    else:
        cmd = ["ping", "-c", "1", "-W", "1", host]
        ttl_pattern = re.compile(r"ttl[=|:](\d+)", re.IGNORECASE)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return False, None

    if proc.returncode != 0:
        return False, None

    match = ttl_pattern.search(proc.stdout)
    ttl = int(match.group(1)) if match else None
    return True, ttl


class Automator:
    """Python port of the original bash-based nmapAutomator."""

    def __init__(self, options: ScanOptions, log: LogFunc = default_logger):
        self.options = options
        self.log = log
        self.start_time = time.time()
        self.host = options.host
        self.scan_type = options.scan_type.lower()
        self.output_root = Path(options.output_dir).expanduser().resolve()
        if options.custom_output_name:
            self.output_root = self.output_root / options.custom_output_name
        self.output_root.mkdir(parents=True, exist_ok=True)
        self.nmap_dir = self.output_root / "nmap"
        self.recon_dir = self.output_root / "recon"
        self.nmap_dir.mkdir(parents=True, exist_ok=True)
        self.recon_dir.mkdir(parents=True, exist_ok=True)

        self.extra_cli_args = list(options.extra_args or [])
        self.selected_scanners = [scanner.lower() for scanner in options.selected_scanners]
        self.nmap_path = self._resolve_nmap_path()

        self.host_ip = self._resolve_host_ip()
        self.subnet = self._derive_subnet()

        self.pingable, self.ttl = ping_host(self.host_ip or self.host)
        self.os_guess = detect_os_from_ttl(self.ttl)
        self.dns_args = (
            ["--dns-server", options.dns_server]
            if options.dns_server
            else ["--system-dns"]
        )
        self.nmap_base = [self.nmap_path]
        if not self.pingable:
            self.nmap_base.append("-Pn")

        self.common_ports: List[int] = []
        self.all_ports: List[int] = []
        self.udp_ports: List[int] = []

    # Public API ---------------------------------------------------------
    def run(self) -> None:
        if self.options.remote_mode:
            raise ScanError("Remote mode is not yet supported in the Python port.")

        self._print_header()
        try:
            dispatch = {
                "network": self.network_scan,
                "port": self.port_scan,
                "script": self.script_scan,
                "full": self.full_scan,
                "udp": self.udp_scan,
                "vulns": self.vulns_scan,
                "recon": self.recon_scan,
                "all": self.run_all,
            }
            action = dispatch.get(self.scan_type)
            if not action:
                raise ScanError(f"Unknown scan type '{self.options.scan_type}'")
            action()
            self._run_selected_scanners()
        finally:
            self._print_footer()

    # Individual scan stages --------------------------------------------
    def network_scan(self) -> None:
        if not self.subnet:
            self.log("Unable to derive subnet; skipping network scan.")
            return
        output = self._nmap_output("Network")
        targets = [f"{self.subnet}/24"]
        args = [
            "-T4",
            "--max-retries",
            "1",
            "--max-scan-delay",
            "20",
            "-n",
            "-sn",
        ]
        self._run_command(
            self._build_nmap_cmd(args, output, targets),
            "Network scan",
            stats_every=2,
        )
        self._summarize_nmap(output)

    def port_scan(self) -> None:
        output = self._nmap_output("Port")
        args = [
            "-T4",
            "--max-retries",
            "1",
            "--max-scan-delay",
            "20",
            "--open",
        ]
        self._run_command(
            self._build_nmap_cmd(args, output, [self.host]),
            "Port scan",
            stats_every=2,
        )
        self._refresh_ports()

    def script_scan(self) -> None:
        if not self.common_ports:
            if not (self.nmap_dir / f"Port_{self.host}.nmap").exists():
                self.port_scan()
            if not self.common_ports:
                self.log("No TCP ports discovered yet; skipping script scan.")
                return
        output = self._nmap_output("Script")
        args = ["-sCV", f"-p{self._ports_to_arg(self.common_ports)}", "--open"]
        self._run_command(
            self._build_nmap_cmd(args, output, [self.host]),
            "Script scan",
            stats_every=2,
        )

    def full_scan(self) -> None:
        output = self._nmap_output("Full")
        args = [
            "-p-",
            "--max-retries",
            "1",
            "--max-rate",
            "500",
            "--max-scan-delay",
            "20",
            "-T4",
            "-v",
            "--open",
        ]
        self._run_command(
            self._build_nmap_cmd(args, output, [self.host]),
            "Full scan",
            stats_every=3,
        )
        self._refresh_ports()
        if not self.all_ports:
            self.log("No extra ports were found beyond the quick scan.")
            return
        extra_ports = sorted(set(self.all_ports) - set(self.common_ports))
        if not extra_ports:
            self.log("No new ports detected after the full sweep.")
            return
        self.log(
            f"Full scan discovered additional ports: "
            f"{', '.join(map(str, extra_ports))}"
        )
        output_extra = self._nmap_output("Full_Extra")
        args = ["-sCV", f"-p{self._ports_to_arg(extra_ports)}", "--open"]
        self._run_command(
            self._build_nmap_cmd(args, output_extra, [self.host]),
            "Full script scan on extra ports",
            stats_every=2,
        )
        self._refresh_ports()

    def udp_scan(self) -> None:
        output = self._nmap_output("UDP")
        args = ["-sU", "--max-retries", "1", "--open", "--open"]
        cmd = self._build_nmap_cmd(args, output, [self.host], require_root=True, stats_every=3)
        self._run_command(cmd, "UDP scan", stats_every=3)
        self._refresh_ports()

        if not self.udp_ports:
            self.log("No UDP ports were found.")
            return
        output_extra = self._nmap_output("UDP_Extra")
        args = ["-sCVU", f"-p{self._ports_to_arg(self.udp_ports)}", "--open"]
        vulners = Path("/usr/share/nmap/scripts/vulners.nse")
        if vulners.exists():
            args.insert(1, "--script")
            args.insert(2, "vulners")
            args.extend(["--script-args", "mincvss=7.0"])
        self._run_command(
            self._build_nmap_cmd(args, output_extra, [self.host], require_root=True, stats_every=2),
            "UDP script scan",
            stats_every=2,
        )

    def vulns_scan(self) -> None:
        if not self.common_ports:
            self.port_scan()
            self._refresh_ports()
        ports = self.all_ports or self.common_ports
        if not ports:
            self.log("No ports to run vulnerability scripts against.")
            return
        port_arg = self._ports_to_arg(ports)

        vulners_script = Path("/usr/share/nmap/scripts/vulners.nse")
        if vulners_script.exists():
            output_cve = self._nmap_output("CVEs")
            args = [
                "-sV",
                "--script",
                "vulners",
                "--script-args",
                "mincvss=7.0",
                f"-p{port_arg}",
                "--open",
            ]
            self._run_command(
                self._build_nmap_cmd(args, output_cve, [self.host], stats_every=3),
                "CVE scan",
                stats_every=3,
            )
        else:
            self.log(
                "Skipping CVE scan because '/usr/share/nmap/scripts/vulners.nse' "
                "is not installed."
            )

        output_vuln = self._nmap_output("Vulns")
        args = ["-sV", "--script", "vuln", f"-p{port_arg}", "--open"]
        self._run_command(
            self._build_nmap_cmd(args, output_vuln, [self.host], stats_every=3),
            "Vuln scan",
            stats_every=3,
        )

    def recon_scan(self) -> None:
        if not self.common_ports:
            self.port_scan()
        if not (self.nmap_dir / f"Script_{self.host}.nmap").exists():
            self.script_scan()
        recon_commands = self._build_recon_recommendations()
        if not recon_commands:
            self.log("No recon recommendations available.")
            return

        recon_file = self.nmap_dir / f"Recon_{self.host}.nmap"
        command_strings = [cmd.command for cmd in recon_commands]
        recon_file.write_text("\n".join(command_strings), encoding="utf-8")
        self.log(f"Saved recon suggestions to {recon_file}")

        if self.options.run_recon_commands:
            self._execute_recon_commands(command_strings)

    def run_all(self) -> None:
        self.port_scan()
        self.script_scan()
        self.full_scan()
        self.udp_scan()
        self.vulns_scan()
        self.recon_scan()

    # Helpers ------------------------------------------------------------
    def _resolve_nmap_path(self) -> str:
        if self.options.static_nmap:
            path = Path(self.options.static_nmap).expanduser().resolve()
            if not path.exists():
                raise ScanError(f"Static nmap binary not found: {path}")
            if not os.access(path, os.X_OK):
                raise ScanError(f"Static nmap binary is not executable: {path}")
            return str(path)
        nmap_path = which("nmap")
        if not nmap_path:
            raise ScanError("nmap binary not found in PATH.")
        return nmap_path

    def _resolve_host_ip(self) -> Optional[str]:
        if self._is_ip(self.host):
            return self.host
        try:
            return socket.gethostbyname(self.host)
        except socket.gaierror:
            return None

    def _derive_subnet(self) -> Optional[str]:
        ip_addr = self.host_ip
        if not ip_addr:
            return None
        try:
            addr = ipaddress.ip_address(ip_addr)
        except ValueError:
            return None
        if isinstance(addr, ipaddress.IPv4Address):
            octets = ip_addr.split(".")
            octets[-1] = "0"
            return ".".join(octets)
        return None

    def _print_header(self) -> None:
        scan_label = "all scans" if self.scan_type == "all" else f"{self.options.scan_type} scan"
        line = f"Running {scan_label} against {self.host}"
        if self.host_ip and self.host_ip != self.host:
            line += f" (resolved IP {self.host_ip})"
        self.log(line)
        if not self.pingable:
            self.log("Host did not respond to ping; nmap will run with -Pn.")
        if self.os_guess:
            self.log(f"Host is likely running {self.os_guess}")
        if self.options.notes:
            self.log(f"Notes: {self.options.notes}")
        self.log("")

    def _print_footer(self) -> None:
        elapsed = int(time.time() - self.start_time)
        if elapsed >= 3600:
            hours = elapsed // 3600
            minutes = (elapsed % 3600) // 60
            seconds = elapsed % 60
            human = f"{hours}h {minutes}m {seconds}s"
        elif elapsed >= 60:
            minutes = elapsed // 60
            seconds = elapsed % 60
            human = f"{minutes}m {seconds}s"
        else:
            human = f"{elapsed}s"
        self.log("")
        self.log(f"Completed scans in {human}")

    def _ports_to_arg(self, ports: Iterable[int]) -> str:
        return ",".join(str(port) for port in ports)

    def _refresh_ports(self) -> None:
        port_file = self.nmap_dir / f"Port_{self.host}.nmap"
        full_file = self.nmap_dir / f"Full_{self.host}.nmap"
        udp_file = self.nmap_dir / f"UDP_{self.host}.nmap"

        self.common_ports = self._parse_port_file(port_file)
        full_ports = self._parse_port_file(full_file)
        self.all_ports = sorted(set(self.common_ports) | set(full_ports))
        self.udp_ports = self._parse_port_file(udp_file)

    def _parse_port_file(self, path: Path) -> List[int]:
        if not path.exists():
            return []
        ports: List[int] = []
        with path.open(encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                match = PORT_LINE.match(line.strip())
                if match:
                    ports.append(int(match.group(1)))
        return sorted(set(ports))

    def _nmap_output(self, prefix: str) -> Path:
        return self.nmap_dir / f"{prefix}_{self.host}.nmap"

    def _build_nmap_cmd(
        self,
        args: List[str],
        output: Path,
        targets: Sequence[str],
        *,
        require_root: bool = False,
        stats_every: int = 2,
    ) -> List[str]:
        cmd: List[str] = []
        if require_root and self._should_try_sudo():
            cmd.extend(["sudo", "-n"])
        cmd.extend(self.nmap_base)
        if stats_every > 0:
            cmd.extend(["--stats-every", f"{stats_every}s"])
        cmd.extend(args)
        cmd.extend(["-oN", str(output)])
        cmd.extend(targets)
        cmd.extend(self.dns_args)
        cmd.extend(self.extra_cli_args)
        return cmd

    def _run_command(self, cmd: List[str], description: str, *, stats_every: int = 2) -> None:
        self.log(f"{description} → {shell_join(cmd)}")
        process = subprocess.Popen(
            cmd,
            cwd=self.output_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert process.stdout is not None
        for line in process.stdout:
            self.log(line.rstrip())
        return_code = process.wait()
        if return_code != 0:
            raise ScanError(f"{description} failed with exit code {return_code}")

    def _summarize_nmap(self, output: Path) -> None:
        if not output.exists():
            return
        with output.open(encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                if PORT_LINE.match(line.strip()):
                    self.log(line.rstrip())

    def _build_recon_recommendations(self) -> List["ReconCommand"]:
        script_file = self.nmap_dir / f"Script_{self.host}.nmap"
        extra_file = self.nmap_dir / f"Full_Extra_{self.host}.nmap"
        udp_extra = self.nmap_dir / f"UDP_Extra_{self.host}.nmap"
        files = []
        if script_file.exists():
            files.append(script_file)
        if extra_file.exists():
            files.append(extra_file)
        if not files:
            return []
        services = self._collect_services(files)
        commands: List[ReconCommand] = []

        available_ports = self.all_ports or self.common_ports
        if available_ports:
            port_arg = self._ports_to_arg(available_ports)
            commands.append(
                ReconCommand(
                    "nmap Vulners",
                    f"{self.nmap_path} -sV --script vulners --script-args mincvss=7.0 "
                    f"-p{port_arg} {self.host}",
                )
            )

        if (
            self.options.dns_server
            and self.subnet
            and any(s.service == "domain" for s in services)
        ):
            commands.extend(
                [
                    ReconCommand(
                        "dnsrecon",
                        f"host -l {self.host} {self.options.dns_server} | tee recon/hostname_{self.host}.txt",
                    ),
                    ReconCommand(
                        "dnsrecon",
                        f"dnsrecon -r {self.subnet}/24 -n {self.options.dns_server} | tee recon/dnsrecon_{self.host}.txt",
                    ),
                    ReconCommand(
                        "dnsrecon",
                        f"dnsrecon -r 127.0.0.0/24 -n {self.options.dns_server} | tee recon/dnsrecon-local_{self.host}.txt",
                    ),
                    ReconCommand(
                        "dnsrecon",
                        f"dig -x {self.host} @{self.options.dns_server} | tee recon/dig_{self.host}.txt",
                    ),
                ]
            )

        http_services = [svc for svc in services if "http" in svc.service.lower()]
        for svc in http_services:
            port = svc.port
            ssl = "ssl/http" in svc.service.lower() or "https" in svc.service.lower()
            scheme = "https" if ssl else "http"
            if ssl:
                commands.append(
                    ReconCommand(
                        "sslscan",
                        f"sslscan {self.host} | tee recon/sslscan_{self.host}_{port}.txt",
                    )
                )
            commands.append(
                ReconCommand(
                    "nikto",
                    f"nikto -host {scheme}://{self.host}:{port} "
                    f"{'-ssl' if ssl else ''} | tee recon/nikto_{self.host}_{port}.txt",
                )
            )
            commands.append(
                ReconCommand(
                    "ffuf",
                    "ffuf -ic -w /usr/share/wordlists/dirb/common.txt "
                    f"-u {scheme}://{self.host}:{port}/FUZZ "
                    f"| tee recon/ffuf_{self.host}_{port}.txt",
                )
            )

        cms_generators = self._extract_cms(script_file)
        cms_templates = {
            "Joomla!": ("joomscan", "joomscan --url {url} | tee recon/joomscan_{host}_{port}.txt"),
            "WordPress": ("wpscan", "wpscan --url {url} --enumerate p | tee recon/wpscan_{host}_{port}.txt"),
            "Drupal": ("droopescan", "droopescan scan drupal -u {url} | tee recon/droopescan_{host}_{port}.txt"),
        }
        for cms, port in cms_generators:
            template_info = cms_templates.get(cms)
            if not template_info:
                continue
            tool, template = template_info
            url = f"http://{self.host}:{port}"
            commands.append(
                ReconCommand(
                    tool,
                    template.format(url=url, host=self.host, port=port),
                )
            )

        smtp_present = any(s.port == 25 and s.protocol == "tcp" for s in services)
        if smtp_present:
            commands.append(
                ReconCommand(
                    "smtp-user-enum",
                    "smtp-user-enum -U /usr/share/wordlists/metasploit/unix_users.txt "
                    f"-t {self.host} | tee recon/smtp_user_enum_{self.host}.txt",
                )
            )

        if udp_extra.exists():
            udp_services = self._collect_services([udp_extra])
            snmp = any(s.port == 161 and s.protocol == "udp" for s in udp_services)
            if snmp:
                commands.extend(
                    [
                        ReconCommand(
                            "snmp-check",
                            f"snmp-check {self.host} -c public | tee recon/snmpcheck_{self.host}.txt",
                        ),
                        ReconCommand(
                            "snmpwalk",
                            f"snmpwalk -Os -c public -v1 {self.host} | tee recon/snmpwalk_{self.host}.txt",
                        ),
                    ]
                )

        ldap = any(s.port == 389 for s in services)
        if ldap:
            commands.extend(
                [
                    ReconCommand(
                        "ldapsearch",
                        f"ldapsearch -x -h {self.host} -s base | tee recon/ldapsearch_{self.host}.txt",
                    ),
                    ReconCommand(
                        "ldapsearch",
                        f"ldapsearch -x -h {self.host} -b \"$(grep rootDomainNamingContext recon/ldapsearch_{self.host}.txt | cut -d ' ' -f2)\" "
                        f"| tee recon/ldapsearch_DC_{self.host}.txt",
                    ),
                ]
            )

        smb = any(s.port == 445 for s in services)
        if smb:
            commands.extend(
                [
                    ReconCommand(
                        "smbmap",
                        f"smbmap -H {self.host} | tee recon/smbmap_{self.host}.txt",
                    ),
                    ReconCommand(
                        "smbclient",
                        f"smbclient -L //{self.host}/ -N | tee recon/smbclient_{self.host}.txt",
                    ),
                ]
            )
            if (self.os_guess or "").startswith("Windows"):
                commands.append(
                    ReconCommand(
                        "nmap",
                        f"nmap -Pn -p445 --script vuln -oN recon/SMB_vulns_{self.host}.txt {self.host}",
                    )
                )
            else:
                commands.append(
                    ReconCommand(
                        "enum4linux",
                        f"enum4linux -a {self.host} | tee recon/enum4linux_{self.host}.txt",
                    )
                )
        elif any(s.port == 139 for s in services) and (self.os_guess or "").startswith("Linux"):
            commands.append(
                ReconCommand(
                    "enum4linux",
                    f"enum4linux -a {self.host} | tee recon/enum4linux_{self.host}.txt",
                )
            )

        oracle = any(s.port == 1521 for s in services)
        if oracle:
            commands.extend(
                [
                    ReconCommand(
                        "odat",
                        f"odat sidguesser -s {self.host} -p 1521",
                    ),
                    ReconCommand(
                        "odat",
                        f"odat passwordguesser -s {self.host} -p 1521 -d XE --accounts-file accounts/accounts-multiple.txt",
                    ),
                ]
            )

        return commands

    def _run_selected_scanners(self) -> None:
        if not self.selected_scanners:
            return
        recon_commands = self._build_recon_recommendations()
        if not recon_commands:
            self.log("Selected scanners requested but no recon data is available yet.")
            return
        lookup: Dict[str, List[str]] = {}
        for cmd in recon_commands:
            lookup.setdefault(cmd.tool.lower(), []).append(cmd.command)

        chosen: List[str] = []
        for name in self.selected_scanners:
            chosen.extend(lookup.get(name, []))

        deduped: List[str] = []
        seen = set()
        for command in chosen:
            if command in seen:
                continue
            seen.add(command)
            deduped.append(command)

        if not deduped:
            self.log("Selected scanners are not applicable to this host.")
            return

        human_readable = ", ".join(self.options.selected_scanners)
        self.log(f"Running selected scanners: {human_readable}")
        self._execute_recon_commands(deduped)

    def _collect_services(self, files: Sequence[Path]) -> List["ServiceLine"]:
        services: List[ServiceLine] = []
        for file in files:
            if not file.exists():
                continue
            with file.open(encoding="utf-8", errors="ignore") as handle:
                for raw in handle:
                    match = SERVICE_LINE.match(raw.strip())
                    if match:
                        port = int(match.group(1))
                        protocol = match.group(2)
                        service = match.group(3)
                        extra = match.group(4).strip()
                        services.append(ServiceLine(port, protocol, service, extra))
        return services

    def _extract_cms(self, script_file: Path) -> List[Tuple[str, int]]:
        if not script_file.exists():
            return []
        cms_entries: List[Tuple[str, int]] = []
        with script_file.open(encoding="utf-8", errors="ignore") as handle:
            content = handle.read()
        for match in re.finditer(r"http-generator: (.+)", content):
            cms = match.group(1).strip()
            port_match = re.search(
                r"(\d+)/(tcp|udp)\s+open\s+\S+.*http-generator: " + re.escape(cms),
                content,
            )
            if port_match:
                cms_entries.append((cms, int(port_match.group(1))))
        return cms_entries

    def _execute_recon_commands(self, commands: Sequence[str]) -> None:
        available = []
        missing_tools = set()
        for command in commands:
            tool = command.split()[0]
            if which(tool):
                available.append(command)
            else:
                missing_tools.add(tool)

        if missing_tools:
            self.log(
                "Skipping recon tools that are not installed: "
                + ", ".join(sorted(missing_tools))
            )
        if not available:
            self.log("No recon commands can be executed with the current toolset.")
            return

        for command in available:
            self.log(f"Running recon command: {command}")
            with (self.output_root / "recon" / "recon.log").open("a", encoding="utf-8") as log_file:
                log_file.write(f"$ {command}\n")
                process = subprocess.Popen(
                    command,
                    cwd=self.output_root,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                assert process.stdout is not None
                for line in process.stdout:
                    self.log(line.rstrip())
                    log_file.write(line)
                process.wait()

    def _should_try_sudo(self) -> bool:
        if platform.system().lower() == "windows":
            return False
        if hasattr(os, "geteuid") and os.geteuid() == 0:  # type: ignore[attr-defined]
            return False
        return which("sudo") is not None

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return False
        return True


@dataclass
class ServiceLine:
    port: int
    protocol: str
    service: str
    extra: str


@dataclass
class ReconCommand:
    tool: str
    command: str
