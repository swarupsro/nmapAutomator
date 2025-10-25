from __future__ import annotations

import csv
import io
import ipaddress
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    render_template,
    request,
    send_file,
)


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_SCRIPT_PATH = BASE_DIR / "automator.py"
SCRIPT_PATH = Path(os.getenv("NMAP_AUTOMATOR_SCRIPT", DEFAULT_SCRIPT_PATH)).resolve()
INTERPRETER = os.getenv("NMAP_AUTOMATOR_INTERPRETER", sys.executable)
OUTPUT_ROOT = Path(os.getenv("NMAP_AUTOMATOR_WEB_OUTPUT", BASE_DIR / "web_output")).resolve()
OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
MAX_LOG_LINES = int(os.getenv("NMAP_AUTOMATOR_MAX_LOG_LINES", "4000"))
MAX_WORKERS = int(os.getenv("NMAP_AUTOMATOR_MAX_WORKERS", "2"))
MAX_TARGETS = int(os.getenv("NMAP_AUTOMATOR_MAX_TARGETS", "256"))
PORT_LINE = re.compile(r"^(\d+)/(tcp|udp)\s+open", re.IGNORECASE)
SERVICE_LINE = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(.*)$", re.IGNORECASE)
SCAN_TYPES = [
    "Network",
    "Port",
    "Script",
    "Full",
    "UDP",
    "Vulns",
    "Recon",
    "All",
]
SCANNER_CHOICES = [
    "nmap Vulners",
    "sslscan",
    "nikto",
    "joomscan",
    "wpscan",
    "droopescan",
    "smbmap",
    "enum4linux",
    "dnsrecon",
    "odat",
    "smtp-user-enum",
    "snmp-check",
    "snmpwalk",
    "ldapsearch",
]


if not SCRIPT_PATH.exists():
    raise FileNotFoundError(f"nmapAutomator CLI not found at {SCRIPT_PATH}")


app = Flask(__name__)


@dataclass
class Job:
    id: str
    host_input: str
    scan_type: str
    options: Dict[str, Optional[str] | List[str]]
    targets: List[str]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    status: str = "queued"
    log: List[str] = field(default_factory=list)
    command: Optional[str] = None
    error: Optional[str] = None
    notes: Optional[str] = None
    output_dir: Path = field(init=False)
    log_file: Optional[Path] = None
    scan_output_dir: Optional[Path] = None
    per_target_logs: Dict[str, List[str]] = field(default_factory=dict)
    per_target_results: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        self.output_dir = OUTPUT_ROOT / self.id

    def start(self) -> None:
        with self._lock:
            self.status = "running"
            self.started_at = datetime.now(timezone.utc)

    def succeed(self) -> None:
        with self._lock:
            self.status = "completed"
            self.finished_at = datetime.now(timezone.utc)

    def fail(self, message: str) -> None:
        with self._lock:
            self.status = "failed"
            self.error = message
            self.finished_at = datetime.now(timezone.utc)

    def append_log(self, line: str) -> None:
        clean_line = line.rstrip("\n")
        with self._lock:
            self.log.append(clean_line)
            if len(self.log) > MAX_LOG_LINES:
                # Keep the newest entries only
                self.log = self.log[-MAX_LOG_LINES :]

    def set_target_log(self, target: str, lines: List[str]) -> None:
        with self._lock:
            self.per_target_logs[target] = lines

    def set_target_results(self, target: str, rows: List[Dict[str, str]]) -> None:
        with self._lock:
            self.per_target_results[target] = rows

    def aggregate_results(self, limit: Optional[int] = None) -> List[Dict[str, str]]:
        rows: List[Dict[str, str]] = []
        for target in self.targets:
            target_rows = self.per_target_results.get(target, [])
            rows.extend(target_rows)
        if limit and len(rows) > limit:
            return rows[:limit]
        return rows

    def csv_rows(self) -> List[Dict[str, str]]:
        return self.aggregate_results()

    def to_dict(self) -> Dict[str, Optional[str]]:
        with self._lock:
            return {
                "id": self.id,
                "host": self.targets[0] if self.targets else self.host_input,
                "hostInput": self.host_input,
                "targets": self.targets,
                "scanType": self.scan_type,
                "options": self.options,
                "status": self.status,
                "notes": self.notes,
                "createdAt": isoformat(self.created_at),
                "startedAt": isoformat(self.started_at),
                "finishedAt": isoformat(self.finished_at),
                "command": self.command,
                "error": self.error,
                "log": "\n".join(self.log),
                "downloadUrl": f"/jobs/{self.id}/download"
                if self.status == "completed"
                else None,
                "results": self.aggregate_results(limit=500),
                "resultsCsvUrl": f"/jobs/{self.id}/results.csv"
                if self.per_target_results
                else None,
                "resultCount": len(self.aggregate_results()),
            }


jobs: Dict[str, Job] = {}
jobs_lock = threading.Lock()
executor = None  # Lazy init for easier testing


def get_executor():
    global executor
    if executor is None:
        from concurrent.futures import ThreadPoolExecutor

        executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    return executor


def isoformat(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return value.isoformat()


def safe_folder_name(raw: Optional[str]) -> str:
    if not raw:
        return "scan"
    clean = "".join(ch if ch.isalnum() or ch in ("-", "_") else "-" for ch in raw.strip())
    return clean or "scan"


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def parse_targets(raw: str) -> List[str]:
    if not raw.strip():
        return []
    tokens = [token.strip() for token in raw.replace(";", ",").split(",")]
    # Allow newline separated values as well
    expanded: List[str] = []
    seen = set()
    for token in tokens:
        if not token:
            continue
        parts = [part.strip() for part in token.splitlines() if part.strip()]
        if len(parts) > 1:
            # Token had newlines; treat each line separately
            for part in parts:
                expanded.extend(_expand_single_target(part, seen))
        else:
            expanded.extend(_expand_single_target(token, seen))
        if len(expanded) > MAX_TARGETS:
            raise ValueError(f"Too many targets requested (limit {MAX_TARGETS})")
    return expanded


def _expand_single_target(token: str, seen: set) -> List[str]:
    results: List[str] = []
    if "/" in token:
        network = ipaddress.ip_network(token, strict=False)
        addresses = [str(ip) for ip in network.hosts()] or [str(network.network_address)]
        for address in addresses:
            _append_target(address, results, seen)
        return results
    if "-" in token and is_ip(token.split("-", 1)[0]):
        start_str, end_str = token.split("-", 1)
        start_str = start_str.strip()
        end_str = end_str.strip()
        start_ip = ipaddress.ip_address(start_str)
        if is_ip(end_str):
            end_ip = ipaddress.ip_address(end_str)
        elif end_str.isdigit():
            prefix = start_str.rsplit(".", 1)[0]
            end_ip = ipaddress.ip_address(f"{prefix}.{end_str}")
        else:
            raise ValueError(f"Invalid IP range token: {token}")
        if start_ip.version != end_ip.version or int(end_ip) < int(start_ip):
            raise ValueError(f"Invalid IP range bounds: {token}")
        for value in range(int(start_ip), int(end_ip) + 1):
            _append_target(str(ipaddress.ip_address(value)), results, seen)
        return results
    # Treat as hostname/IP literal
    _append_target(token, results, seen)
    return results


def _append_target(target: str, bucket: List[str], seen: set) -> None:
    key = target.lower()
    if key in seen:
        return
    seen.add(key)
    bucket.append(target)


def dedupe_lines(lines: Sequence[str]) -> List[str]:
    seen = set()
    unique: List[str] = []
    for line in lines:
        if line in seen:
            continue
        seen.add(line)
        unique.append(line)
    return unique


def collect_results(nmap_dir: Path, target: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    if not nmap_dir.exists():
        return rows
    seen = set()
    for path in sorted(nmap_dir.glob("*.nmap")):
        try:
            with path.open(encoding="utf-8", errors="ignore") as handle:
                for raw in handle:
                    match = SERVICE_LINE.match(raw.strip())
                    if not match:
                        continue
                    port, protocol, service, detail = match.groups()
                    detail = detail.strip()
                    key = (target, port, protocol, service, detail)
                    if key in seen:
                        continue
                    seen.add(key)
                    rows.append(
                        {
                            "target": target,
                            "port": port,
                            "protocol": protocol,
                            "service": service,
                            "detail": detail,
                        }
                    )
        except OSError:
            continue
    return rows


def normalize_scanners(raw: Optional[Sequence[str] | str]) -> List[str]:
    if not raw:
        return []
    if isinstance(raw, str):
        candidates = [item.strip() for item in raw.split(",")]
    else:
        candidates = [str(item).strip() for item in raw]
    normalized: List[str] = []
    lookup = {choice.lower(): choice for choice in SCANNER_CHOICES}
    for item in candidates:
        if not item:
            continue
        key = item.lower()
        choice = lookup.get(key)
        if choice and choice not in normalized:
            normalized.append(choice)
    return normalized


def build_command(job: Job, target: str, target_dir: Path) -> List[str]:
    cmd = [
        INTERPRETER,
        str(SCRIPT_PATH),
        "-H",
        target,
        "-t",
        job.scan_type,
        "-o",
        str(target_dir),
    ]

    dns = job.options.get("dns")
    if dns:
        cmd.extend(["-d", dns])

    static_nmap = job.options.get("staticNmap")
    if static_nmap:
        cmd.extend(["-s", static_nmap])

    if job.options.get("remoteMode"):
        cmd.append("-r")

    if job.options.get("runRecon"):
        cmd.append("--run-recon")

    selected = job.options.get("selectedScanners") or []
    if selected:
        cmd.append("--scanners")
        cmd.extend(selected)

    extra = job.options.get("extraArgs")
    if extra:
        cmd.extend(["--extra", extra])

    if job.notes:
        cmd.extend(["--notes", job.notes])

    return cmd


def run_job(job: Job) -> None:
    job.output_dir.mkdir(parents=True, exist_ok=True)
    scan_dir_name = safe_folder_name(job.options.get("customOutput") or job.id[:8])
    job.scan_output_dir = job.output_dir / scan_dir_name
    job.scan_output_dir.mkdir(parents=True, exist_ok=True)
    job.log_file = job.output_dir / "web.log"

    job.start()
    try:
        with job.log_file.open("w", encoding="utf-8") as log_file:
            for index, target in enumerate(job.targets, start=1):
                target_folder = job.scan_output_dir / safe_folder_name(target)
                target_folder.mkdir(parents=True, exist_ok=True)
                command = build_command(job, target, target_folder)
                if index == 1:
                    job.command = " ".join(shlex.quote(part) for part in command)
                job.append_log(f"=== Target {target} ({index}/{len(job.targets)}) ===")
                log_file.write(f"=== Target {target} ({index}/{len(job.targets)}) ===\n")
                log_file.flush()

                process = subprocess.Popen(
                    command,
                    cwd=BASE_DIR,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )

                assert process.stdout is not None
                target_lines: List[str] = []
                for line in process.stdout:
                    clean = line.rstrip("\n")
                    target_lines.append(clean)
                    job.append_log(line)
                    log_file.write(line)
                    log_file.flush()

                return_code = process.wait()
                job.set_target_log(target, dedupe_lines(target_lines))
                nmap_dir = target_folder / "nmap"
                job.set_target_results(target, collect_results(nmap_dir, target))

                if return_code != 0:
                    job.fail(f"Scan for {target} exited with code {return_code}")
                    return

        job.succeed()
    except FileNotFoundError as exc:
        job.fail(f"Failed to execute command: {exc}")
    except subprocess.SubprocessError as exc:
        job.fail(f"Subprocess error: {exc}")
    except Exception as exc:  # pylint: disable=broad-except
        job.fail(f"Unexpected error: {exc}")


def list_jobs() -> List[Dict[str, Optional[str]]]:
    with jobs_lock:
        return [job.to_dict() for job in jobs.values()]


def get_job_or_404(job_id: str) -> Job:
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        abort(404, description="Job not found")
    return job


@app.get("/")
def index():
    return render_template("index.html", scan_types=SCAN_TYPES, scanner_choices=SCANNER_CHOICES)


@app.get("/jobs")
def jobs_route():
    return jsonify(list_jobs())


@app.get("/jobs/<job_id>")
def job_detail(job_id: str):
    job = get_job_or_404(job_id)
    return jsonify(job.to_dict())


@app.get("/jobs/<job_id>/download")
def job_download(job_id: str):
    job = get_job_or_404(job_id)
    if job.status != "completed" or not job.scan_output_dir or not job.scan_output_dir.exists():
        abort(400, description="Scan output not available yet")

    archive_base = OUTPUT_ROOT / f"{job.id}_results"
    archive_path = shutil.make_archive(str(archive_base), "zip", root_dir=job.scan_output_dir)
    if job.targets:
        name = safe_folder_name(job.targets[0])
    else:
        name = job.id
    download_name = f"{name}_{job.scan_type}.zip"
    return send_file(archive_path, as_attachment=True, download_name=download_name)


@app.get("/jobs/<job_id>/results.csv")
def job_results_csv(job_id: str):
    job = get_job_or_404(job_id)
    rows = job.csv_rows()
    if not rows:
        abort(400, description="No structured results available yet")
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=["target", "port", "protocol", "service", "detail"])
    writer.writeheader()
    writer.writerows(rows)
    buffer.seek(0)
    filename = f"{job.id}_results.csv"
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/scan")
def start_scan():
    payload = request.get_json(silent=True) or request.form or {}

    host_input = (payload.get("hosts") or payload.get("host") or "").strip()
    scan_type = (payload.get("scanType") or payload.get("type") or "").strip()

    if not host_input:
        abort(400, description="At least one host/IP is required")
    try:
        targets = parse_targets(host_input)
    except ValueError as exc:
        abort(400, description=str(exc))
    if not targets:
        abort(400, description="No valid targets found after parsing input")

    if scan_type not in SCAN_TYPES:
        abort(400, description="Invalid scan type")

    options = {
        "dns": (payload.get("dns") or "").strip() or None,
        "staticNmap": (payload.get("staticNmap") or "").strip() or None,
        "remoteMode": bool(payload.get("remoteMode")),
        "customOutput": (payload.get("customOutput") or "").strip() or None,
        "extraArgs": (payload.get("extraArgs") or "").strip() or None,
        "selectedScanners": normalize_scanners(payload.get("selectedScanners")),
    }
    notes = (payload.get("notes") or "").strip() or None

    job = Job(
        id=str(uuid.uuid4()),
        host_input=host_input,
        scan_type=scan_type,
        options=options,
        targets=targets,
        notes=notes,
    )

    with jobs_lock:
        jobs[job.id] = job

    get_executor().submit(run_job, job)

    return jsonify(job.to_dict()), 202


if __name__ == "__main__":
    debug = bool(os.getenv("FLASK_DEBUG", ""))
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=debug)
