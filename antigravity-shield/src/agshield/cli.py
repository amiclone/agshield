"""
AntiGravity Shield — CLI Interface
===================================
Command-line interface for managing the AntiGravity Shield.

Usage:
    agshield start        Start the detection engine
    agshield stop         Stop the detection engine
    agshield status       Check if the engine is running
    agshield config       Show current configuration
    agshield report       View the latest detection report
    agshield test         Run the test harness
    agshield version      Show version information
"""

import os
import sys
import json
import signal
import time
import logging
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from agshield import __version__
from agshield.config import Config
from agshield.detection.engine import DetectionEngine
from agshield.utils.platform import (
    get_default_run_dir, get_default_log_dir, get_default_data_dir,
    get_executable_name, is_windows
)

console = Console()

# Platform-appropriate paths (resolved at runtime)
def _get_pid_file():
    return str(get_default_run_dir() / "shield.pid")

def _get_log_dir():
    return str(get_default_log_dir())


def _setup_logging(log_level: str = "INFO", log_file: Optional[str] = None):
    """Set up logging for the CLI."""
    log_dir = Path(_get_log_dir())
    log_dir.mkdir(parents=True, exist_ok=True)

    log_path = log_file or str(log_dir / "shield.log")

    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=[
            logging.FileHandler(log_path),
            logging.StreamHandler(sys.stderr),
        ],
    )


def _get_pid() -> Optional[int]:
    """Get the PID of the running shield process."""
    pid_file = _get_pid_file()
    if os.path.exists(pid_file):
        try:
            with open(pid_file, "r") as f:
                pid = int(f.read().strip())
            # Check if process is actually running
            os.kill(pid, 0)
            return pid
        except (ValueError, ProcessLookupError, PermissionError):
            return None
    return None


def _write_pid(pid: int) -> None:
    """Write the current PID to the PID file."""
    pid_file = _get_pid_file()
    os.makedirs(os.path.dirname(pid_file), exist_ok=True)
    with open(pid_file, "w") as f:
        f.write(str(pid))


def _remove_pid() -> None:
    """Remove the PID file."""
    pid_file = _get_pid_file()
    if os.path.exists(pid_file):
        os.remove(pid_file)


@click.group()
@click.version_option(version=__version__, prog_name="antigravity-shield")
def main():
    """AntiGravity Shield — Real-time AI anti-forensic detection."""
    pass


@main.command()
@click.option("--config", "-c", "config_path", type=click.Path(exists=True),
              help="Path to configuration file")
@click.option("--watch", "-w", "watch_paths", multiple=True,
              help="Directories to monitor (can be specified multiple times)")
@click.option("--no-canaries", is_flag=True,
              help="Disable canary file deployment")
@click.option("--canary-count", type=int, default=3,
              help="Number of canary files per directory (default: 3)")
@click.option("--log-level", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
              default="INFO", help="Logging level")
@click.option("--daemonize", "-d", is_flag=True,
              help="Run as a background daemon")
def start(config_path, watch_paths, no_canaries, canary_count, log_level, daemonize):
    """Start the AntiGravity Shield detection engine."""

    if _get_pid():
        console.print("[yellow]⚠️  Shield is already running.[/yellow]")
        return

    _setup_logging(log_level)

    # Load config
    config = Config(config_path)

    # Override watch paths if specified
    if watch_paths:
        config._config["general"]["watch_paths"] = list(watch_paths)

    if daemonize:
        # Fork to background
        pid = os.fork()
        if pid > 0:
            console.print(f"[green]✅ Shield started as daemon (PID: {pid})[/green]")
            _write_pid(pid)
            return

        # Child process
        os.setsid()
        _write_pid(os.getpid())

        # Redirect stdout/stderr
        sys.stdout = open(os.devnull, "w")
        sys.stderr = open(os.devnull, "w")

    # Create and start the engine
    engine = DetectionEngine(config)

    # Handle signals
    def handle_signal(signum, frame):
        console.print("\n[yellow][SHIELD] Shutting down...[/yellow]")
        engine.stop()
        _remove_pid()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    engine.start(deploy_canaries=not no_canaries, canary_count=canary_count)
    engine.wait()


@main.command()
def stop():
    """Stop the AntiGravity Shield detection engine."""
    pid = _get_pid()
    if pid is None:
        console.print("[yellow]⚠️  Shield is not running.[/yellow]")
        return

    try:
        os.kill(pid, signal.SIGTERM)
        console.print(f"[green]✅ Shield stopped (PID: {pid})[/green]")
    except ProcessLookupError:
        console.print("[yellow]⚠️  Process not found, cleaning up PID file.[/yellow]")
    except PermissionError:
        console.print("[red]❌ Permission denied. Try with sudo.[/red]")
        return

    _remove_pid()


@main.command()
def status():
    """Check if the AntiGravity Shield is running."""
    pid = _get_pid()
    if pid is None:
        console.print("[red]❌ Shield is not running.[/red]")
        return

    console.print(f"[green]✅ Shield is running (PID: {pid})[/green]")

    # Show uptime
    try:
        import psutil
        process = psutil.Process(pid)
        uptime = time.time() - process.create_time()
        hours = int(uptime // 3600)
        minutes = int((uptime % 3600) // 60)
        seconds = int(uptime % 60)
        console.print(f"   Uptime: {hours}h {minutes}m {seconds}s")
        console.print(f"   Memory: {process.memory_info().rss / 1024 / 1024:.1f} MB")
    except (ImportError, psutil.NoSuchProcess):
        pass


@main.command()
@click.option("--config", "-c", "config_path", type=click.Path(exists=True),
              help="Path to configuration file")
@click.option("--show-secrets", is_flag=True,
              help="WARNING: Display sensitive configuration values in plaintext")
def config(config_path, show_secrets):
    """Show the current configuration (sensitive values are masked)."""
    cfg = Config(config_path)

    table = Table(title="AntiGravity Shield Configuration")
    table.add_column("Section", style="cyan")
    table.add_column("Key", style="green")
    table.add_column("Value", style="yellow")

    def flatten_dict(d, prefix=""):
        for key, value in d.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                yield from flatten_dict(value, full_key)
            else:
                yield full_key, value

    if show_secrets:
        console.print("[red]⚠️  WARNING: Displaying secrets in plaintext![/red]")
        config_data = cfg._config
    else:
        config_data = cfg.get_sanitized_config()

    for key, value in flatten_dict(config_data):
        section = key.split(".")[0]
        table.add_row(section, key, str(value))

    console.print(table)


@main.command()
@click.option("--reports-dir", "-r", type=click.Path(exists=True),
              default="/var/lib/antigravity/reports",
              help="Directory containing reports")
@click.option("--latest", "-l", is_flag=True,
              help="Show only the latest report")
def report(reports_dir, latest):
    """View detection reports."""
    reports_path = Path(reports_dir)
    if not reports_path.exists():
        console.print("[red]❌ No reports directory found.[/red]")
        return

    report_files = sorted(reports_path.glob("shield_report_*.json"))
    if not report_files:
        console.print("[yellow]⚠️  No reports found.[/yellow]")
        return

    if latest:
        report_files = [report_files[-1]]

    for report_file in report_files:
        with open(report_file, "r") as f:
            report_data = json.load(f)

        # Print summary
        summary = report_data.get("summary", {})
        console.print(Panel(
            f"[bold]Report:[/bold] {report_file.name}\n"
            f"[bold]Duration:[/bold] {report_data.get('duration_seconds', 'N/A')}s\n"
            f"[bold]Total Alerts:[/bold] {summary.get('total_alerts', 0)}\n"
            f"[bold]By Severity:[/bold] {summary.get('by_severity', {})}\n"
            f"[bold]Log Integrity:[/bold] {'✅ VERIFIED' if report_data.get('log_integrity', {}).get('valid') else '🚨 COMPROMISED'}",
            title="AntiGravity Shield Report",
            border_style="green",
        ))


@main.command()
@click.option("--stealth-trials", type=click.IntRange(min=1), default=30,
              show_default=True, help="Number of stealth mode trials")
@click.option("--noisy-trials", type=click.IntRange(min=0), default=3,
              show_default=True, help="Number of noisy mode trials")
@click.option("--human-trials", type=click.IntRange(min=0), default=1,
              show_default=True, help="Human-speed baseline timing trials")
@click.option("--control-trials", type=click.IntRange(min=1), default=5,
              show_default=True, help="Historical Wazuh control observations")
@click.option("--fp-duration", type=click.IntRange(min=1), default=10,
              show_default=True,
              help="False positive test duration (seconds)")
@click.option("--human-seed", type=int, default=2026, show_default=True,
              help="Seed for reproducible human baseline timing")
@click.option("--agent-path", type=click.Path(exists=True, file_okay=False),
              help="Path to the separately supplied controlled agent package")
@click.option("--reports-dir", type=click.Path(file_okay=False),
              help="Persistent experiment output directory")
@click.option("--single", type=click.Choice(["stealth", "noisy"]),
              help="Run a single trial instead of full experiment")
def test(stealth_trials, noisy_trials, human_trials, control_trials, fp_duration,
         human_seed, agent_path, reports_dir, single):
    """Run the test harness (agent vs shield)."""
    from agshield.test_harness import ExperimentHarness

    harness = ExperimentHarness(agent_dir=agent_path, reports_dir=reports_dir)

    if single:
        result = harness.run_trial(1, mode=single)
        console.print(json.dumps(result, indent=2, default=str))
    else:
        harness.run_experiment(
            stealth_trials=stealth_trials,
            noisy_trials=noisy_trials,
            human_trials=human_trials,
            control_trials=control_trials,
            fp_duration=fp_duration,
            human_seed=human_seed,
        )


if __name__ == "__main__":
    main()
