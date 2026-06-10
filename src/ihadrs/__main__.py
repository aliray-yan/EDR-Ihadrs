"""
Module: __main__
Purpose: CLI entry point for IHADRS. Invoked via `python -m ihadrs` or the
         `ihadrs` console script installed by pip.
Owner: core
Dependencies: click, rich, ihadrs.app, ihadrs.constants
Performance: Minimal — this is the thin CLI layer only.

Commands:
    ihadrs start      — Start the IHADRS daemon (monitoring + detection)
    ihadrs stop       — Stop a running IHADRS instance
    ihadrs status     — Show current status and health
    ihadrs train      — Train the ML baseline model
    ihadrs retrain    — Retrain the ML model on new data
    ihadrs ui         — Launch the PyQt6 dashboard
    ihadrs api        — Start the REST API server only
    ihadrs scan       — Run a one-shot threat scan
    ihadrs export     — Export logs and events
    ihadrs version    — Show version information
    ihadrs config     — Validate and show configuration
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ihadrs.constants import (
    APP_FULL_NAME,
    APP_NAME,
    APP_URL,
    APP_VERSION,
    IS_WINDOWS,
    PLATFORM,
)
from ihadrs.exceptions import ConfigurationError, IHADRSError

# Rich console for styled output
console = Console()
error_console = Console(stderr=True, style="red")


# =============================================================================
# HELPERS
# =============================================================================

def _check_admin_privileges() -> bool:
    """Return True if the process has administrator/root privileges."""
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    else:
        return os.geteuid() == 0  # type: ignore[attr-defined]


def _require_admin(ctx: click.Context) -> None:
    """
    Exit with a helpful error if not running as administrator.

    Most IHADRS commands require admin for kernel-level monitoring APIs.
    """
    if not _check_admin_privileges():
        console.print(
            Panel(
                Text.from_markup(
                    "[bold red]❌ Administrator Privileges Required[/]\n\n"
                    "IHADRS requires administrator/root privileges to access\n"
                    "system-level APIs for process, network, and kernel monitoring.\n\n"
                    "[bold]Windows:[/] Right-click your terminal → 'Run as administrator'\n"
                    "[bold]Linux:[/]   Run with [cyan]sudo python -m ihadrs[/]"
                ),
                border_style="red",
                title="[red]Access Denied[/]",
            )
        )
        ctx.exit(1)


def _get_config_path(config_override: str | None) -> Path:
    """Resolve configuration file path from CLI override or default."""
    if config_override:
        path = Path(config_override)
        if not path.exists():
            error_console.print(f"Config file not found: {path}")
            sys.exit(1)
        return path

    # Search for config in standard locations
    candidates = [
        Path("config/settings.yaml"),           # Dev: repo root
        Path.home() / ".ihadrs" / "settings.yaml",  # User
        Path("/etc/ihadrs/settings.yaml"),       # Linux system-wide
    ]
    if IS_WINDOWS:
        candidates.append(
            Path(os.environ.get("PROGRAMDATA", "C:/ProgramData"))
            / "IHADRS"
            / "settings.yaml"
        )

    for candidate in candidates:
        if candidate.exists():
            return candidate

    # Fall back to repo default (useful in development)
    return Path("config/settings.yaml")


# =============================================================================
# MAIN CLI GROUP
# =============================================================================

@click.group(
    context_settings={"help_option_names": ["-h", "--help"], "max_content_width": 100},
)
@click.version_option(
    version=APP_VERSION,
    prog_name=APP_NAME,
    message=f"%(prog)s %(version)s — {APP_FULL_NAME}",
)
@click.option(
    "--config",
    "-c",
    metavar="PATH",
    help="Path to settings.yaml. Overrides default search path.",
    envvar="IHADRS_CONFIG_PATH",
    default=None,
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                      case_sensitive=False),
    default=None,
    help="Override log level from configuration.",
    envvar="IHADRS_LOG_LEVEL",
)
@click.option(
    "--no-color",
    is_flag=True,
    default=False,
    help="Disable colored output.",
)
@click.pass_context
def main(
    ctx: click.Context,
    config: Optional[str],
    log_level: Optional[str],
    no_color: bool,
) -> None:
    """
    \b
    ██╗██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗
    ██║██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝
    ██║███████║███████║██║  ██║██████╔╝███████╗
    ██║██╔══██║██╔══██║██║  ██║██╔══██╗╚════██║
    ██║██║  ██║██║  ██║██████╔╝██║  ██║███████║
    ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝

    Intelligent Host-Based Attack Detection and Response System

    Use --help on any subcommand for detailed usage.
    Documentation: https://ihadrs.readthedocs.io
    """
    if no_color:
        import rich
        rich.reconfigure(no_color=True)  # type: ignore[attr-defined]

    # Store shared state in Click context object
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = _get_config_path(config)
    ctx.obj["log_level"] = log_level
    ctx.obj["no_color"] = no_color


# =============================================================================
# ihadrs start
# =============================================================================

@main.command()
@click.option(
    "--daemon", "-d",
    is_flag=True,
    default=False,
    help="Run in background as a daemon process.",
)
@click.option(
    "--no-ui",
    is_flag=True,
    default=False,
    help="Start without launching the dashboard UI.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Start in dry-run mode — detect but do not execute any responses.",
    envvar="IHADRS_RESPONSE_DRY_RUN",
)
@click.pass_context
def start(
    ctx: click.Context,
    daemon: bool,
    no_ui: bool,
    dry_run: bool,
) -> None:
    """
    Start the IHADRS monitoring daemon.

    Launches all configured monitors, the detection engine, classification
    system, and alerting channels. Press Ctrl+C to stop gracefully.

    Requires administrator/root privileges.

    Examples:

    \b
        ihadrs start                    # Interactive mode with console output
        ihadrs start --daemon           # Background daemon
        ihadrs start --dry-run          # Monitor without automated responses
        ihadrs start --no-ui            # Headless (no dashboard)
    """
    _require_admin(ctx)

    config_path: Path = ctx.obj["config_path"]
    log_level: str | None = ctx.obj["log_level"]

    console.print(
        Panel(
            f"[bold green]{APP_FULL_NAME}[/]\n"
            f"Version: {APP_VERSION} | Platform: {PLATFORM.capitalize()}\n"
            f"Config: {config_path}\n"
            f"Mode: {'Dry Run' if dry_run else 'Active Response'} | "
            f"UI: {'Disabled' if no_ui else 'Enabled'}",
            title="[bold]🛡️  IHADRS Starting[/]",
            border_style="green",
        )
    )

    if dry_run:
        console.print(
            "[yellow]⚠  DRY RUN MODE: All response actions will be logged "
            "but NOT executed.[/]"
        )

    # Lazy import to keep startup fast
    from ihadrs.core.config import ConfigLoader

    try:
        config = ConfigLoader.load(config_path)
        if log_level:
            config.logging.level = log_level  # type: ignore[assignment]
        if dry_run:
            config.response.mode = "manual"  # type: ignore[assignment]
    except ConfigurationError as exc:
        error_console.print(f"[red]❌ Configuration Error:[/] {exc}")
        ctx.exit(1)
        return

    from ihadrs.app import Application

    app = Application(config)

    try:
        asyncio.run(app.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]⏹  Shutdown requested — stopping gracefully...[/]")
    except IHADRSError as exc:
        error_console.print(f"[red]❌ Fatal Error:[/] {exc}")
        ctx.exit(1)
    finally:
        console.print("[green]✅ IHADRS stopped.[/]")


# =============================================================================
# ihadrs stop
# =============================================================================

@main.command()
@click.option(
    "--timeout",
    default=10,
    show_default=True,
    metavar="SECONDS",
    help="Maximum seconds to wait for graceful shutdown.",
)
@click.pass_context
def stop(ctx: click.Context, timeout: int) -> None:
    """
    Stop a running IHADRS daemon.

    Sends a graceful shutdown signal to the running IHADRS process.
    If the process does not stop within TIMEOUT seconds, it will be
    forcefully terminated.
    """
    console.print("[yellow]Sending shutdown signal to IHADRS daemon...[/]")

    # TODO: Implement IPC/PID-file based shutdown signal in Phase 1
    console.print(
        "[dim]Note: Daemon stop not yet implemented. "
        "Press Ctrl+C in the running terminal.[/]"
    )


# =============================================================================
# ihadrs status
# =============================================================================

@main.command()
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output status as JSON (for scripting/automation).",
)
@click.pass_context
def status(ctx: click.Context, output_json: bool) -> None:
    """
    Show current IHADRS status and component health.

    Displays:
      - Running state of all monitors
      - Detection engine status
      - ML model status
      - Event queue depth
      - Resource usage
      - Recent alert count
    """
    # TODO: Query running instance via API in Phase 8
    import json

    status_data = {
        "version": APP_VERSION,
        "platform": PLATFORM,
        "running": False,  # Will be True when daemon is running
        "config_path": str(ctx.obj["config_path"]),
        "message": (
            "IHADRS is not currently running. "
            "Start with: ihadrs start"
        ),
    }

    if output_json:
        click.echo(json.dumps(status_data, indent=2))
        return

    table = Table(title="IHADRS Status", show_header=True, header_style="bold cyan")
    table.add_column("Component", style="bold")
    table.add_column("Status")
    table.add_column("Details")

    table.add_row("Daemon", "[red]Stopped[/]", "Run: ihadrs start")
    table.add_row("Version", APP_VERSION, f"Platform: {PLATFORM}")
    table.add_row("Config", str(ctx.obj["config_path"]), "")

    console.print(table)


# =============================================================================
# ihadrs train
# =============================================================================

@main.command()
@click.option(
    "--duration",
    "-t",
    default=600,
    show_default=True,
    metavar="SECONDS",
    help="Observation duration for baseline data collection.",
)
@click.option(
    "--output",
    "-o",
    default="config/baseline_model.pkl",
    show_default=True,
    metavar="PATH",
    help="Output path for the trained model file.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite existing model without prompting.",
)
@click.pass_context
def train(
    ctx: click.Context,
    duration: int,
    output: str,
    force: bool,
) -> None:
    """
    Train the ML behavioral anomaly baseline model.

    IHADRS observes your system for DURATION seconds during normal
    operation to learn what 'normal' looks like. Subsequent monitoring
    will flag deviations from this baseline.

    \b
    IMPORTANT: Run this on a CLEAN system with no malware present.
    The quality of detection depends on a clean baseline.

    \b
    Recommended:
      - Duration: 10 minutes minimum (600s), 30+ minutes is better
      - Run while doing your normal work (browsing, coding, etc.)
      - Do NOT run after a suspected infection

    Examples:

    \b
        ihadrs train                          # 10-minute baseline
        ihadrs train --duration 1800          # 30-minute baseline
        ihadrs train --output /custom/path/model.pkl
    """
    _require_admin(ctx)

    output_path = Path(output)
    if output_path.exists() and not force:
        if not click.confirm(
            f"Model file already exists at {output_path}. Overwrite?"
        ):
            console.print("[yellow]Training cancelled.[/]")
            return

    console.print(
        Panel(
            f"[bold]Starting ML baseline training[/]\n"
            f"Duration: {duration}s ({duration // 60}m {duration % 60}s)\n"
            f"Output: {output_path}\n\n"
            "[yellow]Use your computer normally during training.\n"
            "The more varied your normal activity, the better the model.[/]",
            title="🧠 ML Baseline Training",
            border_style="cyan",
        )
    )

    from ihadrs.classification.ml_classifier import MLClassifier
    from ihadrs.core.config import ConfigLoader

    try:
        config = ConfigLoader.load(ctx.obj["config_path"])
        classifier = MLClassifier(config)
        asyncio.run(classifier.train_baseline(
            duration_seconds=duration,
            output_path=output_path,
        ))
        console.print(f"\n[green]✅ Baseline model saved to: {output_path}[/]")
    except IHADRSError as exc:
        error_console.print(f"[red]❌ Training failed:[/] {exc}")
        ctx.exit(1)


# =============================================================================
# ihadrs retrain
# =============================================================================

@main.command()
@click.option(
    "--validate",
    is_flag=True,
    default=False,
    help="Validate new model against historical alerts before replacing.",
)
@click.pass_context
def retrain(ctx: click.Context, validate: bool) -> None:
    """
    Retrain the ML model on accumulated behavioral data.

    Uses the event database to retrain on validated normal behavior
    patterns since the last training run.

    Typically run weekly via the scheduler. Can also be triggered manually
    after significant system changes (new software installed, etc.).
    """
    _require_admin(ctx)
    console.print("[cyan]Retraining ML model on accumulated data...[/]")
    # TODO: Implement in Phase 4
    console.print("[dim]Retraining not yet implemented (Phase 4).[/]")


# =============================================================================
# ihadrs scan
# =============================================================================

@main.command()
@click.option(
    "--output-format",
    type=click.Choice(["table", "json", "csv"], case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format for scan results.",
)
@click.option(
    "--severity",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
    default=None,
    help="Only show findings at this severity or above.",
)
@click.pass_context
def scan(
    ctx: click.Context,
    output_format: str,
    severity: Optional[str],
) -> None:
    """
    Run a one-shot threat scan of the current system state.

    Performs a point-in-time analysis of:
      - Running processes (suspicious names, paths, parents)
      - Active network connections (unusual ports, C2 patterns)
      - Startup/persistence locations (registry, startup folder)
      - Recently modified files in high-risk paths
      - Windows services (unsigned, unusual paths)

    This is a snapshot scan, not continuous monitoring.
    Use `ihadrs start` for real-time protection.
    """
    _require_admin(ctx)
    console.print(
        Panel(
            "[bold]Running system threat scan...[/]\n"
            "This may take 30-60 seconds.",
            title="🔍 One-Shot Scan",
            border_style="blue",
        )
    )
    # TODO: Implement in Phase 3
    console.print("[dim]One-shot scan not yet implemented (Phase 3).[/]")


# =============================================================================
# ihadrs ui
# =============================================================================

@main.command(name="ui")
@click.option(
    "--connect",
    metavar="HOST:PORT",
    default=None,
    help="Connect to a remote IHADRS API instance instead of local.",
)
@click.pass_context
def launch_ui(ctx: click.Context, connect: Optional[str]) -> None:
    """
    Launch the IHADRS graphical dashboard (PyQt6).

    Requires the [ui] optional dependency group:

    \b
        pip install ihadrs[ui]

    The dashboard connects to the running IHADRS daemon via the local
    REST API. The daemon must be running first (`ihadrs start`).
    """
    try:
        from PyQt6.QtWidgets import QApplication  # noqa: F401
    except ImportError:
        error_console.print(
            "[red]❌ PyQt6 is not installed.[/]\n"
            "Install the UI dependencies:\n"
            "  [bold]pip install ihadrs[ui][/]"
        )
        ctx.exit(1)
        return

    console.print("[cyan]Launching IHADRS dashboard...[/]")
    # TODO: Implement in Phase 7
    console.print("[dim]Dashboard not yet implemented (Phase 7).[/]")


# =============================================================================
# ihadrs api
# =============================================================================

@main.command(name="api")
@click.option(
    "--host",
    default="127.0.0.1",
    show_default=True,
    help="API server bind address.",
    envvar="IHADRS_API_HOST",
)
@click.option(
    "--port",
    default=8765,
    show_default=True,
    type=int,
    help="API server port.",
    envvar="IHADRS_API_PORT",
)
@click.option(
    "--reload",
    is_flag=True,
    default=False,
    help="Enable auto-reload for development (do NOT use in production).",
)
@click.pass_context
def start_api(
    ctx: click.Context,
    host: str,
    port: int,
    reload: bool,
) -> None:
    """
    Start only the REST API server (without full daemon).

    Useful for scenarios where IHADRS is running as a service and you
    want to start the API endpoint separately.
    """
    _require_admin(ctx)

    if reload:
        console.print("[yellow]⚠  Auto-reload enabled — development mode.[/]")

    console.print(f"[cyan]Starting IHADRS API server on http://{host}:{port}[/]")
    # TODO: Implement in Phase 8
    console.print("[dim]REST API not yet implemented (Phase 8).[/]")


# =============================================================================
# ihadrs export
# =============================================================================

@main.command()
@click.option(
    "--output", "-o",
    metavar="PATH",
    default="./ihadrs_export",
    show_default=True,
    help="Output directory for exported files.",
)
@click.option(
    "--format",
    "export_format",
    type=click.Choice(["json", "csv", "jsonl"], case_sensitive=False),
    default="json",
    show_default=True,
    help="Export file format.",
)
@click.option(
    "--days",
    default=30,
    show_default=True,
    metavar="N",
    help="Export events from the last N days.",
)
@click.option(
    "--include-audit",
    is_flag=True,
    default=False,
    help="Include audit log in export.",
)
@click.pass_context
def export(
    ctx: click.Context,
    output: str,
    export_format: str,
    days: int,
    include_audit: bool,
) -> None:
    """
    Export security events and alerts to files.

    Useful for:
      - Sending data to a SIEM
      - Creating incident reports
      - Backing up historical data
      - Sharing with security analysts

    Examples:

    \b
        ihadrs export                             # Last 30 days, JSON
        ihadrs export --days 7 --format csv       # 7 days, CSV
        ihadrs export --include-audit --output /tmp/ir/
    """
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)

    console.print(
        f"[cyan]Exporting last {days} days of events to {output_path} "
        f"({export_format.upper()})...[/]"
    )
    # TODO: Implement in Phase 1 (event store)
    console.print("[dim]Export not yet implemented (requires event store).[/]")


# =============================================================================
# ihadrs config
# =============================================================================

@main.command(name="config")
@click.option(
    "--validate-only",
    is_flag=True,
    default=False,
    help="Only validate — do not print configuration values.",
)
@click.option(
    "--show-secrets",
    is_flag=True,
    default=False,
    help="Show sensitive values like API tokens (DANGEROUS in shared environments).",
)
@click.pass_context
def show_config(
    ctx: click.Context,
    validate_only: bool,
    show_secrets: bool,
) -> None:
    """
    Validate and display current IHADRS configuration.

    Useful for debugging configuration issues. Sensitive values
    (API tokens, SMTP passwords) are masked by default.
    """
    config_path: Path = ctx.obj["config_path"]

    console.print(f"[cyan]Loading configuration from: {config_path}[/]")

    from ihadrs.core.config import ConfigLoader

    try:
        config = ConfigLoader.load(config_path)
        console.print("[green]✅ Configuration is valid.[/]")
    except ConfigurationError as exc:
        error_console.print(f"[red]❌ Configuration Error:[/] {exc}")
        ctx.exit(1)
        return

    if validate_only:
        return

    # Display config summary
    table = Table(
        title=f"IHADRS Configuration ({config_path})",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Setting", style="bold")
    table.add_column("Value")

    def _mask(value: str) -> str:
        if show_secrets:
            return value
        return value[:4] + "****" if len(value) > 4 else "****"

    table.add_row("App Name", config.app.name)  # type: ignore[attr-defined]
    table.add_row("Log Level", config.logging.level)  # type: ignore[attr-defined]
    table.add_row("Response Mode", config.response.mode)  # type: ignore[attr-defined]
    table.add_row("ML Enabled", str(config.ml.enabled))  # type: ignore[attr-defined]
    table.add_row("API Enabled", str(config.api.enabled))  # type: ignore[attr-defined]
    table.add_row(
        "API Token",
        _mask(config.api.token) if config.api.token else "[dim]not set[/]",  # type: ignore[attr-defined]
    )
    table.add_row("Email Alerts", str(config.alerting.email.enabled))  # type: ignore[attr-defined]
    table.add_row("Webhook Alerts", str(config.alerting.webhook.enabled))  # type: ignore[attr-defined]

    console.print(table)


# =============================================================================
# ihadrs version
# =============================================================================

@main.command(name="version")
def show_version() -> None:
    """Display detailed version and environment information."""
    import platform

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold")
    table.add_column("Value", style="cyan")

    table.add_row("IHADRS Version", APP_VERSION)
    table.add_row("Python Version", platform.python_version())
    table.add_row("Platform", f"{PLATFORM.capitalize()} ({platform.machine()})")
    table.add_row("OS", platform.platform())
    table.add_row("Homepage", APP_URL)

    console.print(
        Panel(table, title=f"[bold]🛡️  {APP_NAME}[/]", border_style="green")
    )


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    main(obj={})