import sys
import logging
from urllib.parse import urlparse

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.models import ScanResult, Severity

console = Console()

BANNER = """
[bold blue]
   ____  _    _  ___   _____ _____    _____                                 
  / __ \\| |  | |/ _ \\ / ____|  __ \\  / ____|                                
 | |  | | |  | | |_| | (___ | |__) || (___   ___ __ _ _ __  _ __   ___ _ __ 
 | |  | | |/\\| |  _  |\\___ \\|  ___/  \\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|
 | |__| \\  /\\  / | | |____) | |      ____) | (_| (_| | | | | | | |  __/ |   
  \\____/ \\/  \\/|_| |_|_____/|_|     |_____/ \\___\\__,_|_| |_|_| |_|\\___|_|   
[/bold blue]
[dim]Security Testing Tool - Based on OWASP Top 10:2025[/dim]
"""


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()]
    )
    if not verbose:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)


def validate_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    if not parsed.netloc:
        raise click.BadParameter(f"Invalid URL: {url}")

    return url


def display_confirmation(target: str) -> bool:
    console.print(Panel(
        f"""[bold yellow]⚠️  SECURITY TESTING NOTICE[/bold yellow]

You are about to perform security testing on:
[bold cyan]{target}[/bold cyan]

[bold]Please confirm that:[/bold]
  1. This is YOUR OWN system, OR
  2. You have WRITTEN AUTHORIZATION to test this system

[red]Unauthorized testing is ILLEGAL and unethical![/red]
""",
        title="Confirmation Required",
        border_style="yellow"
    ))

    return click.confirm("Do you confirm you have permission to test this target?", default=False)


def display_results_summary(result: ScanResult):
    # Grade colors
    grade_colors = {
        "A": "green",
        "B": "blue",
        "C": "yellow",
        "D": "orange1",
        "F": "red"
    }
    grade_color = grade_colors.get(result.grade, "white")

    # Summary panel
    console.print(Panel(
        f"""[bold]Scan Complete![/bold]

Target: [cyan]{result.target_url}[/cyan]
Duration: {(result.end_time - result.start_time).total_seconds():.1f} seconds
Total Requests: {result.total_requests}

[bold {grade_color}]Grade: {result.grade} ({result.score}/100)[/bold {grade_color}]
""",
        title="📊 Scan Summary",
        border_style=grade_color
    ))

    # Findings table
    if result.findings:
        table = Table(title="🔍 Security Findings")
        table.add_column("Severity", style="bold")
        table.add_column("Title")
        table.add_column("OWASP")

        severity_styles = {
            Severity.CRITICAL: "bold magenta",
            Severity.HIGH: "bold red",
            Severity.MEDIUM: "bold yellow",
            Severity.LOW: "bold blue",
            Severity.INFO: "dim"
        }

        for finding in result.findings:
            style = severity_styles.get(finding.severity, "")
            owasp = ", ".join(finding.owasp_categories[:2]) if finding.owasp_categories else "-"
            table.add_row(
                finding.severity.value.upper(),
                finding.title[:50] + "..." if len(finding.title) > 50 else finding.title,
                owasp,
                style=style
            )

        console.print(table)
    else:
        console.print("[green]✅ No security findings![/green]")

    # Endpoints summary
    if result.endpoints:
        console.print(f"\n[bold]📍 Discovered Endpoints:[/bold] {len(result.endpoints)}")
        important = [e for e in result.endpoints if e.priority in ["critical", "high"]][:5]
        if important:
            for ep in important:
                priority_color = "magenta" if ep.priority == "critical" else "red"
                console.print(f"  [{priority_color}]●[/{priority_color}] {ep.path} ({ep.status_code or 'N/A'})")

    # Headers summary
    if result.headers:
        missing = [h for h in result.headers if not h.present]
        if missing:
            console.print(f"\n[bold]⚠️  Missing Security Headers:[/bold]")
            for h in missing[:5]:
                console.print(f"  [red]✗[/red] {h.name}")

    # Cookies summary
    if result.cookies:
        insecure = [c for c in result.cookies if c.score < 70]
        if insecure:
            console.print(f"\n[bold]🍪 Insecure Cookies:[/bold]")