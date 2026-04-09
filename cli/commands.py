import sys
import asyncio
from datetime import datetime
from pathlib import Path
from typing import List

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from cli.utils import (
    BANNER,
    setup_logging,
    validate_url,
    display_confirmation,
    display_results_summary,
    console
)
from core.models import ScanResult
from core.session import HTTPSession
from modules.endpoint_discovery import EndpointDiscovery
from modules.header_analyzer import HeaderAnalyzer
from modules.ssl_analyzer import SSLAnalyzer
from modules.sensitive_files import SensitiveFileAnalyzer
from modules.injection_tester import InjectionTester
from modules.auth_tester import AuthTester
from reports.generator import ReportGenerator, get_default_output_dir

# Available modules registry
AVAILABLE_MODULES = {
    "endpoint": {
        "name": "Endpoint Discovery",
        "icon": "🔍",
        "description": "Discovers endpoints via crawling, robots.txt, sitemap, bruteforce",
        "active": False
    },
    "headers": {
        "name": "Header Analyzer",
        "icon": "🔒",
        "description": "Analyzes security headers, cookies, CORS",
        "active": False
    },
    "ssl": {
        "name": "SSL/TLS Analyzer",
        "icon": "🔐",
        "description": "Checks certificates, protocols, cipher suites",
        "active": False
    },
    "files": {
        "name": "Sensitive Files",
        "icon": "📁",
        "description": "Detects exposed .env, .git, config files, credentials",
        "active": False
    },
    "injection": {
        "name": "Injection Tester",
        "icon": "💉",
        "description": "Tests for SQL injection and XSS vulnerabilities",
        "active": True  # WARNING: Active module
    },
    "auth": {
        "name": "Auth Tester",
        "icon": "🔑",
        "description": "Tests authentication and session security",
        "active": True  # WARNING: Active module
    }
}

# Passive modules only (safe)
PASSIVE_MODULES = ["endpoint", "headers", "ssl", "files"]

# Active modules (send payloads)
ACTIVE_MODULES = ["injection", "auth"]


async def run_scan(
        target: str,
        modules: List[str],
        rate_limit: float,
        timeout: int,
        crawl_depth: int,
        no_bruteforce: bool,
        verbose: bool
) -> ScanResult:
    result = ScanResult(target_url=target)

    # Determine which modules to run
    if "all" in modules:
        modules_to_run = list(AVAILABLE_MODULES.keys())
    elif "passive" in modules:
        modules_to_run = PASSIVE_MODULES
    else:
        modules_to_run = modules

    async with HTTPSession(
            timeout=timeout,
            rate_limit=rate_limit,
            verify_ssl=True
    ) as session:

        # Endpoint Discovery
        if "endpoint" in modules_to_run:
            console.print(
                f"\n[bold blue]{AVAILABLE_MODULES['endpoint']['icon']} Running Endpoint Discovery...[/bold blue]")

            discovery = EndpointDiscovery(
                session=session,
                base_url=target,
                crawl_depth=crawl_depth,
                crawl_max_pages=100,
                bruteforce_enabled=not no_bruteforce
            )

            with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
            ) as progress:
                task = progress.add_task("Discovering endpoints...", total=None)
                discovery_result = await discovery.run()
                progress.update(task, completed=True)

            result.endpoints = discovery_result.get("endpoints", [])
            result.findings.extend(discovery_result.get("findings", []))

            stats = discovery_result.get("statistics", {})
            console.print(f"  [green]✓[/green] Found {len(result.endpoints)} endpoints")
            if stats.get("by_priority"):
                console.print(f"  [green]✓[/green] {stats['by_priority']}")

        # Header Analysis
        if "headers" in modules_to_run:
            console.print(f"\n[bold blue]{AVAILABLE_MODULES['headers']['icon']} Running Header Analysis...[/bold blue]")

            analyzer = HeaderAnalyzer(session=session, target_url=target)

            with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
            ) as progress:
                task = progress.add_task("Analyzing headers...", total=None)
                header_result = await analyzer.run()
                progress.update(task, completed=True)

            result.headers = header_result.get("headers", [])
            result.cookies = header_result.get("cookies", [])
            result.cors = header_result.get("cors")
            result.findings.extend(header_result.get("findings", []))
            result.info_disclosures = header_result.get("info_disclosures", [])

            summary = header_result.get("summary", {})
            console.print(f"  [green]✓[/green] Header score: {summary.get('header_score', 0)}/100")
            console.print(f"  [green]✓[/green] Cookie score: {summary.get('cookie_score', 100)}/100")
            console.print(f"  [green]✓[/green] Found {summary.get('findings_count', 0)} issues")

        # SSL/TLS Analysis
        if "ssl" in modules_to_run:
            console.print(f"\n[bold blue]{AVAILABLE_MODULES['ssl']['icon']} Running SSL/TLS Analysis...[/bold blue]")

            ssl_analyzer = SSLAnalyzer(session=session, target_url=target)

            with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
            ) as progress:
                task = progress.add_task("Analyzing SSL/TLS...", total=None)
                ssl_result = await ssl_analyzer.run()
                progress.update(task, completed=True)

            if ssl_result.get("skipped"):
                console.print(f"  [yellow]⚠[/yellow] Skipped: {ssl_result.get('reason')}")
            else:
                result.findings.extend(ssl_result.get("findings", []))
                summary = ssl_result.get("summary", {})

                if summary.get("certificate_valid"):
                    console.print(
                        f"  [green]✓[/green] Certificate valid, expires in {summary.get('days_until_expiry', '?')} days")
                else:
                    console.print(f"  [red]✗[/red] Certificate invalid")

                console.print(f"  [green]✓[/green] Protocol: {summary.get('protocol', 'unknown')}")
                console.print(f"  [green]✓[/green] Found {summary.get('findings_count', 0)} issues")

        # Sensitive Files Analysis
        if "files" in modules_to_run:
            console.print(
                f"\n[bold blue]{AVAILABLE_MODULES['files']['icon']} Running Sensitive Files Analysis...[/bold blue]")

            files_analyzer = SensitiveFileAnalyzer(session=session, target_url=target)

            with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
            ) as progress:
                task = progress.add_task("Checking sensitive files...", total=None)
                files_result = await files_analyzer.run()
                progress.update(task, completed=True)

            result.findings.extend(files_result.get("findings", []))
            summary = files_result.get("summary", {})

            console.print(f"  [green]✓[/green] Checked {summary.get('files_checked', 0)} file paths")

            if summary.get("files_found", 0) > 0:
                console.print(f"  [red]![/red] Found {summary['files_found']} exposed files")
            else:
                console.print(f"  [green]✓[/green] No sensitive files exposed")

            if summary.get("secrets_found", 0) > 0:
                console.print(f"  [red]![/red] Found {summary['secrets_found']} potential secrets")

        # Injection Testing (ACTIVE)
        if "injection" in modules_to_run:
            console.print(
                f"\n[bold yellow]{AVAILABLE_MODULES['injection']['icon']} Running Injection Tester...[/bold yellow] [dim](active)[/dim]")

            injection_tester = InjectionTester(
                session=session,
                target_url=target,
                endpoints=result.endpoints,  # Use discovered endpoints
                test_sqli=True,
                test_xss=True,
                max_tests_per_endpoint=5
            )

            with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
            ) as progress:
                task = progress.add_task("Testing for injections...", total=None)
                injection_result = await injection_tester.run()
                progress.update(task, completed=True)

            result.findings.extend(injection_result.get("findings", []))
            result.injection_results = {  # ÚJ
                "tested_endpoints": injection_result.get("tested_endpoints", []),
                "summary": injection_result.get("summary", {})
            }

            console.print(f"  [green]✓[/green] Tested {summary.get('endpoints_tested', 0)} endpoints")

            if summary.get("sqli_found", 0) > 0:
                console.print(f"  [red]![/red] Found {summary['sqli_found']} potential SQL injection(s)")
            else:
                console.print(f"  [green]✓[/green] No SQL injection found")

            if summary.get("xss_found", 0) > 0:
                console.print(f"  [red]![/red] Found {summary['xss_found']} potential XSS")
            else:
                console.print(f"  [green]✓[/green] No XSS found")

        # Auth Testing (ACTIVE)
        if "auth" in modules_to_run:
            console.print(
                f"\n[bold yellow]{AVAILABLE_MODULES['auth']['icon']} Running Auth Tester...[/bold yellow] [dim](active)[/dim]")

            auth_tester = AuthTester(
                session=session,
                target_url=target,
                test_weak_creds=True,
                test_session=True,
                max_login_attempts=5
            )

            with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
            ) as progress:
                task = progress.add_task("Testing authentication...", total=None)
                auth_result = await auth_tester.run()
                progress.update(task, completed=True)

            result.findings.extend(auth_result.get("findings", []))
            result.auth_results = {  # ÚJ
                "login_forms": auth_result.get("login_forms", []),
                "session_issues": auth_result.get("session_issues", []),
                "summary": auth_result.get("summary", {})
            }

            console.print(f"  [green]✓[/green] Found {summary.get('login_forms_found', 0)} login form(s)")

            if summary.get("weak_creds_found", 0) > 0:
                console.print(f"  [red]![/red] Found {summary['weak_creds_found']} weak credential(s)")
            else:
                console.print(f"  [green]✓[/green] No weak credentials found")

            if summary.get("session_issues", 0) > 0:
                console.print(f"  [yellow]![/yellow] Found {summary['session_issues']} session issue(s)")

        result.total_requests = session.request_count

    result.end_time = datetime.now()
    result.status = "completed"
    result.calculate_grade()

    return result


# Get default output directory for help text
DEFAULT_OUTPUT_DIR = get_default_output_dir()


@click.command()
@click.option("--target", "-t", required=True, help="Target URL to scan")
@click.option("--modules", "-m", default="passive",
              help="Modules: endpoint,headers,ssl,files,injection,auth,passive,all (default: passive)")
@click.option("--output", "-o", default="both",
              help="Output format: json,html,both (default: both)")
@click.option("--output-dir", default=None,
              help=f"Output directory for reports (default: {DEFAULT_OUTPUT_DIR})")
@click.option("--rate-limit", "-r", default=2.0,
              help="Requests per second (default: 2.0)")
@click.option("--timeout", default=10,
              help="Request timeout in seconds (default: 10)")
@click.option("--crawl-depth", default=3,
              help="Maximum crawl depth (default: 3)")
@click.option("--no-bruteforce", is_flag=True,
              help="Disable path bruteforcing")
@click.option("--yes", "-y", is_flag=True,
              help="Skip confirmation prompt")
@click.option("--verbose", "-v", is_flag=True,
              help="Enable verbose output")
def scan(target, modules, output, output_dir, rate_limit, timeout,
         crawl_depth, no_bruteforce, yes, verbose):
    setup_logging(verbose)
    console.print(BANNER)

    # Validate URL
    try:
        target = validate_url(target)
    except click.BadParameter as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    # Parse and validate modules
    module_list = [m.strip().lower() for m in modules.split(",")]
    valid_modules = list(AVAILABLE_MODULES.keys()) + ["all", "passive"]

    for m in module_list:
        if m not in valid_modules:
            console.print(f"[red]Error: Invalid module '{m}'[/red]")
            console.print(f"[dim]Valid modules: {', '.join(valid_modules)}[/dim]")
            sys.exit(1)

    # Determine active modules
    if "all" in module_list:
        active_modules = list(AVAILABLE_MODULES.keys())
    elif "passive" in module_list:
        active_modules = PASSIVE_MODULES
    else:
        active_modules = module_list

    # Check if any active modules are selected
    has_active = any(m in ACTIVE_MODULES for m in active_modules)

    # Show warning for active modules
    if has_active:
        console.print("\n[bold yellow]⚠️  WARNING: Active modules selected![/bold yellow]")
        console.print("[yellow]The following modules will send test payloads to the target:[/yellow]")
        for m in active_modules:
            if m in ACTIVE_MODULES:
                console.print(f"  [yellow]• {AVAILABLE_MODULES[m]['icon']} {AVAILABLE_MODULES[m]['name']}[/yellow]")
        console.print()

    # Confirmation
    if not yes:
        if not display_confirmation(target):
            console.print("[yellow]Scan cancelled.[/yellow]")
            sys.exit(0)

    # Show scan info
    console.print(f"\n[bold]🚀 Starting scan on:[/bold] [cyan]{target}[/cyan]")

    module_display = []
    for m in active_modules:
        if m in ACTIVE_MODULES:
            module_display.append(f"[yellow]{m}[/yellow]")
        else:
            module_display.append(m)

    console.print(f"[dim]Modules: {', '.join(active_modules)} | Rate limit: {rate_limit}/s | Timeout: {timeout}s[/dim]")

    # Run scan
    try:
        result = asyncio.run(run_scan(
            target=target,
            modules=module_list,
            rate_limit=rate_limit,
            timeout=timeout,
            crawl_depth=crawl_depth,
            no_bruteforce=no_bruteforce,
            verbose=verbose
        ))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Error during scan: {e}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    # Display results
    display_results_summary(result)

    # Generate reports
    console.print("\n[bold]📄 Generating Reports...[/bold]")

    try:
        generator = ReportGenerator(result, output_dir)

        console.print(f"  [dim]Output directory: {generator.output_dir}[/dim]")

        if output in ["json", "both"]:
            json_path = generator.generate_json()
            console.print(f"  [green]✓[/green] JSON: {json_path}")

        if output in ["html", "both"]:
            html_path = generator.generate_html()
            console.print(f"  [green]✓[/green] HTML: {html_path}")

    except Exception as e:
        console.print(f"[red]Error generating reports: {e}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()

    console.print("\n[bold green]✅ Scan complete![/bold green]")


@click.command()
def info():
    console.print(BANNER)

    # Modules table
    console.print("\n[bold]Available Modules:[/bold]\n")

    modules_table = Table()
    modules_table.add_column("ID", style="bold cyan")
    modules_table.add_column("Name", style="bold")
    modules_table.add_column("Type")
    modules_table.add_column("Description")

    for mod_id, mod_info in AVAILABLE_MODULES.items():
        mod_type = "[yellow]ACTIVE[/yellow]" if mod_info.get("active") else "[green]passive[/green]"
        modules_table.add_row(
            mod_id,
            f"{mod_info['icon']} {mod_info['name']}",
            mod_type,
            mod_info['description']
        )

    console.print(modules_table)

    # OWASP categories
    console.print("\n[bold]OWASP Top 10:2025 Coverage:[/bold]\n")

    categories = [
        ("A01", "Broken Access Control", "high", "endpoint, files"),
        ("A02", "Security Misconfiguration", "high", "headers, ssl, files"),
        ("A03", "Injection", "critical", "injection"),
        ("A04", "Cryptographic Failures", "high", "headers, ssl"),
        ("A05", "Security Misconfiguration", "high", "headers, ssl, files"),
        ("A06", "Vulnerable Components", "medium", "files"),
        ("A07", "Auth Failures", "high", "auth"),
        ("A08", "Data Integrity Failures", "medium", "-"),
        ("A09", "Logging Failures", "medium", "-"),
        ("A10", "SSRF", "medium", "-"),
    ]

    table = Table(title="OWASP Top 10:2025 Categories")
    table.add_column("ID", style="bold cyan")
    table.add_column("Category", style="bold")
    table.add_column("Risk")
    table.add_column("Covered By")

    risk_colors = {"critical": "red", "high": "yellow", "medium": "blue"}

    for cat_id, name, risk, covered in categories:
        color = risk_colors.get(risk, "white")
        covered_style = "green" if covered != "-" else "dim"
        table.add_row(
            cat_id,
            name,
            f"[{color}]{risk.upper()}[/{color}]",
            f"[{covered_style}]{covered}[/{covered_style}]"
        )

    console.print(table)

    # Output directory info
    console.print(f"\n[bold]Default Report Directory:[/bold] {DEFAULT_OUTPUT_DIR}")

    console.print("\n[bold]Usage Examples:[/bold]")
    console.print("  [dim]python main.py scan -t https://example.com[/dim]              # Passive modules only")
    console.print("  [dim]python main.py scan -t https://example.com -m all[/dim]       # All modules (incl. active)")
    console.print("  [dim]python main.py scan -t https://example.com -m ssl,headers[/dim]  # Specific modules")
    console.print("  [dim]python main.py scan -t https://example.com -m injection -y[/dim] # Injection only")

    console.print("\n[bold yellow]⚠️  Active modules (injection, auth) send test payloads![/bold yellow]")
    console.print("[dim]Use 'passive' or specific passive modules for safe scanning.[/dim]")


@click.command("test-connection")
@click.option("--target", "-t", required=True, help="Target URL to test")
def test_connection(target):
    console.print(BANNER)

    target = validate_url(target)
    console.print(f"[bold]Testing connection to:[/bold] {target}")

    async def test():
        async with HTTPSession(timeout=10, rate_limit=1.0) as session:
            response = await session.get(target)
            return response

    try:
        response = asyncio.run(test())

        if response:
            console.print(f"\n[green]✓ Connection successful![/green]")
            console.print(f"  Status: {response.status_code}")
            console.print(f"  Server: {response.headers.get('Server', 'N/A')}")
            console.print(f"  Content-Type: {response.headers.get('Content-Type', 'N/A')}")
        else:
            console.print(f"\n[red]✗ Connection failed![/red]")

    except Exception as e:
        console.print(f"\n[red]✗ Error: {e}[/red]")