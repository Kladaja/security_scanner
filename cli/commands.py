import sys
import asyncio
from datetime import datetime
from typing import List

import click
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from cli.utils import BANNER, setup_logging, validate_url, display_confirmation, display_results_summary, console
from core.models import ScanResult
from core.session import HTTPSession
from modules.auth_tester import AuthTester
from modules.endpoint_discovery import EndpointDiscovery
from modules.header_analyzer import HeaderAnalyzer
from modules.injection_tester import InjectionTester
from modules.sensitive_files import SensitiveFileAnalyzer
from modules.ssl_analyzer import SSLAnalyzer
from reports.generator import ReportGenerator, get_default_output_dir
import yaml

AVAILABLE_MODULES = {
    "endpoint": {"name": "Endpoint Discovery", "icon": "🔍", "description": "Discovers endpoints via crawling, robots.txt, sitemap, bruteforce", "active": False},
    "headers": {"name": "Header Analyzer", "icon": "🔒", "description": "Analyzes security headers, cookies, CORS", "active": False},
    "ssl": {"name": "SSL/TLS Analyzer", "icon": "🔐", "description": "Checks certificates, protocols, cipher suites", "active": False},
    "files": {"name": "Sensitive Files", "icon": "📁", "description": "Detects exposed .env, .git, config files, credentials", "active": False},
    "injection": {"name": "Injection Tester", "icon": "💉", "description": "Tests for SQL injection and XSS vulnerabilities", "active": True},
    "auth": {"name": "Auth Tester", "icon": "🔑", "description": "Tests authentication and session security", "active": True}
}

PASSIVE_MODULES = ["endpoint", "headers", "ssl", "files"]
ACTIVE_MODULES = ["injection", "auth"]
DEFAULT_OUTPUT_DIR = get_default_output_dir()

MODULE_CONFIG = {
    "endpoint": {
        "class": EndpointDiscovery,
        "progress": "Discovering endpoints...",
        "kwargs": lambda s, t, r, d, nb: {
            "session": s,
            "base_url": t,
            "crawl_depth": d,
            "crawl_max_pages": 100,
            "bruteforce_enabled": not nb
        }
    },
    "headers": {
        "class": HeaderAnalyzer,
        "progress": "Analyzing headers...",
        "kwargs": lambda s, t, *_: {"session": s, "target_url": t}
    },
    "ssl": {
        "class": SSLAnalyzer,
        "progress": "Analyzing SSL/TLS...",
        "kwargs": lambda s, t, *_: {"session": s, "target_url": t}
    },
    "files": {
        "class": SensitiveFileAnalyzer,
        "progress": "Checking sensitive files...",
        "kwargs": lambda s, t, *_: {"session": s, "target_url": t}
    },
    "injection": {
        "class": InjectionTester,
        "progress": "Testing for injections...",
        "kwargs": lambda s, t, r, d, nb, custom_config=None: {
            "session": s,
            "target_url": t,
            "endpoints": r.endpoints,
            "test_sqli": True,
            "test_xss": True,
            "max_tests_per_endpoint": 10,
            "custom_test_cases": custom_config.get("injection", {}).get("endpoints", [])
        }
    },
    "auth": {
        "class": AuthTester,
        "progress": "Testing authentication...",
        "kwargs": lambda s, t, r, d, nb, custom_config=None: {
            "session": s,
            "target_url": t,
            "test_weak_creds": True,
            "test_session": True,
            "max_login_attempts": 5,
            "custom_login_endpoints": custom_config.get("auth", {}).get("login_endpoints", [])
        }
    }
}

def load_test_cases(path):
    if not path:
        return {}

    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def get_modules(modules): return list(AVAILABLE_MODULES) if "all" in modules else PASSIVE_MODULES if "passive" in modules else modules
def ok(msg): console.print(f"  [green]✓[/green] {msg}")
def warn(msg): console.print(f"  [yellow]⚠[/yellow] {msg}")
def bad(msg, color="red"): console.print(f"  [{color}]![/{color}] {msg}")

def start_module(name):
    mod = AVAILABLE_MODULES[name]
    color = "yellow" if mod["active"] else "blue"
    active = " [dim](active)[/dim]" if mod["active"] else ""
    console.print(f"\n[bold {color}]{mod['icon']} Running {mod['name']}...[/bold {color}]{active}")

async def run_progress(desc, coro):
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as p:
        task = p.add_task(desc, total=None)
        result = await coro
        p.update(task, completed=True)
        return result

def validate_modules(modules):
    valid = [*AVAILABLE_MODULES, "all", "passive"]

    for m in modules:
        if m not in valid:
            console.print(f"[red]Error: Invalid module '{m}'[/red]")
            console.print(f"[dim]Valid modules: {', '.join(valid)}[/dim]")
            sys.exit(1)

def show_active_warning(modules):
    active = [m for m in modules if m in ACTIVE_MODULES]

    if not active:
        return

    console.print("\n[bold yellow]⚠️  WARNING: Active modules selected![/bold yellow]")
    console.print("[yellow]The following modules will send test payloads to the target:[/yellow]")

    for m in active:
        mod = AVAILABLE_MODULES[m]
        console.print(f"  [yellow]• {mod['icon']} {mod['name']}[/yellow]")

    console.print()

def process_endpoint(result, data):
    result.endpoints = data.get("endpoints", [])
    result.findings.extend(data.get("findings", []))

    stats = data.get("statistics", {})
    ok(f"Found {len(result.endpoints)} endpoints")

    if stats.get("by_priority"):
        ok(str(stats["by_priority"]))

def process_headers(result, data):
    result.headers = data.get("headers", [])
    result.cookies = data.get("cookies", [])
    result.cors = data.get("cors")
    result.info_disclosures = data.get("info_disclosures", [])
    result.findings.extend(data.get("findings", []))

    s = data.get("summary", {})
    ok(f"Header score: {s.get('header_score', 0)}/100")
    ok(f"Cookie score: {s.get('cookie_score', 100)}/100")
    ok(f"Found {s.get('findings_count', 0)} issues")

def process_ssl(result, data):
    if data.get("skipped"):
        return warn(f"Skipped: {data.get('reason')}")

    result.findings.extend(data.get("findings", []))
    s = data.get("summary", {})

    if s.get("certificate_valid"):
        ok(f"Certificate valid, expires in {s.get('days_until_expiry', '?')} days")
    else:
        console.print("  [red]✗[/red] Certificate invalid")

    ok(f"Protocol: {s.get('protocol', 'unknown')}")
    ok(f"Found {s.get('findings_count', 0)} issues")

def process_files(result, data):
    result.findings.extend(data.get("findings", []))
    s = data.get("summary", {})

    ok(f"Checked {s.get('files_checked', 0)} file paths")

    if s.get("files_found", 0) > 0:
        bad(f"Found {s['files_found']} exposed files")
    else:
        ok("No sensitive files exposed")

    if s.get("secrets_found", 0) > 0:
        bad(f"Found {s['secrets_found']} potential secrets")

def process_injection(result, data):
    result.findings.extend(data.get("findings", []))
    s = data.get("summary", {})

    result.injection_results = {
        "tested_endpoints": data.get("tested_endpoints", []),
        "summary": s
    }

    ok(f"Tested {s.get('endpoints_tested', 0)} endpoints")

    if s.get("sqli_found", 0) > 0:
        bad(f"Found {s['sqli_found']} potential SQL injection(s)")
    else:
        ok("No SQL injection found")

    if s.get("xss_found", 0) > 0:
        bad(f"Found {s['xss_found']} potential XSS")
    else:
        ok("No XSS found")

def process_auth(result, data):
    result.findings.extend(data.get("findings", []))
    s = data.get("summary", {})

    result.auth_results = {
        "login_forms": data.get("login_forms", []),
        "session_issues": data.get("session_issues", []),
        "summary": s
    }

    ok(f"Found {s.get('login_forms_found', 0)} login form(s)")

    if s.get("weak_creds_found", 0) > 0:
        bad(f"Found {s['weak_creds_found']} weak credential(s)")
    else:
        ok("No weak credentials found")

    if s.get("session_issues", 0) > 0:
        bad(f"Found {s['session_issues']} session issue(s)", "yellow")

PROCESSORS = {
    "endpoint": process_endpoint,
    "headers": process_headers,
    "ssl": process_ssl,
    "files": process_files,
    "injection": process_injection,
    "auth": process_auth
}

async def run_scan(target: str, modules: List[str], rate_limit: float,
                   timeout: int, crawl_depth: int, no_bruteforce: bool, custom_endpoints: str = None) -> ScanResult:
    custom_config = load_test_cases(custom_endpoints)
    result = ScanResult(target_url=target)
    modules = get_modules(modules)

    async with HTTPSession(timeout=timeout, rate_limit=rate_limit, verify_ssl=True) as session:
        for name in modules:
            start_module(name)

            cfg = MODULE_CONFIG[name]
            if name in ["injection", "auth"]:
                kwargs = cfg["kwargs"](session, target, result, crawl_depth, no_bruteforce, custom_config)
            else:
                kwargs = cfg["kwargs"](session, target, result, crawl_depth, no_bruteforce)

            analyzer = cfg["class"](**kwargs)

            data = await run_progress(cfg["progress"], analyzer.run())
            PROCESSORS[name](result, data)

        result.total_requests = session.request_count

    result.end_time = datetime.now()
    result.status = "completed"
    result.calculate_grade()

    return result

@click.command()
@click.option("--target", "-t", required=True, help="Target URL to scan")
@click.option("--modules", "-m", default="passive", help="Modules: endpoint,headers,ssl,files,injection,auth,passive,all")
@click.option("--output", "-o", default="both", help="Output format: json,html,both")
@click.option("--output-dir", default=None, help=f"Output directory for reports (default: {DEFAULT_OUTPUT_DIR})")
@click.option("--rate-limit", "-r", default=2.0, help="Requests per second")
@click.option("--timeout", default=10, help="Request timeout in seconds")
@click.option("--crawl-depth", default=3, help="Maximum crawl depth")
@click.option("--no-bruteforce", is_flag=True, help="Disable path bruteforcing")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--custom-endpoints", default=None, help="Optional YAML file with project-specific endpoints")
def scan(target, modules, output, output_dir, rate_limit, timeout,
         crawl_depth, no_bruteforce, yes, verbose, custom_endpoints):
    setup_logging(verbose)
    console.print(BANNER)

    try:
        target = validate_url(target)
    except click.BadParameter as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    module_list = [m.strip().lower() for m in modules.split(",")]
    validate_modules(module_list)

    active_modules = get_modules(module_list)

    show_active_warning(active_modules)

    if not yes and not display_confirmation(target):
        console.print("[yellow]Scan cancelled.[/yellow]")
        sys.exit(0)

    console.print(f"\n[bold]🚀 Starting scan on:[/bold] [cyan]{target}[/cyan]")
    console.print(f"[dim]Modules: {', '.join(active_modules)} | Rate limit: {rate_limit}/s | Timeout: {timeout}s[/dim]")

    try:
        result = asyncio.run(run_scan(
            target=target,
            modules=module_list,
            rate_limit=rate_limit,
            timeout=timeout,
            crawl_depth=crawl_depth,
            no_bruteforce=no_bruteforce,
            custom_endpoints=custom_endpoints
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

    display_results_summary(result)

    console.print("\n[bold]📄 Generating Reports...[/bold]")

    try:
        generator = ReportGenerator(result, output_dir)

        console.print(f"  [dim]Output directory: {generator.output_dir}[/dim]")

        if output in ["json", "both"]:
            ok(f"JSON: {generator.generate_json()}")

        if output in ["html", "both"]:
            ok(f"HTML: {generator.generate_html()}")

    except Exception as e:
        console.print(f"[red]Error generating reports: {e}[/red]")

        if verbose:
            import traceback
            traceback.print_exc()

    console.print("\n[bold green]✅ Scan complete![/bold green]")

@click.command()
def info():
    console.print(BANNER)
    console.print("\n[bold]Available Modules:[/bold]\n")

    modules_table = Table()
    modules_table.add_column("ID", style="bold cyan")
    modules_table.add_column("Name", style="bold")
    modules_table.add_column("Type")
    modules_table.add_column("Description")

    for mod_id, mod in AVAILABLE_MODULES.items():
        modules_table.add_row(
            mod_id,
            f"{mod['icon']} {mod['name']}",
            "[yellow]ACTIVE[/yellow]" if mod["active"] else "[green]passive[/green]",
            mod["description"]
        )

    console.print(modules_table)

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

    colors = {"critical": "red", "high": "yellow", "medium": "blue"}

    for cid, name, risk, covered in categories:
        table.add_row(
            cid,
            name,
            f"[{colors.get(risk, 'white')}]{risk.upper()}[/{colors.get(risk, 'white')}]",
            f"[{'green' if covered != '-' else 'dim'}]{covered}[/{'green' if covered != '-' else 'dim'}]"
        )

    console.print(table)

    console.print(f"\n[bold]Default Report Directory:[/bold] {DEFAULT_OUTPUT_DIR}")
    console.print("\n[bold]Usage Examples:[/bold]")
    console.print("  [dim]python main.py scan -t https://example.com[/dim]")
    console.print("  [dim]python main.py scan -t https://example.com -m all[/dim]")
    console.print("  [dim]python main.py scan -t https://example.com -m ssl,headers[/dim]")
    console.print("  [dim]python main.py scan -t https://example.com -m injection -y[/dim]")
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
            return await session.get(target)

    try:
        response = asyncio.run(test())

        if response:
            console.print("\n[green]✓ Connection successful![/green]")
            console.print(f"  Status: {response.status_code}")
            console.print(f"  Server: {response.headers.get('Server', 'N/A')}")
            console.print(f"  Content-Type: {response.headers.get('Content-Type', 'N/A')}")
        else:
            console.print("\n[red]✗ Connection failed![/red]")

    except Exception as e:
        console.print(f"\n[red]✗ Error: {e}[/red]")