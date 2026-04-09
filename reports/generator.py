import json
from datetime import datetime
from pathlib import Path
from typing import Optional
import logging

from core.models import ScanResult

logger = logging.getLogger(__name__)


def get_default_output_dir() -> Path:
    # Project root / output
    return Path(__file__).parent.parent / "output"


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OWASP Security Scan Report - {target}</title>
    <style>
        :root {{
            --primary: #1a73e8;
            --danger: #dc3545;
            --warning: #ffc107;
            --success: #28a745;
            --info: #17a2b8;
            --dark: #343a40;
            --light: #f8f9fa;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: var(--light);
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}

        header {{
            background: linear-gradient(135deg, var(--dark) 0%, #1a1a2e 100%);
            color: white;
            padding: 40px 20px;
            margin-bottom: 30px;
        }}

        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        header .meta {{
            opacity: 0.8;
            font-size: 0.9em;
        }}

        .grade-badge {{
            display: inline-block;
            font-size: 3em;
            font-weight: bold;
            padding: 20px 30px;
            border-radius: 10px;
            margin: 20px 0;
        }}

        .grade-A {{ background: var(--success); color: white; }}
        .grade-B {{ background: #8bc34a; color: white; }}
        .grade-C {{ background: var(--warning); color: #333; }}
        .grade-D {{ background: #ff9800; color: white; }}
        .grade-F {{ background: var(--danger); color: white; }}

        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .card {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}

        .card h3 {{
            color: var(--dark);
            margin-bottom: 10px;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .card .value {{
            font-size: 2em;
            font-weight: bold;
            color: var(--primary);
        }}

        section {{
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}

        section h2 {{
            color: var(--dark);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--light);
        }}

        .finding {{
            border-left: 4px solid;
            padding: 15px;
            margin-bottom: 15px;
            background: var(--light);
            border-radius: 0 5px 5px 0;
        }}

        .finding.critical {{ border-color: #7b1fa2; background: #f3e5f5; }}
        .finding.high {{ border-color: var(--danger); background: #ffebee; }}
        .finding.medium {{ border-color: var(--warning); background: #fff8e1; }}
        .finding.low {{ border-color: var(--info); background: #e3f2fd; }}
        .finding.info {{ border-color: #9e9e9e; background: #fafafa; }}

        .finding h4 {{
            margin-bottom: 5px;
        }}

        .finding .severity {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
            margin-right: 10px;
        }}

        .severity.critical {{ background: #7b1fa2; color: white; }}
        .severity.high {{ background: var(--danger); color: white; }}
        .severity.medium {{ background: var(--warning); color: #333; }}
        .severity.low {{ background: var(--info); color: white; }}
        .severity.info {{ background: #9e9e9e; color: white; }}

        .finding .description {{
            margin: 10px 0;
            color: #666;
        }}

        .finding .recommendation {{
            background: white;
            padding: 10px;
            border-radius: 5px;
            font-size: 0.9em;
        }}

        .finding .recommendation strong {{
            color: var(--success);
        }}

        .owasp-tag {{
            display: inline-block;
            background: var(--dark);
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.75em;
            margin-right: 5px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}

        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}

        th {{
            background: var(--light);
            font-weight: 600;
        }}

        tr:hover {{
            background: #f5f5f5;
        }}

        .status-badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.85em;
        }}

        .status-200 {{ background: #c8e6c9; color: #2e7d32; }}
        .status-301, .status-302 {{ background: #fff3e0; color: #ef6c00; }}
        .status-401, .status-403 {{ background: #ffcdd2; color: #c62828; }}
        .status-500 {{ background: #7b1fa2; color: white; }}

        .priority-critical {{ color: #7b1fa2; font-weight: bold; }}
        .priority-high {{ color: var(--danger); font-weight: bold; }}
        .priority-medium {{ color: var(--warning); }}
        .priority-low {{ color: var(--info); }}

        .header-score {{
            display: inline-block;
            width: 40px;
            height: 40px;
            line-height: 40px;
            text-align: center;
            border-radius: 50%;
            font-weight: bold;
            color: white;
        }}

        .score-high {{ background: var(--success); }}
        .score-medium {{ background: var(--warning); color: #333; }}
        .score-low {{ background: var(--danger); }}

        .cookie-flags {{
            display: flex;
            gap: 5px;
        }}

        .flag {{
            display: inline-block;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.75em;
        }}

        .flag.present {{
            background: var(--success);
            color: white;
        }}

        .flag.missing {{
            background: var(--danger);
            color: white;
        }}

        footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>🛡️ OWASP Security Scan Report</h1>
            <p class="meta">
                Target: <strong>{target}</strong><br>
                Scan Date: {scan_date} | Scan ID: {scan_id}
            </p>
            <div class="grade-badge grade-{grade}">{grade}</div>
            <p>Security Score: <strong>{score}/100</strong></p>
        </div>
    </header>

    <main class="container">
        <div class="summary-cards">
            <div class="card">
                <h3>Endpoints Found</h3>
                <div class="value">{endpoints_count}</div>
            </div>
            <div class="card">
                <h3>Security Findings</h3>
                <div class="value">{findings_count}</div>
            </div>
            <div class="card">
                <h3>Header Score</h3>
                <div class="value">{header_score}%</div>
            </div>
            <div class="card">
                <h3>Cookie Score</h3>
                <div class="value">{cookie_score}%</div>
            </div>
        </div>

        {findings_section}
        {headers_section}
        {cookies_section}
        {endpoints_section}
        {injection_section}
        {auth_section}
    </main>

    <footer>
        <p>Generated by OWASP Scanner v1.0.0 | {generation_time}</p>
    </footer>
</body>
</html>
"""


class ReportGenerator:
    def __init__(self, result: ScanResult, output_dir: Optional[str] = None):
        self.result = result

        # Use provided output_dir or default to home folder
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = get_default_output_dir()

        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_json(self, filename: Optional[str] = None) -> str:
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_{timestamp}.json"

        filepath = self.output_dir / filename

        report_data = self.result.to_dict()

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)

        logger.info(f"JSON report saved to {filepath}")
        return str(filepath)

    def generate_html(self, filename: Optional[str] = None) -> str:
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_{timestamp}.html"

        filepath = self.output_dir / filename

        # Prepare data
        self.result.calculate_grade()
        data = self.result.to_dict()

        # Generate sections (with safe fallbacks)
        findings_section = self._generate_findings_section(data.get("findings") or [])
        headers_section = self._generate_headers_section(data.get("headers") or [])
        cookies_section = self._generate_cookies_section(data.get("cookies") or [])
        endpoints_section = self._generate_endpoints_section(data.get("endpoints") or [])
        injection_section = self._generate_injection_section(data.get("injection_results"))
        auth_section = self._generate_auth_section(data.get("auth_results"))

        # Calculate scores safely
        header_score = 0
        headers = data.get("headers") or []
        if headers:
            scores = [h.get("score", 0) for h in headers if h.get("score") is not None]
            if scores:
                header_score = sum(scores) // len(scores)

        cookie_score = 100
        cookies = data.get("cookies") or []
        if cookies:
            scores = [c.get("score", 100) for c in cookies if c.get("score") is not None]
            if scores:
                cookie_score = sum(scores) // len(scores)

        # Fill template
        html = HTML_TEMPLATE.format(
            target=self.result.target_url,
            scan_date=self.result.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            scan_id=self.result.scan_id[:8] if self.result.scan_id else "N/A",
            grade=self.result.grade or "?",
            score=self.result.score or 0,
            endpoints_count=len(self.result.endpoints or []),
            findings_count=len(self.result.findings or []),
            header_score=header_score,
            cookie_score=cookie_score,
            findings_section=findings_section,
            headers_section=headers_section,
            cookies_section=cookies_section,
            endpoints_section=endpoints_section,
            injection_section=injection_section,
            auth_section=auth_section,
            generation_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"HTML report saved to {filepath}")
        return str(filepath)

    def _generate_findings_section(self, findings: list) -> str:
        if not findings:
            return """
            <section>
                <h2>🎉 Security Findings</h2>
                <p>No security issues found! Great job!</p>
            </section>
            """

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings = sorted(findings, key=lambda x: severity_order.get(x.get("severity", "info"), 5))

        findings_html = ""
        for finding in findings:
            severity = finding.get("severity", "info")
            title = finding.get("title", "Unknown Issue")
            description = finding.get("description", "")
            recommendation = finding.get("recommendation", "")
            owasp_categories = finding.get("owasp_categories") or []

            owasp_tags = "".join(
                f'<span class="owasp-tag">{cat}</span>'
                for cat in owasp_categories
            )

            recommendation_html = ""
            if recommendation:
                recommendation_html = f'<div class="recommendation"><strong>Recommendation:</strong> {recommendation}</div>'

            findings_html += f"""
            <div class="finding {severity}">
                <h4>
                    <span class="severity {severity}">{severity.upper()}</span>
                    {title}
                </h4>
                <div>{owasp_tags}</div>
                <p class="description">{description}</p>
                {recommendation_html}
            </div>
            """

        return f"""
        <section>
            <h2>🔍 Security Findings ({len(findings)})</h2>
            {findings_html}
        </section>
        """

    def _generate_headers_section(self, headers: list) -> str:
        if not headers:
            return ""

        rows = ""
        for header in headers:
            score = header.get("score", 0)
            score_class = "high" if score >= 70 else "medium" if score >= 40 else "low"

            status = "✅" if header.get("present") else "❌"
            issues = header.get("issues") or []
            issues_html = "<br>".join(issues) if issues else "No issues"

            value = header.get("value") or "Not set"
            if len(value) > 60:
                value = value[:60] + "..."

            rows += f"""
            <tr>
                <td>{status} {header.get('name', 'Unknown')}</td>
                <td><span class="header-score score-{score_class}">{score}</span></td>
                <td><small>{value}</small></td>
                <td><small>{issues_html}</small></td>
            </tr>
            """

        return f"""
        <section>
            <h2>🔒 Security Headers Analysis</h2>
            <table>
                <thead>
                    <tr>
                        <th>Header</th>
                        <th>Score</th>
                        <th>Value</th>
                        <th>Issues</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </section>
        """

    def _generate_cookies_section(self, cookies: list) -> str:
        if not cookies:
            return ""

        rows = ""
        for cookie in cookies:
            # Get flags directly from cookie (not from nested 'flags' dict)
            secure = cookie.get("secure", False)
            httponly = cookie.get("httponly", False)
            samesite = cookie.get("samesite")

            flag_html = f"""
            <span class="flag {'present' if secure else 'missing'}">Secure</span>
            <span class="flag {'present' if httponly else 'missing'}">HttpOnly</span>
            <span class="flag {'present' if samesite else 'missing'}">SameSite</span>
            """

            session_badge = "🔐" if cookie.get("is_session_cookie") else ""
            score = cookie.get("score", 0)
            score_class = "high" if score >= 70 else "medium" if score >= 40 else "low"

            issues = cookie.get("issues") or []
            issues_text = ", ".join(issues) if issues else "No issues"

            rows += f"""
            <tr>
                <td>{session_badge} {cookie.get('name', 'Unknown')}</td>
                <td><span class="header-score score-{score_class}">{score}</span></td>
                <td><div class="cookie-flags">{flag_html}</div></td>
                <td><small>{issues_text}</small></td>
            </tr>
            """

        return f"""
        <section>
            <h2>🍪 Cookie Security Analysis</h2>
            <table>
                <thead>
                    <tr>
                        <th>Cookie Name</th>
                        <th>Score</th>
                        <th>Security Flags</th>
                        <th>Issues</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </section>
        """

    def _generate_endpoints_section(self, endpoints: list) -> str:
        if not endpoints:
            return ""

        total_count = len(endpoints)

        # Limit to top 50 for HTML report
        endpoints = endpoints[:50]

        rows = ""
        for ep in endpoints:
            status_code = ep.get("status_code", "")
            status_class = f"status-{status_code}" if status_code else ""
            priority = ep.get("priority", "low")
            path = ep.get("path", "/")
            source = ep.get("source", "")
            notes = ep.get("notes") or ""

            rows += f"""
            <tr>
                <td class="priority-{priority}">{path}</td>
                <td><span class="status-badge {status_class}">{status_code or 'N/A'}</span></td>
                <td>{source}</td>
                <td><small>{notes}</small></td>
            </tr>
            """

        truncation_note = ""
        if total_count > 50:
            truncation_note = '<p><em>Showing top 50 endpoints. See JSON report for full list.</em></p>'

        return f"""
        <section>
            <h2>🗺️ Discovered Endpoints ({total_count} total)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Path</th>
                        <th>Status</th>
                        <th>Source</th>
                        <th>Notes</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
            {truncation_note}
        </section>
        """

    def _generate_injection_section(self, injection_results: Optional[dict]) -> str:
        if not injection_results:
            return ""

        summary = injection_results.get("summary", {})
        endpoints_tested = summary.get("endpoints_tested", 0)
        sqli_found = summary.get("sqli_found", 0)
        xss_found = summary.get("xss_found", 0)
        findings_count = summary.get("findings_count", 0)

        findings = injection_results.get("findings") or []
        tested_params = injection_results.get("tested_endpoints") or []

        # Build findings rows
        findings_html = ""
        for finding in findings:
            severity = finding.get("severity", "info")
            if hasattr(severity, "value"):
                severity = severity.value
            title = finding.get("title", "Unknown Issue")
            description = finding.get("description", "")
            recommendation = finding.get("recommendation", "")
            evidence = finding.get("evidence") or {}
            param = evidence.get("parameter", "")
            payload = evidence.get("payload", "")
            indicators = evidence.get("indicators") or []

            indicators_html = "<br>".join(indicators) if indicators else ""
            recommendation_html = (
                f'<div class="recommendation"><strong>Recommendation:</strong> {recommendation}</div>'
                if recommendation else ""
            )

            findings_html += f"""
            <div class="finding {severity}">
                <h4>
                    <span class="severity {severity}">{severity.upper()}</span>
                    {title}
                </h4>
                <p class="description">{description}</p>
                <p><small><strong>Parameter:</strong> <code>{param}</code> &nbsp;
                   <strong>Payload:</strong> <code>{payload}</code></small></p>
                {f'<p><small>{indicators_html}</small></p>' if indicators_html else ''}
                {recommendation_html}
            </div>
            """

        if not findings_html:
            findings_html = "<p>✅ No injection vulnerabilities detected.</p>"

        # Summary stats row
        stats_html = f"""
        <div class="summary-cards" style="margin-bottom:15px;">
            <div class="card">
                <h3>Endpoints Tested</h3>
                <div class="value">{endpoints_tested}</div>
            </div>
            <div class="card">
                <h3>SQLi Found</h3>
                <div class="value" style="color:{'var(--danger)' if sqli_found else 'var(--success)'}">
                    {sqli_found}
                </div>
            </div>
            <div class="card">
                <h3>XSS Found</h3>
                <div class="value" style="color:{'var(--danger)' if xss_found else 'var(--success)'}">
                    {xss_found}
                </div>
            </div>
            <div class="card">
                <h3>Total Findings</h3>
                <div class="value" style="color:{'var(--danger)' if findings_count else 'var(--success)'}">
                    {findings_count}
                </div>
            </div>
        </div>
        """

        return f"""
        <section>
            <h2>💉 Injection Testing (SQLi / XSS)</h2>
            {stats_html}
            {findings_html}
        </section>
        """

    def _generate_auth_section(self, auth_results: Optional[dict]) -> str:
        if not auth_results:
            return ""

        findings = auth_results.get("findings") or []
        summary = auth_results.get("summary") or {}
        checks_performed = summary.get("checks_performed", 0)
        issues_found = summary.get("issues_found", len(findings))

        findings_html = ""
        for finding in findings:
            severity = finding.get("severity", "info")
            if hasattr(severity, "value"):
                severity = severity.value
            title = finding.get("title", "Unknown Issue")
            description = finding.get("description", "")
            recommendation = finding.get("recommendation", "")
            url = finding.get("url", "")

            recommendation_html = (
                f'<div class="recommendation"><strong>Recommendation:</strong> {recommendation}</div>'
                if recommendation else ""
            )
            url_html = f'<p><small><strong>URL:</strong> {url}</small></p>' if url else ""

            findings_html += f"""
            <div class="finding {severity}">
                <h4>
                    <span class="severity {severity}">{severity.upper()}</span>
                    {title}
                </h4>
                <p class="description">{description}</p>
                {url_html}
                {recommendation_html}
            </div>
            """

        if not findings_html:
            findings_html = "<p>✅ No authentication issues detected.</p>"

        stats_html = f"""
        <div class="summary-cards" style="margin-bottom:15px;">
            <div class="card">
                <h3>Checks Performed</h3>
                <div class="value">{checks_performed}</div>
            </div>
            <div class="card">
                <h3>Issues Found</h3>
                <div class="value" style="color:{'var(--danger)' if issues_found else 'var(--success)'}">
                    {issues_found}
                </div>
            </div>
        </div>
        """ if (checks_performed or issues_found) else ""

        return f"""
        <section>
            <h2>🔑 Authentication & Authorization Testing</h2>
            {stats_html}
            {findings_html}
        </section>
        """