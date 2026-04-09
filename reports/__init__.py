import json
from datetime import datetime
from pathlib import Path
from typing import Optional
import logging

from core.models import ScanResult

logger = logging.getLogger(__name__)

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
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.8em;
        }}

        .flag.present {{ background: #c8e6c9; color: #2e7d32; }}
        .flag.missing {{ background: #ffcdd2; color: #c62828; }}

        footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}

        @media (max-width: 768px) {{
            header h1 {{ font-size: 1.8em; }}
            .grade-badge {{ font-size: 2em; }}
            .card .value {{ font-size: 1.5em; }}
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>🛡️ OWASP Security Scan Report</h1>
            <div class="meta">
                <p><strong>Target:</strong> {target}</p>
                <p><strong>Scan Date:</strong> {scan_date}</p>
                <p><strong>Scan ID:</strong> {scan_id}</p>
            </div>
            <div class="grade-badge grade-{grade}">{grade}</div>
            <p>Overall Score: {score}/100</p>
        </div>
    </header>

    <div class="container">
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
    </div>

    <footer>
        <p>Generated by OWASP Scanner v1.0 | Based on OWASP Top 10:2025</p>
        <p>Report generated at {generation_time}</p>
    </footer>
</body>
</html>
"""


class ReportGenerator:
    def __init__(self, result: ScanResult, output_dir: str = "./reports/output"):
        self.result = result
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_json(self, filename: Optional[str] = None) -> str:
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_{timestamp}.json"

        filepath = self.output_dir / filename

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.result.to_dict(), f, indent=2, ensure_ascii=False)

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

        # Generate sections
        findings_section = self._generate_findings_section(data["findings"])
        headers_section = self._generate_headers_section(data["headers"])
        cookies_section = self._generate_cookies_section(data["cookies"])
        endpoints_section = self._generate_endpoints_section(data["endpoints"])

        # Calculate scores
        header_score = 0
        if data["headers"]:
            header_score = sum(h["score"] for h in data["headers"]) // len(data["headers"])

        cookie_score = 100
        if data["cookies"]:
            cookie_score = sum(c["score"] for c in data["cookies"]) // len(data["cookies"])

        # Fill template
        html = HTML_TEMPLATE.format(
            target=self.result.target_url,
            scan_date=self.result.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            scan_id=self.result.scan_id[:8],
            grade=self.result.grade,
            score=self.result.score,
            endpoints_count=len(self.result.endpoints),
            findings_count=len(self.result.findings),
            header_score=header_score,
            cookie_score=cookie_score,
            findings_section=findings_section,
            headers_section=headers_section,
            cookies_section=cookies_section,
            endpoints_section=endpoints_section,
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
        findings = sorted(findings, key=lambda x: severity_order.get(x["severity"], 5))

        findings_html = ""
        for finding in findings:
            owasp_tags = "".join(
                f'<span class="owasp-tag">{cat}</span>'
                for cat in finding.get("owasp_categories", [])
            )

            findings_html += f"""
            <div class="finding {finding['severity']}">
                <h4>
                    <span class="severity {finding['severity']}">{finding['severity'].upper()}</span>
                    {finding['title']}
                </h4>
                <div>{owasp_tags}</div>
                <p class="description">{finding['description']}</p>
                {f'<div class="recommendation"><strong>Recommendation:</strong> {finding["recommendation"]}</div>' if finding.get('recommendation') else ''}
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
            score = header["score"]
            score_class = "high" if score >= 70 else "medium" if score >= 40 else "low"

            status = "✅" if header["present"] else "❌"
            issues = "<br>".join(header.get("issues", [])) or "No issues"

            rows += f"""
            <tr>
                <td>{status} {header['name']}</td>
                <td><span class="header-score score-{score_class}">{score}</span></td>
                <td><small>{header.get('value', 'Not set')[:60]}{'...' if header.get('value') and len(header.get('value', '')) > 60 else ''}</small></td>
                <td><small>{issues}</small></td>
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
            flags = cookie.get("flags", {})

            flag_html = f"""
            <span class="flag {'present' if flags.get('secure') else 'missing'}">Secure</span>
            <span class="flag {'present' if flags.get('httponly') else 'missing'}">HttpOnly</span>
            <span class="flag {'present' if flags.get('samesite') else 'missing'}">SameSite</span>
            """

            session_badge = "🔐" if cookie.get("is_session_cookie") else ""

            rows += f"""
            <tr>
                <td>{session_badge} {cookie['name']}</td>
                <td><span class="header-score score-{'high' if cookie['score'] >= 70 else 'medium' if cookie['score'] >= 40 else 'low'}">{cookie['score']}</span></td>
                <td><div class="cookie-flags">{flag_html}</div></td>
                <td><small>{', '.join(cookie.get('issues', [])) or 'No issues'}</small></td>
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

        # Limit to top 50 for HTML report
        endpoints = endpoints[:50]

        rows = ""
        for ep in endpoints:
            status_code = ep.get("status_code", "")
            status_class = f"status-{status_code}" if status_code else ""

            rows += f"""
            <tr>
                <td class="priority-{ep['priority']}">{ep['path']}</td>
                <td><span class="status-badge {status_class}">{status_code or 'N/A'}</span></td>
                <td>{ep['source']}</td>
                <td><small>{ep.get('notes', '') or ''}</small></td>
            </tr>
            """

        return f"""
        <section>
            <h2>🗺️ Discovered Endpoints ({len(self.result.endpoints)} total)</h2>
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
            {f'<p><em>Showing top 50 endpoints. See JSON report for full list.</em></p>' if len(self.result.endpoints) > 50 else ''}
        </section>
        """