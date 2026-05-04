"""
report_generator.py - Audit Report Generator
Generates professional audit reports in CSV and HTML formats.

This is the output module - takes all findings from the audit modules
and creates reports that can be shared with management/compliance teams.

The HTML report is styled to look professional - inspired by Big Four audit reports.
"""

import csv
import os
from datetime import datetime, timezone


def generate_reports(findings, output_dir="sample_output"):
    """
    Generate both CSV and HTML reports from audit findings.
    Returns paths to generated files.
    
    # doing CSV and HTML in the same function - could split but it's fine for now
    """
    print("\n[CloudForge-Auditor] Generating reports...")
    
    # make sure output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"  Created output directory: {output_dir}")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # generate CSV report
    csv_path = os.path.join(output_dir, f"audit_report_{timestamp}.csv")
    try:
        _generate_csv(findings, csv_path)
        print(f"  ✅ CSV report generated: {csv_path}")
    except Exception as e:
        print(f"  ❌ CSV generation failed: {e}")
        csv_path = None
    
    # generate HTML report
    html_path = os.path.join(output_dir, f"audit_report_{timestamp}.html")
    try:
        _generate_html(findings, html_path)
        print(f"  ✅ HTML report generated: {html_path}")
    except Exception as e:
        print(f"  ❌ HTML generation failed: {e}")
        html_path = None
    
    return csv_path, html_path


def _generate_csv(findings, filepath):
    """
    Generate CSV report.
    Simple format that can be opened in Excel for further analysis.
    """
    headers = ["Resource ID", "Risk Area", "Finding", "Severity", "Status", "Recommendation", "Timestamp"]
    
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        for finding in findings:
            writer.writerow([
                finding.get('resource_id', ''),
                finding.get('risk_area', ''),
                finding.get('finding', ''),
                finding.get('severity', ''),
                finding.get('status', ''),
                finding.get('recommendation', ''),
                finding.get('timestamp', ''),
            ])


def _generate_html(findings, filepath):
    """
    Generate a professional-looking HTML report.
    Styled to look like a real audit deliverable.
    
    # using inline CSS because we don't want external dependencies
    # not the most maintainable approach but keeps it self-contained
    """
    
    # count findings by severity and status
    summary = _get_summary_stats(findings)
    
    reportDate = datetime.now().strftime("%B %d, %Y at %H:%M UTC")
    
    # build the HTML - it's a big string, yeah...
    # TODO: maybe use jinja2 templates if this gets more complex
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudForge-Auditor - AWS Security Audit Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0f0f1a;
            color: #e0e0e0;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        /* Header section */
        .report-header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            border: 1px solid #2a2a4a;
            border-radius: 12px;
            padding: 40px;
            margin-bottom: 30px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }}
        
        .report-header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #e94560, #ff6b6b, #ffa502, #2ed573, #1e90ff);
        }}
        
        .report-header h1 {{
            font-size: 2.2em;
            background: linear-gradient(135deg, #e94560, #ff6b6b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 8px;
        }}
        
        .report-header .subtitle {{
            color: #8892b0;
            font-size: 1.1em;
        }}
        
        .report-header .date {{
            color: #64ffda;
            margin-top: 12px;
            font-size: 0.95em;
        }}
        
        /* Summary cards */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }}
        
        .summary-card {{
            background: #1a1a2e;
            border: 1px solid #2a2a4a;
            border-radius: 10px;
            padding: 24px;
            text-align: center;
            transition: transform 0.2s, border-color 0.2s;
        }}
        
        .summary-card:hover {{
            transform: translateY(-2px);
            border-color: #4a4a6a;
        }}
        
        .summary-card .count {{
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 4px;
        }}
        
        .summary-card .label {{
            font-size: 0.85em;
            color: #8892b0;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .count-critical {{ color: #ff4757; }}
        .count-high {{ color: #ffa502; }}
        .count-medium {{ color: #ffdd57; }}
        .count-low {{ color: #2ed573; }}
        .count-pass {{ color: #64ffda; }}
        .count-fail {{ color: #ff6b6b; }}
        .count-total {{ color: #a29bfe; }}
        
        /* Findings table */
        .findings-section {{
            background: #1a1a2e;
            border: 1px solid #2a2a4a;
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 30px;
        }}
        
        .findings-section h2 {{
            padding: 20px 24px;
            border-bottom: 1px solid #2a2a4a;
            font-size: 1.3em;
            color: #ccd6f6;
        }}
        
        .findings-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .findings-table th {{
            background: #16213e;
            padding: 14px 16px;
            text-align: left;
            font-size: 0.8em;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #8892b0;
            border-bottom: 2px solid #2a2a4a;
        }}
        
        .findings-table td {{
            padding: 12px 16px;
            border-bottom: 1px solid #1e1e3a;
            font-size: 0.9em;
            vertical-align: top;
        }}
        
        .findings-table tr:hover {{
            background: #16213e;
        }}
        
        /* Severity badges */
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.75em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .badge-critical {{
            background: rgba(255, 71, 87, 0.15);
            color: #ff4757;
            border: 1px solid rgba(255, 71, 87, 0.3);
        }}
        
        .badge-high {{
            background: rgba(255, 165, 2, 0.15);
            color: #ffa502;
            border: 1px solid rgba(255, 165, 2, 0.3);
        }}
        
        .badge-medium {{
            background: rgba(255, 221, 87, 0.15);
            color: #ffdd57;
            border: 1px solid rgba(255, 221, 87, 0.3);
        }}
        
        .badge-low {{
            background: rgba(46, 213, 115, 0.15);
            color: #2ed573;
            border: 1px solid rgba(46, 213, 115, 0.3);
        }}
        
        .badge-pass {{
            background: rgba(100, 255, 218, 0.1);
            color: #64ffda;
            border: 1px solid rgba(100, 255, 218, 0.25);
        }}
        
        .badge-fail {{
            background: rgba(255, 107, 107, 0.1);
            color: #ff6b6b;
            border: 1px solid rgba(255, 107, 107, 0.25);
        }}
        
        /* Footer */
        .report-footer {{
            text-align: center;
            padding: 30px;
            color: #5a5a7a;
            font-size: 0.85em;
            border-top: 1px solid #2a2a4a;
        }}
        
        .report-footer a {{
            color: #64ffda;
            text-decoration: none;
        }}
        
        /* Disclaimer */
        .disclaimer {{
            background: rgba(255, 165, 2, 0.08);
            border: 1px solid rgba(255, 165, 2, 0.2);
            border-radius: 10px;
            padding: 20px 24px;
            margin-bottom: 30px;
            font-size: 0.9em;
            color: #b8b8d0;
        }}
        
        .disclaimer strong {{
            color: #ffa502;
        }}
        
        /* Responsive */
        @media (max-width: 768px) {{
            .summary-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
            .findings-table {{
                font-size: 0.8em;
            }}
            .report-header h1 {{
                font-size: 1.6em;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="report-header">
            <h1>☁️ CloudForge-Auditor</h1>
            <div class="subtitle">AWS Cloud Security &amp; Compliance Audit Report</div>
            <div class="date">Generated: {reportDate}</div>
        </div>
        
        <div class="disclaimer">
            <strong>⚠️ Disclaimer:</strong> This report is generated by an automated auditing tool for compliance assessment purposes only. 
            Findings should be validated by a qualified security professional. This tool performs read-only checks and does not modify any AWS resources.
        </div>
        
        <!-- Summary Cards -->
        <div class="summary-grid">
            <div class="summary-card">
                <div class="count count-total">{summary['total']}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="summary-card">
                <div class="count count-critical">{summary['critical']}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card">
                <div class="count count-high">{summary['high']}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card">
                <div class="count count-medium">{summary['medium']}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card">
                <div class="count count-low">{summary['low']}</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card">
                <div class="count count-pass">{summary['pass']}</div>
                <div class="label">Passed</div>
            </div>
            <div class="summary-card">
                <div class="count count-fail">{summary['fail']}</div>
                <div class="label">Failed</div>
            </div>
        </div>
        
        <!-- Failed Findings -->
        <div class="findings-section">
            <h2>❌ Failed Checks — Requires Attention</h2>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Resource</th>
                        <th>Risk Area</th>
                        <th>Finding</th>
                        <th>Severity</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
"""
    
    # add failed findings rows
    failedFindings = [f for f in findings if f.get('status') == 'FAIL']
    
    # sort by severity: CRITICAL > HIGH > MEDIUM > LOW
    severityOrder = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    failedFindings.sort(key=lambda x: severityOrder.get(x.get('severity', 'LOW'), 4))
    
    if len(failedFindings) == 0:
        html += """                    <tr><td colspan="5" style="text-align:center; padding:30px; color:#64ffda;">🎉 No failed checks — all clear!</td></tr>
"""
    else:
        for f in failedFindings:
            sev = f.get('severity', 'LOW').lower()
            html += f"""                    <tr>
                        <td>{_escape_html(f.get('resource_id', ''))}</td>
                        <td>{_escape_html(f.get('risk_area', ''))}</td>
                        <td>{_escape_html(f.get('finding', ''))}</td>
                        <td><span class="badge badge-{sev}">{f.get('severity', '')}</span></td>
                        <td>{_escape_html(f.get('recommendation', ''))}</td>
                    </tr>
"""
    
    html += """                </tbody>
            </table>
        </div>
        
        <!-- Passed Findings -->
        <div class="findings-section">
            <h2>✅ Passed Checks</h2>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Resource</th>
                        <th>Risk Area</th>
                        <th>Finding</th>
                        <th>Severity</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
"""
    
    passedFindings = [f for f in findings if f.get('status') == 'PASS']
    
    if len(passedFindings) == 0:
        html += """                    <tr><td colspan="5" style="text-align:center; padding:30px; color:#8892b0;">No passed checks recorded</td></tr>
"""
    else:
        for f in passedFindings:
            html += f"""                    <tr>
                        <td>{_escape_html(f.get('resource_id', ''))}</td>
                        <td>{_escape_html(f.get('risk_area', ''))}</td>
                        <td>{_escape_html(f.get('finding', ''))}</td>
                        <td><span class="badge badge-{f.get('severity', 'LOW').lower()}">{f.get('severity', '')}</span></td>
                        <td><span class="badge badge-pass">PASS</span></td>
                    </tr>
"""
    
    html += f"""                </tbody>
            </table>
        </div>
        
        <div class="report-footer">
            <p>CloudForge-Auditor &copy; {datetime.now().year} | Automated AWS Security Audit Tool</p>
            <p>This report is for compliance and security assessment purposes only.</p>
        </div>
    </div>
</body>
</html>"""
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html)


def _get_summary_stats(findings):
    """Calculate summary statistics from findings list."""
    stats = {
        'total': len(findings),
        'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
        'pass': 0, 'fail': 0,
    }
    
    for f in findings:
        sev = f.get('severity', '').upper()
        status = f.get('status', '').upper()
        
        if sev == 'CRITICAL':
            stats['critical'] += 1
        elif sev == 'HIGH':
            stats['high'] += 1
        elif sev == 'MEDIUM':
            stats['medium'] += 1
        elif sev == 'LOW':
            stats['low'] += 1
        
        if status == 'PASS':
            stats['pass'] += 1
        else:
            stats['fail'] += 1
    
    return stats


def _escape_html(text):
    """Basic HTML escaping - prevents XSS in report output."""
    if text is None:
        return ''
    text = str(text)
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    text = text.replace('"', '&quot;')
    text = text.replace("'", '&#x27;')
    return text
