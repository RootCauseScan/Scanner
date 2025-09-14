#!/usr/bin/env python3
"""Generate professional PDF reports from SAST findings.

This plugin implements the report capability for RootCause.
"""
import json
import sys
import os
import signal
import base64
from datetime import datetime
from typing import Dict, List, Any, Optional
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, black, white, grey
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfgen import canvas
from reportlab.lib import colors


def send(msg_id, result=None, error=None):
    """Send a JSON-RPC message to stdout."""
    payload = {"jsonrpc": "2.0", "id": msg_id}
    if error is None:
        payload["result"] = result
    else:
        payload["error"] = error
    try:
        sys.stdout.write(json.dumps(payload) + "\n")
        sys.stdout.flush()
    except BrokenPipeError:
        sys.exit(0)


def log(level, message):
    """Send a log message to RootCause."""
    payload = {
        "jsonrpc": "2.0",
        "method": "plugin.log",
        "params": {
            "level": level,
            "message": message
        }
    }
    try:
        sys.stdout.write(json.dumps(payload) + "\n")
        sys.stdout.flush()
    except BrokenPipeError:
        sys.exit(0)


def handle_init(params):
    """Handle plugin initialization."""
    opts.update(params.get("options") or {})
    opts["workspace_root"] = params.get("workspace_root", "")
    return {"ok": True, "capabilities": ["report"], "plugin_version": "1.0.0"}


def create_pdf_report(findings: List[Dict], metrics: Dict, output_path: str) -> str:
    """Create a professional PDF report from SAST findings."""
    doc = SimpleDocTemplate(output_path, pagesize=A4, 
                          rightMargin=72, leftMargin=72, 
                          topMargin=72, bottomMargin=18)
    
    # Define custom styles
    styles = getSampleStyleSheet()
    
    # Title style - using official brand colors
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=28,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=HexColor('#151517')  # Brand text primary
    )
    
    # Subtitle style
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Heading2'],
        fontSize=18,
        spaceAfter=20,
        textColor=HexColor('#53535A')  # Brand text secondary
    )
    
    # Body style
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=12,
        textColor=HexColor('#151517')  # Brand text primary
    )
    
    # Code style - using brand colors
    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Code'],
        fontSize=9,
        backColor=HexColor('#F6F7F9'),  # Brand surface
        borderColor=HexColor('#E5E7EB'),  # Brand border
        borderWidth=1,
        leftIndent=10,
        rightIndent=10,
        spaceAfter=10,
        textColor=HexColor('#151517')  # Brand text primary
    )
    
    # Brand accent style for highlights
    brand_style = ParagraphStyle(
        'BrandStyle',
        parent=styles['Normal'],
        fontSize=12,
        spaceAfter=12,
        textColor=HexColor('#FFD700'),  # Brand primary gold
        fontName='Helvetica-Bold'
    )
    
    # Build the story
    story = []
    
    # Title page with logo
    # Add logo if available
    logo_path = os.path.join(os.path.dirname(__file__), 'logo.png')
    if os.path.exists(logo_path):
        logo = Image(logo_path, width=120, height=120)
        logo.hAlign = 'CENTER'
        story.append(logo)
        story.append(Spacer(1, 20))
    
    # Main title
    story.append(Paragraph("RootCause SAST Report", title_style))
    story.append(Spacer(1, 10))
    
    # Subtitle with brand color
    story.append(Paragraph("Static Application Security Testing", brand_style))
    story.append(Spacer(1, 30))
    
    # Report metadata
    report_date = datetime.now().strftime("%B %d, %Y")
    story.append(Paragraph(f"<b>Generated on:</b> {report_date}", body_style))
    story.append(Paragraph(f"<b>Workspace:</b> {opts.get('workspace_root', 'N/A')}", body_style))
    story.append(Spacer(1, 40))
    
    # Executive Summary
    story.append(Paragraph("Executive Summary", subtitle_style))
    
    total_findings = len(findings)
    severity_counts = {}
    for finding in findings:
        severity = finding.get('severity', 'unknown')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    summary_text = f"""
    This security analysis identified <b>{total_findings}</b> potential security issues across the codebase.
    The findings are distributed as follows:
    """
    story.append(Paragraph(summary_text, body_style))
    
    # Severity breakdown table
    if severity_counts:
        severity_data = [['Severity', 'Count', 'Percentage']]
        for severity, count in sorted(severity_counts.items()):
            percentage = (count / total_findings * 100) if total_findings > 0 else 0
            severity_data.append([severity.title(), str(count), f"{percentage:.1f}%"])
        
        severity_table = Table(severity_data)
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#FFD700')),  # Brand primary gold
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#151517')),  # Brand text primary
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#F6F7F9')),  # Brand surface
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#E5E7EB'))  # Brand border
        ]))
        story.append(severity_table)
        story.append(Spacer(1, 20))
    
    # Metrics
    if metrics:
        story.append(Paragraph("Analysis Metrics", subtitle_style))
        metrics_text = f"""
        <b>Total Issues Found:</b> {metrics.get('issues', total_findings)}<br/>
        <b>Analysis Time:</b> {metrics.get('ms', 0)}ms<br/>
        <b>Files Analyzed:</b> {metrics.get('files', 'N/A')}<br/>
        """
        story.append(Paragraph(metrics_text, body_style))
        story.append(Spacer(1, 20))
    
    story.append(PageBreak())
    
    # Detailed Findings
    story.append(Paragraph("Detailed Findings", subtitle_style))
    
    if not findings:
        story.append(Paragraph("No security issues were found during the analysis.", body_style))
    else:
        for i, finding in enumerate(findings, 1):
            # Finding header
            rule_id = finding.get('rule_id', 'Unknown Rule')
            severity = finding.get('severity', 'unknown')
            file_path = finding.get('file', 'Unknown Path')
            # Make path relative to workspace root if possible
            workspace_root = opts.get('workspace_root', '')
            if workspace_root and file_path.startswith(workspace_root):
                file_path = os.path.relpath(file_path, workspace_root)
            elif file_path != 'Unknown Path':
                # If it's an absolute path, show just the filename
                file_path = os.path.basename(file_path)
            
            line = finding.get('line', 'N/A')
            column = finding.get('column', 'N/A')
            excerpt = finding.get('excerpt', '')
            remediation = finding.get('remediation', '')
            
            finding_title = f"Finding #{i}: {rule_id}"
            story.append(Paragraph(finding_title, subtitle_style))
            
            # Finding details table
            details_data = [
                ['Property', 'Value'],
                ['Rule ID', rule_id],
                ['Severity', severity.title()],
                ['File Path', file_path],
                ['Line Number', str(line)],
                ['Column', str(column)],
                ['Message', finding.get('message', 'No message provided')]
            ]
            
            # Add excerpt if available
            if excerpt:
                details_data.append(['Code Excerpt', excerpt])
            
            # Add remediation if available
            if remediation:
                details_data.append(['Remediation', remediation])
            
            details_table = Table(details_data, colWidths=[1.5*inch, 4*inch])
            details_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#FFD700')),  # Brand primary gold
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#151517')),  # Brand text primary
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor('#F6F7F9')),  # Brand surface
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#E5E7EB')),  # Brand border
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            story.append(details_table)
            
            # Additional context if available
            if 'context' in finding:
                story.append(Spacer(1, 10))
                story.append(Paragraph("Context:", body_style))
                story.append(Paragraph(finding['context'], code_style))
            
            story.append(Spacer(1, 20))
            
            # Add page break every 3 findings to avoid overcrowding
            if i % 3 == 0 and i < len(findings):
                story.append(PageBreak())
    
    # Footer
    story.append(Spacer(1, 30))
    story.append(Paragraph("Generated by RootCause SAST Plugin", brand_style))
    story.append(Spacer(1, 10))
    story.append(Paragraph("rootcause.sh", body_style))
    
    # Build PDF
    doc.build(story)
    return output_path


def handle_report(params):
    """Handle report generation request."""
    try:
        findings = params.get("findings", [])
        metrics = params.get("metrics", {})
        
        log("info", f"Generating PDF report for {len(findings)} findings")
        
        # Get output filename from options, default to "report.pdf"
        output_filename = opts.get("output", "report.pdf")
        
        # Use workspace_root for output directory, fallback to current directory
        workspace_root = opts.get("workspace_root", ".")
        if not workspace_root or not os.path.exists(workspace_root):
            workspace_root = "."
            log("warning", "Workspace root not found, using current directory")
        
        output_path = os.path.join(workspace_root, output_filename)
        log("info", f"Output path: {output_path}")
        
        # Create the PDF report
        pdf_path = create_pdf_report(findings, metrics, output_path)
        
        # Read the generated PDF and encode it
        with open(pdf_path, 'rb') as f:
            pdf_content = f.read()
        
        pdf_b64 = base64.b64encode(pdf_content).decode('utf-8')
        
        # Log the output path BEFORE returning the result
        log("info", f"PDF report generated: {pdf_path}")
        
        return {
            "report_path": pdf_path,
            "report_content_b64": pdf_b64,
            "report_type": "application/pdf",
            "metrics": {
                "findings_processed": len(findings),
                "pdf_size_bytes": len(pdf_content),
                "ms": 0
            }
        }
    except Exception as e:
        log("error", f"Failed to generate PDF report: {str(e)}")
        return {
            "error": f"Failed to generate PDF report: {str(e)}",
            "metrics": {"ms": 0}
        }


def signal_handler(signum, frame):
    """Handle signals for graceful termination."""
    sys.exit(0)


# Configure signal handlers
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

opts = {"workspace_root": "", "output": "report.pdf"}

try:
    for line in sys.stdin:
        msg = json.loads(line)
        mid = msg.get("id")
        method = msg.get("method")
        params = msg.get("params", {})
        
        if method == "plugin.init":
            send(mid, handle_init(params))
        elif method == "scan.report":
            send(mid, handle_report(params))
        elif method == "plugin.ping":
            send(mid, {"pong": True})
        elif method == "plugin.shutdown":
            send(mid, {"ok": True})
            break
        else:
            send(mid, None, {"code": 1002, "message": "unknown method", "data": {"method": method}})
except (BrokenPipeError, KeyboardInterrupt, OSError):
    sys.exit(0)
