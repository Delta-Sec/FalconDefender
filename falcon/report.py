import json
import smtplib
import ssl
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

logger = logging.getLogger(__name__)

class ReportManager:

    def __init__(self, report_dir: Path, config_manager: Any = None):
        self.report_dir = report_dir
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.json_report_path = self.report_dir / "Scan_Reports.json"
        self.config_manager = config_manager

    def _load_reports(self) -> List[Dict[str, Any]]:
        if self.json_report_path.exists():
            try:
                with open(self.json_report_path, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                logger.warning(f"Could not decode existing reports file at {self.json_report_path}. Starting with empty reports.")
                return []
        return []

    def _save_reports(self, reports: List[Dict[str, Any]]):
        try:
            with open(self.json_report_path, 'w') as f:
                json.dump(reports, f, indent=4)
        except IOError as e:
            logger.error(f"Failed to save reports to {self.json_report_path}: {e}")

    def add_scan_report(self, scan_results: Dict[str, Any]):

        reports = self._load_reports()
        report_entry = {
            "timestamp": datetime.now().isoformat(),
            "scan_results": scan_results
        }
        reports.append(report_entry)
        self._save_reports(reports)
        logger.info(f"Scan report saved to {self.json_report_path}")

    def get_all_reports(self) -> List[Dict[str, Any]]:

        return self._load_reports()
    def generate_summary_report(self, scan_results: Dict[str, Any]) -> str:
        summary = f"--- FalconDefender Scan Report ---\n"
        summary += f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        summary += f"Scanned Path: {scan_results.get('scanned_path', 'N/A')}\n"
        summary += f"Total Files Scanned: {scan_results.get('total_files_scanned', 0)}\n"
        summary += f"Threats Found: {len(scan_results.get('matches', []))}\n"
        summary += "\nDetected Threats:\n"

        if not scan_results.get('matches'):
            summary += "  No threats detected.\n"
        else:
            for i, match in enumerate(scan_results['matches'], 1): 
                summary += f"  --- Match #{i} ---\n" 
                summary += f"  File       : {match.get('file_path')}\n"
                summary += f"  Rule       : {match.get('rule_name')}\n"
       
                if match.get('namespace'):
                    summary += f"  Namespace  : {match.get('namespace')}\n"
                if match.get('tags'):
                    summary += f"  Tags       : {', '.join(match.get('tags', []))}\n"
                    summary += f"  Description: {match.get('description', 'N/A')}\n"
                    summary += f"  Confidence : {match.get('confidence', 'N/A')}\n"
                    summary += f"  Action     : {match.get('action', 'N/A')}\n"
                    summary += "  ---------------\n\n"
        return summary

    def save_summary_report_to_file(self, scan_results: Dict[str, Any], filename: str = "summary_report.txt"):
        summary_content = self.generate_summary_report(scan_results)
        file_path = self.report_dir / filename
        try:
            with open(file_path, 'w') as f:
                f.write(summary_content)
            logger.info(f"Summary report saved to {file_path}")
        except IOError as e:
            logger.error(f"Failed to save summary report to {file_path}: {e}")

    def generate_pdf_report(self, scan_results: Dict[str, Any], filename: str = "summary_report.pdf") -> Optional[Path]:

        pdf_path = self.report_dir / filename
        doc = SimpleDocTemplate(str(pdf_path), pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        story.append(Paragraph("FalconDefender Scan Report", styles['h1']))
        story.append(Spacer(1, 0.2 * inch))

        summary_data = [
            (f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"),
            (f"Scanned Path: {scan_results.get('scanned_path', 'N/A')}"),
            (f"Total Files Scanned: {scan_results.get('total_files_scanned', 0)}"),
            (f"Threats Found: {len(scan_results.get('matches', []))}")
        ]
        for line in summary_data:
            story.append(Paragraph(line, styles['Normal']))
            story.append(Spacer(1, 0.1 * inch))
        
        story.append(Spacer(1, 0.2 * inch))
        story.append(Paragraph("Detected Threats:", styles['h2']))
        story.append(Spacer(1, 0.1 * inch))

        if not scan_results.get('matches'):
            story.append(Paragraph("No threats detected.", styles['Normal']))
        else:
            for match in scan_results['matches']:
                story.append(Paragraph(f"<b>File:</b> {match.get('file_path')}", styles['Normal']))
                story.append(Paragraph(f"<b>Rule:</b> {match.get('rule_name')}", styles['Normal']))
                story.append(Paragraph(f"<b>Description:</b> {match.get('description', 'N/A')}", styles['Normal']))
                story.append(Paragraph(f"<b>Confidence:</b> {match.get('confidence', 'N/A')}", styles['Normal']))
                story.append(Paragraph(f"<b>Action:</b> {match.get('action', 'N/A')}", styles['Normal']))
                story.append(Spacer(1, 0.1 * inch))
        
        try:
            doc.build(story)
            logger.info(f"PDF report saved to {pdf_path}")
            return pdf_path
        except Exception as e:
            logger.error(f"Failed to generate PDF report to {pdf_path}: {e}")
            return None

    def send_email_report(self, scan_results: Dict[str, Any], recipient_emails: Optional[List[str]] = None) -> bool:

        if not self.config_manager:
            logger.error("ConfigManager not provided. Cannot send email report.")
            return False

        email_config = self.config_manager.get("email_reporting", {})
        if not email_config.get("enabled"):
            logger.info("Email reporting is disabled in configuration.")
            return False

        smtp_server = email_config.get("smtp_server")
        smtp_port = email_config.get("smtp_port")
        smtp_username = email_config.get("smtp_username")
        smtp_password = email_config.get("smtp_password")
        sender_email = email_config.get("sender_email")
        use_tls = email_config.get("use_tls", True)

        if not all([smtp_server, smtp_port, smtp_username, smtp_password, sender_email]):
            logger.error("Incomplete SMTP configuration. Cannot send email.")
            return False

        if not recipient_emails:
            recipient_emails = email_config.get("recipient_emails", [])
        if not recipient_emails:
            logger.warning("No recipient emails specified for report.")
            return False

        message = MIMEMultipart("alternative")
        message["Subject"] = f"FalconDefender Scan Report - {datetime.now().strftime('%Y-%m-%d')}"
        message["From"] = sender_email
        message["To"] = ", ".join(recipient_emails)

        text_report = self.generate_summary_report(scan_results)
        html_report = text_report.replace("\n", "<br>")

        part1 = MIMEText(text_report, "plain")
        part2 = MIMEText(html_report, "html")

        message.attach(part1)
        message.attach(part2)

        context = ssl.create_default_context()
        try:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if use_tls:
                    server.starttls(context=context)
                server.login(smtp_username, smtp_password)
                server.sendmail(sender_email, recipient_emails, message.as_string())
            logger.info(f"Email report sent successfully to {', '.join(recipient_emails)}.")
            return True
        except Exception as e:
            logger.error(f"Failed to send email report: {e}")
            return False
    def save_data_as_json(self, data: Dict[str, Any], filename: str) -> Optional[Path]:

        if not filename.lower().endswith(".json"):
            filename += ".json"

        file_path = self.report_dir / filename
        try:
         
            self.report_dir.mkdir(parents=True, exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            logger.info(f"Data saved successfully to JSON file: {file_path}")
            return file_path
        except IOError as e:
            logger.error(f"Failed to save data to JSON file {file_path}: {e}")
            return None
        except TypeError as e:
            logger.error(f"Data contains non-serializable elements for JSON: {e}")
            return None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    class MockConfigManager:
        def __init__(self):
            self._config = {
                "email_reporting": {
                    "enabled": True,
                    "smtp_server": "smtp.example.com",
                    "smtp_port": 587,
                    "smtp_username": "user@example.com",
                    "smtp_password": "your_app_password",
                    "sender_email": "falcondefender@example.com",
                    "recipient_emails": ["admin@example.com"],
                    "use_tls": True,
                }
            }
        def get(self, key: str, default: Any = None) -> Any:
            keys = key.split('.')
            current_level = self._config
            for k in keys:
                if isinstance(current_level, dict) and k in current_level:
                    current_level = current_level[k]
                else:
                    return default
            return current_level

    mock_config = MockConfigManager()

    test_report_dir = Path("./test_reports")
    if test_report_dir.exists():
        import shutil
        shutil.rmtree(test_report_dir)
    test_report_dir.mkdir()

    report_manager = ReportManager(report_dir=test_report_dir, config_manager=mock_config)

    sample_scan_result = {
        "scanned_path": "/tmp/test_malware.exe",
        "total_files_scanned": 1,
        "matches": [
            {
                "file_path": "/tmp/test_malware.exe",
                "rule_name": "EICAR_Test_String",
                "description": "Known EICAR test file",
                "confidence": "High",
                "action": "Quarantined"
            }
        ]
    }

    print("--- Adding scan report ---")
    report_manager.add_scan_report(sample_scan_result)

    print("\n--- Generating and saving text summary report ---")
    report_manager.save_summary_report_to_file(sample_scan_result, "scan_summary.txt")

    print("\n--- Generating and saving PDF report ---")
    pdf_report_path = report_manager.generate_pdf_report(sample_scan_result, "scan_summary.pdf")
    if pdf_report_path: print(f"PDF report generated at {pdf_report_path}")

    print("\n--- Attempting to send email report (will likely fail without real SMTP server) ---")
    report_manager.send_email_report(sample_scan_result)

    print("\n--- Cleaning up test report directory ---")
    if test_report_dir.exists():
        import shutil
        shutil.rmtree(test_report_dir)
        print(f"Removed test report directory: {test_report_dir}")
