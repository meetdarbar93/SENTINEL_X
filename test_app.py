import unittest
import json
from app import app
from database.db import save_investigation

class SentinelXTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.app.testing = True

    def test_pages(self):
        """Test all frontend page routes return HTTP 200."""
        routes = ["/", "/osint", "/domain", "/analyzer", "/redirects", "/scanner", "/subdomains", "/history", "/reports", "/about", "/settings"]
        for r in routes:
            response = self.client.get(r)
            self.assertEqual(response.status_code, 200, f"Route {r} failed with status {response.status_code}")

    def test_dashboard_stats_api(self):
        """Test dashboard stats endpoint."""
        response = self.client.get("/api/dashboard/stats")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertIn("stats", data)
        self.assertIn("total_urls", data["stats"])
        self.assertIn("timeline", data["stats"])

    def test_osint_generator_api(self):
        """Test OSINT query generation endpoint."""
        response = self.client.post("/api/osint/generate", 
                                  data=json.dumps({"domain": "example.com"}),
                                  content_type="application/json")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["domain"], "example.com")
        self.assertEqual(len(data["data"]["categories"]), 10)
        self.assertGreater(data["data"]["total_queries"], 30)

    def test_ssrf_block_url_analyzer(self):
        """Test that SSRF blocks private and localhost IPs in URL analyzer."""
        private_targets = [
            "http://127.0.0.1:8080/admin",
            "http://localhost:5000/secret",
            "http://192.168.1.1/router",
            "http://169.254.169.254/latest/meta-data/"
        ]
        for target in private_targets:
            response = self.client.post("/api/url/analyze",
                                      data=json.dumps({"url": target}),
                                      content_type="application/json")
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertTrue(data["success"])
            self.assertEqual(data["data"]["risk_assessment"]["level"], "High")
            ind_ids = [i["id"] for i in data["data"]["risk_assessment"]["indicators"]]
            self.assertIn("SSRF_BLOCKED", ind_ids)

    def test_url_analyzer_phishing_heuristic(self):
        """Test detection of brand typosquatting, executable, and @ symbol."""
        phishing_url = "http://paypal.com@verify-secure-update.com:8443/account/login/update.exe?token=123%25"
        response = self.client.post("/api/url/analyze",
                                  data=json.dumps({"url": phishing_url}),
                                  content_type="application/json")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["risk_assessment"]["level"], "High")
        self.assertGreaterEqual(data["data"]["risk_assessment"]["score"], 70)

    def test_history_and_reports_api(self):
        """Test history retrieval, PDF generation, and JSON export."""
        # Ensure at least one investigation is saved
        inv_id = save_investigation(
            target="https://verified-site.org",
            inv_type="url_analysis",
            risk_score=10,
            risk_level="Low",
            summary="Test audit record.",
            details={
                "url_structure": {"scheme": "https", "hostname": "verified-site.org"},
                "risk_assessment": {"score": 10, "level": "Low", "indicators": [], "precautions": ["Verify TLS cert."]}
            }
        )

        # Query history
        hist_resp = self.client.get("/api/history")
        self.assertEqual(hist_resp.status_code, 200)
        hist_data = json.loads(hist_resp.data)
        self.assertTrue(hist_data["success"])
        self.assertGreater(len(hist_data["records"]), 0)

        # Test single item API
        item_resp = self.client.get(f"/api/history/{inv_id}")
        self.assertEqual(item_resp.status_code, 200)
        item_data = json.loads(item_resp.data)
        self.assertTrue(item_data["success"])
        self.assertEqual(item_data["record"]["id"], inv_id)

        # Test JSON export
        json_report_resp = self.client.get(f"/api/reports/json/{inv_id}")
        self.assertEqual(json_report_resp.status_code, 200)
        json_report = json.loads(json_report_resp.data)
        self.assertIn("investigation", json_report)
        self.assertIn("metadata", json_report)

        # Test PDF export
        pdf_report_resp = self.client.get(f"/api/reports/pdf/{inv_id}")
        self.assertEqual(pdf_report_resp.status_code, 200)
        self.assertEqual(pdf_report_resp.content_type, "application/pdf")
        self.assertGreater(len(pdf_report_resp.data), 1000)

    def test_threat_scanner_api(self):
        """Test VirusTotal-grade multi-engine scanner API."""
        # 1. Test clean target
        resp_clean = self.client.post("/api/scanner/analyze",
                                      data=json.dumps({"target": "https://wikipedia.org"}),
                                      content_type="application/json")
        self.assertEqual(resp_clean.status_code, 200)
        data_clean = json.loads(resp_clean.data)
        self.assertTrue(data_clean["success"])
        self.assertEqual(data_clean["data"]["detection_ratio"]["total"], 68)
        self.assertEqual(data_clean["data"]["overall_verdict"], "CLEAN")

        # 2. Test malicious phishing & dropper target
        bad_url = "http://paypal.com@verify-auth-session.top/update_login.exe?auth=1"
        resp_bad = self.client.post("/api/scanner/analyze",
                                    data=json.dumps({"target": bad_url}),
                                    content_type="application/json")
        self.assertEqual(resp_bad.status_code, 200)
        data_bad = json.loads(resp_bad.data)
        self.assertTrue(data_bad["success"])
        self.assertGreater(data_bad["data"]["detection_ratio"]["malicious"], 0)
        self.assertIn(data_bad["data"]["overall_verdict"], ["MALICIOUS", "SUSPICIOUS"])
        self.assertGreaterEqual(data_bad["data"]["risk_score"], 50)
        self.assertGreater(len(data_bad["data"]["attack_findings"]), 0)
        self.assertGreater(len(data_bad["data"]["mitigation_playbook"]), 0)

        # 3. Test SSRF blocked endpoint
        resp_ssrf = self.client.post("/api/scanner/analyze",
                                     data=json.dumps({"target": "http://127.0.0.1:8080/admin"}),
                                     content_type="application/json")
        self.assertEqual(resp_ssrf.status_code, 200)
        data_ssrf = json.loads(resp_ssrf.data)
        self.assertTrue(data_ssrf["success"])
        self.assertIn("SSRF_ATTEMPT", data_ssrf["data"]["triggered_signatures"])

    def test_primary_theme_setting(self):
        """Test setting and retrieving simple normal primary theme via settings API."""
        resp = self.client.post("/api/settings",
                                data=json.dumps({"theme": "primary"}),
                                content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertTrue(data["success"])

        get_resp = self.client.get("/api/settings")
        self.assertEqual(get_resp.status_code, 200)
        get_data = json.loads(get_resp.data)
        self.assertEqual(get_data["theme"], "primary")

    def test_safe_preview_api(self):
        """Test Safe Headless Visual Preview API and SSRF boundary enforcement."""
        # 1. Test SSRF block
        ssrf_resp = self.client.post("/api/preview/capture",
                                     data=json.dumps({"target": "http://127.0.0.1:8080/admin"}),
                                     content_type="application/json")
        self.assertEqual(ssrf_resp.status_code, 200)
        ssrf_data = json.loads(ssrf_resp.data)
        self.assertFalse(ssrf_data["success"])
        self.assertIn("SSRF", ssrf_data["error"])

        # 2. Test valid target preview
        clean_resp = self.client.post("/api/preview/capture",
                                      data=json.dumps({"target": "https://example.com"}),
                                      content_type="application/json")
        self.assertEqual(clean_resp.status_code, 200)
        clean_data = json.loads(clean_resp.data)
        self.assertTrue(clean_data["success"])
        self.assertIn("sanitized_html", clean_data["data"])
        self.assertIn("status_code", clean_data["data"])
        self.assertIn("forms", clean_data["data"])

    def test_threat_topology_graph_api(self):
        """Test interactive Threat Graph generation API."""
        resp = self.client.post("/api/topology/graph",
                                data=json.dumps({"target": "https://wikipedia.org"}),
                                content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertTrue(data["success"])
        self.assertIn("nodes", data["data"])
        self.assertIn("edges", data["data"])
        self.assertGreater(len(data["data"]["nodes"]), 0)
        self.assertGreater(len(data["data"]["edges"]), 0)

    def test_subdomains_api(self):
        """Test Subdomain Enumeration API."""
        resp = self.client.post("/api/subdomains/scan",
                                data=json.dumps({"domain": "example.com"}),
                                content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertTrue(data["success"])
        self.assertIn("subdomains", data["data"])
        self.assertGreater(data["data"]["total_discovered"], 0)

    def test_batch_scanner_api(self):
        """Test Multi-Target Batch Threat Scanner API."""
        resp = self.client.post("/api/scanner/batch",
                                data=json.dumps({"targets": ["https://wikipedia.org", "http://127.0.0.1:8080/admin"]}),
                                content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["total_targets"], 2)
        self.assertIn("results", data["data"])

    def test_ioc_export_api(self):
        """Test SOC IOC Export API across STIX, Snort, Splunk, and CSV formats."""
        inv_id = save_investigation(
            target="http://malicious-test-c2.xyz/dropper.exe",
            inv_type="threat_scan",
            risk_score=85,
            risk_level="High",
            summary="Hostile C2 test node.",
            details={"primary_ip": "198.51.100.25", "overall_verdict": "MALICIOUS"}
        )

        # STIX 2.1
        stix_resp = self.client.get(f"/api/reports/ioc/{inv_id}?format=stix")
        self.assertEqual(stix_resp.status_code, 200)
        stix_data = json.loads(stix_resp.data)
        self.assertEqual(stix_data["type"], "bundle")
        self.assertGreater(len(stix_data["objects"]), 1)

        # Snort
        snort_resp = self.client.get(f"/api/reports/ioc/{inv_id}?format=snort")
        self.assertEqual(snort_resp.status_code, 200)
        self.assertIn("alert", snort_resp.data.decode("utf-8"))

        # Splunk
        splunk_resp = self.client.get(f"/api/reports/ioc/{inv_id}?format=splunk")
        self.assertEqual(splunk_resp.status_code, 200)
        self.assertIn("index=", splunk_resp.data.decode("utf-8"))

        # CSV
        csv_resp = self.client.get(f"/api/reports/ioc/{inv_id}?format=csv")
        self.assertEqual(csv_resp.status_code, 200)
        self.assertIn("indicator,indicator_type", csv_resp.data.decode("utf-8"))

if __name__ == "__main__":
    unittest.main()
