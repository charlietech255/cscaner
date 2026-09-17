import os
import socket
import threading
import time
import unittest
from types import SimpleNamespace

from cscan import SUPPORTED_MODULES, build_parser
from modules.ai_analyst import _build_findings_prompt, _ground_truth_summary
from modules.api_emulator import ApiEmulatorServer, scan_api_contract
from modules.web import _cookie_security_flags
from modules.stealth import StealthSession
from modules.ui import print_table, progress_bar
from modules.utils import normalize_target


class CliParserTests(unittest.TestCase):
    def test_supported_modules_include_core_workflows(self):
        self.assertIn("dns", SUPPORTED_MODULES)
        self.assertIn("web", SUPPORTED_MODULES)
        self.assertIn("auto", SUPPORTED_MODULES)

    def test_build_parser_accepts_target_and_module(self):
        parser = build_parser()
        args = parser.parse_args([
            "--target",
            "https://example.com",
            "--module",
            "auto",
            "--stealth",
            "--insecure",
            "--credential-testing",
        ])

        self.assertEqual(args.target, "https://example.com")
        self.assertEqual(args.module, "auto")
        self.assertTrue(args.stealth)
        self.assertTrue(args.insecure)
        self.assertTrue(args.credential_testing)

    def test_credential_testing_is_disabled_by_default(self):
        args = build_parser().parse_args(["--target", "https://example.com"])
        self.assertFalse(args.credential_testing)

    def test_normalize_target_preserves_https_path_and_query(self):
        self.assertEqual(
            normalize_target("https://charlietech.site/app/search?q=test"),
            "https://charlietech.site/app/search?q=test",
        )
        self.assertEqual(normalize_target("charlietech.site"), "https://charlietech.site")
        with self.assertRaises(ValueError):
            normalize_target("ftp://charlietech.site")

    def test_stealth_configuration_rejects_invalid_values(self):
        with self.assertRaises(ValueError):
            StealthSession(proxy="ftp://proxy.example:21")
        with self.assertRaises(ValueError):
            StealthSession(jitter_min=2, jitter_max=1)

    def test_stealth_headers_do_not_fabricate_network_identity(self):
        session = StealthSession(random_headers=True)
        headers = session._get_headers()
        self.assertNotIn("X-Forwarded-For", headers)
        self.assertNotIn("Referer", headers)

    def test_progress_bar_handles_empty_and_out_of_range_totals(self):
        progress_bar(1, 0)
        progress_bar(-1, 2)
        progress_bar(3, 2)

    def test_print_table_handles_mismatched_row_widths(self):
        print_table(["Name"], [["alpha", "extra"], []])

    def test_build_parser_supports_list_modules(self):
        parser = build_parser()
        args = parser.parse_args(["--list-modules"])
        self.assertTrue(args.list_modules)

    def test_supported_modules_include_nuclei_template_scan(self):
        self.assertIn("nuclei", SUPPORTED_MODULES)

    def test_direct_sqli_scan_accepts_url_or_form_payload(self):
        from modules.active_vuln import scan_sqli_target

        result = scan_sqli_target("https://example.com/search?q=test")
        self.assertIn("findings", result)
        self.assertIn("target", result)

    def test_requirements_include_camoufox_for_cloudflare_bypass(self):
        requirements_path = __file__.rsplit("/tests", 1)[0] + "/requirements.txt"
        with open(requirements_path, "r", encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("camoufox[geoip]", text)

    def test_ground_truth_summary_contains_only_observed_evidence(self):
        results = {
            "dns": {"ipv4": ["93.184.216.34"], "mx": ["mail.example.com"]},
            "ports_common": [{"port": 443, "state": "open", "banner": "Apache 2.4.41"}],
            "ssl": {"subject": {"commonName": "example.com"}, "issuer": {"organizationName": "Example CA"}},
            "web_vuln": {"exposed": [("/admin", 403, "forbidden")]},
        }

        summary = _ground_truth_summary(results)
        self.assertIn("93.184.216.34", summary)
        self.assertIn("443/tcp", summary)
        self.assertIn("/admin", summary)
        self.assertIn("ONLY VERIFIED FINDINGS", summary)
        self.assertNotIn("CVE-", summary)

    def test_ground_truth_summary_handles_empty_results(self):
        summary = _ground_truth_summary({})
        self.assertIn("No verified findings", summary)

    def test_ai_findings_prompt_handles_port_result_shapes(self):
        prompt = _build_findings_prompt("https://example.com", {
            "ports_common": [
                {"port": 443, "state": "open", "banner": "nginx"},
                (8080, "HTTP service", "extra metadata"),
            ],
            "ssh": {"vulnerable": True, "credential": ("alice", "secret")},
        })
        self.assertIn("443/tcp", prompt)
        self.assertIn("8080/tcp", prompt)
        self.assertNotIn("alice:secret", prompt)

    def test_cookie_security_flags_parse_raw_set_cookie_headers(self):
        raw_headers = SimpleNamespace(getlist=lambda name: [
            "session=abc; Secure; HttpOnly; SameSite=Lax",
            "tracking=xyz",
        ])
        response = SimpleNamespace(raw=SimpleNamespace(headers=raw_headers), headers={})

        cookies = _cookie_security_flags(response)

        self.assertEqual(cookies, [
            {"name": "session", "secure": True, "httponly": True, "samesite": "Lax"},
            {"name": "tracking", "secure": False, "httponly": False, "samesite": None},
        ])

    def test_api_emulator_contract_works_on_live_local_server(self):
        server = ApiEmulatorServer(("127.0.0.1", 0), state_file="/tmp/cscan_api_emulator_test_state.json")
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        deadline = time.time() + 5
        while time.time() < deadline:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.2)
                try:
                    sock.connect(("127.0.0.1", port))
                    break
                except OSError:
                    time.sleep(0.1)
        else:
            server.shutdown()
            server.server_close()
            self.fail("live emulator server did not start in time")

        try:
            result = scan_api_contract(
                f"http://127.0.0.1:{port}",
                username="alice",
                password="secret",
            )
            self.assertTrue(result["token_issued"])
            self.assertTrue(result["contract_ok"])
            self.assertTrue(any(item["route"] == "/api/v1/users" for item in result["findings"]))
        finally:
            server.shutdown()
            server.server_close()
            try:
                import os
                os.remove("/tmp/cscan_api_emulator_test_state.json")
            except FileNotFoundError:
                pass

    def test_api_emulator_lists_all_routes(self):
        server = ApiEmulatorServer(("127.0.0.1", 0), state_file="/tmp/cscan_api_emulator_routes_state.json")
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        deadline = time.time() + 5
        while time.time() < deadline:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.2)
                try:
                    sock.connect(("127.0.0.1", port))
                    break
                except OSError:
                    time.sleep(0.1)
        else:
            server.shutdown()
            server.server_close()
            self.fail("live emulator server did not start in time")

        try:
            result = scan_api_contract(
                f"http://127.0.0.1:{port}",
                username="alice",
                password="secret",
            )
            self.assertIn("routes", result)
            self.assertTrue(any(route.get("path") == "/api/v1/endpoints" for route in result["routes"]))
        finally:
            server.shutdown()
            server.server_close()
            try:
                os.remove("/tmp/cscan_api_emulator_routes_state.json")
            except FileNotFoundError:
                pass

    def test_termux_mobile_api_enum_returns_candidate_endpoints(self):
        from modules.mobile_api_enum import enumerate_mobile_api_endpoints

        result = enumerate_mobile_api_endpoints(
            "https://example.com",
            wordlist=["/api", "/api/v1", "/health"],
            probe=False,
        )
        self.assertIn("target", result)
        self.assertIn("endpoints", result)
        self.assertTrue(any(item["path"] == "/api" for item in result["endpoints"]))

    def test_auto_scan_pipeline_adds_api_and_sqli_steps(self):
        from cscan import _build_auto_scan_steps

        steps = _build_auto_scan_steps("https://example.com", 10, False, None, None, False)
        labels = [label for label, _, _ in steps]
        self.assertTrue(any("API Enumeration" in label for label in labels))
        self.assertTrue(any("SQLi Smoke" in label for label in labels))

    def test_scan_api_contract_accepts_hosted_url_and_token(self):
        result = scan_api_contract(
            "http://127.0.0.1:8081",
            username="alice",
            password="secret",
        )
        self.assertIn("base_url", result)
        self.assertIn("findings", result)


class OriginIPDiscoveryTests(unittest.TestCase):
    """Tests for the osnit_origin_ip module."""

    def test_origin_candidate_dedupe_merges_sources(self):
        from modules.osnit_origin_ip import OriginCandidate, OriginIPReport

        report = OriginIPReport(domain="example.com")
        report.add(OriginCandidate(ip="1.2.3.4", source="mx:mail", evidence="lead A", confidence="possible"))
        report.add(OriginCandidate(ip="1.2.3.4", source="cert_sh:old", evidence="lead B", confidence="confirmed",
                                   verified_response_snippet="<html>real</html>"))
        self.assertEqual(len(report.candidates), 1)
        self.assertEqual(report.candidates[0].confidence, "confirmed")
        self.assertIn("mx:mail", report.candidates[0].source)
        self.assertIn("cert_sh:old", report.candidates[0].source)

    def test_is_cloudflare_ip_matches_published_ranges(self):
        from modules.osnit_origin_ip import _is_cloudflare_ip

        self.assertTrue(_is_cloudflare_ip("104.16.5.5"))
        self.assertTrue(_is_cloudflare_ip("172.67.214.70"))
        self.assertTrue(_is_cloudflare_ip("131.0.72.3"))
        self.assertFalse(_is_cloudflare_ip("203.0.113.5"))
        self.assertFalse(_is_cloudflare_ip("8.8.8.8"))

    def test_find_origin_ip_returns_report_shape(self):
        from modules.osnit_origin_ip import find_origin_ip

        report = find_origin_ip("https://mruhakika.site", verify=False)
        self.assertIsNotNone(report.cf_ips)
        self.assertIsInstance(report.candidates, list)

    def test_crtsh_query_returns_candidates_or_empty_list(self):
        from modules.osnit_origin_ip import _query_crtsh

        results = _query_crtsh("example.com")
        self.assertIsInstance(results, list)


class SubdomainFinderTests(unittest.TestCase):
    """Tests for the dedicated deep subdomain finder module (offline parsers)."""

    def test_parse_crtsh_json_filters_apex_and_wildcards(self):
        from modules.subdomain_finder import _parse_crtsh

        data = [
            {"name_value": "api.example.com\n*.api.example.com"},
            {"name_value": "example.com"},
            {"name_value": " mail.example.com\n*."},
        ]
        names = _parse_crtsh(data, "example.com")
        self.assertIn("api.example.com", names)
        self.assertIn("mail.example.com", names)
        self.assertNotIn("example.com", names)
        self.assertNotIn("*.api.example.com", names)

    def test_parse_rapiddns_html_extracts_subdomains(self):
        from modules.subdomain_finder import _parse_rapiddns

        html = (
            '<a href="//api.example.com">api.example.com</a> '
            '<td>mail.example.com</td> '
            '<td>example.com</td> unrelated'
        )
        names = _parse_rapiddns(html, "example.com")
        self.assertIn("api.example.com", names)
        self.assertIn("mail.example.com", names)
        self.assertNotIn("example.com", names)

    def test_parse_hackertarget_csv(self):
        from modules.subdomain_finder import _parse_hackertarget

        text = (
            "api.example.com,1.2.3.4\n"
            "mail.example.com,5.6.7.8\n"
            "bad.example.com,not-an-ip\n"
            "example.com,9.9.9.9\n"
        )
        names, ips = _parse_hackertarget(text, "example.com")
        self.assertIn("api.example.com", names)
        self.assertIn("mail.example.com", names)
        self.assertNotIn("bad.example.com", names)
        self.assertNotIn("example.com", names)
        self.assertEqual(ips.get("api.example.com"), "1.2.3.4")

    def test_parse_otx_json(self):
        from modules.subdomain_finder import _parse_otx

        data = {
            "passive_dns": [
                {"hostname": "admin.example.com."},
                {"hostname": "example.com"},
                {"hostname": ""},
            ]
        }
        names = _parse_otx(data, "example.com")
        self.assertIn("admin.example.com", names)
        self.assertNotIn("example.com", names)

    def test_extract_hostname_strips_scheme_and_path(self):
        from modules.subdomain_finder import extract_hostname

        self.assertEqual(extract_hostname("https://example.com/admin?q=1"), "example.com")
        self.assertEqual(extract_hostname("example.com"), "example.com")


if __name__ == "__main__":
    unittest.main()
