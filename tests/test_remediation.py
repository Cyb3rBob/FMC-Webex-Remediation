import ast
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "module"))
import build_module
import send_webex_message as app


class RemediationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = Path(self.temp.name) / "instance.conf"
        self.config.write_bytes((ROOT / "examples/instance.conf").read_bytes())

    def rewrite_config(self, change):
        tree = ET.parse(str(self.config))
        change(tree.getroot())
        tree.write(str(self.config), encoding="utf-8")

    def run_main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = app.main(["--config", str(self.config)] + list(args))
        return code, out.getvalue(), err.getvalue()

    def test_password_token_and_xml_entities(self):
        self.rewrite_config(lambda root: setattr(root.find("config/string[@name='WEBEX_MESSAGE']"), "text", "A & B <alert>"))
        token, room, title, proxy_url = app.parse_instance_config(str(self.config), "NotifyWebex")
        self.assertEqual(token, "EXAMPLE_TOKEN_DO_NOT_USE")
        self.assertEqual(title, "A & B <alert>")
        self.assertEqual(proxy_url, "")

    def test_proxy_config_and_main_delivery(self):
        self.rewrite_config(lambda root: setattr(root.find("config/string[@name='WEBEX_PROXY_URL']"),
                                                "text", "http://proxy.example.com:8080"))
        with patch.object(app, "send_webex_message", return_value=0) as send:
            self.assertEqual(self.run_main("NotifyWebex")[0], 0)
        self.assertEqual(send.call_args.args[-1], "http://proxy.example.com:8080")
        code, out, err = self.run_main("--dry-run", "NotifyWebex")
        self.assertEqual(code, 0)
        self.assertIn("configured HTTP proxy", out)
        self.assertNotIn("proxy.example.com", out + err)

    def test_invalid_proxy_never_sends_or_discloses_value(self):
        for value in ("proxy.example.com:8080", "https://proxy.example.com:8080",
                      "http://user:secret@proxy:8080", "http://proxy:invalid",
                      "http://proxy:65536", "http://proxy:0", "http://proxy/path",
                      "http://proxy?secret", "http://proxy#secret", "http://pro xy:8080"):
            with self.subTest(value=value):
                self.rewrite_config(lambda root: setattr(root.find("config/string[@name='WEBEX_PROXY_URL']"), "text", value))
                with patch.object(app, "send_webex_message") as send:
                    code, out, err = self.run_main("NotifyWebex")
                self.assertEqual(code, 130)
                self.assertNotIn("secret", out + err)
                send.assert_not_called()

    def test_explicit_proxy_overrides_environment_selection(self):
        with patch.dict(os.environ, {"https_proxy": "http://environment-proxy:8080"}), patch.object(app, "build_opener") as factory:
            response = factory.return_value.open.return_value.__enter__.return_value
            response.getcode.return_value = 201
            with redirect_stdout(io.StringIO()):
                self.assertEqual(app.send_webex_message("token", "room", "message", app.create_tls_context(),
                                                       "http://configured-proxy:8080"), 0)
            proxies = [handler for handler in factory.call_args.args if isinstance(handler, app.ProxyHandler)]
            self.assertEqual(len(proxies), 1)
            self.assertEqual(proxies[0].proxies, {"https": "http://configured-proxy:8080"})

    def test_unset_proxy_preserves_automatic_discovery(self):
        self.rewrite_config(lambda root: root.find("config").remove(root.find("config/string[@name='WEBEX_PROXY_URL']")))
        self.assertEqual(app.parse_instance_config(str(self.config), "NotifyWebex")[-1], "")
        with patch.object(app, "build_opener") as factory:
            factory.return_value.open.return_value.__enter__.return_value.getcode.return_value = 201
            with redirect_stdout(io.StringIO()):
                self.assertEqual(app.send_webex_message("token", "room", "message", app.create_tls_context()), 0)
            self.assertFalse(any(isinstance(handler, app.ProxyHandler) for handler in factory.call_args.args))

    def test_legacy_string_token(self):
        self.rewrite_config(lambda root: setattr(root.find("config/password"), "tag", "string"))
        self.assertEqual(app.parse_instance_config(str(self.config), "NotifyWebex")[0], "EXAMPLE_TOKEN_DO_NOT_USE")

    def test_invalid_config_never_sends(self):
        for content in ("<broken", "<instance/>", "<other><config/></other>",
                        "<instance><config><string name='WEBEX_TOKEN'>secret</string></config></instance>"):
            with self.subTest(content=content), patch.object(app, "send_webex_message") as send:
                self.config.write_text(content, encoding="utf-8")
                code, out, err = self.run_main("NotifyWebex")
                self.assertEqual(code, 130)
                send.assert_not_called()
                self.assertNotIn("secret", out + err)

    def test_missing_config(self):
        self.config.unlink()
        self.assertEqual(self.run_main("NotifyWebex")[0], 130)

    def test_wrong_action_name_or_type(self):
        self.assertEqual(self.run_main("WrongAction")[0], 130)
        self.rewrite_config(lambda root: root.find("remediation").set("type", "wrong_type"))
        self.assertEqual(self.run_main("NotifyWebex")[0], 130)

    def test_no_per_action_config_is_allowed(self):
        self.rewrite_config(lambda root: root.remove(root.find("remediation")))
        self.assertEqual(self.run_main("--dry-run", "NotifyWebex")[0], 0)

    def test_header_injection_rejected(self):
        self.rewrite_config(lambda root: setattr(root.find("config/password"), "text", "secret\nInjected: value"))
        with patch.object(app, "send_webex_message") as send:
            code, out, err = self.run_main("NotifyWebex")
        self.assertEqual(code, 130)
        self.assertNotIn("secret", out + err)
        send.assert_not_called()

    def test_dry_run_never_opens_network(self):
        with patch.object(app, "build_opener") as opener:
            code, out, err = self.run_main("--dry-run", "NotifyWebex", "Cisco", "Linux", "9")
        self.assertEqual(code, 0)
        self.assertIn("**Remediation:** NotifyWebex", out)
        self.assertIn("**OS Vendor:** Cisco", out)
        self.assertIn("**OS Product:** Linux", out)
        self.assertNotIn("EXAMPLE_TOKEN", out + err)
        opener.assert_not_called()

    def test_missing_os_values_preserve_positions(self):
        message = app.build_message("", "NotifyWebex", ["undefined", "Linux", ""])
        self.assertNotIn("OS Vendor", message)
        self.assertIn("**OS Product:** Linux", message)
        self.assertNotIn("OS Version", message)
        self.assertIn("Cisco FMC Correlation Event", message)

    def test_excess_args_rejected(self):
        with patch.object(app, "send_webex_message") as send:
            self.assertEqual(self.run_main("NotifyWebex", "a", "b", "c", "d", "e")[0], 130)
        send.assert_not_called()

    def test_source_ip_preserves_os_positions(self):
        for address in ("192.0.2.25", "2001:db8::25"):
            with self.subTest(address=address):
                message = app.build_message("", "NotifyWebex", ["Cisco", "Linux", "9", address])
                self.assertIn("**Source IP:** " + address, message)
                self.assertIn("**OS Vendor:** Cisco", message)
                self.assertIn("**OS Product:** Linux", message)
                self.assertIn("**OS Version:** 9", message)

    def test_missing_source_ip_always_has_placeholder(self):
        for values in ([], ["Cisco", "Linux", "9"]):
            self.assertIn("**Source IP:** " + app.markdown_value("IP-not-identified"),
                          app.build_message("", "NotifyWebex", values))
        for missing in ("", "undefined", "NULL", "(null)", "  undefined  ", " "):
            with self.subTest(missing=missing):
                message = app.build_message("", "NotifyWebex", ["undefined", "Linux", "9", missing])
                self.assertIn("**Source IP:** " + app.markdown_value("IP-not-identified"), message)
                self.assertIn("**OS Product:** Linux", message)
                self.assertNotIn("OS Vendor", message)

    def test_source_ip_reaches_webex_payload(self):
        with patch.object(app, "build_opener") as factory:
            factory.return_value.open.return_value.__enter__.return_value.getcode.return_value = 201
            code, out, err = self.run_main("NotifyWebex", "undefined", "undefined", "undefined", "192.0.2.25")
        self.assertEqual(code, 0)
        payload = json.loads(factory.return_value.open.call_args.args[0].data)
        self.assertIn("**Source IP:** 192.0.2.25", payload["markdown"])
        self.assertNotIn("OS Vendor", payload["markdown"])

    def test_unicode_length_and_markup(self):
        message = app.build_message("<@all> [link](url)", "NotifyWebex", ["\u96ea" * 3000])
        self.assertNotIn("<@all>", message)
        self.assertNotIn("[link](url)", message)
        self.assertLessEqual(len(message.encode("utf-8")), 6000)
        self.assertIn("Message truncated", message)

    def test_ca_bundle_and_verification(self):
        context = app.create_tls_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreater(context.cert_store_stats()["x509_ca"], 50)

    def test_missing_ca_fails_without_network(self):
        with patch.object(app, "CA_FILE", str(Path(self.temp.name) / "missing.pem")), patch.object(app, "build_opener") as opener:
            self.assertEqual(self.run_main("NotifyWebex")[0], 133)
        opener.assert_not_called()

    def test_success_posts_expected_payload_once(self):
        for status in (200, 201):
            with self.subTest(status=status), patch.object(app, "build_opener") as factory:
                response = factory.return_value.open.return_value.__enter__.return_value
                response.getcode.return_value = status
                with redirect_stdout(io.StringIO()):
                    result = app.send_webex_message("test-token", "test-room", "Test \u96ea", app.create_tls_context())
                self.assertEqual(result, 0)
                factory.return_value.open.assert_called_once()
                args, kwargs = factory.return_value.open.call_args
                request = args[0]
                self.assertEqual(request.full_url, "https://webexapis.com/v1/messages")
                self.assertEqual(request.get_method(), "POST")
                self.assertEqual(request.get_header("Authorization"), "Bearer test-token")
                self.assertEqual(json.loads(request.data), {"roomId": "test-room", "markdown": "Test \u96ea"})
                self.assertEqual(kwargs["timeout"], 15)
                self.assertTrue(any(isinstance(handler, app.NoRedirects) for handler in factory.call_args[0]))

    def test_http_errors_are_classified_and_redacted(self):
        for status, expected in ((400, 129), (401, 131), (403, 131), (404, 129), (407, 132), (429, 134), (500, 129), (302, 129)):
            with self.subTest(status=status), patch.object(app, "build_opener") as factory:
                body = io.BytesIO(b"secret-token")
                factory.return_value.open.side_effect = HTTPError(app.WEBEX_URL, status, "secret-token", {}, body)
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    result = app.send_webex_message("secret-token", "room", "message", app.create_tls_context())
                self.assertEqual(result, expected)
                self.assertNotIn("secret-token", out.getvalue() + err.getvalue())
                self.assertTrue(body.closed)
                factory.return_value.open.assert_called_once()

    def test_network_errors_do_not_retry(self):
        cases = [(URLError(ssl.SSLError("secret-token")), 133),
                 (ssl.SSLError("secret-token"), 133),
                 (URLError(socket.timeout("secret-token")), 132),
                 (socket.timeout("secret-token"), 132),
                 (URLError(socket.gaierror("secret-token")), 132),
                 (http.client.RemoteDisconnected("secret-token"), 132)]
        for error, expected in cases:
            with self.subTest(error=type(error).__name__), patch.object(app, "build_opener") as factory:
                factory.return_value.open.side_effect = error
                err = io.StringIO()
                with redirect_stderr(err):
                    result = app.send_webex_message("secret-token", "room", "message", app.create_tls_context())
                self.assertEqual(result, expected)
                self.assertNotIn("secret-token", err.getvalue())
                factory.return_value.open.assert_called_once()

    def test_python39_grammar(self):
        for file in (ROOT / "module/send_webex_message.py", ROOT / "build_module.py"):
            ast.parse(file.read_text(encoding="utf-8"), feature_version=(3, 9))

    def test_template_contract(self):
        root = ET.parse(str(ROOT / "module/module.template")).getroot()
        fields = root.findall("remediation_type/policy_event_data/pe_item")
        self.assertEqual([field.text for field in fields], ["src_os_vendor", "src_os_product", "src_os_version", "src_ip_addr"])
        self.assertTrue(all(field.get("required") == "false" for field in fields))
        self.assertEqual(root.findtext("config_template/password/name"), "WEBEX_TOKEN")
        self.assertEqual(root.findtext("global_config/version"), "1.4")
        self.assertEqual(root.find("config_template/string[name='WEBEX_PROXY_URL']").get("required"), "false")
        self.assertEqual({int(item.get("value")) for item in root.findall("exit_status")}, set(range(129, 135)))

    def test_built_archive_runs_from_fmc_instance_directory(self):
        archive_path = build_module.build_package(self.temp.name)
        original_hash = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        build_module.build_package(self.temp.name)
        self.assertEqual(hashlib.sha256(archive_path.read_bytes()).hexdigest(), original_hash)
        installed = Path(self.temp.name) / "installed"
        installed.mkdir()
        with tarfile.open(str(archive_path)) as archive:
            self.assertEqual(set(archive.getnames()), set(build_module.FILES) | {"lib"})
            self.assertEqual(archive.getmember("send_webex_message.py").mode, 0o755)
            self.assertEqual(archive.getmember("lib").mode, 0o755)
            for name in build_module.FILES:
                content = archive.extractfile(name).read()
                self.assertNotIn(b"\r\n", content)
                target = installed / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
        self.assertTrue((installed / "send_webex_message.py").read_bytes().startswith(b"#!/usr/bin/env python3\n"))
        instance = installed / "WebexAlerts"
        instance.mkdir()
        (instance / "instance.conf").write_bytes(self.config.read_bytes())
        # -S disables site-packages; only the packaged script and stdlib are present.
        result = subprocess.run([sys.executable, "-B", "-S", "../send_webex_message.py",
                                 "--dry-run", "NotifyWebex", "Cisco", "Linux", "9", "192.0.2.25"],
                                cwd=str(instance), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("OS Vendor", result.stdout)
        self.assertIn("**Source IP:** 192.0.2.25", result.stdout)
        self.assertNotIn("EXAMPLE_TOKEN", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
