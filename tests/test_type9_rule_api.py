import json
import os
import tempfile
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import core.type9_special_rules as special_rules
from core.type9_online import BINARY_CODE
from core.type9_special_rules import HOT_RULE_SCHEMA, Type9HotRuleStore

try:
    from core.admin_api import AdminApiServer
except ModuleNotFoundError as exc:
    if exc.name != "PySide6":
        raise
    AdminApiServer = None


@unittest.skipIf(AdminApiServer is None, "PySide6 is not installed")
class Type9RuleApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_store = special_rules.type9_hot_rule_store
        special_rules.type9_hot_rule_store = Type9HotRuleStore(
            os.path.join(self.tmp.name, "rules.json"),
            auto_reload_interval=0,
        )
        self.server = AdminApiServer("127.0.0.1", 0, "test-token")
        self.server.start()
        self.port = self.server._httpd.server_address[1]

    def tearDown(self):
        self.server.stop()
        special_rules.type9_hot_rule_store = self.old_store
        self.tmp.cleanup()

    def request(self, path, *, method="GET", body=None, token="test-token"):
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"X-Admin-Token": token}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        with urlopen(req, timeout=3) as response:
            return response.status, json.loads(response.read().decode("utf-8"))

    def test_authenticated_upload_status_and_reload(self):
        with self.assertRaises(HTTPError) as ctx:
            self.request("/api/type9/rules", token="wrong")
        self.assertEqual(ctx.exception.code, 401)

        document = {
            "schema": HOT_RULE_SCHEMA,
            "revision": "api-test-1",
            "rules": [
                {
                    "id": "api-0207",
                    "enabled": True,
                    "match": {
                        "record_code": "0x0102000A",
                        "message_id": "0x0207",
                        "length": 116,
                    },
                    "action": "patch_live",
                    "patches": [{"offset": "0x48", "hex": "00000000"}],
                }
            ],
        }
        status, result = self.request(
            "/api/type9/rules", method="POST", body=document
        )
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        self.assertEqual(result["active_rule_count"], 1)
        self.assertEqual(result["document"]["revision"], "api-test-1")

        status, result = self.request("/api/type9/rules")
        self.assertEqual(status, 200)
        self.assertEqual(result["active_rule_count"], 1)
        self.assertIsNotNone(
            special_rules.type9_hot_rule_store.get_rule((BINARY_CODE, 0x0207, 116))
        )

        status, result = self.request(
            "/api/type9/rules/reload", method="POST", body={}
        )
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])

    def test_invalid_upload_does_not_replace_active_rules(self):
        good = {
            "schema": HOT_RULE_SCHEMA,
            "revision": "good",
            "rules": [],
        }
        self.request("/api/type9/rules", method="POST", body=good)
        bad = {
            "schema": HOT_RULE_SCHEMA,
            "revision": "bad",
            "rules": [{"id": "broken"}],
        }
        with self.assertRaises(HTTPError) as ctx:
            self.request("/api/type9/rules", method="POST", body=bad)
        self.assertEqual(ctx.exception.code, 400)
        _status, current = self.request("/api/type9/rules")
        self.assertEqual(current["document"]["revision"], "good")

    def test_runtime_password_change_takes_effect_immediately(self):
        self.server.token = "new-test-token"
        with self.assertRaises(HTTPError) as ctx:
            self.request("/api/ping", token="test-token")
        self.assertEqual(ctx.exception.code, 401)
        status, result = self.request("/api/ping", token="new-test-token")
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])

    def test_management_port_can_be_rebound_after_stop(self):
        port = self.port
        self.server.stop()
        self.server.port = port
        self.server.start()
        self.port = self.server._httpd.server_address[1]
        status, result = self.request("/api/ping")
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])


if __name__ == "__main__":
    unittest.main()
