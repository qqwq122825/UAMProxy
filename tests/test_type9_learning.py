import json
import os
import tempfile
import unittest

from core.type9_learning import Type9LearningRegistry


def _event(*, message_id=0x8024, length=44, flags=None, diff=True):
    live = bytes(range(length))
    template = bytearray(live)
    if diff and length:
        template[-1] ^= 0x5A
    return {
        "event_id": 1,
        "time": "2026-08-01T12:00:00.000",
        "decision": "REPLACE",
        "reason": "TEST",
        "game_id": "LIVE-UID",
        "connection": {"conn_id": "conn-1"},
        "cross_account": {"donor_game_id": "DONOR-UID"},
        "checks": {
            "output_crc_ok": True,
            "output_validation_ok": True,
            "shadow_decode_ok": True,
        },
        "shadow_rebuild": {
            "leaf_results": [
                {
                    "record_code": 0x0102000A,
                    "message_id": message_id,
                    "length": length,
                    "live_hex": live.hex(),
                    "template_hex": bytes(template).hex(),
                    "suspect_watch": True,
                    "suspect_flags": flags or [],
                    "shadow_only_diff_ranges": (
                        [{"start": length - 1, "end": length - 1}]
                        if diff and length else []
                    ),
                    "identity_rewrite": {"blocked": False},
                }
            ]
        },
    }


class Type9LearningRegistryTests(unittest.TestCase):
    def test_new_schema_writes_profiles_and_ai_bundle(self):
        with tempfile.TemporaryDirectory() as root:
            run_dir = os.path.join(root, "run")
            registry = Type9LearningRegistry(data_dir=root, run_dir=run_dir)

            result = registry.observe(_event(flags=["NEW_IDENTITY"]))

            self.assertEqual(result["observed"], 1)
            self.assertGreaterEqual(result["alerts"], 2)
            self.assertTrue(os.path.isfile(os.path.join(run_dir, "01_schema_registry.json")))
            self.assertTrue(os.path.isfile(os.path.join(run_dir, "01_field_profiles.json")))
            self.assertTrue(os.path.isfile(os.path.join(run_dir, "NeedsAIAnalysis", "manifest.json")))
            with open(os.path.join(run_dir, "01_schema_registry.json"), encoding="utf-8") as stream:
                saved = json.load(stream)
            row = next(iter(saved["schemas"].values()))
            self.assertEqual(row["accounts"], ["LIVE-UID"])
            self.assertEqual(row["donor_accounts"], ["DONOR-UID"])

    def test_existing_stable_schema_does_not_repeat_ai_alerts(self):
        with tempfile.TemporaryDirectory() as root:
            first_run = os.path.join(root, "first")
            Type9LearningRegistry(data_dir=root, run_dir=first_run).observe(
                _event(diff=False)
            )
            second_run = os.path.join(root, "second")
            result = Type9LearningRegistry(data_dir=root, run_dir=second_run).observe(
                _event(diff=False)
            )

            self.assertEqual(result, {"observed": 1, "alerts": 0})
            self.assertTrue(os.path.isfile(os.path.join(second_run, "01_field_profiles.json")))
            self.assertFalse(os.path.exists(os.path.join(second_run, "NeedsAIAnalysis")))

    def test_new_length_is_a_separate_schema(self):
        with tempfile.TemporaryDirectory() as root:
            registry = Type9LearningRegistry(data_dir=root, run_dir=os.path.join(root, "run"))
            registry.observe(_event(length=44, diff=False))
            result = registry.observe(_event(length=45, flags=["NEW_LENGTH"], diff=False))

            self.assertGreaterEqual(result["alerts"], 2)
            self.assertEqual(len(registry.registry["schemas"]), 2)

    def test_byte_profile_does_not_recount_values_after_sample_cap(self):
        with tempfile.TemporaryDirectory() as root:
            registry = Type9LearningRegistry(data_dir=root, run_dir=os.path.join(root, "run"))
            for value in range(10):
                event = _event(length=44, diff=False)
                raw = bytearray.fromhex(
                    event["shadow_rebuild"]["leaf_results"][0]["live_hex"]
                )
                raw[20] = value
                event["shadow_rebuild"]["leaf_results"][0]["live_hex"] = raw.hex()
                registry.observe(event)
            event = _event(length=44, diff=False)
            raw = bytearray.fromhex(
                event["shadow_rebuild"]["leaf_results"][0]["live_hex"]
            )
            raw[20] = 9
            event["shadow_rebuild"]["leaf_results"][0]["live_hex"] = raw.hex()
            registry.observe(event)

            row = next(iter(registry.registry["schemas"].values()))
            self.assertEqual(row["live_profile"]["bytes"][20]["changes"], 9)
            self.assertEqual(row["live_profile"]["bytes"][20]["unique_values"], 10)


if __name__ == "__main__":
    unittest.main()
