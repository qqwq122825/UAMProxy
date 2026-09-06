import json
from pathlib import Path
import tempfile
import unittest

from core.config import AppConfig


class FullRebuildConfigTests(unittest.TestCase):
    def test_migrates_legacy_same_device_switch(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "config.json"
            path.write_text(
                json.dumps({"same_device_replenish_mode": True}),
                encoding="utf-8",
            )
            config = AppConfig(str(path))
            self.assertTrue(config.get("full_rebuild_01_mode"))

    def test_canonical_full_rebuild_switch_has_priority(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "same_device_replenish_mode": True,
                        "full_rebuild_01_mode": False,
                    }
                ),
                encoding="utf-8",
            )
            config = AppConfig(str(path))
            self.assertFalse(config.get("full_rebuild_01_mode"))

    def test_recorded_device_mode_is_migrated_to_inherit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "config.json"
            path.write_text(
                json.dumps({"type9_device_mode": "replace_recorded"}),
                encoding="utf-8",
            )
            config = AppConfig(str(path))
            self.assertEqual(config.get("type9_device_mode"), "inherit_live")

    def test_match_event_mode_defaults_to_off(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = AppConfig(str(Path(temp_dir) / "config.json"))
            self.assertEqual(config.get("rebuild_match_events"), "off")
            self.assertEqual(config.get("match_event_min_seconds"), 600)
            self.assertEqual(config.get("match_event_max_seconds"), 1200)
            self.assertEqual(config.get("match_event_lobby_quiet_seconds"), 360)
            self.assertEqual(config.get("rebuild_scan_waves"), "repeat_first")

    def test_rebuild_multiselect_defaults_preserve_legacy_migration(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = AppConfig(str(Path(temp_dir) / "config.json"))
            self.assertFalse(config.get("rebuild_controls_v2"))
            self.assertFalse(config.get("rebuild_controls_v3"))
            self.assertTrue(config.get("rebuild_central9_enabled"))
            self.assertTrue(config.get("rebuild_strong_profile"))
            self.assertFalse(config.get("rebuild_player_base_enabled"))
            self.assertFalse(config.get("rebuild_match_events_enabled"))
            self.assertFalse(config.get("rebuild_scan_waves_enabled"))
            for message_id in (
                "8007", "800A", "800C", "800D",
                "800F", "8023", "8024", "802C",
            ):
                self.assertFalse(config.get(f"rebuild_player_{message_id}_enabled"))

    def test_snapshot_and_scoped_reset_cover_new_log_limits(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = AppConfig(str(Path(temp_dir) / "config.json"))
            config.set("ai_log_retention_days", 30)
            config.set("ai_log_max_gb", 25.5)
            snapshot = config.snapshot()
            self.assertEqual(snapshot["ai_log_retention_days"], 30)
            self.assertEqual(snapshot["ai_log_max_gb"], 25.5)
            config.reset_keys(("ai_log_retention_days", "ai_log_max_gb"))
            self.assertEqual(config.get("ai_log_retention_days"), 7)
            self.assertEqual(config.get("ai_log_max_gb"), 10.0)


if __name__ == "__main__":
    unittest.main()
