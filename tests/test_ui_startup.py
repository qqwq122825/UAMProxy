from __future__ import annotations

import os
import unittest


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication
    from ui.views import APP_VERSION, MainWindow
except ImportError:  # 本地只安装运行时核心依赖时跳过，Windows 构建环境会执行。
    QApplication = None
    MainWindow = None
    APP_VERSION = ""


@unittest.skipIf(QApplication is None, "PySide6 is not installed")
class MainWindowStartupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_config_widgets_survive_ui_construction(self):
        window = MainWindow()
        try:
            self.assertGreaterEqual(
                window.tabs.indexOf(window._local_file_replay_page), 0
            )
            self.assertEqual(
                window.tabs.tabText(
                    window.tabs.indexOf(window._local_file_replay_page)
                ),
                "📄 本地文件重放",
            )
            self.assertFalse(hasattr(window, "cb_ace_https_block"))
            self.assertFalse(hasattr(window, "cb_ace_https_block_replay_only"))
            self.assertFalse(hasattr(window, "edit_ace_https_block_host"))

            # 这些控件曾因所属页面未被 Qt 持有而在配置加载时变成
            # "Internal C++ object already deleted"。调用 Qt 方法可验证
            # Python 包装器背后的 C++ 对象仍然存活。
            for checkbox in (
                window.cb_az_dl_intercept,
                window.cb_hok_dl_intercept,
                window.cb_hok_33_replay_replace,
            ):
                self.assertIsInstance(checkbox.isChecked(), bool)

            self.assertEqual(len(window._legacy_intercept_pages), 2)
            self.assertTrue(all(
                page.isHidden() for page in window._legacy_intercept_pages
            ))
            self.assertTrue(all(
                widget.isHidden()
                for widget in window._legacy_dz_intercept_widgets
            ))
            self.assertFalse(window.dl_01_block_box.isHidden())
            self.assertFalse(window.cb_dl_01_block.isHidden())
            self.assertFalse(window.cb_dl_01_mrpcs_mutate.isHidden())
            self.assertEqual(
                window.dl_01_block_box.title(),
                "01 下行拦截",
            )
            self.assertTrue(hasattr(window, "btn_block_3366"))
            self.assertTrue(window.btn_block_3366.isCheckable())
            self.assertFalse(window.btn_block_3366.isChecked())
            self.assertFalse(window.btn_block_3366.isEnabled())
            self.assertEqual(window.btn_block_3366.text(), "⛔ 阻断3366")
            self.assertFalse(hasattr(window, "combo_type9_device_mode"))
            intercept_index = window.tabs.indexOf(window._intercept_page)
            config_index = window.tabs.indexOf(window._config_page)
            self.assertEqual(config_index, intercept_index + 1)
            self.assertEqual(window.tabs.tabText(config_index), "⚙️ 配置")
            self.assertTrue(
                window._config_page.isAncestorOf(window.cb_replenish_01)
            )
            self.assertFalse(hasattr(window, "btn_set_official"))
            self.assertTrue(hasattr(window, "cb_replenish_01"))
            self.assertEqual(window.cb_replenish_01.text(), "重建模式")
            self.assertFalse(window.cb_replenish_01.isChecked())
            self.assertFalse(window.rebuild_options_box.isEnabled())
            self.assertFalse(window.cb_rebuild_central9.isChecked())
            self.assertTrue(window.cb_rebuild_strong_profile.isChecked())
            self.assertFalse(window.cb_rebuild_player_base.isChecked())
            for message_id in (
                "8007", "800A", "800C", "800D",
                "800F", "8023", "8024", "802C",
            ):
                self.assertFalse(
                    getattr(window, f"cb_rebuild_player_{message_id}").isChecked()
                )
            self.assertFalse(window.cb_rebuild_match_events.isChecked())
            self.assertFalse(window.cb_rebuild_scan_waves.isChecked())
            self.assertTrue(hasattr(window, "cb_hold_01"))
            self.assertEqual(window.cb_hold_01.text(), "01只收录（阈值后）")
            self.assertFalse(window.cb_hold_01.isChecked())
            self.assertEqual(window.cb_detail_01.text(), "记录详细01日志")
            self.assertEqual(window.edit_detail_01_users.text(), "test")
            self.assertIn("test", window.edit_detail_01_users.selectedValues())
            self.assertIn("每次事件", window.edit_detail_01_users.toolTip())
            self.assertIn("其他用户", window.spin_ai_log_periodic_full.toolTip())
            for checkbox in (
                window.cb_replenish_01,
                window.cb_rebuild_central9,
                window.cb_rebuild_strong_profile,
                window.cb_rebuild_player_base,
                window.cb_rebuild_match_events,
                window.cb_rebuild_scan_waves,
                window.cb_hold_01,
                window.cb_detail_01,
            ):
                self.assertTrue(window._config_page.isAncestorOf(checkbox))
            self.assertFalse(hasattr(window, "cb_cross_account_01"))
            for control in (
                window.spin_01_threshold,
                window.combo_record_goal,
                window.rebuild_options_box,
                window.spin_message_coverage_threshold,
                window.edit_detail_01_users,
                window.spin_ai_log_periodic_full,
                window.spin_ai_log_context_before,
                window.spin_ai_log_context_after,
                window.spin_record_idle_timeout,
                window.spin_hold_01_keepalive,
                window.spin_ai_log_retention_days,
                window.spin_ai_log_max_gb,
                window.lbl_config_summary,
                window.btn_config_save,
                window.btn_config_reset,
                window.btn_config_open_dir,
                window.btn_config_open_ai_log,
                window.btn_config_clear_ai_log,
                window.btn_config_export,
            ):
                self.assertTrue(window._config_page.isAncestorOf(control))
            self.assertEqual(window.spin_01_threshold.value(), 100)
            self.assertEqual(window.combo_record_goal.currentData(), "count")
            self.assertEqual(window.combo_record_goal.count(), 5)
            self.assertGreaterEqual(
                window.combo_record_goal.findData("coverage_periodic"), 0
            )
            self.assertEqual(window.spin_message_coverage_threshold.value(), 100)
            self.assertEqual(window.rec_session_table.columnCount(), 12)
            self.assertEqual(
                window.rec_session_table.horizontalHeaderItem(3).text(),
                "设备特征",
            )
            self.assertEqual(
                window.rec_session_table.horizontalHeaderItem(5).text(),
                "80xx覆盖率",
            )
            self.assertEqual(
                window.rec_session_table.horizontalHeaderItem(6).text(),
                "周期就绪",
            )
            self.assertEqual(window.rec_coverage_table.columnCount(), 6)
            self.assertEqual(window.spin_record_idle_timeout.value(), 180)
            self.assertEqual(window.spin_hold_01_keepalive.value(), 8)
            self.assertEqual(window.spin_ai_log_retention_days.value(), 7)
            self.assertEqual(window.spin_ai_log_max_gb.value(), 10.0)
            self.assertEqual(
                window.btn_config_clear_ai_log.text(),
                "🧹 清空AI日志",
            )
            self.assertIn(
                "全部内容", window.btn_config_clear_ai_log.toolTip()
            )
            self.assertIn("录制", window.lbl_record_port_summary.text())
            self.assertIn("重放", window.lbl_replay_port_summary.text())
            self.assertTrue(window.lbl_ext_proxy_summary.text())
            self.assertIn("继承重放设备", window.lbl_config_summary.text())
            self.assertFalse(hasattr(window, "btn_official_new"))
            self.assertFalse(hasattr(window, "btn_official_publish"))
            self.assertEqual(window.user_table.columnCount(), 8)
            self.assertTrue(window.btn_type9_rule_load.isEnabled())
            self.assertTrue(window.btn_type9_rule_reload.isEnabled())
            self.assertTrue(window.btn_type9_rule_clear_stats.isEnabled())
            self.assertEqual(
                window.btn_type9_rule_clear_stats.text(),
                "🧹 清空统计",
            )
            self.assertTrue(window.btn_type9_rule_export.isEnabled())
            self.assertGreaterEqual(window.type9_rule_table.rowCount(), 1)
            self.assertEqual(window.type9_rule_table.columnCount(), 8)
            self.assertEqual(
                window.type9_rule_table.horizontalHeaderItem(2).text(),
                "中文说明",
            )
            self.assertEqual(
                window.type9_rule_table.horizontalHeaderItem(7).text(),
                "成功改写",
            )
            self.assertIn("active=", window.lbl_type9_rule_status.text())
            self.assertIn(APP_VERSION, window.windowTitle())
            self.assertEqual(APP_VERSION, "v1.131.2")
            self.assertEqual(
                window._format_replay_progress_text(30, 0, 0, 0),
                "30/-",
            )
            self.assertEqual(
                window._format_replay_progress_text(31, 0, 0, 0),
                "31/-",
            )
            self.assertEqual(
                window._format_replay_progress_text(30, 100, 0, 0),
                "01:30/100",
            )
            self.assertEqual(
                window._format_replay_progress_text(120, 100, 0, 0),
                "01:120/100",
            )
            self.assertEqual(
                window._format_replay_progress_text(
                    0, 120, 155, 120, 120, 100, 35, 20,
                ),
                "01:0/120 | 33:09 120/100 21 35/20",
            )
        finally:
            window.close()
            window.deleteLater()
            self.app.processEvents()

    def test_3366_block_button_toggles_engine_flag(self):
        from core.server import engine

        window = MainWindow()
        try:
            self.assertFalse(engine.manual_3366_block_enabled)
            window.btn_block_3366.setEnabled(True)
            window.btn_block_3366.click()
            self.assertTrue(window.btn_block_3366.isChecked())
            self.assertTrue(engine.manual_3366_block_enabled)
            self.assertEqual(window.btn_block_3366.text(), "✓ 恢复3366")
            window.btn_block_3366.click()
            self.assertFalse(window.btn_block_3366.isChecked())
            self.assertFalse(engine.manual_3366_block_enabled)
            self.assertEqual(window.btn_block_3366.text(), "⛔ 阻断3366")
        finally:
            engine.set_3366_block(False)
            window.close()
            window.deleteLater()
            self.app.processEvents()


if __name__ == "__main__":
    unittest.main()
