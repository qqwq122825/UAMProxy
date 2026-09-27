"""UAM 专版关闭三角洲 Type9 内置链时，跳过仅验证该行为的测试。"""

from __future__ import annotations

import functools
import unittest

from core.edition import type9_legacy_builtin_intercepts_enabled


def skip_unless_dfm_type9_legacy_intercepts(test_func):
    @functools.wraps(test_func)
    def wrapper(self, *args, **kwargs):
        if not type9_legacy_builtin_intercepts_enabled():
            raise unittest.SkipTest(
                "UAM 专版已关闭 tfp_called / empty_2000 内置链"
            )
        return test_func(self, *args, **kwargs)

    return wrapper
