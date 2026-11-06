from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))


class TempDirMixin(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.tmpdir = tempfile.mkdtemp(prefix="pi-hub-test-")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        super().tearDown()
