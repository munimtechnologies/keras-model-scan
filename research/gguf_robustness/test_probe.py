"""Self-tests for the gguf robustness corpus and probe.

Made with AI by MV2 of Munim, Inc. (Apache-2.0). Runs offline. The corpus-builder
tests are pure standard library; the one test that loads a file with the real gguf-py
reader is skipped automatically when the optional `gguf` package is not installed, so
the suite passes in a minimal environment and verifies end-to-end where gguf is present.
"""

import os
import sys
import tempfile
import unittest

# Make `import builder` resolve no matter which directory the test runner uses.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import builder


class CorpusTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="gguf-corpus-")
        self.paths = builder.generate_corpus(self.dir)

    def test_all_fixtures_written(self):
        self.assertEqual(set(self.paths), set(builder.CORPUS))
        for name, path in self.paths.items():
            self.assertTrue(os.path.getsize(path) > 0, name)

    def test_files_are_tiny(self):
        # Every fixture is small -- the whole point is "huge declared vs tiny actual".
        for name, path in self.paths.items():
            self.assertLess(os.path.getsize(path), 4096, name)

    def test_magic_present(self):
        for name, path in self.paths.items():
            with open(path, "rb") as fh:
                self.assertEqual(fh.read(4), b"GGUF", name)

    def test_control_loads_with_reader(self):
        # Guards that the hand-built control matches what gguf-py expects.
        try:
            from gguf import GGUFReader
        except Exception:
            self.skipTest("optional 'gguf' package not installed")
        reader = GGUFReader(self.paths["control_valid"], "r")
        self.assertEqual(len(reader.tensors), 1)
        self.assertEqual([int(d) for d in reader.tensors[0].shape], [4])


if __name__ == "__main__":
    unittest.main()
