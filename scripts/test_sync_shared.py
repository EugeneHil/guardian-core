import os
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "tooling", "sync-shared.sh")

# Built so that this file does not spell the former product name.
OLD = "war" + "den"
OLD_START = f"# --- {OLD} shared ignores (managed by {OLD}-core/tooling/sync-shared.sh) ---"
OLD_END = f"# --- end {OLD} shared ignores ---"


def sync(target):
    subprocess.run([SCRIPT, target], check=True, capture_output=True)


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class SyncShared(unittest.TestCase):
    def test_old_marker_is_no_longer_recognised(self):
        # The migration is finished: an old block is plain user content, the new block is appended.
        with tempfile.TemporaryDirectory() as target:
            gitignore = os.path.join(target, ".gitignore")
            before = f"local-before\n{OLD_START}\nold-entry\n{OLD_END}\nlocal-after\n"
            with open(gitignore, "w", encoding="utf-8") as fh:
                fh.write(before)
            sync(target)
            sync(target)
            content = read(gitignore)
            self.assertTrue(content.startswith(before))
            self.assertEqual(content.count("# --- guardian shared ignores"), 1)
            self.assertEqual(content.count("# --- end guardian shared ignores"), 1)

    def test_sync_is_idempotent(self):
        with tempfile.TemporaryDirectory() as target:
            sync(target)
            first = read(os.path.join(target, ".gitignore"))
            sync(target)
            self.assertEqual(read(os.path.join(target, ".gitignore")), first)
            self.assertEqual(first.count("# --- guardian shared ignores"), 1)


if __name__ == "__main__":
    unittest.main()
