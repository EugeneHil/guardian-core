import os
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "tooling", "sync-shared.sh")

OLD_START = "# --- warden shared ignores (managed by warden-core/tooling/sync-shared.sh) ---"
OLD_END = "# --- end warden shared ignores ---"


def sync(target):
    subprocess.run([SCRIPT, target], check=True, capture_output=True)


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class SyncShared(unittest.TestCase):
    def test_old_marker_block_is_replaced_not_duplicated(self):
        with tempfile.TemporaryDirectory() as target:
            gitignore = os.path.join(target, ".gitignore")
            with open(gitignore, "w", encoding="utf-8") as fh:
                fh.write(f"local-before\n{OLD_START}\nold-entry\n{OLD_END}\nlocal-after\n")
            sync(target)
            sync(target)
            content = read(gitignore)
            lines = content.splitlines()
            self.assertEqual(sum(l.startswith("# --- guardian shared ignores") for l in lines), 1)
            self.assertEqual(sum(l.startswith("# --- end guardian shared ignores") for l in lines), 1)
            self.assertNotIn("warden", content.lower())
            self.assertNotIn("old-entry", content)
            self.assertIn("local-before", lines)
            self.assertIn("local-after", lines)

    def test_sync_is_idempotent(self):
        with tempfile.TemporaryDirectory() as target:
            sync(target)
            first = read(os.path.join(target, ".gitignore"))
            sync(target)
            self.assertEqual(read(os.path.join(target, ".gitignore")), first)
            self.assertEqual(first.count("# --- guardian shared ignores"), 1)


if __name__ == "__main__":
    unittest.main()
