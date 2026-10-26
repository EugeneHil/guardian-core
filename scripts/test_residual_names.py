"""Guards against leftovers of the former product name (Warden -> Guardian).

Each group pairs the pattern with the set of files it covers and a flag that says
whether it is enforced yet. Groups are switched on as the rename lands.
Run: python3 -I -B -m unittest discover -s scripts
"""
import os
import re
import subprocess
import unittest
from collections import namedtuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

Group = namedtuple("Group", "pattern paths enforced")

PATTERN = re.compile(r"warden|wdn(?!_)", re.IGNORECASE)

TEXT_EXTS = (".md", ".yml", ".yaml", ".toml", ".sh", ".json")
TEXT_DIRS = ("tooling/", ".github/", "docs/")
ROOT_TEXT = (".gitignore", ".gitleaks.toml", "CLAUDE.md")
CODE_EXTS = (".cpp", ".hpp", ".cmake", ".py")
CODE_DIRS = ("design-tokens/", "cmake/", "include/", "src/", "tests/")
CMAKE_FILES = ("CMakeLists.txt", "CMakePresets.json")


def is_text_path(path):
    if "/" not in path:
        return path.startswith("README") or path in ROOT_TEXT
    return path.startswith(TEXT_DIRS) and path.endswith(TEXT_EXTS)


def is_code_path(path):
    name = os.path.basename(path)
    if name in CMAKE_FILES:
        return True
    if path.startswith("scripts/") and path.endswith(".sh"):
        return True
    return path.startswith(CODE_DIRS) and path.endswith(CODE_EXTS)


GROUPS = {
    "text": Group(PATTERN, is_text_path, True),
    "code": Group(PATTERN, is_code_path, False),
    # Not applicable in warden-core: there is no .gitmodules.
    "submodule": Group(PATTERN, lambda path: False, False),
    "all": Group(PATTERN, lambda path: True, False),
}

# Files exempt from a group because they must spell the old name.
ALLOW = {
    "text": {
        # Recognizes the old shared-ignores marker; dropped once all repos are migrated.
        "tooling/sync-shared.sh",
    },
    "code": set(),
    "submodule": set(),
    "all": {
        "scripts/test_residual_names.py",
        "scripts/test_sync_shared.py",
        "tooling/sync-shared.sh",
    },
}


def tracked_files():
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    ).stdout
    return [p for p in out.decode("utf-8").split("\0") if p]


def read_text(path):
    try:
        with open(os.path.join(ROOT, path), "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def offenders(group_name):
    group = GROUPS[group_name]
    allowed = ALLOW[group_name]
    found = []
    for path in tracked_files():
        if path in allowed or not group.paths(path):
            continue
        if group.pattern.search(path):
            found.append(f"{path}: path name")
        text = read_text(path)
        if text is None:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if group.pattern.search(line):
                found.append(f"{path}:{number}: {line.strip()}")
    return found


class ResidualNames(unittest.TestCase):
    def _check(self, name):
        if not GROUPS[name].enforced:
            self.skipTest(f"group {name!r} is not enforced yet")
        found = offenders(name)
        self.assertEqual(found, [], f"residual names in group {name!r}:\n" + "\n".join(found))

    def test_group_text(self):
        self._check("text")

    def test_group_code(self):
        self._check("code")

    def test_group_submodule(self):
        self._check("submodule")

    def test_group_all(self):
        self._check("all")


if __name__ == "__main__":
    unittest.main()
