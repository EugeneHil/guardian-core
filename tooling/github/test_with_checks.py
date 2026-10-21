import json
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "with_checks.py"
RULESETS = [HERE / "ruleset-develop.json", HERE / "ruleset-main.json"]


def run(path, *checks):
    out = subprocess.run(
        [sys.executable, "-I", "-B", str(SCRIPT), str(path), *checks],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return json.loads(out)


def contexts(ruleset):
    for rule in ruleset["rules"]:
        if rule["type"] == "required_status_checks":
            return [c["context"] for c in rule["parameters"]["required_status_checks"]]
    raise AssertionError("no required_status_checks rule")


class WithChecksTest(unittest.TestCase):
    def test_appends_checks(self):
        for path in RULESETS:
            got = contexts(run(path, "cpp-macos", "cpp-windows"))
            self.assertEqual(got, ["gitleaks", "cpp-macos", "cpp-windows"])

    def test_is_idempotent(self):
        for path in RULESETS:
            once = run(path, "cpp-macos", "cpp-windows")
            twice = run(path, "cpp-macos", "cpp-windows", "cpp-macos")
            self.assertEqual(once, twice)

    def test_keeps_existing_gitleaks_first(self):
        for path in RULESETS:
            self.assertEqual(contexts(run(path, "cpp-macos"))[0], "gitleaks")

    def test_no_extras_returns_input_unchanged(self):
        for path in RULESETS:
            self.assertEqual(run(path), json.loads(path.read_text()))


if __name__ == "__main__":
    unittest.main()
