"""Print a ruleset JSON with extra required status checks appended.

Usage: with_checks.py <ruleset.json> [check ...]
Existing checks keep their order; duplicates are never added.
"""
import json
import sys


def with_checks(ruleset, checks):
    for rule in ruleset.get("rules", []):
        if rule.get("type") != "required_status_checks":
            continue
        listed = rule["parameters"]["required_status_checks"]
        known = {entry["context"] for entry in listed}
        for check in checks:
            if check not in known:
                listed.append({"context": check})
                known.add(check)
    return ruleset


def main(argv):
    if len(argv) < 2:
        print("usage: with_checks.py <ruleset.json> [check ...]", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as handle:
        ruleset = json.load(handle)
    json.dump(with_checks(ruleset, argv[2:]), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
