"""Print a hashed requirements file without its direct-URL requirements.

pip-audit cannot audit direct-URL requirements (the spaCy model wheel
``en-core-web-lg @ https://...``); it is not on PyPI/OSV and is pinned by its
sha256 in the lock. CI audits everything else with ``--strict``:

    python tools/strip_url_requirements.py requirements-lock.txt > /tmp/audit.txt
    pip-audit --strict --require-hashes --disable-pip -r /tmp/audit.txt
"""

from __future__ import annotations

import sys
from pathlib import Path


def strip_url_requirements(text: str) -> tuple[str, list[str]]:
    kept: list[str] = []
    dropped: list[str] = []
    skipping = False
    for line in text.splitlines():
        if line and not line[0].isspace() and not line.startswith("#"):
            skipping = " @ " in line
            if skipping:
                dropped.append(line.split(" @ ", 1)[0].strip())
                continue
        elif skipping and line[:1].isspace():
            continue
        kept.append(line)
    return "\n".join(kept) + "\n", dropped


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: strip_url_requirements.py REQUIREMENTS", file=sys.stderr)
        return 2
    out, dropped = strip_url_requirements(Path(args[0]).read_text(encoding="utf-8"))
    sys.stdout.write(out)
    for name in dropped:
        print(f"not audited (direct URL, hash-pinned): {name}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
