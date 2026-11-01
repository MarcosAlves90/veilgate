"""Run project tests and generate Cobertura XML for POLIS coverage gates."""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_tests() -> bool:
    sys.path.insert(0, str(ROOT / "src"))
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    return unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("test", "coverage"))
    args = parser.parse_args()

    # Prefer the existing project venv when the host Python lacks the optional
    # coverage dependency. The same command also works in CI without a venv.
    if args.mode == "coverage" and importlib.util.find_spec("coverage") is None:
        venv_python = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if venv_python.exists() and sys.prefix == sys.base_prefix:
            os.execv(str(venv_python), [str(venv_python), __file__, args.mode])

    os.chdir(ROOT)
    if args.mode == "test":
        return 0 if run_tests() else 1

    try:
        from coverage import Coverage
    except ImportError:
        parser.error("coverage is required; install the optional dev dependencies: pip install -e '.[dev]'")
    cov = Coverage(source=[str(ROOT / "src" / "veilgate")], branch=True, data_file=str(ROOT / ".coverage"))
    cov.start()
    try:
        passed = run_tests()
    finally:
        cov.stop()
        cov.save()
    cov.xml_report(outfile=str(ROOT / "coverage.xml"))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
