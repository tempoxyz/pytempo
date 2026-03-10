"""Version consistency tests."""

import re
import runpy
from pathlib import Path

from pytempo import __version__

ROOT = Path(__file__).resolve().parent.parent


def _project_version() -> str:
    pyproject = ROOT / "pyproject.toml"
    in_project_section = False
    version_re = re.compile(r'^version\s*=\s*"([^"]+)"\s*$')

    for raw_line in pyproject.read_text().splitlines():
        line = raw_line.strip()

        if line.startswith("[") and line.endswith("]"):
            in_project_section = line == "[project]"
            continue

        if not in_project_section:
            continue

        match = version_re.match(line)
        if match:
            return match.group(1)

    raise AssertionError("Unable to find [project].version in pyproject.toml")


def test_package_version_matches_pyproject() -> None:
    assert __version__ == _project_version()


def test_docs_release_matches_package_version() -> None:
    conf_vars = runpy.run_path(str(ROOT / "docs" / "conf.py"))
    assert conf_vars["release"] == __version__
