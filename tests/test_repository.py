"""Packaging, frontmatter and offline CLI regression checks for every script."""
import json
import re
import subprocess
import sys

import pytest
import yaml

from conftest import ROOT

SKILLS = sorted((ROOT / "skills").glob("*/SKILL.md"))
SCRIPTS = sorted((ROOT / "skills").glob("*/scripts/*.py"))


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_frontmatter(path):
    data = yaml.safe_load(path.read_text().split("---", 2)[1])
    assert data["name"] == path.parent.name
    assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", data["name"])
    assert len(data["name"]) <= 64
    assert isinstance(data["description"], str) and 0 < len(data["description"]) <= 1024
    assert set(data) <= {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in data["metadata"].items())
    assert "## Evidence contract" in path.read_text()


def test_marketplace_matches_disk():
    plugin = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text())["plugins"][0]
    expected = ["./" + str(p.parent.relative_to(ROOT)) for p in SKILLS]
    assert plugin["skills"] == expected
    assert f"{len(SKILLS)} domain skills" in plugin["description"]


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.stem)
def test_cli_help_and_unknown_argument(path, tmp_path):
    for args, code in [(["--help"], 0), (["--cyberskill-invalid-argument"], 2)]:
        result = subprocess.run([sys.executable, str(path), *args], cwd=tmp_path,
                                capture_output=True, text=True, timeout=15)
        assert result.returncode == code, result.stdout + result.stderr
        assert "usage:" in (result.stdout + result.stderr).lower()
