from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

ROOT = Path(__file__).resolve().parents[1]
LINK_CHECKER_PATH = ROOT / "scripts" / "check_markdown_links.py"
COVERAGE_CHECKER_PATH = ROOT / "scripts" / "check_coverage_drop.py"
COVERAGE_BADGE_SYNC_PATH = ROOT / "scripts" / "sync_coverage_badge.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


LINK_CHECKER = _load_module("check_markdown_links", LINK_CHECKER_PATH)
COVERAGE_BADGE_SYNC = _load_module("sync_coverage_badge", COVERAGE_BADGE_SYNC_PATH)


def _run_script(path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(path), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def _write_coverage(path: Path, percent: float) -> None:
    path.write_text(
        dedent(
            f"""
            {{
              "totals": {{
                "percent_covered": {percent}
              }}
            }}
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )


def _run_git(args: list[str], cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def _git_output(args: list[str], cwd: Path) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_markdown_link_checker_accepts_existing_paths_anchors_and_code_samples(
    tmp_path: Path,
) -> None:
    guide = tmp_path / "guide.md"
    guide.write_text(
        dedent(
            """
            # Guide

            ## Next Steps

            Details.
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    readme = tmp_path / "README.md"
    readme.write_text(
        dedent(
            """
            # Title

            See [Guide](guide.md#next-steps) and [Local](#details).

            ```md
            [Ignored](missing.md)
            ```

            ## Details

            Done.
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    assert LINK_CHECKER.validate_markdown_file(readme) == []


def test_markdown_link_checker_reports_missing_paths_and_anchors(tmp_path: Path) -> None:
    readme = tmp_path / "README.md"
    readme.write_text(
        dedent(
            """
            # Title

            See [Missing file](missing.md), [Missing local anchor](#nope), and
            [Missing remote anchor](guide.md#nope).
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    guide = tmp_path / "guide.md"
    guide.write_text("# Guide\n", encoding="utf-8")

    errors = LINK_CHECKER.validate_markdown_file(readme)

    assert f"{readme}: missing path missing.md" in errors
    assert f"{readme}: missing anchor #nope" in errors
    assert f"{readme}: missing anchor #nope in guide.md" in errors


def test_markdown_link_checker_cli_scans_directories(tmp_path: Path) -> None:
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()
    (docs_dir / "guide.md").write_text("# Guide\n", encoding="utf-8")

    result = _run_script(LINK_CHECKER_PATH, str(docs_dir))

    assert result.returncode == 0
    assert "Validated markdown links in 1 file(s)." in result.stdout


def test_coverage_drop_check_passes_without_previous_baseline(tmp_path: Path) -> None:
    current = tmp_path / "coverage.json"
    summary = tmp_path / "summary.md"
    _write_coverage(current, 91.5)

    result = _run_script(
        COVERAGE_CHECKER_PATH,
        "--current",
        str(current),
        "--summary-file",
        str(summary),
    )

    assert result.returncode == 0
    assert "Baseline coverage: unavailable" in result.stdout
    assert "no drop check ran" in summary.read_text(encoding="utf-8")


def test_coverage_drop_check_fails_when_coverage_drops(tmp_path: Path) -> None:
    current = tmp_path / "current.json"
    previous = tmp_path / "previous.json"
    _write_coverage(current, 88.0)
    _write_coverage(previous, 90.0)

    result = _run_script(
        COVERAGE_CHECKER_PATH,
        "--current",
        str(current),
        "--previous",
        str(previous),
        "--baseline-label",
        "run 42",
    )

    assert result.returncode == 1
    assert "Baseline coverage (run 42): 90.00%" in result.stdout
    assert "coverage dropped by 2.00 percentage points" in result.stdout.lower()
    assert "Coverage dropped from 90.00% to 88.00%." in result.stderr


def test_coverage_drop_check_passes_when_coverage_improves(tmp_path: Path) -> None:
    current = tmp_path / "current.json"
    previous = tmp_path / "previous.json"
    _write_coverage(current, 92.0)
    _write_coverage(previous, 90.0)

    result = _run_script(
        COVERAGE_CHECKER_PATH,
        "--current",
        str(current),
        "--previous",
        str(previous),
    )

    assert result.returncode == 0
    assert "coverage improved by 2.00 percentage points" in result.stdout.lower()


def test_render_coverage_badge_uses_expected_label_message_and_color() -> None:
    payload = COVERAGE_BADGE_SYNC.render_badge_payload(92.34)

    assert payload == {
        "schemaVersion": 1,
        "label": "coverage",
        "message": "92.3%",
        "color": "green",
    }


def test_render_coverage_badge_write_is_stable_when_content_matches(tmp_path: Path) -> None:
    badge_file = tmp_path / "coverage-badge.json"
    payload = COVERAGE_BADGE_SYNC.render_badge_payload(88.8)

    first = COVERAGE_BADGE_SYNC.write_badge(badge_file, payload)
    second = COVERAGE_BADGE_SYNC.write_badge(badge_file, payload)

    assert first is True
    assert second is False


def test_publish_coverage_badge_commits_changes_then_noops_when_content_matches(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("GIT_AUTHOR_NAME", "Codex")
    monkeypatch.setenv("GIT_AUTHOR_EMAIL", "codex@example.com")
    monkeypatch.setenv("GIT_COMMITTER_NAME", "Codex")
    monkeypatch.setenv("GIT_COMMITTER_EMAIL", "codex@example.com")

    remote_dir = tmp_path / "badges.git"
    coverage_json = tmp_path / "coverage.json"
    checkout_dir = tmp_path / "badge-checkout"
    inspect_dir = tmp_path / "inspect"
    _write_coverage(coverage_json, 91.25)

    subprocess.run(
        ["git", "init", "--bare", "--initial-branch=badges", str(remote_dir)],
        check=True,
        capture_output=True,
        text=True,
    )

    first_publish = COVERAGE_BADGE_SYNC.publish_badge(
        ROOT,
        coverage_json,
        checkout_dir,
        remote=str(remote_dir),
    )

    assert first_publish.committed is True
    assert first_publish.coverage_percent == 91.25

    subprocess.run(
        ["git", "clone", str(remote_dir), str(inspect_dir)],
        check=True,
        capture_output=True,
        text=True,
    )
    first_head = _git_output(["rev-parse", "HEAD"], cwd=inspect_dir)
    published_badge = json.loads((inspect_dir / "coverage-badge.json").read_text(encoding="utf-8"))

    assert published_badge["message"] == "91.2%"
    assert published_badge["label"] == "coverage"

    second_publish = COVERAGE_BADGE_SYNC.publish_badge(
        ROOT,
        coverage_json,
        checkout_dir,
        remote=str(remote_dir),
    )

    assert second_publish.committed is False

    _run_git(["pull", "--ff-only"], cwd=inspect_dir)
    second_head = _git_output(["rev-parse", "HEAD"], cwd=inspect_dir)

    assert second_head == first_head
