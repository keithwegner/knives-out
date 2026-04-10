from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "sync_wiki.py"
SPEC = importlib.util.spec_from_file_location("sync_wiki", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Could not load scripts/sync_wiki.py")
SYNC_WIKI = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SYNC_WIKI
SPEC.loader.exec_module(SYNC_WIKI)


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


def test_extract_section_includes_nested_subsections() -> None:
    markdown = dedent(
        """
        # Title

        ## Alpha

        Paragraph.

        ### Nested

        More detail.

        ## Beta

        Done.
        """
    )

    section = SYNC_WIKI.extract_section(markdown, "Alpha")

    assert "## Alpha" in section
    assert "### Nested" in section
    assert "## Beta" not in section


def test_page_slug_and_filename_follow_github_wiki_conventions() -> None:
    assert SYNC_WIKI.page_slug("CI Usage") == "CI-Usage"
    assert SYNC_WIKI.page_filename("CLI Guide") == "CLI-Guide.md"


def test_rewrite_internal_links_points_repo_docs_to_wiki_pages() -> None:
    source = "See `docs/ci.md`, `docs/architecture.md`, and docs/roadmap.md for more detail."

    rewritten = SYNC_WIKI.rewrite_internal_links(source)

    assert "[CI Usage](CI-Usage)" in rewritten
    assert "[Architecture](Architecture)" in rewritten
    assert "[Roadmap](Roadmap)" in rewritten


def test_write_pages_is_stable_when_content_is_unchanged(tmp_path: Path) -> None:
    pages = [SYNC_WIKI.WikiPage(title="Home", body="# Home\n\nStable content.\n")]

    first = SYNC_WIKI.write_pages(tmp_path, pages)
    second = SYNC_WIKI.write_pages(tmp_path, pages)

    assert first == ["Home.md"]
    assert second == []


def test_render_pages_smoke_test_generates_expected_wiki_files(tmp_path: Path) -> None:
    pages = SYNC_WIKI.render_pages(
        ROOT,
        repo_url="https://github.com/keithwegner/knives-out",
    )

    changed_pages = SYNC_WIKI.write_pages(tmp_path, pages)

    assert {page.title for page in pages} == set(SYNC_WIKI.WIKI_PAGE_TITLES)
    assert set(changed_pages) == {
        "Home.md",
        "Getting-Started.md",
        "CLI-Guide.md",
        "CI-Usage.md",
        "Architecture.md",
        "Extensibility.md",
        "Roadmap.md",
        "_Sidebar.md",
    }
    home = (tmp_path / "Home.md").read_text(encoding="utf-8")
    getting_started = (tmp_path / "Getting-Started.md").read_text(encoding="utf-8")
    extensibility = (tmp_path / "Extensibility.md").read_text(encoding="utf-8")

    assert "reader-friendly guide generated from the canonical docs" in home
    assert "https://github.com/keithwegner/knives-out" in home
    assert "--auto-workflows" in getting_started
    assert "## Development" not in getting_started
    assert "Dev Container" not in home
    assert "WorkflowAttackCase" in extensibility


def test_publish_wiki_commits_changes_then_noops_when_content_matches(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("GIT_AUTHOR_NAME", "Codex")
    monkeypatch.setenv("GIT_AUTHOR_EMAIL", "codex@example.com")
    monkeypatch.setenv("GIT_COMMITTER_NAME", "Codex")
    monkeypatch.setenv("GIT_COMMITTER_EMAIL", "codex@example.com")

    remote_dir = tmp_path / "wiki.git"
    seed_dir = tmp_path / "seed"
    publish_dir = tmp_path / "wiki-checkout"
    inspect_dir = tmp_path / "inspect"

    subprocess.run(
        ["git", "init", "--bare", "--initial-branch=main", str(remote_dir)],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "init", "--initial-branch=main", str(seed_dir)],
        check=True,
        capture_output=True,
        text=True,
    )
    _run_git(["remote", "add", "origin", str(remote_dir)], cwd=seed_dir)
    (seed_dir / "Home.md").write_text("# Home\n\nBootstrap page.\n", encoding="utf-8")
    _run_git(["add", "Home.md"], cwd=seed_dir)
    _run_git(["commit", "-m", "bootstrap wiki"], cwd=seed_dir)
    _run_git(["push", "-u", "origin", "main"], cwd=seed_dir)

    first_publish = SYNC_WIKI.publish_wiki(
        ROOT,
        publish_dir,
        remote=str(remote_dir),
    )

    assert first_publish.committed is True
    assert "Home.md" in first_publish.changed_pages

    subprocess.run(
        ["git", "clone", str(remote_dir), str(inspect_dir)],
        check=True,
        capture_output=True,
        text=True,
    )
    first_head = _git_output(["rev-parse", "HEAD"], cwd=inspect_dir)
    published_home = (inspect_dir / "Home.md").read_text(encoding="utf-8")

    assert "reader-friendly guide generated from the canonical docs" in published_home
    assert (inspect_dir / "_Sidebar.md").exists()

    second_publish = SYNC_WIKI.publish_wiki(
        ROOT,
        publish_dir,
        remote=str(remote_dir),
    )

    assert second_publish.committed is False
    assert second_publish.changed_pages == []

    _run_git(["pull", "--ff-only"], cwd=inspect_dir)
    second_head = _git_output(["rev-parse", "HEAD"], cwd=inspect_dir)

    assert second_head == first_head
