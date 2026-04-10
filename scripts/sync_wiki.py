#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent

ROOT = Path(__file__).resolve().parents[1]
README_PATH = ROOT / "README.md"
ARCHITECTURE_DOC_PATH = ROOT / "docs" / "architecture.md"
CI_DOC_PATH = ROOT / "docs" / "ci.md"
ROADMAP_DOC_PATH = ROOT / "docs" / "roadmap.md"
SYNC_COMMIT_MESSAGE = "docs: sync wiki"
WIKI_PAGE_TITLES = (
    "Home",
    "Getting Started",
    "CLI Guide",
    "CI Usage",
    "Architecture",
    "Extensibility",
    "Roadmap",
    "_Sidebar",
)
LINK_REWRITES = {
    "`docs/ci.md`": "[CI Usage](CI-Usage)",
    "docs/ci.md": "[CI Usage](CI-Usage)",
    "`docs/architecture.md`": "[Architecture](Architecture)",
    "docs/architecture.md": "[Architecture](Architecture)",
    "`docs/roadmap.md`": "[Roadmap](Roadmap)",
    "docs/roadmap.md": "[Roadmap](Roadmap)",
}


@dataclass(frozen=True)
class WikiPage:
    title: str
    body: str

    @property
    def filename(self) -> str:
        return page_filename(self.title)

    @property
    def rendered(self) -> str:
        return normalize_markdown(rewrite_internal_links(self.body))


@dataclass(frozen=True)
class PublishResult:
    changed_pages: list[str]
    committed: bool


def page_slug(title: str) -> str:
    sanitized = re.sub(r'[\\/:*?"<>|]+', "", title).strip()
    sanitized = re.sub(r"\s+", "-", sanitized)
    return sanitized


def page_filename(title: str) -> str:
    return f"{page_slug(title)}.md"


def wiki_link(title: str) -> str:
    return f"[{title}]({page_slug(title)})"


def normalize_markdown(text: str) -> str:
    return text.strip() + "\n"


def rewrite_internal_links(text: str) -> str:
    rewritten = text
    for source, target in LINK_REWRITES.items():
        rewritten = rewritten.replace(source, target)
    return rewritten


def extract_section(markdown: str, heading: str) -> str:
    lines = markdown.splitlines()
    start_index: int | None = None
    level: int | None = None

    for index, line in enumerate(lines):
        match = re.fullmatch(r"(#+)\s+(.*)", line)
        if match and match.group(2).strip() == heading:
            start_index = index
            level = len(match.group(1))
            break

    if start_index is None or level is None:
        raise ValueError(f"Could not find heading: {heading}")

    end_index = len(lines)
    for index in range(start_index + 1, len(lines)):
        match = re.fullmatch(r"(#+)\s+.*", lines[index])
        if match and len(match.group(1)) <= level:
            end_index = index
            break

    return "\n".join(lines[start_index:end_index]).strip() + "\n"


def strip_leading_heading(markdown: str) -> str:
    lines = markdown.strip().splitlines()
    if lines and re.fullmatch(r"#\s+.*", lines[0]):
        lines = lines[1:]
    return "\n".join(lines).lstrip("\n").rstrip() + "\n"


def extract_section_body(markdown: str, heading: str) -> str:
    section = extract_section(markdown, heading)
    lines = section.splitlines()
    return "\n".join(lines[1:]).lstrip("\n").rstrip() + "\n"


def extract_intro(markdown: str) -> str:
    lines = markdown.splitlines()
    intro_lines: list[str] = []
    for line in lines[1:]:
        if line.startswith("## "):
            break
        if line.startswith("[!["):
            continue
        intro_lines.append(line)
    return "\n".join(intro_lines).strip() + "\n"


def first_code_block(markdown: str) -> str:
    match = re.search(r"```[\s\S]*?```", markdown)
    if not match:
        raise ValueError("Expected a fenced code block.")
    return match.group(0)


def git_output(args: list[str], *, cwd: Path | None = None) -> str:
    return subprocess.run(
        args,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def run_command(args: list[str], *, cwd: Path | None = None) -> None:
    subprocess.run(args, cwd=cwd, check=True)


def normalize_repo_url(remote_url: str) -> str:
    if remote_url.startswith("git@github.com:"):
        path = remote_url.removeprefix("git@github.com:")
        return f"https://github.com/{path.removesuffix('.git')}"
    if remote_url.startswith("https://github.com/"):
        return remote_url.removesuffix(".git")
    if remote_url.startswith("http://github.com/"):
        return remote_url.removesuffix(".git").replace("http://", "https://", 1)
    return remote_url.removesuffix(".git")


def derive_repo_url(repo_root: Path) -> str:
    return normalize_repo_url(
        git_output(["git", "-C", str(repo_root), "remote", "get-url", "origin"])
    )


def derive_wiki_remote(repo_root: Path) -> str:
    origin = git_output(["git", "-C", str(repo_root), "remote", "get-url", "origin"])
    if origin.startswith("git@"):
        host, path = origin.split(":", 1)
        return f"{host}:{path.removesuffix('.git')}.wiki.git"
    if origin.startswith(("https://", "http://")):
        return origin.removesuffix(".git") + ".wiki.git"
    return origin + ".wiki.git"


def render_pages(repo_root: Path, *, repo_url: str | None = None) -> list[WikiPage]:
    readme = README_PATH.read_text(encoding="utf-8")
    architecture_doc = ARCHITECTURE_DOC_PATH.read_text(encoding="utf-8")
    ci_doc = CI_DOC_PATH.read_text(encoding="utf-8")
    roadmap_doc = ROADMAP_DOC_PATH.read_text(encoding="utf-8")
    repo_url = repo_url or derive_repo_url(repo_root)

    intro = extract_intro(readme)
    what_it_does = extract_section_body(readme, "What it does")
    current_attack_types = extract_section_body(readme, "Current attack types")
    quick_start = extract_section(readme, "Quick start")
    cli_guide = extract_section(readme, "CLI")
    custom_attack_packs = extract_section(readme, "Custom attack packs")
    custom_workflow_packs = extract_section(readme, "Custom workflow packs")

    home = WikiPage(
        title="Home",
        body=dedent(
            f"""
            # knives-out

            {intro}

            This wiki is a reader-friendly guide generated from the canonical docs
            in the repository.

            ## Quick links

            - {wiki_link("Getting Started")}
            - {wiki_link("CLI Guide")}
            - {wiki_link("CI Usage")}
            - {wiki_link("Architecture")}
            - {wiki_link("Extensibility")}
            - {wiki_link("Roadmap")}
            - [Repository]({repo_url})

            ## What it does

            {what_it_does.rstrip()}

            ## Current attack types

            {current_attack_types.rstrip()}

            ## Quick start

            {first_code_block(quick_start)}

            - Inspect the sample spec with `knives-out inspect`.
            - Generate a replayable suite with `knives-out generate`.
            - Add `--auto-workflows` when you want built-in stateful coverage.
            - Run attacks against a live API, then render `report.md` and verify the results.

            See {wiki_link("Getting Started")} for the full install and command walkthrough.
            """
        ),
    )
    getting_started = WikiPage(
        title="Getting Started",
        body=dedent(
            f"""
            # Getting Started

            {intro}

            This page tracks the canonical quick-start flow from the repository README.

            {quick_start.rstrip()}
            """
        ),
    )
    cli = WikiPage(
        title="CLI Guide",
        body=dedent(
            f"""
            # CLI Guide

            The command surface below is derived from the repository README.

            {cli_guide.rstrip()}
            """
        ),
    )
    ci_usage = WikiPage(
        title="CI Usage",
        body=dedent(
            f"""
            # CI Usage

            {strip_leading_heading(ci_doc).rstrip()}
            """
        ),
    )
    architecture = WikiPage(
        title="Architecture",
        body=dedent(
            f"""
            # Architecture

            {strip_leading_heading(architecture_doc).rstrip()}
            """
        ),
    )
    extensibility = WikiPage(
        title="Extensibility",
        body=dedent(
            f"""
            # Extensibility

            Extend `knives-out` with custom attack packs and workflow packs
            without forking the core project.

            {custom_attack_packs.rstrip()}

            {custom_workflow_packs.rstrip()}
            """
        ),
    )
    roadmap = WikiPage(
        title="Roadmap",
        body=dedent(
            f"""
            # Roadmap

            {strip_leading_heading(roadmap_doc).rstrip()}
            """
        ),
    )
    sidebar = WikiPage(
        title="_Sidebar",
        body=dedent(
            f"""
            ### knives-out

            - {wiki_link("Home")}
            - {wiki_link("Getting Started")}
            - {wiki_link("CLI Guide")}
            - {wiki_link("CI Usage")}
            - {wiki_link("Architecture")}
            - {wiki_link("Extensibility")}
            - {wiki_link("Roadmap")}
            """
        ),
    )
    return [home, getting_started, cli, ci_usage, architecture, extensibility, roadmap, sidebar]


def write_pages(output_dir: Path, pages: list[WikiPage]) -> list[str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    changed_pages: list[str] = []
    for page in pages:
        path = output_dir / page.filename
        rendered = page.rendered
        previous = path.read_text(encoding="utf-8") if path.exists() else None
        if previous != rendered:
            path.write_text(rendered, encoding="utf-8")
            changed_pages.append(path.name)
    return changed_pages


def ensure_wiki_checkout(wiki_dir: Path, remote: str) -> None:
    if not wiki_dir.exists():
        wiki_dir.parent.mkdir(parents=True, exist_ok=True)
        try:
            run_command(["git", "clone", remote, str(wiki_dir)])
        except subprocess.CalledProcessError as error:
            raise SystemExit(
                "Could not clone the wiki repository. Create the first wiki page in GitHub, "
                "then rerun sync_wiki.py publish."
            ) from error
        return

    if not (wiki_dir / ".git").exists():
        raise SystemExit(f"{wiki_dir} exists but is not a git checkout.")

    run_command(["git", "-C", str(wiki_dir), "remote", "set-url", "origin", remote])
    run_command(["git", "-C", str(wiki_dir), "pull", "--ff-only"])


def has_staged_changes(repo_dir: Path, paths: list[str]) -> bool:
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "diff", "--cached", "--quiet", "--", *paths],
        check=False,
    )
    return result.returncode == 1


def publish_wiki(repo_root: Path, wiki_dir: Path, *, remote: str | None = None) -> PublishResult:
    remote = remote or derive_wiki_remote(repo_root)
    ensure_wiki_checkout(wiki_dir, remote)
    pages = render_pages(repo_root)
    changed_pages = write_pages(wiki_dir, pages)
    tracked_pages = [page.filename for page in pages]

    run_command(["git", "-C", str(wiki_dir), "add", "--", *tracked_pages])
    if not has_staged_changes(wiki_dir, tracked_pages):
        return PublishResult(changed_pages=changed_pages, committed=False)

    run_command(["git", "-C", str(wiki_dir), "commit", "-m", SYNC_COMMIT_MESSAGE])
    run_command(["git", "-C", str(wiki_dir), "push", "origin", "HEAD"])
    return PublishResult(changed_pages=changed_pages, committed=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render or publish the project GitHub wiki.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    render_parser = subparsers.add_parser("render", help="Render wiki pages to a directory.")
    render_parser.add_argument("--out-dir", type=Path, required=True)

    publish_parser = subparsers.add_parser("publish", help="Publish wiki pages to a wiki checkout.")
    publish_parser.add_argument("--wiki-dir", type=Path, required=True)
    publish_parser.add_argument("--remote", help="Override the wiki remote URL.")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "render":
        changed_pages = write_pages(args.out_dir, render_pages(ROOT))
        print(f"Rendered {len(WIKI_PAGE_TITLES)} wiki pages to {args.out_dir}.")
        if changed_pages:
            print(f"Updated pages: {', '.join(changed_pages)}")
        return

    publish_result = publish_wiki(ROOT, args.wiki_dir, remote=args.remote)
    if publish_result.committed:
        print(f"Published wiki pages from {ROOT} to {args.wiki_dir}.")
        print(f"Updated pages: {', '.join(publish_result.changed_pages)}")
    else:
        print("No wiki changes to publish.")


if __name__ == "__main__":
    main()
