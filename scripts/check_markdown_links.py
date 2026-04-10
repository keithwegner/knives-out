#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
EXTERNAL_PREFIXES = ("http://", "https://", "mailto:", "tel:")


def collect_markdown_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(
                sorted(candidate for candidate in path.rglob("*.md") if candidate.is_file())
            )
        elif path.is_file():
            files.append(path)
    return files


def strip_fenced_code_blocks(text: str) -> str:
    return re.sub(r"```[\s\S]*?```", "", text)


def slugify_heading(heading: str) -> str:
    slug = heading.strip().lower()
    slug = re.sub(r"[`*_~]", "", slug)
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"\s+", "-", slug)
    slug = re.sub(r"-{2,}", "-", slug)
    return slug.strip("-")


def collect_anchors(markdown: str) -> set[str]:
    anchors: set[str] = set()
    seen: dict[str, int] = {}
    for line in markdown.splitlines():
        match = HEADING_RE.match(line)
        if not match:
            continue
        base = slugify_heading(match.group(2))
        if not base:
            continue
        count = seen.get(base, 0)
        anchor = base if count == 0 else f"{base}-{count}"
        seen[base] = count + 1
        anchors.add(anchor)
    return anchors


def validate_markdown_file(path: Path) -> list[str]:
    markdown = path.read_text(encoding="utf-8")
    text = strip_fenced_code_blocks(markdown)
    errors: list[str] = []
    local_anchors = collect_anchors(markdown)

    for target in MARKDOWN_LINK_RE.findall(text):
        if target.startswith(EXTERNAL_PREFIXES):
            continue
        if target.startswith("#"):
            if target.removeprefix("#") not in local_anchors:
                errors.append(f"{path}: missing anchor {target}")
            continue

        path_part, _, fragment = target.partition("#")
        target_path = (path.parent / path_part).resolve()
        if not target_path.exists():
            errors.append(f"{path}: missing path {path_part}")
            continue
        if fragment and target_path.suffix.lower() == ".md":
            target_anchors = collect_anchors(target_path.read_text(encoding="utf-8"))
            if fragment not in target_anchors:
                errors.append(f"{path}: missing anchor #{fragment} in {path_part}")

    return errors


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate repo-local markdown links and anchors.")
    parser.add_argument(
        "paths",
        nargs="+",
        type=Path,
        help="Markdown files or directories to scan.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    files = collect_markdown_files(args.paths)
    if not files:
        print("No markdown files found.", file=sys.stderr)
        return 1

    errors: list[str] = []
    for path in files:
        errors.extend(validate_markdown_file(path))

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print(f"Validated markdown links in {len(files)} file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
