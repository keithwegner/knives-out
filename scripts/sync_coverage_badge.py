#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BADGE_BRANCH = "badges"
BADGE_PATH = "coverage-badge.json"
SYNC_COMMIT_MESSAGE = "docs: sync coverage badge"
BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"


@dataclass(frozen=True)
class PublishResult:
    committed: bool
    coverage_percent: float
    branch: str
    badge_path: str


def load_coverage_percent(path: Path) -> float:
    payload = json.loads(path.read_text(encoding="utf-8"))
    totals = payload.get("totals", {})
    if "percent_covered" in totals:
        return float(totals["percent_covered"])
    if "percent_covered_display" in totals:
        return float(totals["percent_covered_display"])
    raise ValueError(f"Could not find total coverage percentage in {path}")


def badge_color(coverage_percent: float) -> str:
    if coverage_percent >= 95:
        return "brightgreen"
    if coverage_percent >= 90:
        return "green"
    if coverage_percent >= 80:
        return "yellowgreen"
    if coverage_percent >= 70:
        return "yellow"
    if coverage_percent >= 60:
        return "orange"
    return "red"


def render_badge_payload(coverage_percent: float) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "label": "coverage",
        "message": f"{coverage_percent:.1f}%",
        "color": badge_color(coverage_percent),
    }


def write_badge(path: Path, payload: dict[str, object]) -> bool:
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    previous = path.read_text(encoding="utf-8") if path.exists() else None
    if previous == rendered:
        return False

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")
    return True


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


def derive_repo_remote(repo_root: Path) -> str:
    return git_output(["git", "-C", str(repo_root), "remote", "get-url", "origin"])


def ensure_git_checkout(checkout_dir: Path) -> None:
    if not checkout_dir.exists():
        checkout_dir.parent.mkdir(parents=True, exist_ok=True)
        run_command(["git", "init", str(checkout_dir)])
        return

    if not (checkout_dir / ".git").exists():
        raise SystemExit(f"{checkout_dir} exists but is not a git checkout.")


def ensure_remote(checkout_dir: Path, remote: str) -> None:
    remotes = git_output(["git", "-C", str(checkout_dir), "remote"]).splitlines()
    if "origin" in remotes:
        run_command(["git", "-C", str(checkout_dir), "remote", "set-url", "origin", remote])
        return
    run_command(["git", "-C", str(checkout_dir), "remote", "add", "origin", remote])


def ensure_git_identity(checkout_dir: Path) -> None:
    name_result = subprocess.run(
        ["git", "-C", str(checkout_dir), "config", "--get", "user.name"],
        check=False,
        capture_output=True,
        text=True,
    )
    email_result = subprocess.run(
        ["git", "-C", str(checkout_dir), "config", "--get", "user.email"],
        check=False,
        capture_output=True,
        text=True,
    )
    if not name_result.stdout.strip():
        run_command(["git", "-C", str(checkout_dir), "config", "user.name", BOT_NAME])
    if not email_result.stdout.strip():
        run_command(["git", "-C", str(checkout_dir), "config", "user.email", BOT_EMAIL])


def clear_checkout_contents(checkout_dir: Path) -> None:
    for path in checkout_dir.iterdir():
        if path.name == ".git":
            continue
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()


def checkout_branch(checkout_dir: Path, branch: str) -> None:
    fetch = subprocess.run(
        ["git", "-C", str(checkout_dir), "fetch", "--depth=1", "origin", branch],
        check=False,
        capture_output=True,
        text=True,
    )
    if fetch.returncode == 0:
        run_command(["git", "-C", str(checkout_dir), "checkout", "-B", branch, "FETCH_HEAD"])
        return

    run_command(["git", "-C", str(checkout_dir), "checkout", "--orphan", branch])
    clear_checkout_contents(checkout_dir)


def has_staged_changes(repo_dir: Path, path: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "diff", "--cached", "--quiet", "--", path],
        check=False,
    )
    return result.returncode == 1


def publish_badge(
    repo_root: Path,
    coverage_json: Path,
    checkout_dir: Path,
    *,
    remote: str | None = None,
    branch: str = BADGE_BRANCH,
    badge_path: str = BADGE_PATH,
) -> PublishResult:
    remote = remote or derive_repo_remote(repo_root)
    coverage_percent = load_coverage_percent(coverage_json)
    payload = render_badge_payload(coverage_percent)

    ensure_git_checkout(checkout_dir)
    ensure_remote(checkout_dir, remote)
    checkout_branch(checkout_dir, branch)
    ensure_git_identity(checkout_dir)

    badge_file = checkout_dir / badge_path
    write_badge(badge_file, payload)

    run_command(["git", "-C", str(checkout_dir), "add", "--", badge_path])
    if not has_staged_changes(checkout_dir, badge_path):
        return PublishResult(
            committed=False,
            coverage_percent=coverage_percent,
            branch=branch,
            badge_path=badge_path,
        )

    run_command(["git", "-C", str(checkout_dir), "commit", "-m", SYNC_COMMIT_MESSAGE])
    run_command(["git", "-C", str(checkout_dir), "push", "origin", branch])
    return PublishResult(
        committed=True,
        coverage_percent=coverage_percent,
        branch=branch,
        badge_path=badge_path,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render or publish the README coverage badge.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    render_parser = subparsers.add_parser("render", help="Render the coverage badge payload.")
    render_parser.add_argument("--coverage-json", type=Path, required=True)
    render_parser.add_argument("--out", type=Path, required=True)

    publish_parser = subparsers.add_parser("publish", help="Publish the coverage badge branch.")
    publish_parser.add_argument("--coverage-json", type=Path, required=True)
    publish_parser.add_argument("--checkout-dir", type=Path, required=True)
    publish_parser.add_argument("--remote", help="Override the git remote URL to publish to.")
    publish_parser.add_argument("--branch", default=BADGE_BRANCH)
    publish_parser.add_argument("--badge-path", default=BADGE_PATH)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "render":
        coverage_percent = load_coverage_percent(args.coverage_json)
        payload = render_badge_payload(coverage_percent)
        changed = write_badge(args.out, payload)
        print(f"Rendered coverage badge at {args.out} for {coverage_percent:.1f}% coverage.")
        if not changed:
            print("Coverage badge content was already up to date.")
        return

    publish_result = publish_badge(
        ROOT,
        args.coverage_json,
        args.checkout_dir,
        remote=args.remote,
        branch=args.branch,
        badge_path=args.badge_path,
    )
    if publish_result.committed:
        print(
            "Published coverage badge "
            f"({publish_result.coverage_percent:.1f}%) "
            f"to {publish_result.branch}:{publish_result.badge_path}."
        )
    else:
        print(
            "Coverage badge already matched "
            f"{publish_result.coverage_percent:.1f}% on "
            f"{publish_result.branch}:{publish_result.badge_path}."
        )


if __name__ == "__main__":
    main()
