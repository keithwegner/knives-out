from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from knives_out.models import AuthProfile, AuthProfilesFile


def load_auth_profiles(path: str | Path) -> AuthProfilesFile:
    raw = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        raise ValueError("Auth profile file must contain a top-level mapping.")
    try:
        return AuthProfilesFile.model_validate(data)
    except ValidationError as exc:
        raise ValueError(str(exc)) from exc


def select_auth_profiles(
    profiles_file: AuthProfilesFile,
    *,
    include_names: list[str] | None = None,
) -> list[AuthProfile]:
    if not include_names:
        return list(profiles_file.profiles)

    selected: list[AuthProfile] = []
    missing = list(include_names)
    for profile in profiles_file.profiles:
        if profile.name not in include_names:
            continue
        selected.append(profile)
        if profile.name in missing:
            missing.remove(profile.name)

    if missing:
        raise ValueError("Unknown auth profile name(s): " + ", ".join(sorted(missing)))
    return selected


def resolve_auth_profile_modules(
    profiles: list[AuthProfile],
    *,
    relative_to: str | Path,
) -> list[AuthProfile]:
    base_dir = Path(relative_to).resolve().parent
    resolved_profiles: list[AuthProfile] = []
    for profile in profiles:
        resolved_modules = []
        for module_path in profile.auth_plugin_modules:
            resolved_path = Path(module_path)
            if not resolved_path.is_absolute():
                resolved_path = base_dir / resolved_path
            resolved_modules.append(str(resolved_path.resolve()))
        resolved_profiles.append(
            profile.model_copy(update={"auth_plugin_modules": resolved_modules})
        )
    return resolved_profiles
