from __future__ import annotations

from pathlib import Path

from knives_out.models import LearnedModel, LoadedOperations


def load_learned_model(path: str | Path) -> LearnedModel:
    learned_path = Path(path)
    return LearnedModel.model_validate_json(learned_path.read_text(encoding="utf-8"))


def load_learned_model_with_warnings(path: str | Path) -> LoadedOperations:
    learned_model = load_learned_model(path)
    return LoadedOperations(
        source_kind="learned",
        operations=learned_model.operations,
        warnings=learned_model.warnings,
        learned_model=learned_model,
    )
