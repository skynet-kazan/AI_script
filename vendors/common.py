"""Общие утилиты сценариев (не привязаны к одному вендору)."""

from __future__ import annotations

from typing import Any


def substitute_params(command: str, params: dict[str, Any]) -> str:
    """Подставляет в строку команды значения из словаря вместо плейсхолдеров {ключ}."""
    for key, value in params.items():
        command = command.replace("{" + key + "}", str(value))
    return command
