"""Парсинг MAC-адресов из текстовых таблиц CLI (FDB, L2 MAC) — общее для нескольких вендоров."""

from __future__ import annotations

import re


def extract_unique_macs_from_cli_table(output: str) -> set[str]:
    """Из вывода таблицы MAC (fdb / l2) извлекает MAC и возвращает множество уникальных (lower)."""
    dot_mac_re = re.compile(r"\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b")
    colon_mac_re = re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b")
    macs: set[str] = set()
    for m in dot_mac_re.findall(output or ""):
        macs.add(m.lower())
    for m in colon_mac_re.findall(output or ""):
        macs.add(m.lower())
    return macs
