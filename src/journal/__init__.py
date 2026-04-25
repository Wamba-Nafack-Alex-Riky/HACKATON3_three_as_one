"""
src/journal/__init__.py
Expose l'API publique du module de journalisation HackVerse IDS.

Usage :
    from src.journal import write, read_alerts, export_jury, stats
    from src.journal import validate, to_jury_summary
"""

from src.journal.logger import (
    write,
    write_batch,
    read_all,
    read_alerts,
    read_blocked,
    read_by_ip,
    read_by_source,
    stats,
    export_jury,
    rotate,
    JOURNAL_PATH,
)

from src.journal.schema import (
    validate,
    to_jury_summary,
    format_for_jury,
    JOURNAL_SCHEMA,
    EXAMPLE_ENTRY,
    VALID_DECISIONS,
    VALID_SOURCES,
    VALID_LEVELS,
)

__all__ = [
    # Écriture
    "write",
    "write_batch",
    # Lecture
    "read_all",
    "read_alerts",
    "read_blocked",
    "read_by_ip",
    "read_by_source",
    # Analyse
    "stats",
    "export_jury",
    "rotate",
    # Schéma & validation
    "validate",
    "to_jury_summary",
    "format_for_jury",
    "JOURNAL_SCHEMA",
    "EXAMPLE_ENTRY",
    "VALID_DECISIONS",
    "VALID_SOURCES",
    "VALID_LEVELS",
    # Config
    "JOURNAL_PATH",
]
