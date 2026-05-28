import json
from pathlib import Path
from functools import lru_cache

_DB: dict = {}
_DB_PATH = Path(__file__).parent.parent / "data" / "security_events.json"


def load() -> dict:
    global _DB
    if not _DB:
        with open(_DB_PATH, encoding="utf-8") as f:
            _DB = json.load(f)
    return _DB


@lru_cache(maxsize=2048)
def lookup(event_id: int | str) -> dict | None:
    return load().get(str(event_id))


def enrich(event_id: int | str) -> dict:
    info = lookup(event_id) or {}
    return {
        "name": info.get("name", f"Unknown Event {event_id}"),
        "cat":  info.get("cat",  "other"),
        "sev":  info.get("sev",  "info"),
        "desc": info.get("desc", "No description available."),
        "mitre": info.get("mitre", []),
    }


def all_categories() -> list[str]:
    cats = {v["cat"] for v in load().values()}
    return sorted(cats)
