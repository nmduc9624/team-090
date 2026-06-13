import re

from app.schemas.hunt_package import IOC


PROCESS_RE = re.compile(r"\b[a-zA-Z0-9_\-]+\.exe\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|test|example)\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
WIN_PATH_RE = re.compile(r"[A-Z]:\\[^\s`'\"]+")
LINUX_PATH_RE = re.compile(r"(?<!:)\/(?:tmp|var|etc|home|opt)\/[^\s`'\"]+")
REG_RE = re.compile(r"\bHK(?:CU|LM|CR|U|CC)\\[^\n`]+", re.IGNORECASE)


def _dedupe(values: list[str]) -> list[str]:
    seen = set()
    out = []
    for value in values:
        cleaned = value.strip().strip(".,;:)(")
        if cleaned and cleaned.lower() not in seen:
            seen.add(cleaned.lower())
            out.append(cleaned)
    return out


def extract_ioc(text: str) -> IOC:
    normalized = text.replace("[.]", ".")
    processes = _dedupe(PROCESS_RE.findall(normalized))
    domains = _dedupe(DOMAIN_RE.findall(normalized))
    ips = _dedupe(IP_RE.findall(normalized))
    hashes = _dedupe(HASH_RE.findall(normalized))
    files = _dedupe(WIN_PATH_RE.findall(normalized) + LINUX_PATH_RE.findall(normalized))
    registry_keys = _dedupe(REG_RE.findall(normalized))

    # Include common filename indicators even when not full paths.
    filename_candidates = re.findall(r"\b[\w.-]+\.(?:xlsm|docm|lnk|dll|exe|sys|js|vbs|ps1|sh|zip|aspx|jsp)\b", normalized)
    for name in filename_candidates:
        if name not in files and name.lower() not in {p.lower() for p in processes}:
            files.append(name)

    return IOC(
        domains=domains,
        ips=ips,
        hashes=hashes,
        files=_dedupe(files),
        processes=processes,
        registry_keys=registry_keys,
    )

