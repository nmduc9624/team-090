import argparse
import json
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = ROOT / "backend"

import sys

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.firebase import get_firestore_client  # noqa: E402


def seed_firestore(seed_path: Path) -> int:
    load_dotenv(BACKEND_ROOT / ".env")
    data = json.loads(seed_path.read_text(encoding="utf-8"))
    db = get_firestore_client()
    for document_path, payload in data.items():
        db.document(document_path).set(payload, merge=True)
    return len(data)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Firestore with demo schema documents.")
    parser.add_argument(
        "--seed",
        default=str(ROOT / "data" / "firestore_seed" / "firestore_schema_seed.json"),
        help="Path to a JSON object mapping Firestore document paths to payloads.",
    )
    args = parser.parse_args()
    count = seed_firestore(Path(args.seed))
    print(f"Seeded {count} Firestore documents.")


if __name__ == "__main__":
    main()
