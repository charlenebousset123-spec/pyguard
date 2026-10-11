"""Quarantaine : le fichier est déplacé, "neutralisé" (XOR) et ses métadonnées sont conservées."""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

XOR_KEY = 0x5A  # pédagogique : il s'agit d'obfuscation, pas de chiffrement fort


def _xor(data: bytes) -> bytes:
    return bytes(b ^ XOR_KEY for b in data)


class Quarantine:
    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)

    def add(self, path: Path, reason: str, sha256: str) -> str:
        qid = uuid.uuid4().hex[:12]
        (self.dir / f"{qid}.quar").write_bytes(_xor(Path(path).read_bytes()))
        meta = {
            "id": qid,
            "original_path": str(Path(path).resolve()),
            "sha256": sha256,
            "reason": reason,
            "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        (self.dir / f"{qid}.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False))
        Path(path).unlink()
        return qid

    def list(self) -> list[dict]:
        return [json.loads(p.read_text()) for p in sorted(self.dir.glob("*.json"))]

    def restore(self, qid: str, dest: Path | None = None) -> Path:
        meta = json.loads((self.dir / f"{qid}.json").read_text())
        target = Path(dest or meta["original_path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(_xor((self.dir / f"{qid}.quar").read_bytes()))
        (self.dir / f"{qid}.quar").unlink()
        (self.dir / f"{qid}.json").unlink()
        return target
