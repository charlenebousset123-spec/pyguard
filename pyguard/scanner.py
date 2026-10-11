import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from . import heuristics
from .hashing import sha256_file
from .yara_engine import YaraEngine

log = logging.getLogger("pyguard")


@dataclass
class Detection:
    path: Path
    verdict: str  # "clean" | "suspicious" | "malicious"
    score: int = 0
    sha256: str = ""
    reasons: list[str] = field(default_factory=list)


class Scanner:
    def __init__(self, signatures_file: Path, rules_dir: Path | None = None,
                 suspicious_threshold: int = 40, max_size: int = 100 * 1024 * 1024):
        self.signatures: dict[str, str] = json.loads(Path(signatures_file).read_text())
        self.yara = YaraEngine(rules_dir) if rules_dir else None
        self.threshold = suspicious_threshold
        self.max_size = max_size

    def scan_file(self, path: Path) -> Detection:
        path = Path(path)
        try:
            if path.stat().st_size > self.max_size:
                return Detection(path, "clean", reasons=["ignoré : fichier trop volumineux"])

            sha = sha256_file(path)

            # 1) Signatures : correspondance exacte de hash
            if sha in self.signatures:
                return Detection(path, "malicious", 100, sha, [f"signature : {self.signatures[sha]}"])

            score, reasons = 0, []

            # 2) YARA
            if self.yara and self.yara.available:
                for rule in self.yara.match(path):
                    score += 100
                    reasons.append(f"règle YARA : {rule}")

            # 3) Heuristiques
            h_score, h_reasons = heuristics.analyze(path)
            score += h_score
            reasons += h_reasons

            verdict = "malicious" if score >= 100 else "suspicious" if score >= self.threshold else "clean"
            return Detection(path, verdict, score, sha, reasons)
        except OSError as e:
            log.warning("Impossible de lire %s : %s", path, e)
            return Detection(path, "clean", reasons=[f"erreur de lecture : {e}"])

    def scan_path(self, root: Path) -> Iterator[Detection]:
        root = Path(root)
        if root.is_file():
            yield self.scan_file(root)
            return
        for p in root.rglob("*"):
            if p.is_file() and not p.is_symlink():
                yield self.scan_file(p)
