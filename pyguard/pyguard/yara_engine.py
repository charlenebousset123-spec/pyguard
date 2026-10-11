"""Moteur YARA optionnel : si yara-python n'est pas installé, il est simplement désactivé."""
from pathlib import Path

try:
    import yara
except ImportError:
    yara = None


class YaraEngine:
    def __init__(self, rules_dir: Path):
        self.rules = None
        if yara is None:
            return
        files = {p.stem: str(p) for p in Path(rules_dir).glob("*.yar")}
        if files:
            self.rules = yara.compile(filepaths=files)

    @property
    def available(self) -> bool:
        return self.rules is not None

    def match(self, path: Path) -> list[str]:
        return [m.rule for m in self.rules.match(str(path))] if self.available else []
