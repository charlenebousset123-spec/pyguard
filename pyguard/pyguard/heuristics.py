"""Analyse heuristique statique : entropie, double extension, imports PE suspects."""
import math
from collections import Counter
from pathlib import Path

try:
    import pefile
except ImportError:  # pefile est optionnel
    pefile = None

EXECUTABLE_EXT = {".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".vbs", ".ps1", ".jar"}
DECOY_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt", ".mp3"}
SUSPICIOUS_IMPORTS = {
    b"VirtualAllocEx": 15,
    b"WriteProcessMemory": 15,
    b"CreateRemoteThread": 20,
    b"SetWindowsHookExA": 10,
    b"SetWindowsHookExW": 10,
    b"IsDebuggerPresent": 5,
}
READ_LIMIT = 10 * 1024 * 1024  # on n'analyse que les 10 premiers Mo


def entropy(data: bytes) -> float:
    """Entropie de Shannon (0 à 8 bits/octet). > 7.2 : souvent packé ou chiffré."""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def has_double_extension(path: Path) -> bool:
    """Ex. facture.pdf.exe : un exécutable déguisé en document."""
    suffixes = [s.lower() for s in path.suffixes]
    return len(suffixes) >= 2 and suffixes[-1] in EXECUTABLE_EXT and suffixes[-2] in DECOY_EXT


def analyze(path: Path) -> tuple[int, list[str]]:
    """Retourne (score, raisons). Plus le score est élevé, plus le fichier est suspect."""
    score, reasons = 0, []

    if has_double_extension(path):
        score += 40
        reasons.append("double extension (exécutable déguisé)")

    with open(path, "rb") as f:
        data = f.read(READ_LIMIT)

    if len(data) > 1024:
        e = entropy(data)
        if e > 7.2:
            score += 25
            reasons.append(f"entropie élevée ({e:.2f}) : fichier packé ou chiffré ?")

    if pefile and data[:2] == b"MZ":
        try:
            pe = pefile.PE(data=data, fast_load=False)
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                for imp in entry.imports:
                    if imp.name in SUSPICIOUS_IMPORTS:
                        score += SUSPICIOUS_IMPORTS[imp.name]
                        reasons.append(f"import suspect : {imp.name.decode()}")
            for section in pe.sections:
                if section.get_entropy() > 7.2:
                    score += 10
                    name = section.Name.rstrip(b"\x00").decode(errors="replace")
                    reasons.append(f"section {name} à forte entropie")
        except pefile.PEFormatError:
            score += 10
            reasons.append("en-tête PE malformé")

    return score, reasons
