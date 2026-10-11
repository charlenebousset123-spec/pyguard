"""Analyse des points de persistance Windows.

Un malware cherche presque toujours à survivre au redémarrage. Les endroits classiques :
  - les clés de registre Run / RunOnce ;
  - les dossiers Démarrage ;
  - les tâches planifiées.
Ce module liste ces entrées et leur attribue un score de suspicion.
"""
import csv
import io
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .heuristics import has_double_extension

try:
    import winreg  # disponible uniquement sous Windows
except ImportError:
    winreg = None

REGISTRY_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
]

# (expression régulière appliquée à la commande en minuscules, points, explication)
RULES = [
    (r"\\temp\\", 25, "exécuté depuis un dossier temporaire"),
    (r"\\users\\public\\", 25, "exécuté depuis Users\\Public"),
    (r"\\downloads\\", 20, "exécuté depuis le dossier Téléchargements"),
    (r"\\appdata\\roaming\\", 10, "exécuté depuis AppData\\Roaming"),
    (r"\\programdata\\", 10, "exécuté depuis ProgramData"),
    (r"\s-enc(odedcommand)?\s", 40, "PowerShell avec commande encodée (base64)"),
    (r"-(executionpolicy|ep)\s+bypass", 20, "politique d'exécution PowerShell contournée"),
    (r"-(windowstyle|w)\s+hidden", 20, "fenêtre cachée"),
    (r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|\biex\b|invoke-expression",
     30, "téléchargement ou exécution de code à distance"),
    (r"https?://", 20, "contacte une adresse web"),
    (r"\b(mshta|wscript|cscript|regsvr32|rundll32|certutil|bitsadmin)(\.exe)?\b", 15,
     "utilise un outil Windows souvent détourné"),
    (r"\b(powershell|pwsh)(\.exe)?\b", 10, "lance PowerShell"),
    (r"\bcmd(\.exe)?\s+/c", 10, "lance une commande via cmd /c"),
]
SCRIPT_EXT = {".vbs", ".js", ".bat", ".cmd", ".ps1", ".scr", ".pif"}
SUSPICIOUS_SCORE = 30


@dataclass
class Entry:
    source: str    # "registre" | "démarrage" | "tâche planifiée"
    location: str
    name: str
    command: str
    score: int = 0
    verdict: str = "clean"  # "clean" | "suspicious" | "malicious"
    reasons: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- analyse (pure)

def extract_path(command: str) -> Path | None:
    """Extrait le chemin de l'exécutable d'une ligne de commande."""
    cmd = os.path.expandvars(command).strip()
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return Path(cmd[1:end]) if end > 1 else None
    m = re.match(r"^(.+?\.(?:exe|bat|cmd|com|scr|vbs|js|ps1|dll|jar|lnk))(?:\s|$)", cmd, re.I)
    return Path(m.group(1)) if m else None


def analyze_entry(entry: Entry, scanner=None) -> Entry:
    """Calcule le score d'une entrée. Si un Scanner est fourni, analyse aussi le fichier cible."""
    cmd = os.path.expandvars(entry.command)
    low = " " + cmd.lower() + " "
    score, reasons = 0, []

    for pattern, points, text in RULES:
        if re.search(pattern, low):
            score += points
            reasons.append(text)

    path = extract_path(entry.command)
    if path:
        if has_double_extension(path):
            score += 40
            reasons.append("double extension (exécutable déguisé)")
        if path.suffix.lower() in SCRIPT_EXT:
            score += 10
            reasons.append(f"lance un script ({path.suffix.lower()})")
        if path.is_absolute() and not path.exists():
            score += 10
            reasons.append("fichier cible introuvable")

    verdict = "suspicious" if score >= SUSPICIOUS_SCORE else "clean"

    if scanner and path and path.is_file():
        det = scanner.scan_file(path)
        if det.verdict != "clean":
            score += det.score
            reasons += [f"analyse du fichier : {r}" for r in det.reasons]
            verdict = "malicious" if det.verdict == "malicious" else "suspicious"

    entry.score, entry.verdict, entry.reasons = score, verdict, reasons
    return entry


def parse_schtasks_csv(text: str, include_microsoft: bool = False) -> list[Entry]:
    """Lit la sortie de `schtasks /query /fo CSV /v /nh`.

    On utilise les positions des colonnes (et non leurs noms) car les titres
    changent selon la langue de Windows : colonne 1 = nom, colonne 8 = commande.
    """
    entries, seen = [], set()
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 9:
            continue
        name, command = row[1].strip(), row[8].strip()
        if "." not in command:  # "N/A", "N/D", gestionnaire COM, etc.
            continue
        if not include_microsoft and name.lower().startswith("\\microsoft\\"):
            continue
        if (name, command) in seen:
            continue
        seen.add((name, command))
        entries.append(Entry("tâche planifiée", "Planificateur de tâches", name, command))
    return entries


# ---------------------------------------------------------- collecte (Windows)

def collect_registry() -> list[Entry]:
    if winreg is None:
        return []
    hives = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    entries = []
    for hive_name, subkey in REGISTRY_KEYS:
        try:
            with winreg.OpenKey(hives[hive_name], subkey) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    i += 1
                    entries.append(Entry("registre", f"{hive_name}\\{subkey}", name, str(value)))
        except OSError:
            continue  # clé absente ou accès refusé
    return entries


def collect_startup_folders() -> list[Entry]:
    entries = []
    for var in ("APPDATA", "PROGRAMDATA"):
        base = os.environ.get(var)
        if not base:
            continue
        folder = Path(base) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        if folder.is_dir():
            for f in folder.iterdir():
                if f.is_file() and f.name.lower() != "desktop.ini":
                    entries.append(Entry("démarrage", str(folder), f.name, str(f)))
    return entries


def collect_tasks(include_microsoft: bool = False) -> list[Entry]:
    try:
        res = subprocess.run(["schtasks", "/query", "/fo", "CSV", "/v", "/nh"],
                             capture_output=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return []
    try:
        text = res.stdout.decode("oem")  # page de code de la console Windows
    except (LookupError, UnicodeDecodeError):
        text = res.stdout.decode("utf-8", errors="replace")
    return parse_schtasks_csv(text, include_microsoft)


def scan_persistence(scanner=None, include_microsoft_tasks: bool = False) -> list[Entry]:
    entries = collect_registry() + collect_startup_folders() + collect_tasks(include_microsoft_tasks)
    return [analyze_entry(e, scanner) for e in entries]
