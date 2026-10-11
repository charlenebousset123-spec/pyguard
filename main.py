#!/usr/bin/env python3
"""PyGuard CLI : scan, monitor, persistence, list, restore."""
import argparse
import json
import logging
import sys
import time
from pathlib import Path

from pyguard import persistence
from pyguard.quarantine import Quarantine
from pyguard.scanner import Scanner

BASE = Path(__file__).parent
QUARANTINE_DIR = BASE / "quarantine"


def build_scanner() -> Scanner:
    return Scanner(BASE / "signatures" / "hashes.json", BASE / "rules")


def handle(det, quarantine: Quarantine | None) -> None:
    if det.verdict == "clean":
        return
    print(f"[{det.verdict.upper():10}] {det.path}  (score {det.score})")
    for r in det.reasons:
        print(f"      - {r}")
    logging.getLogger("pyguard").warning("%s %s %s", det.verdict, det.path, det.reasons)
    if quarantine and det.verdict == "malicious":
        qid = quarantine.add(det.path, "; ".join(det.reasons), det.sha256)
        print(f"      -> mis en quarantaine (id {qid})")


def cmd_scan(args) -> None:
    scanner, q = build_scanner(), (Quarantine(QUARANTINE_DIR) if args.quarantine else None)
    total = bad = 0
    results = []
    for det in scanner.scan_path(Path(args.path)):
        total += 1
        bad += det.verdict != "clean"
        results.append({"path": str(det.path), "verdict": det.verdict, "score": det.score,
                        "sha256": det.sha256, "reasons": det.reasons})
        if not args.json:
            handle(det, q)
    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        print(f"\n{total} fichier(s) analysé(s), {bad} détection(s).")


def cmd_persistence(args) -> None:
    if sys.platform != "win32":
        raise SystemExit("Cette commande fonctionne uniquement sous Windows.")
    entries = persistence.scan_persistence(build_scanner(), include_microsoft_tasks=args.all_tasks)
    shown = [e for e in entries if e.verdict != "clean"] if args.suspicious_only else entries

    if args.json:
        print(json.dumps([e.__dict__ for e in shown], indent=2, ensure_ascii=False))
        return

    tags = {"clean": "OK", "suspicious": "SUSPECT", "malicious": "MALVEILLANT"}
    for e in shown:
        print(f"[{tags[e.verdict]:11}] ({e.source}) {e.name}")
        print(f"      {e.command}")
        for r in e.reasons:
            print(f"      - {r}")
        if e.verdict != "clean":
            logging.getLogger("pyguard").warning("persistance %s %s %s", e.verdict, e.command, e.reasons)

    bad = sum(e.verdict != "clean" for e in entries)
    print(f"\n{len(entries)} entrée(s) de démarrage analysée(s), {bad} suspecte(s).")


def cmd_monitor(args) -> None:
    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError:
        raise SystemExit("Installe watchdog : pip install watchdog")

    scanner, q = build_scanner(), (Quarantine(QUARANTINE_DIR) if args.quarantine else None)

    class Handler(FileSystemEventHandler):
        def on_created(self, event):
            if not event.is_directory:
                time.sleep(0.3)  # laisse le fichier finir d'être écrit
                handle(scanner.scan_file(Path(event.src_path)), q)

        on_modified = on_created

    observer = Observer()
    observer.schedule(Handler(), args.path, recursive=True)
    observer.start()
    print(f"Surveillance de {args.path} (Ctrl+C pour arrêter)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def cmd_list(_args) -> None:
    for m in Quarantine(QUARANTINE_DIR).list():
        print(f"{m['id']}  {m['date']}  {m['original_path']}")


def cmd_restore(args) -> None:
    print("Restauré :", Quarantine(QUARANTINE_DIR).restore(args.id))


def main() -> None:
    logging.basicConfig(filename=BASE / "pyguard.log", level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="PyGuard - mini antivirus éducatif")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="analyser un fichier ou un dossier")
    p.add_argument("path")
    p.add_argument("--quarantine", action="store_true", help="isoler les fichiers malveillants")
    p.add_argument("--json", action="store_true", help="sortie JSON")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("persistence", help="analyser les points de persistance Windows")
    p.add_argument("--suspicious-only", action="store_true", help="n'afficher que les entrées suspectes")
    p.add_argument("--all-tasks", action="store_true", help="inclure les tâches Microsoft")
    p.add_argument("--json", action="store_true", help="sortie JSON")
    p.set_defaults(func=cmd_persistence)

    p = sub.add_parser("monitor", help="surveillance en temps réel d'un dossier")
    p.add_argument("path")
    p.add_argument("--quarantine", action="store_true")
    p.set_defaults(func=cmd_monitor)

    sub.add_parser("list", help="lister la quarantaine").set_defaults(func=cmd_list)

    p = sub.add_parser("restore", help="restaurer un fichier de la quarantaine")
    p.add_argument("id")
    p.set_defaults(func=cmd_restore)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
