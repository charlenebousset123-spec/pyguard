import os
import tempfile
import unittest
from pathlib import Path

from pyguard.heuristics import entropy, has_double_extension
from pyguard.quarantine import Quarantine
from pyguard.scanner import Scanner

BASE = Path(__file__).resolve().parent.parent
# Chaîne de test standard EICAR : inoffensive, reconnue par tous les antivirus
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class PyGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(dir=BASE))
        self.scanner = Scanner(BASE / "signatures" / "hashes.json", BASE / "rules")

    def test_eicar_detected(self):
        f = self.tmp / "eicar.com"
        f.write_bytes(EICAR)
        self.assertEqual(self.scanner.scan_file(f).verdict, "malicious")

    def test_clean_file(self):
        f = self.tmp / "notes.txt"
        f.write_text("bonjour, ceci est un fichier normal")
        self.assertEqual(self.scanner.scan_file(f).verdict, "clean")

    def test_double_extension_suspicious(self):
        f = self.tmp / "facture.pdf.exe"
        f.write_text("contenu quelconque")
        self.assertEqual(self.scanner.scan_file(f).verdict, "suspicious")

    def test_entropy(self):
        self.assertEqual(entropy(b"aaaa"), 0.0)
        self.assertGreater(entropy(os.urandom(8192)), 7.5)

    def test_double_extension_helper(self):
        self.assertTrue(has_double_extension(Path("cv.docx.scr")))
        self.assertFalse(has_double_extension(Path("setup.exe")))

    def test_quarantine_roundtrip(self):
        f = self.tmp / "eicar.com"
        f.write_bytes(EICAR)
        q = Quarantine(self.tmp / "q")
        qid = q.add(f, "test", "abc")
        self.assertFalse(f.exists())
        self.assertEqual(len(q.list()), 1)
        q.restore(qid)
        self.assertEqual(f.read_bytes(), EICAR)


if __name__ == "__main__":
    unittest.main()
