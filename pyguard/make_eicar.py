"""Crée un fichier de test EICAR (inoffensif) pour vérifier que le scanner fonctionne."""
import sys

EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
out = sys.argv[1] if len(sys.argv) > 1 else "eicar.com"
with open(out, "w") as f:
    f.write(EICAR)
print("Fichier de test créé :", out)
