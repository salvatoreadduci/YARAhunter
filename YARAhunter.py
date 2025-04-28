import sys
import os

# Aggiunge la directory "scripts" al percorso di ricerca dei moduli
sys.path.append(os.path.join(os.path.dirname(__file__), "scripts"))

from scripts.cli import app

if __name__ == "__main__":
    app()
