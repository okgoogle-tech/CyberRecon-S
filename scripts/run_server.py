import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cyberrecon.app import create_app

port = int(sys.argv[1]) if len(sys.argv) > 1 else 5096
app = create_app()
app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
