"""Load standalone scripts without invoking their CLI entrypoints."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_script(name):
    path = next((ROOT / "skills").glob(f"*/scripts/{name}.py"))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
