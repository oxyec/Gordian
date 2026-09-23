"""Create a history-free source snapshot with an explicit publication allowlist.

Default destination is dist/public-source. Existing destinations are refused.
Review PUBLIC_MANIFEST.json and run tests in the snapshot before creating a repo.
This is a packaging boundary, not a substitute for a dedicated secret scanner.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = {
    ".gitignore", "LICENSE", "README.md", "SECURITY.md", "main.py",
    "requirements.txt", "requirements-dev.txt", "pytest.ini",
}
FIXTURES = {
    "data/sample_network.json", "data/cve_feed.json", "data/offensive_config.json",
    "data/scope_policy.example.json", "data/wordlists/demo.txt",
}


def publishable(name: str) -> bool:
    path = Path(name)
    if name in ROOT_FILES or name in FIXTURES:
        return True
    if any(part.startswith(".") for part in path.parts[1:]):
        return False
    if name.startswith("tests/fixtures/offensive/"):
        return path.suffix in {".txt", ".jsonl", ".json"}
    if name.startswith(("src/", "api/", "tests/", "scripts/")):
        return path.suffix == ".py"
    if name.startswith(".github/"):
        return path.suffix in {".yml", ".yaml"}
    if name.startswith(("tui/cmd/", "tui/internal/")):
        return path.suffix == ".go" or name == "tui/internal/ui/assets/worldmap.txt"
    if name in {"tui/go.mod", "tui/go.sum", "tui/README.md", "tui/internal/ui/assets/worldmap.txt"}:
        return True
    if name.startswith("dashboard/src/"):
        return path.suffix in {".js", ".jsx", ".css"}
    return name in {
        "dashboard/package.json", "dashboard/package-lock.json", "dashboard/index.html",
        "dashboard/vite.config.js", "dashboard/postcss.config.js", "dashboard/tailwind.config.js",
        "dashboard/.gitignore", "dashboard/README.md",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, default=ROOT / "dist/public-source")
    args = parser.parse_args()
    destination = args.destination.resolve()
    if destination.exists():
        parser.error("destination already exists; choose a new empty path")
    if destination == ROOT or ROOT.is_relative_to(destination):
        parser.error("destination cannot contain the source repository")
    raw = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
    ).decode("utf-8")
    names = sorted(set(filter(None, raw.split("\0"))))
    selected = [name for name in names if publishable(name)]
    # Fail closed on symlinks and junctions instead of accidentally copying their targets.
    for name in selected:
        source = ROOT / name
        if not source.is_file() or not source.resolve().is_relative_to(ROOT):
            raise ValueError(f"invalid publication source: {name}")
        for component in (source, *source.relative_to(ROOT).parents):
            component = component if component.is_absolute() else ROOT / component
            if component.is_symlink() or getattr(component, "is_junction", lambda: False)():
                raise ValueError(f"publication source contains a link: {name}")
    destination.mkdir(parents=True)
    manifest = []
    for name in selected:
        source, target = ROOT / name, destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        # copyfile omits source owner/timestamp metadata.
        shutil.copyfile(source, target)
        manifest.append({"path": name, "sha256": hashlib.sha256(target.read_bytes()).hexdigest()})
    (destination / "reports").mkdir()
    (destination / "reports/.gitkeep").touch()
    (destination / "PUBLIC_MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Exported {len(manifest)} source files without Git history to {destination}")


if __name__ == "__main__":
    main()
