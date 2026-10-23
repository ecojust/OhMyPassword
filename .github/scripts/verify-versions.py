"""Validate committed version metadata before any platform build."""

import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read_json(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


version = read_json("package.json")["version"]
assert re.fullmatch(r"\d+\.\d+\.\d+", version), "Use a stable semantic version"
node_lock = read_json("package-lock.json")
assert node_lock["packages"][""]["version"] == version, "Root npm lock version mismatch"
for workspace in ("desktop", "mobile", "extension"):
    assert read_json(f"{workspace}/package.json")["version"] == version, workspace
    assert node_lock["packages"][workspace]["version"] == version, f"npm lock: {workspace}"
for path in (
    "desktop/core/Cargo.toml",
    "desktop/service/Cargo.toml",
    "desktop/src-tauri/Cargo.toml",
    "mobile/src-tauri/Cargo.toml",
):
    with (ROOT / path).open("rb") as file:
        package = tomllib.load(file)["package"]
    assert package["version"] == version, path
    lock_path = (ROOT / path).with_name("Cargo.lock")
    with lock_path.open("rb") as file:
        rust_lock = tomllib.load(file)
    entries = [entry for entry in rust_lock["package"] if entry["name"] == package["name"]]
    assert len(entries) == 1 and entries[0]["version"] == version, lock_path
for workspace in ("desktop", "mobile"):
    config_path = ROOT / workspace / "src-tauri/tauri.conf.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert config["version"] == version, config_path
    frontend = (config_path.parent / config["build"]["frontendDist"]).resolve()
    assert frontend == ROOT / "desktop/dist", f"Unexpected frontend path: {frontend}"
assert read_json("extension/src/manifest.json")["version"] == version
print(f"OhMyPassword {version}: workspace, Rust, Tauri and extension versions agree")
