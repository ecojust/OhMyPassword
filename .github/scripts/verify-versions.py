"""Validate committed version metadata for every application."""

import base64
import hashlib
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
manifest = read_json("extension/src/manifest.json")
assert manifest["version"] == version
public_key = base64.b64decode(manifest["key"], validate=True)
extension_id = "".join(chr(ord("a") + int(digit, 16)) for digit in hashlib.sha256(public_key).hexdigest()[:32])
origin = (ROOT / "desktop/service/src/browser-origin.txt").read_text(encoding="utf-8").strip()
assert origin == f"chrome-extension://{extension_id}", "Extension identity and local service Origin differ"
print(f"OhMyPassword {version}: workspace, Rust, Tauri and extension versions agree")
