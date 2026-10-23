"""Collect actual build outputs; fail if a platform produced the wrong artifact."""

import argparse
import hashlib
import json
import plistlib
import shutil
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "ci-artifacts"
VERSION = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))["version"]


def unique(paths, description):
    paths = sorted(set(paths))
    if len(paths) != 1:
        raise RuntimeError(f"Expected one {description}, found {paths}")
    return paths[0]


def copy(source, name):
    if not source.is_file() or source.stat().st_size == 0:
        raise RuntimeError(f"Missing or empty artifact: {source}")
    destination = OUTPUT / name
    shutil.copy2(source, destination)
    return destination


parser = argparse.ArgumentParser()
parser.add_argument("platform", choices=("extension", "windows-x64", "macos-arm64", "linux-x64", "android", "ios"))
parser.add_argument("--target")
args = parser.parse_args()
OUTPUT.mkdir(exist_ok=True)
prefix = f"OhMyPassword-{VERSION}"
files = []

if args.platform == "extension":
    source = ROOT / "extension/dist"
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["version"] == VERSION
    assert manifest["manifest_version"] == 3
    references = [manifest.get("background", {}).get("service_worker"), manifest.get("action", {}).get("default_popup")]
    references.extend(manifest.get("icons", {}).values())
    for content_script in manifest.get("content_scripts", []):
        references.extend(content_script.get("js", []) + content_script.get("css", []))
    for reference in filter(None, references):
        assert (source / reference).is_file(), f"Missing extension entry point: {reference}"
    destination = OUTPUT / f"{prefix}-extension.zip"
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(source).as_posix())
    files.append(destination)
elif args.platform in ("windows-x64", "macos-arm64", "linux-x64"):
    if not args.target:
        parser.error("--target is required for desktop artifacts")
    release = ROOT / "desktop/src-tauri/target" / args.target / "release"
    if args.platform == "windows-x64":
        files.append(copy(unique((release / "bundle/nsis").glob("*.exe"), "NSIS installer"), f"{prefix}-windows-x64-setup.exe"))
        files.append(copy(release / "ohmypassword-desktop.exe", f"{prefix}-windows-x64-portable.exe"))
    elif args.platform == "macos-arm64":
        files.append(copy(unique((release / "bundle/dmg").glob("*.dmg"), "DMG"), f"{prefix}-macos-arm64.dmg"))
    else:
        files.append(copy(unique((release / "bundle/deb").glob("*.deb"), "DEB"), f"{prefix}-linux-x64.deb"))
elif args.platform == "android":
    directory = ROOT / "mobile/src-tauri/gen/android/app/build/outputs/apk"
    apk = unique(directory.rglob("*-debug.apk"), "development APK")
    with zipfile.ZipFile(apk) as archive:
        assert "lib/arm64-v8a/libohmypassword_mobile.so" in archive.namelist(), "ARM64 Rust library missing"
        assert "AndroidManifest.xml" in archive.namelist()
    files.append(copy(apk, f"{prefix}-android-arm64-debug.apk"))
else:
    directory = ROOT / "mobile/src-tauri/gen/apple/build"
    applications = []
    for application in directory.rglob("*.app"):
        info_path = application / "Info.plist"
        if not info_path.is_file():
            continue
        with info_path.open("rb") as file:
            info = plistlib.load(file)
        if "iPhoneSimulator" not in info.get("CFBundleSupportedPlatforms", []):
            continue
        assert info.get("CFBundleShortVersionString") == VERSION
        assert "_ohmypassword._tcp" in info.get("NSBonjourServices", []) or "_ohmypassword._tcp." in info.get("NSBonjourServices", [])
        assert info.get("NSLocalNetworkUsageDescription"), "Missing local-network permission explanation"
        applications.append(application)
    if not applications:
        raise RuntimeError(f"No iOS Simulator application found in {directory}")
    # Tauri can leave intermediate copies alongside the exported application.
    application = min(applications, key=lambda path: ("export" not in path.parts, len(path.parts), str(path)))
    destination = OUTPUT / f"{prefix}-ios-arm64-simulator.zip"
    subprocess.run(["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(application), str(destination)], check=True)
    files.append(destination)

notes = (
    "OhMyPassword CI build artifacts\n"
    "Desktop macOS bundles use ad-hoc signing; they are not Apple-notarized.\n"
    "Android APKs use a development/debug signing key and are not store releases.\n"
    "The iOS .app is for an ARM64 iOS Simulator, not a physical iPhone.\n"
    "Physical iOS device distribution requires Apple signing and provisioning.\n"
    "No production release is published by this workflow.\n"
)
(OUTPUT / "BUILD-NOTES.txt").write_text(notes, encoding="utf-8")
checksums = []
for path in files:
    with path.open("rb") as file:
        digest = hashlib.file_digest(file, "sha256").hexdigest()
    checksums.append(f"{digest}  {path.name}\n")
    print(f"{path.name}: {path.stat().st_size} bytes; SHA256 {digest}")
(OUTPUT / "SHA256SUMS.txt").write_text("".join(checksums), encoding="utf-8")
