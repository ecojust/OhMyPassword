"""Verify the distributable DMG, its sealed application and an installed copy."""

import argparse
import json
import plistlib
import re
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def run(*command):
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {command}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def verify(application):
    with (application / "Contents/Info.plist").open("rb") as file:
        info = plistlib.load(file)
    assert info["CFBundleShortVersionString"] == config["version"]
    assert info["LSMinimumSystemVersion"] == "11.0"
    executable = application / "Contents/MacOS" / info["CFBundleExecutable"]
    assert "arm64" in run("lipo", "-archs", str(executable)).split()
    load_commands = run("otool", "-l", str(executable))
    minimums = re.findall(r"\bminos\s+(\d+(?:\.\d+)+)", load_commands)
    assert minimums and all(tuple(map(int, item.split(".")[:2])) <= (11, 0) for item in minimums), minimums
    run("codesign", "--verify", "--deep", "--strict", "--verbose=2", str(application))
    print(f"Verified {application.name}: ARM64, macOS 11.0+, complete bundle signature")
    return executable


parser = argparse.ArgumentParser()
parser.add_argument("--target", required=True)
args = parser.parse_args()
config = json.loads((ROOT / "desktop/src-tauri/tauri.conf.json").read_text(encoding="utf-8"))
dmgs = list((ROOT / "desktop/src-tauri/target" / args.target / "release/bundle/dmg").glob("*.dmg"))
assert len(dmgs) == 1, dmgs
run("hdiutil", "verify", str(dmgs[0]))
with tempfile.TemporaryDirectory(prefix="ohmypassword-install-") as temporary:
    temporary = Path(temporary)
    mount = temporary / "volume"
    mount.mkdir()
    run("hdiutil", "attach", "-readonly", "-nobrowse", "-mountpoint", str(mount), str(dmgs[0]))
    try:
        apps = list(mount.glob("*.app"))
        assert len(apps) == 1, apps
        verify(apps[0])
        installed = temporary / apps[0].name
        run("ditto", str(apps[0]), str(installed))
    finally:
        run("hdiutil", "detach", str(mount))
    executable = verify(installed)
    with (temporary / "startup.log").open("w+") as log:
        process = subprocess.Popen([str(executable)], stdout=log, stderr=log)
        try:
            time.sleep(5)
            if process.poll() is not None:
                log.seek(0)
                raise RuntimeError(f"Installed application exited early ({process.returncode}): {log.read()}")
            print("Installed copy stayed running for 5 seconds; no vault was unlocked")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
print("DMG signature/install/startup checks passed; Apple notarization and Gatekeeper approval are not tested.")
