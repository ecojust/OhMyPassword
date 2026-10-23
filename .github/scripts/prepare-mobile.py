"""Apply reproducible settings after `tauri android/ios init --ci`."""

import argparse
import json
import plistlib
import re
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ANDROID = "http://schemas.android.com/apk/res/android"
ET.register_namespace("android", ANDROID)
ET.register_namespace("tools", "http://schemas.android.com/tools")


def android():
    project = ROOT / "mobile/src-tauri/gen/android"
    gradle = project / "app/build.gradle.kts"
    content = gradle.read_text(encoding="utf-8")
    # Keep the generated app and the native discovery plugin on the SDK installed
    # by CI. Tauri CLI 2.12 generates API 37 by default; this app targets API 36.
    for setting in ("compileSdk", "targetSdk"):
        content, count = re.subn(rf"(?m)^([ \t]*{setting}[ \t]*=[ \t]*)\d+[ \t]*$", rf"\g<1>36", content)
        assert count == 1, f"Cannot locate generated {setting} in {gradle}"
    assert re.search(r"\bminSdk\s*=\s*24\b", content), "Expected Android API 24 minimum"
    gradle.write_text(content, encoding="utf-8")

    plugin = (ROOT / "mobile/plugins/discovery/android/build.gradle.kts").read_text(encoding="utf-8")
    assert re.search(r"\bcompileSdk\s*=\s*36\b", plugin), "Discovery plugin must compile against SDK 36"
    assert re.search(r"\bminSdk\s*=\s*24\b", plugin), "Discovery plugin minimum must match the app"

    main = project / "app/src/main/AndroidManifest.xml"
    assert main.is_file(), "Run tauri android init first"
    for path in (project / "app/src").rglob("AndroidManifest.xml"):
        tree = ET.parse(path)
        manifest = tree.getroot()
        if path == main:
            permissions = {element.get(f"{{{ANDROID}}}name") for element in manifest.findall("uses-permission")}
            for permission in ("android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"):
                if permission not in permissions:
                    ET.SubElement(manifest, "uses-permission", {f"{{{ANDROID}}}name": permission})
        application = manifest.find("application")
        if path == main:
            assert application is not None, "Main Android manifest has no application"
        if application is not None:
            application.set(f"{{{ANDROID}}}allowBackup", "false")
            application.set(f"{{{ANDROID}}}usesCleartextTraffic", "false")
        ET.indent(tree, space="    ")
        tree.write(path, encoding="utf-8", xml_declaration=True)
    print("Android prepared: compile/target SDK 36, minimum API 24, backup disabled, WebView cleartext disabled")


def ios():
    directory = ROOT / "mobile/src-tauri"
    config = json.loads((directory / "tauri.conf.json").read_text(encoding="utf-8"))
    settings = config["bundle"]["iOS"]
    assert settings["minimumSystemVersion"] == "15.0"
    with (directory / settings["infoPlist"]).open("rb") as file:
        info = plistlib.load(file)
    assert "_ohmypassword._tcp." in info.get("NSBonjourServices", [])
    assert info.get("NSLocalNetworkUsageDescription"), "Missing local-network explanation"
    assert list((directory / "gen/apple").glob("*.xcodeproj/project.pbxproj")), "Run tauri ios init first"
    print("iOS prepared: minimum iOS 15, Bonjour service declared, local-network purpose declared")
    print("CI builds only an unsigned ARM64 Simulator app; physical-device distribution needs Apple signing.")


parser = argparse.ArgumentParser()
parser.add_argument("platform", choices=("android", "ios"))
arguments = parser.parse_args()
{"android": android, "ios": ios}[arguments.platform]()
