"""Apply reproducible settings after `tauri android/ios init --ci`."""

import argparse
import json
import plistlib
import re
import shutil
import struct
import xml.etree.ElementTree as ET
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ANDROID = "http://schemas.android.com/apk/res/android"
ET.register_namespace("android", ANDROID)
ET.register_namespace("tools", "http://schemas.android.com/tools")


def android_resource_exists(directory, reference):
    match = re.fullmatch(r"@(mipmap|drawable|color)/([A-Za-z0-9_]+)", reference)
    assert match, f"Unexpected launcher resource: {reference}"
    kind, name = match.groups()
    if kind == "color":
        return any(
            element.get("name") == name
            for path in directory.glob("values*/*.xml")
            for element in ET.parse(path).getroot().findall("color")
        )
    return any(path.is_file() for path in directory.glob(f"{kind}*/{name}.*"))


def copy_android_icons(project):
    source = ROOT / "desktop/src-tauri/icons/android"
    destination = project / "app/src/main/res"
    assert source.is_dir(), "Generate the shared Android icons first"
    assert destination.is_dir(), "Android resources directory is missing; run init first"
    manifest = ET.parse(project / "app/src/main/AndroidManifest.xml").getroot()
    application = manifest.find("application")
    references = [application.get(f"{{{ANDROID}}}{name}") for name in ("icon", "roundIcon")]
    assert references[0], "Android launcher icon is not declared"
    for path in source.rglob("*.xml"):
        for element in ET.parse(path).iter():
            references.extend(value for value in element.attrib.values() if value.startswith("@"))
    for reference in filter(None, references):
        assert android_resource_exists(source, reference), f"Missing shared launcher resource: {reference}"
    shutil.copytree(source, destination, dirs_exist_ok=True)
    for path in source.rglob("*"):
        if path.is_file():
            assert path.read_bytes() == (destination / path.relative_to(source)).read_bytes()
    for reference in filter(None, references):
        assert android_resource_exists(destination, reference), f"Missing generated launcher resource: {reference}"
    print("Android launcher icons copied; adaptive foreground/background references verified")


def copy_ios_icons(project):
    source = ROOT / "desktop/src-tauri/icons/ios"
    destination = project / "Assets.xcassets/AppIcon.appiconset"
    contents = json.loads((destination / "Contents.json").read_text(encoding="utf-8"))
    images = contents.get("images", [])
    assert images, "Generated iOS AppIcon Contents.json has no images"
    for item in images:
        filename = item.get("filename")
        assert filename and Path(filename).name == filename, f"Invalid iOS icon entry: {item}"
        icon = source / filename
        assert icon.is_file(), f"Missing shared iOS icon required by Contents.json: {filename}"
        with icon.open("rb") as file:
            header = file.read(24)
        assert header[:8] == b"\x89PNG\r\n\x1a\n" and header[12:16] == b"IHDR", filename
        actual = struct.unpack(">II", header[16:24])
        scale = Decimal(item["scale"].removesuffix("x"))
        expected = tuple(int(Decimal(size) * scale) for size in item["size"].split("x"))
        assert actual == expected, f"Incorrect iOS icon dimensions: {filename}: {actual}, expected {expected}"
        shutil.copy2(icon, destination / filename)
        assert icon.read_bytes() == (destination / filename).read_bytes()
    print(f"iOS launcher icons copied; all {len(images)} Contents.json entries and PNG dimensions verified")


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
    copy_android_icons(project)
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
    copy_ios_icons(directory / "gen/apple")
    print("iOS prepared: minimum iOS 15, Bonjour service declared, local-network purpose declared")
    print("CI builds only an unsigned ARM64 Simulator app; physical-device distribution needs Apple signing.")


parser = argparse.ArgumentParser()
parser.add_argument("platform", choices=("android", "ios"))
arguments = parser.parse_args()
{"android": android, "ios": ios}[arguments.platform]()
