"""Verify pinned CI artifacts and prepare a release draft; never publish it."""

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "ecojust/OhMyPassword"
SUFFIXES = (
    "extension.zip", "windows-x64-setup.exe", "windows-x64-portable.exe",
    "macos-arm64.dmg", "linux-x64.deb", "ios-arm64-simulator.zip",
    "android-arm64-debug.apk",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(arguments, **kwargs):
    # Arguments are always an argv list; no shell interpolation or token logging.
    result = subprocess.run(arguments, stderr=subprocess.PIPE, timeout=300, **kwargs)
    require(result.returncode == 0, f"Command failed ({result.returncode}): {arguments[0]} {arguments[1]}")
    return result


def api(path):
    return json.loads(command(["gh", "api", "--method", "GET", path], stdout=subprocess.PIPE).stdout)


def pages(path, field=None):
    page = 1
    while True:
        value = api(f"{path}?per_page=100&page={page}")
        entries = value[field] if field else value
        yield from entries
        if len(entries) < 100:
            return
        page += 1


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def manifest_data(path, target, repository):
    require(repository == REPOSITORY, "Unexpected repository")
    require(re.fullmatch(r"[0-9a-f]{40}", target), "Target must be a full commit SHA")
    actual_head = command(["git", "-C", str(ROOT), "rev-parse", "HEAD"], stdout=subprocess.PIPE).stdout.decode().strip()
    require(actual_head == target, "Checkout does not match the release target")
    version = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))["version"]
    require(re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", version), "Invalid package version")
    tag = f"v{version}"
    path = path.resolve()
    require(path == ROOT / ".github" / "releases" / f"{tag}.json", "Manifest path must match the package version")
    data = json.loads(path.read_text(encoding="utf-8"))
    require(data["tag"] == tag, "Manifest tag and package version differ")
    require(isinstance(data["title"], str) and data["title"].strip(), "Missing release title")
    notes = (ROOT / data["notes_file"]).resolve()
    require(notes.is_relative_to(ROOT / ".github" / "releases") and notes.suffix == ".md", "Invalid release notes path")
    require(notes.is_file() and notes.read_text(encoding="utf-8").strip(), "Empty release notes")
    expected, artifacts, runs = {}, set(), set()
    require(isinstance(data["builds"], list) and data["builds"], "Missing source builds")
    for build in data["builds"]:
        require(type(build["run_id"]) is int and build["run_id"] > 0 and build["run_id"] not in runs, "Invalid or duplicate source run")
        runs.add(build["run_id"])
        require(re.fullmatch(r"[0-9a-f]{40}", build["head_sha"]), "Invalid source commit")
        command(["git", "-C", str(ROOT), "merge-base", "--is-ancestor", build["head_sha"], target], stdout=subprocess.PIPE)
        changed = command(["git", "-C", str(ROOT), "diff", "--name-only", "-z", build["head_sha"], target], stdout=subprocess.PIPE).stdout.decode().split("\0")
        unbuilt = [name for name in changed if name and not (name.startswith(".github/") or name.endswith(".md"))]
        require(not unbuilt, "Target has unbuilt application changes: " + ", ".join(unbuilt))
        require(build["artifacts"], "Missing source artifacts")
        for artifact in build["artifacts"]:
            require(re.fullmatch(r"[A-Za-z0-9._-]+", artifact["name"]) and artifact["name"] not in artifacts, "Invalid or duplicate artifact name")
            artifacts.add(artifact["name"])
            require(artifact["files"], "Empty artifact file list")
            for item in artifact["files"]:
                name = item["name"]
                require(isinstance(name, str) and name not in expected, "Invalid or duplicate file name")
                require(type(item["bytes"]) is int and item["bytes"] > 0, "Invalid file size")
                require(re.fullmatch(r"[0-9a-f]{64}", item["sha256"]), "Invalid SHA256")
                expected[name] = item
    require(set(expected) == {f"OhMyPassword-{version}-{suffix}" for suffix in SUFFIXES}, "Manifest must contain the seven expected platform packages")
    return data, notes, expected


def verify_archive(path, files, output):
    expected = {item["name"]: item for item in files}
    with zipfile.ZipFile(path) as archive:
        entries = [entry for entry in archive.infolist() if not entry.is_dir()]
        names = [entry.filename for entry in entries]
        require(len(names) == len(set(names)), "Duplicate ZIP entries")
        require(set(names) == set(expected) | {"SHA256SUMS.txt", "BUILD-NOTES.txt"}, "Unexpected artifact ZIP contents")
        require(all(not stat.S_ISLNK(entry.external_attr >> 16) for entry in entries), "Artifact contains a symlink")
        require(archive.getinfo("SHA256SUMS.txt").file_size < 65536, "Oversized checksum file")
        checksums = {}
        for line in archive.read("SHA256SUMS.txt").decode("utf-8").splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\]+)", line)
            require(match and match[2] not in checksums, "Invalid artifact checksum list")
            checksums[match[2]] = match[1]
        require(checksums == {name: item["sha256"] for name, item in expected.items()}, "Artifact checksums differ from the release manifest")
        for name, item in expected.items():
            require(archive.getinfo(name).file_size == item["bytes"], f"ZIP size mismatch: {name}")
            destination = output / name
            with archive.open(name) as source, destination.open("xb") as target:
                while block := source.read(1024 * 1024):
                    target.write(block)
            require(destination.stat().st_size == item["bytes"] and sha256(destination) == item["sha256"], f"File verification failed: {name}")


def prepare(manifest, target, repository):
    data, notes, expected = manifest_data(manifest, target, repository)
    prefix = f"repos/{repository}"
    require(not any(release["tag_name"] == data["tag"] for release in pages(f"{prefix}/releases")), "Release already exists; leave it unchanged for manual review")
    tag = subprocess.run(["git", "-C", str(ROOT), "show-ref", "--verify", "--quiet", f"refs/tags/{data['tag']}"], check=False)
    require(tag.returncode in (0, 1), "Unable to inspect existing tag")
    if tag.returncode == 0:
        commit = command(["git", "-C", str(ROOT), "rev-list", "-n", "1", data["tag"]], stdout=subprocess.PIPE).stdout.decode().strip()
        require(commit == target, "Existing tag points to a different commit")

    with tempfile.TemporaryDirectory(prefix="ohmypassword-release-") as temporary:
        directory = Path(temporary)
        output = directory / "packages"
        output.mkdir()
        sources = []
        for build in data["builds"]:
            run = api(f"{prefix}/actions/runs/{build['run_id']}")
            require(run["status"] == "completed" and run["conclusion"] == "success", "Source build did not complete successfully")
            require(run["head_sha"] == build["head_sha"] and run["head_repository"]["full_name"] == repository, "Source build commit or repository mismatch")
            require(run["path"] == ".github/workflows/build.yml", "Unexpected source workflow")
            available = list(pages(f"{prefix}/actions/runs/{build['run_id']}/artifacts", "artifacts"))
            for artifact in build["artifacts"]:
                found = [item for item in available if item["name"] == artifact["name"]]
                require(len(found) == 1 and not found[0]["expired"], "Source artifact is missing, duplicated or expired")
                metadata = found[0]
                archive = directory / f"{metadata['id']}.zip"
                with archive.open("wb") as stream:
                    command(["gh", "api", "--method", "GET", f"{prefix}/actions/artifacts/{metadata['id']}/zip"], stdout=stream)
                if metadata.get("digest"):
                    require(metadata["digest"] == f"sha256:{sha256(archive)}", "Downloaded artifact archive digest mismatch")
                verify_archive(archive, artifact["files"], output)
                sources.append(f"Run {build['run_id']} ({build['head_sha']}), artifact {artifact['name']}: " + ", ".join(item["name"] for item in artifact["files"]))

        (output / "SHA256SUMS.txt").write_text("".join(f"{expected[name]['sha256']}  {name}\n" for name in sorted(expected)), encoding="utf-8")
        (output / "BUILD-NOTES.txt").write_text(
            f"OhMyPassword {data['tag']}\nRelease target: {target}\nRepository: {repository}\n\n"
            "Android APK: optimized development/debug build, signed with an Android Debug key; not a store release.\n"
            "iOS ZIP: ARM64 Simulator app only, not installable on a physical iPhone. Device distribution requires Apple signing and provisioning.\n"
            "macOS DMG: ARM64, ad-hoc signed, not Apple-notarized.\n"
            "Windows needs WebView2; Linux needs compatible GTK/WebKitGTK system libraries.\n"
            "Native mobile compilation does not verify real-device discovery, synchronization or background behavior.\n\n"
            "Pinned CI sources (each package verified against the release manifest and its artifact checksum file):\n"
            + "\n".join(sources) + "\n", encoding="utf-8",
        )
        packages = sorted(output.iterdir())
        details = {path.name: (path.stat().st_size, sha256(path)) for path in packages}
        command(["gh", "release", "create", data["tag"], "--repo", repository, "--draft", "--target", target, "--title", data["title"], "--notes-file", str(notes)], stdout=subprocess.PIPE)
        command(["gh", "release", "upload", data["tag"], "--repo", repository, *map(str, packages)], stdout=subprocess.PIPE)
        # The tag endpoint only finds published releases; locate our draft by ID.
        matches = [item for item in pages(f"{prefix}/releases") if item["tag_name"] == data["tag"]]
        require(len(matches) == 1, "Cannot uniquely locate the created release draft")
        release = api(f"{prefix}/releases/{matches[0]['id']}")
        require(release["draft"] is True and release["target_commitish"] == target and release["tag_name"] == data["tag"], "Release draft metadata mismatch")
        require(release["body"].rstrip("\r\n") == notes.read_text(encoding="utf-8").rstrip("\r\n"), "Release notes were changed")
        assets = list(pages(f"{prefix}/releases/{release['id']}/assets"))
        require(len(assets) == len(details) and {asset["name"] for asset in assets} == set(details), "Uploaded release asset list mismatch")
        for asset in assets:
            size, digest = details[asset["name"]]
            require(asset["state"] == "uploaded" and asset["size"] == size, f"Uploaded asset size/state mismatch: {asset['name']}")
            if asset.get("digest"):
                require(asset["digest"] == f"sha256:{digest}", f"Uploaded asset digest mismatch: {asset['name']}")
        print(release["html_url"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--repo", required=True)
    arguments = parser.parse_args()
    try:
        prepare(arguments.manifest, arguments.target, arguments.repo)
    except (ValueError, KeyError, OSError, subprocess.TimeoutExpired, zipfile.BadZipFile) as error:
        sys.exit(f"Release draft preparation failed: {error}")
