# Build verification

The workflow builds the three applications in `extension`, `desktop`, and
`mobile`. These scripts are build helpers, not another application. They use
Python 3.11 or newer and run from any working directory.

- `verify-versions.py` checks the shared version and both Tauri frontend paths.
- `prepare-mobile.py android` applies SDK 36 / minimum API 24 settings to the
  generated Android project, disables Android backup and WebView cleartext
  traffic, and checks the discovery plugin SDK. Run it after Android init.
- `prepare-mobile.py ios` checks the generated Xcode project and the declared
  Bonjour service / local-network purpose. Run it after iOS init.
- Both mobile preparation commands copy the shared launcher artwork from
  `desktop/src-tauri/icons` into the generated native projects. Android adaptive
  icon references and every iOS `Contents.json` entry / PNG dimension are checked.
- `verify-macos-bundle.py --target aarch64-apple-darwin` verifies the DMG,
  minimum macOS version, complete application signature and installed startup.
- `collect-artifacts.py PLATFORM [--target RUST_TARGET]` checks real outputs,
  copies them into `ci-artifacts`, and writes SHA256 checksums and build notes.

The host-side checks are:

```sh
npm ci
python .github/scripts/verify-versions.py
npm run build
npm run test:extension
npx playwright install --with-deps chromium
npm run test:login-pages --workspace @ohmypassword/extension
npm run test:browser --workspace @ohmypassword/extension
npm run test:ui --workspace @ohmypassword/desktop
cargo test --locked --manifest-path desktop/core/Cargo.toml
cargo test --locked --manifest-path desktop/service/Cargo.toml
```

The real extension test must load the extension in an environment where that
is permitted. Browser policy blocking extensions is not a passing result.
CI installs system dependencies and downloads Chromium in separate steps, with
15-minute and five-minute timeouts respectively. The dependency budget accounts
for the observed slow hosted-runner APT mirror. It downloads the full Chromium browser only and sets
`CHROMIUM_PATH` for both tests, so a second headless-shell download is unnecessary.
Tests and native builds run in parallel; a successful platform artifact does not
mean the complete workflow passed.
Pushes and pull requests run every job. Manual runs default to `target=all`;
`target=android` builds and verifies only the Android APK for focused build
configuration checks, and does not replace the complete validation run.

The mobile jobs generate their native projects before building:

```sh
npm run tauri --workspace @ohmypassword/mobile -- android init --ci --skip-targets-install
python .github/scripts/prepare-mobile.py android
CARGO_PROFILE_DEV_OPT_LEVEL=s CARGO_PROFILE_DEV_DEBUG=0 \
  CARGO_PROFILE_DEV_STRIP=symbols CARGO_PROFILE_DEV_CODEGEN_UNITS=1 \
  npm run tauri --workspace @ohmypassword/mobile -- android build --ci --debug --target aarch64 --apk -- --locked

# Run the following on an Apple Silicon macOS host with Xcode and XcodeGen.
npm run tauri --workspace @ohmypassword/mobile -- ios init --ci --skip-targets-install
python .github/scripts/prepare-mobile.py ios
npm run tauri --workspace @ohmypassword/mobile -- ios build --ci --debug --target aarch64-sim --no-sign -- --locked
```

The Android job installs JDK 17, SDK platform 36, build tools 36.0.0 and NDK
27.2.12479018, using the Ubuntu runner's preinstalled `sdkmanager` after checking
its path and accepting SDK licenses. The corresponding Rust targets are `aarch64-linux-android`
and `aarch64-apple-ios-sim`. All Rust builds use committed lockfiles.
The Android job sets the Cargo development profile to optimize for size, remove
debug information and strip symbols, with one code-generation unit. These
job-level environment variables apply to Tauri and its Gradle/Rust child
processes. The APK retains its debug variant and development signing key; this
size optimization does not create a production-signed release. Compare actual
collected APK bytes rather than the outer Actions artifact ZIP size.

The build workflow uploads artifacts without publishing a Release. The APK uses a development
signing key that is not persisted between CI builds; APKs signed by different keys cannot update one another. Preserve existing vault data before replacing a development installation. The iOS archive contains a Simulator `.app`, not an iPhone install
package; physical-device distribution needs Apple signing and provisioning.
macOS bundles have ad-hoc signatures and are not Apple-notarized. Desktop
startup and mobile compilation do not demonstrate real-device LAN discovery,
pairing or background operation.

## Preparing a GitHub Release

`release.yml` is a separate manual workflow. Its versioned manifest in
`.github/releases/` identifies the successful build runs, exact artifacts,
package sizes and SHA256 values. `prepare-release.py` downloads those artifacts
on the GitHub runner, verifies the package files and their bundled checksums,
then uploads the seven packages, combined `SHA256SUMS.txt` and `BUILD-NOTES.txt`
to a draft Release. It also checks the uploaded asset inventory and any SHA256
digests returned by GitHub. Existing releases with the same tag are left intact.

```sh
gh workflow run release.yml --ref master -f tag=v0.2.4
# After verifying the prepared draft and its assets:
gh release edit v0.2.4 --repo ecojust/OhMyPassword --draft=false --latest
```

This workflow packages existing verified binaries; it does not rebuild the
applications or publish the draft automatically.
