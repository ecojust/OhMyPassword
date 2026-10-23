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
npm run test:browser --workspace @ohmypassword/extension
npm run test:ui --workspace @ohmypassword/desktop
cargo test --locked --manifest-path desktop/core/Cargo.toml
cargo test --locked --manifest-path desktop/service/Cargo.toml
```

The real extension test must load the extension in an environment where that
is permitted. Browser policy blocking extensions is not a passing result.

The mobile jobs generate their native projects before building:

```sh
npm run tauri --workspace @ohmypassword/mobile -- android init --ci --skip-targets-install
python .github/scripts/prepare-mobile.py android
npm run tauri --workspace @ohmypassword/mobile -- android build --ci --debug --target aarch64 --apk -- --locked

# Run the following on an Apple Silicon macOS host with Xcode and XcodeGen.
npm run tauri --workspace @ohmypassword/mobile -- ios init --ci --skip-targets-install
python .github/scripts/prepare-mobile.py ios
npm run tauri --workspace @ohmypassword/mobile -- ios build --ci --debug --target aarch64-sim --no-sign -- --locked
```

The Android job installs JDK 17, SDK platform 36, build tools 36.0.0 and NDK
27.2.12479018. The corresponding Rust targets are `aarch64-linux-android`
and `aarch64-apple-ios-sim`. All Rust builds use committed lockfiles.

CI uploads artifacts without publishing a Release. The APK uses a development
signing key. The iOS archive contains a Simulator `.app`, not an iPhone install
package; physical-device distribution needs Apple signing and provisioning.
macOS bundles have ad-hoc signatures and are not Apple-notarized. Desktop
startup and mobile compilation do not demonstrate real-device LAN discovery,
pairing or background operation.
