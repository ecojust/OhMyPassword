# iOS adapter

Swift Package Manager library loaded by Tauri's mobile plugin bridge. It uses system Bonjour with the declarations in `mobile/Info.plist`; it does not request raw multicast or background execution entitlements. The generated Xcode project references this package automatically. Build it through the mobile Tauri app on macOS/Xcode.
