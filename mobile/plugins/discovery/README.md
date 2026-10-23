# Native discovery adapter

Android uses `NsdManager`; iOS uses `NetServiceBrowser`/Bonjour to advertise and discover `_ohmypassword._tcp.`. TXT records contain only `protocol=1`, a stable device ID and device name. No password or pairing key is advertised. Discovery only supplies candidate IPv4 endpoints to the Rust service; the service verifies pairing and encrypted authentication before accepting data.

There are no JavaScript commands. The shared native shell starts discovery only while unlocked, polls resolved endpoints, and stops discovery on lock/background. Android also applies `FLAG_SECURE`; iOS covers the WebView in the app switcher. Neither implementation requests a persistent background mode or raw multicast entitlement.
