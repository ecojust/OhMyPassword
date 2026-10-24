# Native discovery adapter

Android uses `NsdManager`; iOS uses `NetServiceBrowser`/Bonjour for `_ohmypassword._tcp.`. TXT records contain only `protocol=2` and a stable device ID. No device name, password or key is advertised. Discovered endpoints are candidates; discovering a device never reads or merges its password book.

There are no JavaScript commands. The Rust shell starts native publication while unlocked, and the service requests a 20-second browse window every 300 seconds or after a manual detection request. Publication remains active between browse windows so devices can find one another. Resolved endpoints carry their actual `last_seen` timestamp; polling cached peers does not renew discovery freshness. Cache entries expire after 660 seconds.

Locking or backgrounding stops both publication and browsing, cancels queued resolutions, and clears the native cache. Android also applies `FLAG_SECURE`; iOS covers the WebView in the app switcher. No persistent background mode or raw multicast entitlement is requested.
