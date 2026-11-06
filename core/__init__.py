"""Hub core: plain stdlib HTTP server, SQLite state, loopback upstream proxy.

Nothing in this package imports Hermes. It can be lifted out into a standalone
service in minutes: give it a data directory, an upstream base URL and a key.
"""
