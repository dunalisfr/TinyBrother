# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## \[0.1.0-alpha] - 2025-05-14

### Added

* Initial alpha release.
* File opening monitoring via eBPF tracepoints.
* JSON logging of events with fields: PID, user, command, access type, filename, etc.
* Configuration file (`--file-open-cnf`) support with up to 100 absolute paths (max 256 chars each).
* Command-line arguments: `--file-open-logs`, `--file-open-cnf`, `--help`.
* Basic usage documentation and build instructions in README.

### Notes

* This is a proof-of-concept and not production-ready.
* Requires root privileges and a loaded BPF program (`file_event`).
