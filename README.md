# TinyBrother

> *"TinyBrother is watching you ... because Big is outdated."*

**TinyBrother** is a lightweight tool used to monitor kernel events and log them into files for SIEM/EDR systems.

---

## Supported Monitoring Events

* File opening (via eBPF tracepoints)

---

⚠️ **Warning — Alpha Version**

This is a **proof of concept**. It may be **unstable**, and the code is **not yet production-ready**.

---

## Usage

```bash
Usage: ./tinybrother [--file-open-logs <path>] [--file-open-cnf <path>]
```

### Requirements

* The eBPF program (BNF module) `file_event` must be **attached to the kernel**.
* This program **must be run as root** (e.g., using `sudo`).

### Options

| Option                    | Description                                                                                                                                                                                                                                                                |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--file-open-logs <path>` | Path to the log file where file access events will be recorded. <br>**Default**: `./file_event.log`                                                                                                                                                                        |
| `--file-open-cnf <path>`  | Path to the configuration file listing the files to monitor. <br>This file must contain **one absolute path per line**. <br>**Maximum**: 100 files, each path up to 256 characters. <br>**Example**:<br>`/etc/passwd`<br>`/etc/shadow` <br>**Default**: `./file_event.cnf` |
| `--help`                  | Display this help message.                                                                                                                                                                                                                                                 |

---

## Build

### Requirements

* `libbpf-dev`
* `bpftool`

### Build Steps

```bash
bash ./scripts/vmlinux.sh
mkdir build && cd build
cmake ../CMakeLists.txt
make
```

### Install eBPF Programs Locally

```bash
sudo make install_bpf
```

---

### Output

* The compiled binary is located at: `./build/build/tinybrother`
* BPF programs are located inside: `./buildbpf/*.bpf.o`
