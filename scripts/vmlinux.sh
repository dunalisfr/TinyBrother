#!/bin/bash

set -e

OUT_DIR="./src/bpf"
OUT_FILE="${OUT_DIR}/vmlinux.h"

if ! command -v bpftool &> /dev/null; then
    echo "Error: bpftool is not installed or not in PATH." >&2
    exit 1
fi

if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "Error: /sys/kernel/btf/vmlinux not found." >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

echo "Generating ${OUT_FILE} from /sys/kernel/btf/vmlinux..."
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$OUT_FILE"
echo "File generated: $OUT_FILE"
