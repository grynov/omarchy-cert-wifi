#!/usr/bin/env python3
# Safe descriptor-based file operations helper for Omarchy Certificate Wi-Fi backend engine.
# Opens files once with O_NOFOLLOW | O_NONBLOCK, validates owner/type/size with fstat,
# reads cap-plus-one bytes from the descriptor, and rejects oversized input.

import sys
import os
import stat
import json

def open_and_validate(path, max_bytes):
    """
    Opens path with O_NOFOLLOW | O_NONBLOCK | O_RDONLY and validates:
      - Owner matches EUID (or EUID == 0)
      - Regular file (S_ISREG)
      - fstat size <= max_bytes
    Returns (fd, st). Raises ValueError / OSError on failure.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Not a regular file: {path}")
        euid = os.geteuid()
        if euid != 0 and st.st_uid != euid:
            raise ValueError(f"Owner mismatch (expected UID {euid}, got {st.st_uid}): {path}")
        if st.st_size > max_bytes:
            raise ValueError(f"File size ({st.st_size} bytes) exceeds limit ({max_bytes} bytes): {path}")
        return fd, st
    except Exception:
        os.close(fd)
        raise

def read_fd_bounded(fd, max_bytes):
    """
    Reads from fd up to max_bytes + 1 bytes.
    If total bytes read > max_bytes, raises ValueError (rejects oversized input).
    """
    chunks = []
    total = 0
    while total <= max_bytes:
        to_read = min(65536, max_bytes + 1 - total)
        chunk = os.read(fd, to_read)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)

    if total > max_bytes:
        raise ValueError(f"Data exceeds maximum allowed size ({max_bytes} bytes)")
    return b"".join(chunks)

def cmd_read(path, max_bytes):
    fd, _ = open_and_validate(path, max_bytes)
    try:
        data = read_fd_bounded(fd, max_bytes)
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    finally:
        os.close(fd)

def cmd_stage(src_path, dst_path, max_bytes):
    fd, _ = open_and_validate(src_path, max_bytes)
    try:
        data = read_fd_bounded(fd, max_bytes)
        dst_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        dst_fd = os.open(dst_path, dst_flags, 0o600)
        try:
            os.write(dst_fd, data)
        finally:
            os.close(dst_fd)
    finally:
        os.close(fd)

def cmd_stat(path, max_bytes):
    fd, st = open_and_validate(path, max_bytes)
    try:
        _ = read_fd_bounded(fd, max_bytes)
        result = {
            "size": st.st_size,
            "mtime": int(st.st_mtime)
        }
        sys.stdout.write(json.dumps(result))
        sys.stdout.flush()
    finally:
        os.close(fd)

def cmd_discover(max_bytes, max_count):
    raw_input = sys.stdin.read()
    if not raw_input.strip():
        sys.stdout.write("[]")
        return
    try:
        paths = json.loads(raw_input)
    except Exception:
        paths = [p for p in raw_input.splitlines() if p.strip()]

    valid_files = []
    for p in paths:
        if len(valid_files) >= max_count:
            break
        try:
            fd, st = open_and_validate(p, max_bytes)
            try:
                _ = read_fd_bounded(fd, max_bytes)
                fname = os.path.basename(p)
                valid_files.append({
                    "path": p,
                    "name": fname,
                    "size": st.st_size,
                    "mtime": int(st.st_mtime)
                })
            finally:
                os.close(fd)
        except Exception:
            continue

    sys.stdout.write(json.dumps(valid_files))
    sys.stdout.flush()

def main():
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: fd-helper.py {read|stage|stat|discover} [args...]\n")
        sys.exit(1)

    subcmd = sys.argv[1]
    try:
        if subcmd == "read":
            if len(sys.argv) != 4:
                sys.stderr.write("Usage: fd-helper.py read <file> <max_bytes>\n")
                sys.exit(1)
            cmd_read(sys.argv[2], int(sys.argv[3]))
        elif subcmd == "stage":
            if len(sys.argv) != 5:
                sys.stderr.write("Usage: fd-helper.py stage <src_file> <dst_file> <max_bytes>\n")
                sys.exit(1)
            cmd_stage(sys.argv[2], sys.argv[3], int(sys.argv[4]))
        elif subcmd == "stat":
            if len(sys.argv) != 4:
                sys.stderr.write("Usage: fd-helper.py stat <file> <max_bytes>\n")
                sys.exit(1)
            cmd_stat(sys.argv[2], int(sys.argv[3]))
        elif subcmd == "discover":
            if len(sys.argv) != 4:
                sys.stderr.write("Usage: fd-helper.py discover <max_bytes> <max_count>\n")
                sys.exit(1)
            cmd_discover(int(sys.argv[2]), int(sys.argv[3]))
        else:
            sys.stderr.write(f"Unknown subcommand: {subcmd}\n")
            sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
