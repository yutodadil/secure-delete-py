import os
import argparse
import secrets
import time
import stat
import sys
from contextlib import contextmanager, nullcontext
import ctypes
from datetime import datetime

CHUNK_SIZE = 64 * 1024


def clear_memory_random_ctypes(data):
    """Overwrite the original writable, contiguous buffer (best effort)."""
    if not isinstance(data, (bytearray, memoryview)):
        raise TypeError("Data must be a writable bytearray or memoryview.")
    view = memoryview(data)
    try:
        if view.readonly or not view.c_contiguous:
            raise TypeError("Data must be writable and contiguous.")
        byte_view = view.cast("B")
        try:
            if not byte_view.nbytes:
                return
            ptr = (ctypes.c_char * byte_view.nbytes).from_buffer(byte_view)
            try:
                for _ in range(5):
                    for offset in range(0, byte_view.nbytes, CHUNK_SIZE):
                        size = min(CHUNK_SIZE, byte_view.nbytes - offset)
                        ctypes.memmove(ctypes.addressof(ptr) + offset,
                                       secrets.token_bytes(size), size)
            finally:
                # Always zero the original allocation, even if randomness fails.
                ctypes.memset(ptr, 0, byte_view.nbytes)
                del ptr
        finally:
            byte_view.release()
    finally:
        view.release()


def _sync(fp):
    fp.flush()
    os.fsync(fp.fileno())


def _require_safe_platform():
    required = (os.open, os.stat, os.unlink, os.rmdir)
    if (not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY")
            or not all(fn in os.supports_dir_fd for fn in required)
            or os.listdir not in os.supports_fd):
        raise OSError("Safe deletion requires POSIX directory-FD support.")


def _same_file(a, b):
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


def _check_regular(info):
    if not stat.S_ISREG(info.st_mode):
        raise OSError("Refusing a non-regular file.")
    if info.st_nlink != 1:
        raise OSError("Refusing a file with multiple hard links.")


@contextmanager
def _target_parent(path):
    _require_safe_platform()
    raw = os.fsdecode(os.fspath(path)).rstrip(os.sep)
    if not raw or raw.split(os.sep)[-1] in (".", ".."):
        raise OSError("Refusing root, . or .. as a deletion target.")
    if ".." in raw.split(os.sep):
        raise OSError("Parent traversal is unsupported.")
    # abspath does not resolve symbolic links; open each ancestor separately.
    parts = os.path.abspath(raw).split(os.sep)[1:]
    fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            new_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=fd)
            os.close(fd)
            fd = new_fd
        yield fd, parts[-1]
    finally:
        os.close(fd)


def _open_at(parent_fd, name):
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    _check_regular(before)
    fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                 dir_fd=parent_fd)
    try:
        info = os.fstat(fd)
        _check_regular(info)
        if not _same_file(before, info):
            raise OSError("Target changed while opening it.")
        return os.fdopen(fd, "wb", buffering=0)
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def _open_write_only(filename):
    with _target_parent(filename) as (parent, name):
        with _open_at(parent, name) as fp:
            yield fp


def _output(filename):
    return nullcontext(filename) if hasattr(filename, "write") else _open_write_only(filename)


def corrupt_step(filename, filesize, pattern):
    if not pattern:
        return
    # Keep complete pattern cycles across chunk boundaries.
    repeats = max(1, CHUNK_SIZE // len(pattern))
    block = pattern * repeats
    with _output(filename) as fp:
        remaining = filesize
        while remaining:
            part = memoryview(block)[:min(remaining, len(block))]
            count = fp.write(part)
            if count != len(part):
                raise OSError("Short write during pattern overwrite.")
            remaining -= count
        _sync(fp)


def secure_erase(filename, filesize, no_debug):
    with _output(filename) as fp:
        for pass_number in range(3):
            if not no_debug:
                print(f"Rewriting random/random/zero {filename}... ({pass_number + 1}/3)")
            fp.seek(0)
            remaining = filesize
            while remaining:
                size = min(CHUNK_SIZE, remaining)
                block = secrets.token_bytes(size) if pass_number < 2 else bytes(size)
                if fp.write(block) != size:
                    raise OSError("Short write during random overwrite.")
                remaining -= size
            _sync(fp)

def _assert_target(parent, name, info):
    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if not _same_file(current, info) or current.st_mode != info.st_mode:
        raise OSError("Target changed during deletion.")


def _delete_at(parent, name, no_debug):
    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if stat.S_ISDIR(info.st_mode):
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                     dir_fd=parent)
        try:
            if not _same_file(info, os.fstat(fd)):
                raise OSError("Directory changed while opening it.")
            for child in os.listdir(fd):
                _assert_target(parent, name, info)
                _delete_at(fd, child, no_debug)
            _assert_target(parent, name, info)
            os.rmdir(name, dir_fd=parent)
        finally:
            os.close(fd)
    else:
        _check_regular(info)
        with _open_at(parent, name) as fp:
            opened = os.fstat(fp.fileno())
            filesize = opened.st_size
            steps = [b"\x00", b"\x00", b"\x00", b"\x00", b"\x55", b"\xAA",
                 b"\x92\x49\x24", b"\x49\x24\x92",
                 b"\x24\x92\x49", b"\x00", b"\x11",
                 b"\x22", b"\x33", b"\x44", b"\x55",
                 b"\x66", b"\x77", b"\x88", b"\x99",
                 b"\xAA", b"\xBB", b"\xCC", b"\xDD",
                 b"\xEE", b"\xFF", b"\x92\x49\x24",
                 b"\x49\x24\x92", b"\x24\x92\x49",
                 b"\x6D\xB6\xDB", b"\xB6\xDB\x6D",
                 b"\xDB\x6D\xB6", b"\x00", b"\x00", b"\x00", b"\x00"]
            for i, step in enumerate(steps):
                _assert_target(parent, name, opened)
                _check_regular(os.fstat(fp.fileno()))
                fp.seek(0)
                corrupt_step(fp, filesize, step)
                if not no_debug:
                    print(f"Pattern overwrite {name} ({i + 1}/{len(steps)})")
            secure_erase(fp, filesize, no_debug)
            _assert_target(parent, name, opened)
            _check_regular(os.fstat(fp.fileno()))
            if os.fstat(fp.fileno()).st_size != filesize:
                raise OSError("File size changed during deletion.")
            os.unlink(name, dir_fd=parent)
    if not no_debug:
        print(f"{name} is deleted!")


def corrupt_file(filename, no_debug):
    with _target_parent(filename) as (parent, name):
        _check_regular(os.stat(name, dir_fd=parent, follow_symlinks=False))
        _delete_at(parent, name, no_debug)


def corrupt_directory(directory, no_debug):
    with _target_parent(directory) as (parent, name):
        if not stat.S_ISDIR(os.stat(name, dir_fd=parent, follow_symlinks=False).st_mode):
            raise OSError("Refusing a non-directory target.")
        _delete_at(parent, name, no_debug)


def corrupt_file_or_directory(path, no_debug):
    with _target_parent(path) as (parent, name):
        _delete_at(parent, name, no_debug)


def main():
    current_date = datetime.now()

    if current_date.month == 9 and current_date.day == 2:
        print("Happy Anniversary!!")
    elif current_date.month == 12 and current_date.day in [24, 25]:
        print("Happy Xmas!!")

    parser = argparse.ArgumentParser(description=(
        "Overwrites files and directories without reading their contents, using "
        "35 pattern passes, random/random/zero passes, and validated target removal.\n"
        "OS caches are outside this tool\'s control. Physical erasure on SSDs, snapshots and "
        "backups is not guaranteed. Use only on files you intend to delete.\n"
        "Requires POSIX directory-FD support; links and special files are refused.\n"
        "Created by milkey_saurus\n"
        "Version: 1.0.2"
    ), formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("path", nargs="+", help="Files or directories to shred")
    parser.add_argument("-nd", "--NoDebug", action="store_true", help="Suppress debug output")
    parser.add_argument("-bm", "--benchmark", action="store_true", help="Measure and display the time taken for processing")
    args = parser.parse_args()

    # ベンチマークモードの場合、開始時間を記録
    if args.benchmark:
        start_time = time.monotonic()

    failed = False
    for path in args.path:
        try:
            corrupt_file_or_directory(path, args.NoDebug)
        except Exception as error:
            failed = True
            print(f"corrupt: {path!r}: deletion incomplete: {error}", file=sys.stderr)

    # ベンチマークモードの場合、終了時間を記録し、経過時間を計算・表示
    if args.benchmark:
        end_time = time.monotonic()
        elapsed_time = end_time - start_time
        
        # 経過時間をHour:min:second.millisecondsで表示
        hours, remainder = divmod(elapsed_time, 3600)
        minutes, seconds = divmod(remainder, 60)
        milliseconds = (seconds % 1) * 1000
        print("Time: {:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), int(seconds)+(milliseconds / 1000)))

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

