import os
import argparse
import secrets
import time
import string
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


def _open_write_only(filename):
    """Open an existing file without read access or truncation."""
    flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(filename, flags)
    try:
        return os.fdopen(fd, "wb", buffering=0)
    except BaseException:
        os.close(fd)
        raise


def corrupt_step(filename, filesize, pattern):
    if not pattern:
        return
    # Keep complete pattern cycles across chunk boundaries.
    repeats = max(1, CHUNK_SIZE // len(pattern))
    block = pattern * repeats
    with _open_write_only(filename) as fp:
        remaining = filesize
        while remaining:
            part = memoryview(block)[:min(remaining, len(block))]
            count = fp.write(part)
            if count != len(part):
                raise OSError("Short write during pattern overwrite.")
            remaining -= count
        _sync(fp)


def secure_erase(filename, filesize, no_debug):
    with _open_write_only(filename) as fp:
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

def random_string(length):
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))

def corrupt_directory(directory, no_debug):
    # ディレクトリ内のファイルを再帰的に削除
    for root, dirs, files in os.walk(directory, topdown=False):
        for file in files:
            file_path = os.path.join(root, file)
            corrupt_file(file_path, no_debug)  # ファイルをグートマン方式で削除
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            corrupt_directory(dir_path, no_debug)  # ディレクトリを再帰的に削除

    # ディレクトリ名をランダムな文字列で書き換え（35回）
    for i in range(35):
        new_dir_name = random_string(10)
        if not no_debug:
            print(f"Randomly renaming {directory} to {new_dir_name}... ({i+1}/35)")
        os.rename(directory, os.path.join(os.path.dirname(directory), new_dir_name))
        directory = os.path.join(os.path.dirname(directory), new_dir_name)

    # ディレクトリを削除
    try:
        os.rmdir(directory)
        if not no_debug:
            print(f"{directory} is deleted!")

    except FileNotFoundError:
        if not no_debug:
            print(f"corrupt: '{directory}' not found")
    except Exception as e:
        if not no_debug:
            print(f"corrupt: error occurred while shredding '{directory}': {e}")

def corrupt_file(filename, no_debug):
    try:
        filesize = os.path.getsize(filename)
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
            corrupt_step(filename, filesize, step)
            if not no_debug:
                print(f"Rewriting with Gutmann method {filename}... ({i+1}/{len(steps)})")

        secure_erase(filename, filesize, no_debug)

        # ファイル名をランダムな文字列で書き換え（35回）
        for i in range(35):
            new_file_name = random_string(10)
            if not no_debug:
                print(f"Randomly renaming {filename} to {new_file_name}... ({i+1}/35)")
            os.rename(filename, os.path.join(os.path.dirname(filename), new_file_name))
            filename = os.path.join(os.path.dirname(filename), new_file_name)

        # ファイルを削除
        os.remove(filename)
        if not no_debug:
            print(f"{filename} is deleted!")

    except FileNotFoundError:
        if not no_debug:
            print(f"corrupt: '{filename}' not found")
    except Exception as e:
        if not no_debug:
            print(f"corrupt: error occurred while shredding '{filename}': {e}")

def corrupt_file_or_directory(path, no_debug):
    if os.path.isfile(path):
        # ファイルが存在する場合、ファイルをグートマン方式で削除
        corrupt_file(path, no_debug)

    elif os.path.isdir(path):
        # ディレクトリが存在する場合、ディレクトリ内のファイルを削除してからディレクトリを削除
        corrupt_directory(path, no_debug)

def main():
    current_date = datetime.now()

    if current_date.month == 9 and current_date.day == 2:
        print("Happy Anniversary!!")
    elif current_date.month == 12 and current_date.day in [24, 25]:
        print("Happy Xmas!!")

    parser = argparse.ArgumentParser(description=(
        "Overwrites files and directories without reading their contents, using "
        "35 pattern passes, random/random/zero passes, and random renaming.\n"
        "OS caches are outside this tool\'s control. Physical erasure on SSDs, snapshots and "
        "backups is not guaranteed. Use only on files you intend to delete.\n"
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

    for path in args.path:
        corrupt_file_or_directory(path, args.NoDebug)

    # ベンチマークモードの場合、終了時間を記録し、経過時間を計算・表示
    if args.benchmark:
        end_time = time.monotonic()
        elapsed_time = end_time - start_time
        
        # 経過時間をHour:min:second.millisecondsで表示
        hours, remainder = divmod(elapsed_time, 3600)
        minutes, seconds = divmod(remainder, 60)
        milliseconds = (seconds % 1) * 1000
        print("Time: {:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), int(seconds)+(milliseconds / 1000)))

if __name__ == "__main__":
    main()

