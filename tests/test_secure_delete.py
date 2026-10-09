import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "secure_delete", Path(__file__).resolve().parents[1] / "secure-delete.py")
sd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sd)


class MemoryTests(unittest.TestCase):
    def test_original_buffer_and_typed_view_are_zeroed(self):
        import array
        data = bytearray(b"secret data")
        sd.clear_memory_random_ctypes(memoryview(data)[2:8])
        self.assertEqual(data, b"se" + bytes(6) + b"ata")
        typed = array.array("I", [0xffffffff, 0x12345678])
        sd.clear_memory_random_ctypes(memoryview(typed))
        self.assertEqual(typed.tolist(), [0, 0])
        sd.clear_memory_random_ctypes(bytearray())

    def test_invalid_buffers_rejected(self):
        for data in (b"secret", memoryview(b"secret"),
                     memoryview(bytearray(b"secret"))[::2]):
            with self.assertRaises(TypeError):
                sd.clear_memory_random_ctypes(data)

    def test_random_failure_still_zeroes_original(self):
        data = bytearray(b"secret")
        with patch.object(sd.secrets, "token_bytes", side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):
                sd.clear_memory_random_ctypes(data)
        self.assertEqual(data, bytes(6))
        data.extend(b"x")  # No surviving ctypes export prevents resizing.


class FileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "sample"

    def test_file_descriptors_are_write_only(self):
        import os
        self.path.write_bytes(b"secret plaintext")
        real_open = sd.os.open
        calls = []

        def check_open(path, flags, *args, **kwargs):
            if not flags & os.O_DIRECTORY:
                self.assertEqual(flags & os.O_ACCMODE, os.O_WRONLY)
                self.assertFalse(flags & os.O_TRUNC)
                calls.append(flags)
            return real_open(path, flags, *args, **kwargs)

        with patch.object(sd, "_require_safe_platform"), patch.object(sd.os, "open", side_effect=check_open):
            sd.corrupt_file(str(self.path), True)
        self.assertEqual(len(calls), 1)
        self.assertEqual(list(Path(self.temp.name).iterdir()), [])

    def test_memory_does_not_scale_with_file_size(self):
        import tracemalloc
        peaks = []
        for size in (128 * 1024, 2 * 1024 * 1024):
            with open(self.path, "wb") as fp:
                block = bytes(4096)
                for _ in range(size // len(block)):
                    fp.write(block)
            with patch.object(sd, "CHUNK_SIZE", 4096):
                tracemalloc.start()
                try:
                    sd.corrupt_step(self.path, size, b"abc")
                    sd.secure_erase(self.path, size, True)
                    peaks.append(tracemalloc.get_traced_memory()[1])
                finally:
                    tracemalloc.stop()
        self.assertLess(max(peaks), 128 * 1024)

    def test_passes_preserve_length_and_pattern(self):
        for size in (0, 1, 3, 31, 32, 33, 65):
            with self.subTest(size=size):
                self.path.write_bytes(b"x" * size)
                with patch.object(sd, "CHUNK_SIZE", 32):
                    sd.corrupt_step(self.path, size, b"abc")
                    self.assertEqual(self.path.read_bytes(),
                                     (b"abc" * ((size + 2) // 3))[:size])
                    calls = []

                    def random_bytes(n):
                        calls.append(n)
                        return b"r" * n

                    with patch.object(sd.secrets, "token_bytes",
                                      side_effect=random_bytes):
                        sd.secure_erase(self.path, size, True)
                    self.assertEqual(sum(calls), 2 * size)
                    self.assertTrue(all(n <= 32 for n in calls))
                    self.assertEqual(self.path.read_bytes(), bytes(size))

    def test_delete_overwrites_original_size(self):
        self.path.write_bytes(b"secret")
        lengths = []
        real_step = sd.corrupt_step

        def capture(path, size, pattern):
            lengths.append(size)
            real_step(path, size, pattern)

        with patch.object(sd, "CHUNK_SIZE", 32), patch.object(
                sd, "corrupt_step", side_effect=capture):
            sd.corrupt_file(str(self.path), True)
        self.assertEqual(lengths, [6] * 35)
        self.assertEqual(list(Path(self.temp.name).iterdir()), [])

    def test_empty_file_is_deleted(self):
        self.path.touch()
        sd.corrupt_file(self.path, True)
        self.assertFalse(self.path.exists())

    def test_helpers_reject_invalid_or_mismatched_sizes_before_write(self):
        self.path.write_bytes(b"keep")
        cases = ((-1, ValueError), (True, ValueError), (4.0, ValueError),
                 (3, OSError), (5, OSError))
        for function in (sd.corrupt_step, sd.secure_erase):
            for size, error in cases:
                with self.subTest(function=function.__name__, size=size):
                    args = ((self.path, size, b"x")
                            if function is sd.corrupt_step
                            else (self.path, size, True))
                    with patch.object(sd, "_sync") as synced:
                        with self.assertRaises(error):
                            function(*args)
                        synced.assert_not_called()
                    self.assertEqual(self.path.read_bytes(), b"keep")

    def test_corrupt_step_rewinds_open_file(self):
        self.path.write_bytes(b"keep")
        with self.path.open("r+b", buffering=0) as fp:
            fp.seek(2)
            sd.corrupt_step(fp, 4, b"x")
        self.assertEqual(self.path.read_bytes(), b"xxxx")


class SafetyTests(unittest.TestCase):
    def setUp(self):
        import os
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / "chosen"
        self.target.mkdir()
        self.outside = self.root / "outside"
        self.outside.mkdir()
        self.sentinel = self.outside / "sentinel"
        self.sentinel.write_bytes(b"keep me")

    def assert_sentinel(self):
        self.assertEqual(self.sentinel.read_bytes(), b"keep me")

    def test_directory_links_and_cycles_rejected(self):
        for destination in (self.outside, self.target):
            link = self.target / "link"
            link.symlink_to(destination, target_is_directory=True)
            with self.assertRaises(OSError):
                sd.corrupt_directory(self.target, True)
            self.assert_sentinel()
            self.assertTrue(link.is_symlink())
            link.unlink()

    def test_top_level_and_ancestor_links_rejected(self):
        link = self.root / "link"
        link.symlink_to(self.outside, target_is_directory=True)
        for path in (link, link / "sentinel"):
            with self.assertRaises(OSError):
                sd.corrupt_file_or_directory(path, True)
            self.assert_sentinel()

    def test_file_and_broken_links_rejected(self):
        for destination in (self.sentinel, self.root / "missing"):
            link = self.target / "link"
            link.symlink_to(destination)
            with self.assertRaises(OSError):
                sd.corrupt_file_or_directory(link, True)
            self.assert_sentinel()
            link.unlink()

    def test_hard_links_rejected(self):
        import os
        link = self.target / "hard"
        os.link(self.sentinel, link)
        with self.assertRaises(OSError):
            sd.corrupt_directory(self.target, True)
        self.assert_sentinel()
        self.assertEqual(link.read_bytes(), b"keep me")

    def test_sparse_file_refused_before_open_or_allocation(self):
        sparse = self.target / "sparse"
        logical_size = 16 * 1024 * 1024
        with sparse.open("wb") as fp:
            fp.truncate(logical_size)
        before = sparse.stat()
        if not hasattr(before, "st_blocks"):
            self.skipTest("st_blocks is unavailable")
        if before.st_blocks * 512 >= before.st_size:
            self.skipTest("fixture filesystem did not create a sparse file")

        with patch.object(sd, "_open_at") as opened:
            with self.assertRaisesRegex(OSError, "sparse or compressed"):
                sd.corrupt_file(sparse, True)
            opened.assert_not_called()

        after = sparse.stat()
        self.assertEqual(after.st_size, before.st_size)
        self.assertEqual(after.st_blocks, before.st_blocks)
        self.assert_sentinel()

    def test_cross_filesystem_child_refused_before_open(self):
        import os
        mounted = self.target / "mounted"
        mounted.mkdir()
        real_stat = os.stat
        real_open = os.open

        def cross_device(path, *args, **kwargs):
            info = real_stat(path, *args, **kwargs)
            if path == "mounted" and kwargs.get("dir_fd") is not None:
                fields = list(info)
                fields[2] += 1  # st_dev
                return os.stat_result(fields)
            return info

        def guarded_open(path, flags, *args, **kwargs):
            self.assertNotEqual(os.fspath(path), "mounted")
            return real_open(path, flags, *args, **kwargs)

        with patch.object(sd, "_require_safe_platform"), patch.object(
                sd.os, "stat", side_effect=cross_device), patch.object(
                sd.os, "open", side_effect=guarded_open):
            with self.assertRaisesRegex(OSError, "filesystem boundary"):
                sd.corrupt_directory(self.target, True)
        self.assertTrue(mounted.is_dir())
        self.assert_sentinel()

    def test_fifo_rejected_without_opening(self):
        import os
        fifo = self.target / "fifo"
        os.mkfifo(fifo)
        real_open = os.open
        def guarded(path, flags, *args, **kwargs):
            self.assertNotEqual(os.fspath(path), "fifo")
            return real_open(path, flags, *args, **kwargs)
        with patch.object(sd, "_require_safe_platform"), patch.object(sd.os, "open", side_effect=guarded):
            with self.assertRaises(OSError):
                sd.corrupt_directory(self.target, True)
        self.assertTrue(fifo.exists())

    def test_swap_to_symlink_before_open_is_rejected(self):
        import os
        victim = self.target / "victim"
        victim.write_bytes(b"original")
        real_open = os.open
        def swapped(path, flags, *args, **kwargs):
            if path == "victim":
                victim.unlink()
                victim.symlink_to(self.sentinel)
            return real_open(path, flags, *args, **kwargs)
        with patch.object(sd, "_require_safe_platform"), patch.object(sd.os, "open", side_effect=swapped):
            with self.assertRaises(OSError):
                sd.corrupt_file(victim, True)
        self.assert_sentinel()

    def test_swap_to_regular_file_before_open_is_rejected(self):
        import os
        victim = self.target / "victim"
        victim.write_bytes(b"original")
        replacement = self.target / "replacement"
        replacement.write_bytes(b"new data")
        real_open = os.open
        def swapped(path, flags, *args, **kwargs):
            if path == "victim":
                os.replace(replacement, victim)
            return real_open(path, flags, *args, **kwargs)
        with patch.object(sd, "_require_safe_platform"), patch.object(sd.os, "open", side_effect=swapped):
            with self.assertRaises(OSError):
                sd.corrupt_file(victim, True)
        self.assertEqual(victim.read_bytes(), b"new data")

    def test_directory_swap_before_open_is_rejected(self):
        import os
        real_open = os.open
        def swapped(path, flags, *args, **kwargs):
            if path == "chosen":
                self.target.rename(self.root / "moved")
                self.target.symlink_to(self.outside, target_is_directory=True)
            return real_open(path, flags, *args, **kwargs)
        with patch.object(sd, "_require_safe_platform"), patch.object(sd.os, "open", side_effect=swapped):
            with self.assertRaises(OSError):
                sd.corrupt_directory(self.target, True)
        self.assert_sentinel()

    def test_replacement_before_open_at_keeps_initial_identity(self):
        import os
        victim = self.target / "victim"
        victim.write_bytes(b"original")
        replacement = self.target / "replacement"
        replacement.write_bytes(b"replacement")
        saved = self.target / "saved"
        real_open_at = sd._open_at

        def swapped(parent, name, *args, **kwargs):
            if name == "victim":
                victim.rename(saved)
                os.replace(replacement, victim)
            return real_open_at(parent, name, *args, **kwargs)

        with patch.object(sd, "_open_at", side_effect=swapped), patch.object(
                sd, "corrupt_step") as step, patch.object(sd, "secure_erase") as erase:
            with self.assertRaises(OSError):
                sd.corrupt_file_or_directory(victim, True)
            step.assert_not_called()
            erase.assert_not_called()
        self.assertEqual(victim.read_bytes(), b"replacement")
        self.assertEqual(saved.read_bytes(), b"original")

    def test_recursive_replacement_before_open_at_is_rejected(self):
        import os
        victim = self.target / "victim"
        victim.write_bytes(b"original")
        replacement = self.outside / "replacement"
        replacement.write_bytes(b"replacement")
        saved = self.outside / "saved"
        real_open_at = sd._open_at

        def swapped(parent, name, *args, **kwargs):
            victim.rename(saved)
            os.replace(replacement, victim)
            return real_open_at(parent, name, *args, **kwargs)

        with patch.object(sd, "_open_at", side_effect=swapped), patch.object(
                sd, "corrupt_step") as step, patch.object(sd, "secure_erase") as erase:
            with self.assertRaises(OSError):
                sd.corrupt_directory(self.target, True)
            step.assert_not_called()
            erase.assert_not_called()
        self.assertEqual(victim.read_bytes(), b"replacement")
        self.assertEqual(saved.read_bytes(), b"original")
        self.assert_sentinel()

    def test_library_entrypoints_keep_identity_across_dispatch(self):
        import os
        cases = ((sd.corrupt_file, False, False),
                 (sd.corrupt_file, False, True),
                 (sd.corrupt_directory, True, False),
                 (sd.corrupt_directory, True, True))
        for index, (entrypoint, was_directory, is_directory) in enumerate(cases):
            with self.subTest(entrypoint=entrypoint.__name__, replacement_dir=is_directory):
                victim = self.root / f"victim-{index}"
                replacement = self.root / f"replacement-{index}"
                saved = self.root / f"saved-{index}"
                if was_directory:
                    victim.mkdir()
                    (victim / "data").write_bytes(b"original")
                else:
                    victim.write_bytes(b"original")
                if is_directory:
                    replacement.mkdir()
                    (replacement / "data").write_bytes(b"replacement")
                else:
                    replacement.write_bytes(b"replacement")
                real_delete_at = sd._delete_at

                def swapped(parent, name, *args, **kwargs):
                    if name == victim.name:
                        victim.rename(saved)
                        os.replace(replacement, victim)
                    return real_delete_at(parent, name, *args, **kwargs)

                with patch.object(sd, "_delete_at", side_effect=swapped), patch.object(
                        sd, "corrupt_step") as step, patch.object(sd, "secure_erase") as erase:
                    with self.assertRaises(OSError):
                        entrypoint(victim, True)
                    step.assert_not_called()
                    erase.assert_not_called()
                new_data = victim / "data" if is_directory else victim
                old_data = saved / "data" if was_directory else saved
                self.assertEqual(new_data.read_bytes(), b"replacement")
                self.assertEqual(old_data.read_bytes(), b"original")

    def test_trailing_separator_and_nested_tree(self):
        import os
        for relative in (False, True):
            for suffix in ("", os.sep, os.sep * 2):
                with self.subTest(relative=relative, suffix=suffix):
                    self.target.mkdir(exist_ok=True)
                    child = self.target / "child"
                    child.mkdir()
                    (child / "data").write_bytes(b"delete")
                    old_cwd = os.getcwd()
                    try:
                        if relative:
                            os.chdir(self.root)
                        path = "chosen" if relative else str(self.target)
                        sd.corrupt_directory(path + suffix, True)
                    finally:
                        os.chdir(old_cwd)
                    self.assertFalse(self.target.exists())
                    self.assert_sentinel()

    def test_file_trailing_separator_cli_refuses_before_write_open(self):
        import os
        import io
        for relative in (False, True):
            for suffix in (os.sep, os.sep * 2):
                with self.subTest(relative=relative, suffix=suffix):
                    old_cwd = os.getcwd()
                    real_open = os.open
                    calls = []
                    def guarded(path, flags, *args, **kwargs):
                        calls.append(flags)
                        self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
                        return real_open(path, flags, *args, **kwargs)
                    errors = io.StringIO()
                    try:
                        if relative:
                            os.chdir(self.root)
                        path = "outside/sentinel" if relative else str(self.sentinel)
                        with patch.object(sd, "_require_safe_platform"), patch.object(sd.os, "open", side_effect=guarded), patch.object(sd.sys, "stderr", errors), patch.object(sd.sys, "argv", ["secure-delete", "--NoDebug", path + suffix]):
                            self.assertEqual(sd.main(), 1)
                    finally:
                        os.chdir(old_cwd)
                    self.assertTrue(calls)
                    self.assertIn("Trailing separator requires a directory", errors.getvalue())
                    self.assert_sentinel()

    def test_file_trailing_separator_library_entrypoints_refuse(self):
        for suffix in ("/", "//"):
            path = str(self.sentinel) + suffix
            for function in (sd.corrupt_file, sd.corrupt_directory, sd.corrupt_file_or_directory):
                with self.assertRaises(NotADirectoryError):
                    function(path, True)
                self.assert_sentinel()
            with self.assertRaises(NotADirectoryError):
                sd.corrupt_step(path, 7, b"x")
            with self.assertRaises(NotADirectoryError):
                sd.secure_erase(path, 7, True)
            self.assert_sentinel()

    def test_trailing_separator_symlinks_refused(self):
        for destination in (self.outside, self.sentinel):
            link = self.target / "link"
            link.symlink_to(destination)
            for suffix in ("/", "//"):
                with self.assertRaises(NotADirectoryError):
                    sd.corrupt_file_or_directory(str(link) + suffix, True)
                self.assert_sentinel()
            link.unlink()

    def test_dangerous_paths_rejected(self):
        for path in ("/", ".", "..", str(self.target / ".."), str(self.target) + "/."):
            with self.assertRaises(OSError):
                sd.corrupt_file_or_directory(path, True)
        self.assertTrue(self.target.exists())

    def test_unsupported_platform_refuses_before_open(self):
        with patch.object(sd.os, "supports_dir_fd", set()), patch.object(sd.os, "open") as opened:
            with self.assertRaises(OSError):
                sd.corrupt_file(self.sentinel, True)
            opened.assert_not_called()

    def test_cli_errors_visible_and_other_arguments_continue(self):
        import io
        errors = io.StringIO()
        victim = self.target / "victim"
        victim.write_bytes(b"delete")
        with patch.object(sd.sys, "argv", ["secure-delete", "--NoDebug", str(self.root / "missing"), str(victim)]), patch.object(sd.sys, "stderr", errors):
            self.assertEqual(sd.main(), 1)
        self.assertIn("deletion incomplete", errors.getvalue())
        self.assertFalse(victim.exists())

    def test_open_sync_and_unlink_failures_propagate(self):
        victim = self.target / "victim"
        for operation in ("_open_at", "_sync"):
            victim.write_bytes(b"keep")
            with patch.object(sd, "_require_safe_platform"), patch.object(sd, operation, side_effect=OSError("injected")), patch.object(sd.os, "unlink") as unlink:
                with self.assertRaises(OSError):
                    sd.corrupt_file(victim, True)
                unlink.assert_not_called()
            self.assertTrue(victim.exists())
        with patch.object(sd, "_require_safe_platform"), patch.object(sd, "corrupt_step"), patch.object(sd, "secure_erase"), patch.object(sd.os, "unlink", side_effect=OSError("injected")):
            with self.assertRaises(OSError):
                sd.corrupt_file(victim, True)
        self.assertTrue(victim.exists())

    def test_short_write_aborts_without_unlink(self):
        victim = self.target / "victim"
        victim.write_bytes(b"keep")
        real_open_at = sd._open_at
        class ShortWriter:
            def __init__(self, fp): self.fp = fp
            def __enter__(self): return self
            def __exit__(self, *args): self.fp.close()
            def fileno(self): return self.fp.fileno()
            def seek(self, pos): return self.fp.seek(pos)
            def write(self, data): return 0
        with patch.object(sd, "_require_safe_platform"), patch.object(sd, "_open_at", side_effect=lambda *args, **kwargs: ShortWriter(real_open_at(*args, **kwargs))), patch.object(sd.os, "unlink") as unlink:
            with self.assertRaises(OSError):
                sd.corrupt_file(victim, True)
            unlink.assert_not_called()
        self.assertEqual(victim.read_bytes(), b"keep")

    def test_listdir_failure_does_not_remove_directory(self):
        with patch.object(sd.os, "supports_fd", sd.os.supports_fd | {sd.os.listdir}), patch.object(sd.os, "listdir", side_effect=OSError("injected")), patch.object(sd, "_require_safe_platform"), patch.object(sd.os, "rmdir") as remove:
            with self.assertRaises(OSError):
                sd.corrupt_directory(self.target, True)
            remove.assert_not_called()


if __name__ == "__main__":
    unittest.main()

