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
            self.assertEqual(flags & os.O_ACCMODE, os.O_WRONLY)
            self.assertFalse(flags & os.O_TRUNC)
            calls.append(flags)
            return real_open(path, flags, *args, **kwargs)

        with patch.object(sd.os, "open", side_effect=check_open):
            sd.corrupt_file(str(self.path), True)
        self.assertEqual(len(calls), 36)
        self.assertEqual(list(Path(self.temp.name).iterdir()), [])

    def test_memory_does_not_scale_with_file_size(self):
        import tracemalloc
        peaks = []
        for size in (128 * 1024, 2 * 1024 * 1024):
            with open(self.path, "wb") as fp:
                fp.truncate(size)
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


if __name__ == "__main__":
    unittest.main()
