import base64
import csv
import hashlib
import io
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

from tools.verify_dist import (
    INFO,
    PROJECT,
    WHEEL_FILES,
    _entry_points,
    _metadata,
    check_member,
    members,
    verify_record,
)


class ReleasePolicyTests(unittest.TestCase):
    def test_rejects_unlisted_material_in_wheel_and_sdist(self):
        for name, wheel in (
            ("sovereign_chain/ca.pem", True),
            ("sovereign_chain-2.1.0.dev1/client_key.pem", False),
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                check_member(name, b"", wheel)

    def test_rejects_private_material_even_in_an_allowed_file(self):
        marker = b"-----BEGIN " + b"ENCRYPTED PRIVATE KEY-----"
        with self.assertRaises(ValueError):
            check_member("sovereign_chain/client.py", marker, True)

    def test_record_hash_size_self_entry_and_completeness(self):
        name, record = "sovereign_chain/client.py", INFO + "RECORD"
        file = b"# verified\n"
        digest = "sha256=" + base64.urlsafe_b64encode(
            hashlib.sha256(file).digest()
        ).decode().rstrip("=")
        base = [(name, digest, str(len(file))), (record, "", "")]

        def files(rows):
            out = io.StringIO()
            csv.writer(out).writerows(rows)
            return {name: file, record: out.getvalue().encode()}

        verify_record(files(base))
        for invalid in (
            base[:1],
            base[1:],
            base + [base[0]],
            [(name, digest, "1"), base[1]],
            [(name, "sha256=wrong", str(len(file))), base[1]],
            [base[0], (record, digest, "0")],
        ):
            with self.subTest(rows=invalid), self.assertRaises(ValueError):
                verify_record(files(invalid))

    def test_missing_and_duplicate_wheel_members_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "test.whl"
            member = next(iter(WHEEL_FILES))
            for repeats in (1, 2):
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    with zipfile.ZipFile(path, "w") as wheel:
                        for _ in range(repeats):
                            wheel.writestr(member, b"data")
                with self.assertRaisesRegex(ValueError, "missing|duplicate"):
                    members(path, True)

    def test_version_and_entry_point_must_match_pyproject(self):
        _entry_points(
            b"[console_scripts]\nsovereign-chain = sovereign_chain.__main__:main\n"
        )
        with self.assertRaises(ValueError):
            _entry_points(b"[console_scripts]\nsovereign-chain = different:main\n")
        with self.assertRaises(ValueError):
            _metadata(f"Name: {PROJECT['name']}\nVersion: 0\n".encode())
