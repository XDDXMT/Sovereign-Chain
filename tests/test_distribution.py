import unittest

from tools.verify_dist import check_member


class ReleasePolicyTests(unittest.TestCase):
    def test_rejects_unlisted_material_in_wheel_and_sdist(self):
        for name, wheel in (
            ("sovereign_chain/ca.pem", True),
            ("sovereign_chain-2.1.0.dev0/client_key.pem", False),
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                check_member(name, b"", wheel)

    def test_rejects_private_material_even_in_an_allowed_file(self):
        marker = b"-----BEGIN " + b"ENCRYPTED PRIVATE KEY-----"
        with self.assertRaises(ValueError):
            check_member("sovereign_chain/client.py", marker, True)
