"""Unit tests for password_analyzer.py. Run with: python3 -m unittest discover -s tests -v"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import password_analyzer as pa  # noqa: E402


class CharacterPoolTest(unittest.TestCase):
    def test_pool_grows_with_each_class(self):
        self.assertEqual(pa.character_pool("abc"), 26)
        self.assertEqual(pa.character_pool("abcABC"), 52)
        self.assertEqual(pa.character_pool("abcABC123"), 62)
        self.assertEqual(pa.character_pool("abcABC123!"), 94)


class CommonPasswordTest(unittest.TestCase):
    def test_plain_common_password(self):
        self.assertTrue(pa.is_common("password"))

    def test_dressed_up_variants(self):
        for pw in ("Password123!", "p@ssw0rd", "Admin@2024", "123dragon"):
            with self.subTest(pw=pw):
                self.assertTrue(pa.is_common(pw))

    def test_random_password_not_common(self):
        self.assertFalse(pa.is_common("Tr0ub4dor&3"))


class EvaluateTest(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        r = pa.evaluate("Password123!")
        self.assertEqual(r["strength"], "Very Weak")
        self.assertEqual(r["crack_time"], "instantly")

    def test_long_passphrase_is_strong(self):
        r = pa.evaluate("correct-horse-battery-staple")
        self.assertIn(r["strength"], ("Strong", "Very Strong"))

    def test_result_never_contains_the_password(self):
        secret = "MyS3cret!Value"
        self.assertNotIn(secret, repr(pa.evaluate(secret)))

    def test_weaknesses_listed(self):
        issues = pa.find_weaknesses("aaa")
        self.assertIn("Shorter than 8 characters", issues)
        self.assertIn("Contains 3+ repeated characters in a row", issues)


if __name__ == "__main__":
    unittest.main()
