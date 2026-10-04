"""Unit tests for password_analyzer.py. Run with: python3 -m unittest discover -s tests -v"""
import json
import os
import subprocess
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

    def test_wordlist_entry_with_extra_symbol(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("Summer2024\n")
        try:
            self.assertEqual(pa.load_wordlist(fh.name), 1)
            self.assertTrue(pa.is_common("Summer2024!"))
        finally:
            os.remove(fh.name)
            pa.COMMON_PASSWORDS.discard("summer2024")

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


SCRIPT = os.path.join(os.path.dirname(__file__), "..", "password_analyzer.py")


class CommandLineTest(unittest.TestCase):
    def run_cli(self, args, stdin=""):
        return subprocess.run([sys.executable, SCRIPT] + args, input=stdin,
                              capture_output=True, text=True, check=True).stdout

    def test_stdin_and_json(self):
        out = json.loads(self.run_cli(["--stdin", "--json"], "password123\n"))
        self.assertEqual(out["strength"], "Very Weak")
        self.assertNotIn("password123", json.dumps(out))

    def test_password_starting_with_dash(self):
        out = self.run_cli(["--json", "--", "-Secret123!"])
        self.assertEqual(json.loads(out)["length"], 11)


if __name__ == "__main__":
    unittest.main()
