#!/usr/bin/env python3
"""
Password strength analyzer.

Scores a password on length and character variety, estimates its entropy,
gives a rough offline brute-force crack-time estimate, and flags common
weak patterns. Purely local — nothing is sent anywhere.

Author: Usman Faraz (https://github.com/usmanfarazz)
"""

import argparse
import getpass
import json
import math
import re
import sys

# A tiny sample of very common passwords. In a real audit you would load a
# large wordlist (e.g. rockyou.txt) instead of this inline list.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "111111", "password1", "admin", "letmein", "welcome",
    "iloveyou", "monkey", "dragon", "sunshine", "princess", "football",
    # more top leaked passwords, plus very common local choices
    "baseball", "superman", "batman", "trustno1", "shadow", "master",
    "qwertyuiop", "passw0rd", "secret", "summer", "cricket", "pakistan",
    "lahore", "karachi", "islamabad", "bismillah", "admin123", "changeme",
}

# Guesses per second a modern GPU rig can try against a fast, unsalted hash.
GUESSES_PER_SECOND = 10_000_000_000

# Common substitutions attackers' rules undo first (p@ssw0rd -> password).
LEET_MAP = str.maketrans({"@": "a", "4": "a", "0": "o", "1": "i", "!": "i",
                          "3": "e", "$": "s", "5": "s", "7": "t"})


def character_pool(password: str) -> int:
    """Estimate the size of the character set the password draws from."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool += 32  # rough count of common symbols
    return pool


def entropy_bits(password: str) -> float:
    """Shannon-style entropy estimate: length * log2(pool size)."""
    pool = character_pool(password)
    return len(password) * math.log2(pool) if pool else 0.0


def human_time(seconds: float) -> str:
    """Turn a raw number of seconds into a readable estimate."""
    if seconds < 1:
        return "instantly"
    units = [
        ("century", 60 * 60 * 24 * 365 * 100),
        ("year", 60 * 60 * 24 * 365),
        ("day", 60 * 60 * 24),
        ("hour", 60 * 60),
        ("minute", 60),
        ("second", 1),
    ]
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            if value >= 2:
                name = "centuries" if name == "century" else name + "s"
            return f"{value:,.1f} {name}"
    return "instantly"


def load_wordlist(path: str) -> int:
    """Add every line of a wordlist (e.g. rockyou.txt) to the common set.

    Returns how many new entries were added. Lines are lower-cased, and the
    file is read as latin-1 so odd bytes in big leaked lists never crash it.
    """
    before = len(COMMON_PASSWORDS)
    with open(path, encoding="latin-1") as fh:
        for line in fh:
            word = line.strip().lower()
            if word:
                COMMON_PASSWORDS.add(word)
    return len(COMMON_PASSWORDS) - before


def is_common(password: str) -> bool:
    """True if the password is a common password, possibly dressed up.

    Catches the usual tricks cracking rules undo first: capitalisation,
    digits/symbols tacked onto the ends (Password123!, admin@2024) and
    simple leetspeak (p@ssw0rd).
    """
    lowered = password.lower()
    core = re.sub(r"^[\d\W_]+|[\d\W_]+$", "", lowered)
    # Only the trailing symbols removed: "summer2024!" -> "summer2024"
    no_symbols = re.sub(r"[\W_]+$", "", lowered)
    candidates = {lowered, core, no_symbols, lowered.translate(LEET_MAP),
                  core.translate(LEET_MAP)}
    return any(c in COMMON_PASSWORDS for c in candidates if c)


def find_weaknesses(password: str):
    """Return a list of human-readable weakness warnings."""
    issues = []
    if len(password) < 8:
        issues.append("Shorter than 8 characters")
    if is_common(password):
        issues.append("Based on a common password (dictionary attacks try this first)")
    if password and password.lower() == password:
        issues.append("No uppercase letters")
    if not re.search(r"\d", password):
        issues.append("No digits")
    if not re.search(r"[^A-Za-z0-9]", password):
        issues.append("No symbols")
    if re.search(r"(.)\1\1", password):
        issues.append("Contains 3+ repeated characters in a row")
    if re.search(r"(0123|1234|2345|abcd|qwer)", password.lower()):
        issues.append("Contains a simple sequence (e.g. 1234 / qwer)")
    return issues


def rating(bits: float) -> str:
    if bits < 28:
        return "Very Weak"
    if bits < 36:
        return "Weak"
    if bits < 60:
        return "Reasonable"
    if bits < 128:
        return "Strong"
    return "Very Strong"


def evaluate(password: str) -> dict:
    """Score a password and return the results as a dict.

    The password itself is never included in the result.
    """
    bits = entropy_bits(password)
    combinations = 2 ** bits
    crack_seconds = combinations / 2 / GUESSES_PER_SECOND  # average case
    if is_common(password):
        # Brute-force maths doesn't apply: a wordlist + rules finds it at once.
        bits = min(bits, 10.0)
        crack_seconds = 0
    return {
        "length": len(password),
        "character_pool": character_pool(password),
        "entropy_bits": round(bits, 1),
        "strength": rating(bits),
        "crack_time_seconds": crack_seconds,
        "crack_time": human_time(crack_seconds),
        "weaknesses": find_weaknesses(password),
    }


def analyze(password: str):
    r = evaluate(password)
    print("\n=== Password Analysis ===")
    print(f"Length          : {r['length']}")
    print(f"Character pool  : {r['character_pool']}")
    print(f"Entropy         : {r['entropy_bits']:.1f} bits (effective)")
    print(f"Strength        : {r['strength']}")
    print(f"Est. crack time : {r['crack_time']} "
          f"(offline, ~{GUESSES_PER_SECOND:,}/s)")

    if r["weaknesses"]:
        print("\nWeaknesses:")
        for issue in r["weaknesses"]:
            print(f"  [!] {issue}")
    else:
        print("\n[+] No obvious weaknesses found.")
    print()


def main():
    parser = argparse.ArgumentParser(description="Analyze password strength locally.")
    parser.add_argument("password", nargs="?",
                        help="Password to analyze (omit to be prompted securely)")
    parser.add_argument("--stdin", action="store_true",
                        help="Read the password from standard input (keeps it out of the process list)")
    parser.add_argument("-w", "--wordlist",
                        help="Extra list of known passwords to check against, one per line (e.g. rockyou.txt)")
    parser.add_argument("--json", action="store_true",
                        help="Print the result as JSON (the password itself is not included)")
    args = parser.parse_args()

    if args.wordlist:
        try:
            load_wordlist(args.wordlist)
        except OSError as exc:
            sys.exit(f"[!] Could not read wordlist: {exc}")

    if args.stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        password = args.password or getpass.getpass("Enter password to analyze: ")
    if not password:
        sys.exit("[!] No password provided.")
    if args.json:
        print(json.dumps(evaluate(password), indent=2))
    else:
        analyze(password)


if __name__ == "__main__":
    main()
