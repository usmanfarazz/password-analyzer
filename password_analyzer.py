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
import math
import re
import sys

# A tiny sample of very common passwords. In a real audit you would load a
# large wordlist (e.g. rockyou.txt) instead of this inline list.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "111111", "password1", "admin", "letmein", "welcome",
    "iloveyou", "monkey", "dragon", "sunshine", "princess", "football",
}

# Guesses per second a modern GPU rig can try against a fast, unsalted hash.
GUESSES_PER_SECOND = 10_000_000_000


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


def find_weaknesses(password: str):
    """Return a list of human-readable weakness warnings."""
    issues = []
    if len(password) < 8:
        issues.append("Shorter than 8 characters")
    if password.lower() in COMMON_PASSWORDS:
        issues.append("Appears in the common-password list")
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


def analyze(password: str):
    bits = entropy_bits(password)
    combinations = 2 ** bits
    crack_seconds = combinations / 2 / GUESSES_PER_SECOND  # average case

    print("\n=== Password Analysis ===")
    print(f"Length          : {len(password)}")
    print(f"Character pool  : {character_pool(password)}")
    print(f"Entropy         : {bits:.1f} bits")
    print(f"Strength        : {rating(bits)}")
    print(f"Est. crack time : {human_time(crack_seconds)} "
          f"(offline, ~{GUESSES_PER_SECOND:,}/s)")

    issues = find_weaknesses(password)
    if issues:
        print("\nWeaknesses:")
        for issue in issues:
            print(f"  [!] {issue}")
    else:
        print("\n[+] No obvious weaknesses found.")
    print()


def main():
    parser = argparse.ArgumentParser(description="Analyze password strength locally.")
    parser.add_argument("password", nargs="?",
                        help="Password to analyze (omit to be prompted securely)")
    args = parser.parse_args()

    password = args.password or getpass.getpass("Enter password to analyze: ")
    if not password:
        sys.exit("[!] No password provided.")
    analyze(password)


if __name__ == "__main__":
    main()
