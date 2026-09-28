# 🔐 Password Analyzer

A local password strength analyzer written in Python, with a Bash helper for
batch auditing. It scores a password on length and character variety, estimates
its **entropy**, gives a rough **offline crack-time** estimate, and flags common
weak patterns.

> 🔒 **Everything runs locally.** No password is ever sent over the network.
> Use this only on your own passwords or in authorised audits.

## Features

- 📏 Entropy estimate (bits) based on length and character pool
- ⏱️ Offline brute-force crack-time estimate
- 🚩 Weak-pattern detection (common passwords — including dressed-up variants like `Password123!` or `p@ssw0rd` — sequences, repeats, missing character classes)
- 🗂️ Bash wrapper to audit a whole list of passwords at once
- 🐍 No dependencies — Python standard library only

## Requirements

- Python 3.6+
- Bash (for the batch script)

## Usage

```bash
# Analyze a single password (prompts securely, nothing shown on screen)
python3 password_analyzer.py

# Or pass it directly
python3 password_analyzer.py "Tr0ub4dor&3"

# Audit a whole file (one password per line)
./check_passwords.sh passwords.txt
```

## Example output

```
=== Password Analysis ===
Length          : 11
Character pool  : 94
Entropy         : 72.1 bits (effective)
Strength        : Strong
Est. crack time : 80.3 centuries (offline, ~10,000,000,000/s)

[+] No obvious weaknesses found.
```

A common password stays weak even when it's dressed up:

```
=== Password Analysis ===
Length          : 12
Character pool  : 94
Entropy         : 10.0 bits (effective)
Strength        : Very Weak
Est. crack time : instantly (offline, ~10,000,000,000/s)

Weaknesses:
  [!] Based on a common password (dictionary attacks try this first)
```

## How the score works

Entropy is estimated as `length × log2(pool size)`, where the pool grows with
each character class used (lowercase, uppercase, digits, symbols). Crack time
assumes a fast, unsalted hash at ~10 billion guesses/second — a deliberately
pessimistic, attacker-friendly assumption.

## Roadmap

- [ ] Load a real wordlist (e.g. rockyou.txt) for dictionary checks
- [ ] Check against the "Have I Been Pwned" k-anonymity API (opt-in)
- [ ] JSON output mode

## License

MIT © [Usman Faraz](https://github.com/usmanfarazz)
