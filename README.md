# 🔐 Markov Password Strength Meter

A password strength evaluation tool that uses a **character-level Markov chain** trained on real-world password datasets (e.g., `rockyou.txt`) to estimate password likelihood, entropy, and guessability.

It combines statistical modeling with pattern detection to produce realistic strength scores, crack-time estimates, and actionable feedback. The design is inspired by ideas used in **zxcvbn**, **passwd-strength**, and **KeePass**, while remaining lightweight and dependency-free.

---

# ✨ Features

**Markov-Based Guessability**

* Learns character transition probabilities from large password datasets
* Estimates password probability using `<START>` and `<END>` tokens
* Converts sequence probability into entropy and expected guesses

**Pattern Detection**

Identifies common password weaknesses:

* Common passwords and leet variants
  (`password`, `p@ssw0rd`)
* Sequential characters
  (`12345`, `abcdef`)
* Repeated characters
  (`aaa`, `111`)
* Keyboard walks
  (`qwerty`, `asdfgh`)
* Years and date patterns
  (`1990`, `12/31/2025`)

**Realistic Strength Scoring (0–100)**

Combines:

* Markov entropy
* Password length
* Character variety
* Pattern-based penalties

**Crack-Time Estimates**

Simulates multiple attack scenarios:

* Online throttled (rate-limited services)
* Online unthrottled
* Offline fast-hash attacks
* Offline slow-hash attacks
* Specialized cracking hardware

**Actionable Feedback**

Explains *why* a password is weak and how to improve it.

**Cached Model**

Builds the Markov model once and reuses it for faster startup.

---

# 📦 Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/markov-password-meter.git
cd markov-password-meter
```

Requirements:

* Python **3.7+**
* No external dependencies
  (uses only: `os`, `pickle`, `math`, `re`, `collections`)

Download a password dataset:

Example: `rockyou.txt`

Place it in the project directory, or update:

```python
PASSWORD_DATASET = "rockyou.txt"
```

(Optional)

Add:

```text
common_passwords.txt
```

to improve blacklist detection.

---

# 🚀 Usage

Run:

```bash
python main.py
```

Example:

```text
[password_corpus] Loading cached model from 'markov_model.pkl'...

Password Strength Meter using Start-End Markov Model
Inspired by zxcvbn, passwd-strength, and KeePass.

Enter password (or 'quit'): P@ssw0rd123!

Password: P@ssw0rd123!
Length:               12
Unique chars:         10
Character classes:    4/4
Entropy (Markov):     47.3 bits
Entropy (Shannon):    37.2 bits
Expected guesses:     1.64e+14
Strength score:       45/100 (Weak)

Feedback:
  • Uses leet substitutions in a common word
  • Contains a sequential pattern

Estimated crack times:
  Online (throttled):         5,200.65 years
  Online (unthrottled):       1.90 days
  Offline (fast hash):        2.73 minutes
  Offline (specialized):      27.33 seconds
  Offline (slow hash):        520.07 years
```

---

# ⚙️ How It Works

## 1. Markov Model Entropy

The model learns character transition probabilities from a password corpus.

For a password:

* `<START>` and `<END>` tokens are added
* Transition probabilities are multiplied across the sequence
* Entropy is computed as:

```
Entropy = −log₂(probability)
```

Expected guesses:

```
Expected guesses ≈ 1 / probability
```

This estimates how likely the password is relative to real-world usage patterns.

---

## 2. Pattern Detection

The following weaknesses are identified:

**Common password**

Direct matches or known variants.

**Short length**

* < 8 characters → high penalty
* < 12 characters → moderate penalty

**Low character variety**

Fewer than 3 of:

* lowercase
* uppercase
* digits
* symbols

**Sequential patterns**

Examples:

```
abc
789
```

**Repetition**

Examples:

```
aaa
111
```

**Keyboard walks**

Examples:

```
qwerty
asdfgh
```

Supports QWERTY and AZERTY layouts.

**Leet substitutions**

Examples:

```
@ → a
0 → o
```

**Date patterns**

Matches:

```
19xx
20xx
MM/DD/YYYY
```

---

## 3. Strength Score (0–100)

Score components:

**Base score (0–60)**
Derived from Markov entropy.

**Length bonus (0–20)**
Scaled from short to long passwords.

**Variety bonus (0–20)**
Based on number of character classes.

**Penalties**

Applied for detected weaknesses.

Final mapping:

```
90–100  Very Strong
75–89   Strong
50–74   Medium
25–49   Weak
0–24    Very Weak
```

---

## 4. Crack-Time Estimation

Time estimates are based on:

```
expected_guesses / guesses_per_second
```

Example attack rates:

| Scenario            | Rate   |
| ------------------- | ------ |
| Online throttled    | 1k/s   |
| Online unthrottled  | 1B/s   |
| Offline fast hash   | 1T/s   |
| Offline specialized | 100B/s |
| Offline slow hash   | 10k/s  |

Note:

These are **approximate reference values**, not real-world guarantees.

Actual cracking speeds vary widely depending on:

* hashing algorithm
* hardware
* password storage configuration

---

# 📁 File Structure

```
.
├── main.py
├── password_corpus.py
├── markov_model.pkl
├── rockyou.txt
├── common_passwords.txt
└── README.md
```

---

# 🔧 Configuration

All tunable parameters are in:

```
password_corpus.py
```

Key variables:

| Variable            | Default              | Description          |
| ------------------- | -------------------- | -------------------- |
| PASSWORD_DATASET    | `"rockyou.txt"`      | Training dataset     |
| MODEL_CACHE_FILE    | `"markov_model.pkl"` | Cached model path    |
| MAX_PASSWORD_LENGTH | 128                  | Ignore longer inputs |
| BUILD_LIMIT         | None                 | Limit training size  |

Attack rate constants:

```
ONLINE_THROTTLED
ONLINE_UNTHROTTLED
OFFLINE_FAST_HASH
OFFLINE_SLOW_HASH
OFFLINE_SPECIALIZED
```

Scoring penalties can be modified in:

```
compute_strength_score()
```

---

# 📚 Background & Research

Inspired by:

* **zxcvbn (Dropbox)** — Pattern-based password estimation
* **passwd-strength (Rust)** — Additive scoring models
* **KeePass** — Entropy-based scoring thresholds
* **NIST SP 800-63B** — Modern authentication guidance

Markov methodology based on:

**"Using Markov Models to Crack Passwords"**
van Heerden & Vorster

---

# 🤝 Contributing

Pull requests welcome.

Potential improvements:

* Dictionary-based leet detection
* Reversed-word detection
* Spatial keyboard modeling
* Higher-order Markov models (trigrams)
* Custom dataset training tools

---

# 📄 License

MIT License
See `LICENSE`.

---

# ⚠️ Disclaimer

This tool is intended for **educational purposes only**.

Strength estimates are probabilistic and should not be treated as guarantees of security.
