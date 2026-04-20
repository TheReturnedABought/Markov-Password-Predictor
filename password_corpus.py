"""
Password analysis library using a Markov model trained on a real password corpus.
Exports the model `CORPUS_MODEL` and all strength evaluation functions.
"""

import os
import pickle
import math
import re
from collections import defaultdict
from typing import Optional, Generator, Dict, Set, List, Tuple

# ==================================================
# CONFIGURATION – CORPUS BUILDING
# ==================================================
PASSWORD_DATASET = "rockyou.txt"          # Path to wordlist
MODEL_CACHE_FILE = "markov_model.pkl"     # Cached model file
MAX_PASSWORD_LENGTH = 128                 # Skip overly long lines
BUILD_LIMIT = None                        # Limit for faster testing (e.g., 1_000_000)

# ==================================================
# CONFIGURATION – CRACK SPEEDS & COMMON PASSWORDS
# ==================================================
ONLINE_THROTTLED = 1_000
ONLINE_UNTHROTTLED = 1_000_000_000
OFFLINE_FAST_HASH = 1_000_000_000_000     # 1T/s
OFFLINE_SLOW_HASH = 10_000
OFFLINE_SPECIALIZED = 100_000_000_000     # 100B/s (specialised hardware)

# Built‑in common passwords (used if common_passwords.txt is missing)
BUILTIN_COMMON: Set[str] = {
    "password", "123456", "12345678", "1234", "qwerty", "12345", "dragon",
    "pussy", "baseball", "football", "letmein", "monkey", "696969", "abc123",
    "mustang", "michael", "shadow", "master", "jennifer", "111111", "2000",
    "jordan", "superman", "harley", "1234567", "hunter", "trustno1", "ranger",
    "buster", "thomas", "robert", "soccer", "batman", "test", "pass", "fuck",
    "love", "hello", "admin", "welcome", "sunshine", "princess", "password1",
    "passw0rd", "p@ssword", "p@ssw0rd"
}

# ==================================================
# CORPUS LOADING & MARKOV MODEL BUILDING
# ==================================================
def clean_password_line(line: str) -> Optional[str]:
    pw = line.strip()
    if not pw or len(pw) > MAX_PASSWORD_LENGTH:
        return None
    if not pw.isprintable():
        return None
    return pw.lower()


def password_generator(file_path: str, limit: int = None) -> Generator[str, None, None]:
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            if limit and i >= limit:
                break
            pw = clean_password_line(line)
            if pw:
                yield pw


def build_markov_from_file(file_path: str, limit: int = None, smoothing: float = 0.01) -> Dict:
    print(f"[password_corpus] Building model from '{file_path}'...")
    counts = defaultdict(lambda: defaultdict(int))
    total = 0

    for pw in password_generator(file_path, limit):
        total += 1
        for i in range(len(pw) - 1):
            counts[pw[i]][pw[i+1]] += 1
        if total % 100000 == 0:
            print(f"  Processed {total:,} passwords...")

    print(f"[password_corpus] Processed {total:,} passwords. Converting to probabilities...")

    model = {}
    vocab_size = 95

    for from_char, trans in counts.items():
        total_trans = sum(trans.values()) + smoothing * vocab_size
        model[from_char] = {
            to_char: (cnt + smoothing) / total_trans
            for to_char, cnt in trans.items()
        }

    return model


def load_cached_model(cache_path: str, file_path: str, limit: int = None) -> Dict:
    if os.path.exists(cache_path):
        print(f"[password_corpus] Loading cached model from '{cache_path}'...")
        with open(cache_path, 'rb') as f:
            return pickle.load(f)

    model = build_markov_from_file(file_path, limit)
    print(f"[password_corpus] Saving model to '{cache_path}'...")
    with open(cache_path, 'wb') as f:
        pickle.dump(model, f)
    return model


# ==================================================
# EXPORTED CORPUS MODEL
# ==================================================
CORPUS_MODEL = load_cached_model(MODEL_CACHE_FILE, PASSWORD_DATASET, BUILD_LIMIT)


# ==================================================
# CHARACTER CLASSIFICATION UTILITIES
# ==================================================
def get_type(c: str) -> str:
    if 'a' <= c <= 'z': return "lower"
    if 'A' <= c <= 'Z': return "upper"
    if '0' <= c <= '9': return "digit"
    return "symbol"


def _char_type_size(char_type: str) -> int:
    return {'lower': 26, 'upper': 26, 'digit': 10, 'symbol': 32}.get(char_type, 32)


def shannon_entropy(password: str) -> float:
    """Calculate Shannon entropy of the password."""
    if not password:
        return 0
    freq = defaultdict(int)
    for char in password:
        freq[char] += 1
    length = len(password)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# ==================================================
# MARKOV MODEL PROBABILITY FUNCTIONS
# ==================================================
def get_transition_prob(from_char: str, to_char: str, corpus_model: Dict) -> float:
    trans_dict = corpus_model.get(from_char)
    if not trans_dict:
        return 1.0 / _char_type_size(get_type(to_char))
    prob = trans_dict.get(to_char)
    if prob is not None and prob > 0:
        return prob
    total_mass = sum(trans_dict.values())
    return 1.0 / (total_mass + _char_type_size(get_type(to_char)))


def password_log_probability(password: str, corpus_model: Dict) -> float:
    """Negative log2 probability (bits) under the Start‑End Markov model."""
    chars = ['<START>'] + list(password) + ['<END>']
    log_prob = 0.0
    for i in range(len(chars) - 1):
        p = get_transition_prob(chars[i], chars[i+1], corpus_model)
        if p <= 0:
            p = 1e-12
        log_prob += -math.log2(p)
    return log_prob


def expected_guesses(password: str, corpus_model: Dict) -> float:
    prob = 2 ** (-password_log_probability(password, corpus_model))
    return 1.0 / prob if prob > 0 else float('inf')


# ==================================================
# COMMON PASSWORD HANDLING
# ==================================================
def load_common_passwords(filepath: str = "common_passwords.txt") -> Set[str]:
    common = set()
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                common.add(line.strip())
    return common


COMMON_PASSWORDS = load_common_passwords() or BUILTIN_COMMON


def is_common_password(password: str) -> bool:
    pw_lower = password.lower()
    if pw_lower in COMMON_PASSWORDS:
        return True

    leet_map = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's'}
    reversed_pw = ''.join(leet_map.get(c, c) for c in pw_lower)
    if reversed_pw in COMMON_PASSWORDS:
        return True

    for common in COMMON_PASSWORDS:
        if len(common) >= 4 and common in pw_lower:
            return True
    return False


# ==================================================
# PATTERN DETECTION FUNCTIONS
# ==================================================
def detect_leet_speak(password: str) -> bool:
    has_leet = bool(set(password) & set('013457@$'))
    if not has_leet:
        return False

    leet_map = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's'}
    reversed_pw = ''.join(leet_map.get(c, c) for c in password.lower())

    if reversed_pw in COMMON_PASSWORDS:
        return True

    common_words = ["password", "admin", "welcome", "monkey", "dragon", "master", "hello", "love"]
    for word in common_words:
        if word in reversed_pw:
            return True
    return False


def detect_sequential(password: str) -> int:
    if len(password) < 2:
        return 0
    max_streak = 1
    current_streak = 1
    direction = 0
    for i in range(1, len(password)):
        diff = ord(password[i]) - ord(password[i-1])
        if abs(diff) == 1:
            if direction == 0:
                direction = diff
                current_streak = 2
            elif diff == direction:
                current_streak += 1
            else:
                direction = diff
                current_streak = 2
        else:
            direction = 0
            current_streak = 1
        max_streak = max(max_streak, current_streak)
    return max_streak


def detect_repetition(password: str) -> int:
    if len(password) < 2:
        return 0
    max_run = 1
    current_run = 1
    for i in range(1, len(password)):
        if password[i] == password[i-1]:
            current_run += 1
            max_run = max(max_run, current_run)
        else:
            current_run = 1
    return max_run


def detect_keyboard_walk(password: str) -> bool:
    keyboard_rows = [
        "`1234567890-=", "~!@#$%^&*()_+",
        "qwertyuiop[]\\", "QWERTYUIOP{}|",
        "asdfghjkl;'", "ASDFGHJKL:\"",
        "zxcvbnm,./", "ZXCVBNM<>?"
    ]
    azerty_rows = [
        "azertyuiop^$", "AZERTYUIOP¨£",
        "qsdfghjklmù", "QSDFGHJKLM%",
        "wxcvbn,;:!", "WXCVBN?./§"
    ]
    all_rows = keyboard_rows + azerty_rows
    pw_lower = password.lower()

    for row in all_rows:
        row_lower = row.lower()
        for i in range(len(row_lower) - 3):
            substr = row_lower[i:i+4]
            if substr in pw_lower or substr[::-1] in pw_lower:
                return True
    return False


def detect_date_year(password: str) -> bool:
    year_pattern = r'(19|20)\d{2}'
    if re.search(year_pattern, password):
        return True
    date_patterns = [
        r'\d{1,2}[/-]\d{1,2}[/-]\d{2,4}',
        r'\d{1,2}[./-]\d{1,2}[./-]\d{2,4}'
    ]
    for pat in date_patterns:
        if re.search(pat, password):
            return True
    return False


def analyze_patterns(password: str) -> Tuple[List[str], List[str]]:
    patterns = []
    feedback = []

    if is_common_password(password):
        patterns.append("common_password")
        feedback.append("This is a very common password and will be cracked instantly.")

    if len(password) < 8:
        patterns.append("too_short")
        feedback.append("Password is too short. Use at least 12 characters.")
    elif len(password) < 12:
        patterns.append("short")
        feedback.append("Consider using a longer password (12+ characters).")

    has_lower = any('a' <= c <= 'z' for c in password)
    has_upper = any('A' <= c <= 'Z' for c in password)
    has_digit = any('0' <= c <= '9' for c in password)
    has_symbol = any(not ('a' <= c <= 'z' or 'A' <= c <= 'Z' or '0' <= c <= '9') for c in password)
    char_classes = sum([has_lower, has_upper, has_digit, has_symbol])
    if char_classes < 3:
        patterns.append("low_variety")
        feedback.append("Use a mix of uppercase, lowercase, numbers, and symbols.")

    seq_len = detect_sequential(password)
    if seq_len >= 3:
        patterns.append("sequential")
        feedback.append(f"Contains a sequential pattern of length {seq_len}.")

    rep_len = detect_repetition(password)
    if rep_len >= 3:
        patterns.append("repetition")
        feedback.append(f"Contains {rep_len} repeated characters in a row.")

    if detect_keyboard_walk(password):
        patterns.append("keyboard_walk")
        feedback.append("Contains a keyboard pattern (e.g., 'qwerty').")

    if detect_leet_speak(password):
        patterns.append("leet_speak")
        feedback.append("Uses leet-speak substitutions (@ for a, 0 for o) in a common word.")

    if detect_date_year(password):
        patterns.append("date_year")
        feedback.append("Contains a year or date pattern.")

    return patterns, feedback


# ==================================================
# SCORING & RATING
# ==================================================
def score_to_rating(score: int) -> str:
    if score >= 90:
        return "Very Strong"
    elif score >= 75:
        return "Strong"
    elif score >= 50:
        return "Medium"
    elif score >= 25:
        return "Weak"
    else:
        return "Very Weak"


def compute_strength_score(entropy_bits: float, length: int, char_variety: int, patterns: List[str]) -> int:
    if entropy_bits < 40:
        base_score = entropy_bits / 40 * 20
    elif entropy_bits < 50:
        base_score = 20 + (entropy_bits - 40) / 20 * 20
    elif entropy_bits < 80:
        base_score = 40 + (entropy_bits - 50) / 20 * 15
    else:
        base_score = 55 + min((entropy_bits - 80) / 40 * 5, 5)

    length_bonus = min(length / 12 * 20, 20)
    variety_bonus = min(char_variety / 4 * 20, 20)

    score = base_score + length_bonus + variety_bonus

    penalty_map = {
        "common_password": 40,
        "too_short": 30,
        "short": 10,
        "low_variety": 20,
        "sequential": 10,
        "repetition": 10,
        "keyboard_walk": 15,
        "leet_speak": 20,
        "date_year": 15
    }

    for pattern in patterns:
        score -= penalty_map.get(pattern, 0)

    return round(max(0, min(score, 100)))


# ==================================================
# CRACK TIME ESTIMATION
# ==================================================
def format_time(seconds: float) -> str:
    if seconds < 0:
        return "instant"
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds / 3600:.2f} hours"
    elif seconds < 31536000:
        return f"{seconds / 86400:.2f} days"
    elif seconds < 31536000 * 1000:
        return f"{seconds / 31536000:.2f} years"
    else:
        return "centuries"


def crack_time_estimate(guesses: float) -> Dict[str, str]:
    if guesses == float('inf'):
        return {k: "infinite" for k in [
            'online_throttled', 'online_unthrottled',
            'offline_fast', 'offline_slow', 'offline_specialized'
        ]}
    return {
        'online_throttled':    format_time(guesses / ONLINE_THROTTLED),
        'online_unthrottled':  format_time(guesses / ONLINE_UNTHROTTLED),
        'offline_fast':        format_time(guesses / OFFLINE_FAST_HASH),
        'offline_slow':        format_time(guesses / OFFLINE_SLOW_HASH),
        'offline_specialized': format_time(guesses / OFFLINE_SPECIALIZED),
    }