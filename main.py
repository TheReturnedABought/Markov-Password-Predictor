"""
Password Strength Meter – Interactive Console Interface
Uses the password_corpus library for all analysis.
"""

import os
from password_corpus import (
    CORPUS_MODEL,
    password_log_probability,
    expected_guesses,
    shannon_entropy,
    analyze_patterns,
    compute_strength_score,
    score_to_rating,
    crack_time_estimate
)


def analyse_password(password: str, corpus_model: dict) -> None:
    if len(password) < 2:
        print("Password too short (use at least 2 characters).")
        return

    entropy_bits = password_log_probability(password, corpus_model)
    guesses = expected_guesses(password, corpus_model)
    shannon = shannon_entropy(password)

    # Character variety count
    has_lower = any('a' <= c <= 'z' for c in password)
    has_upper = any('A' <= c <= 'Z' for c in password)
    has_digit = any('0' <= c <= '9' for c in password)
    has_symbol = any(not ('a' <= c <= 'z' or 'A' <= c <= 'Z' or '0' <= c <= '9') for c in password)
    char_variety = sum([has_lower, has_upper, has_digit, has_symbol])

    patterns, feedback = analyze_patterns(password)

    final_score = compute_strength_score(entropy_bits, len(password), char_variety, patterns)
    rating = score_to_rating(final_score)
    times = crack_time_estimate(guesses)

    print(f"\nPassword: {password}")
    print(f"Length:               {len(password)}")
    print(f"Unique chars:         {len(set(password))}")
    print(f"Character classes:    {char_variety}/4")
    print(f"Entropy (Markov):     {entropy_bits:.1f} bits")
    print(f"Entropy (Shannon):    {shannon:.1f} bits")
    print(f"Expected guesses:     {guesses:.2e}")
    print(f"Strength score:       {final_score}/100 ({rating})")

    if feedback:
        print("\nFeedback:")
        for fb in feedback:
            print(f"  • {fb}")
    else:
        print("\nFeedback: Good password! No obvious weaknesses detected.")

    print("\nEstimated crack times (offline attack, fast hash):")
    print(f"  Online (throttled, 1k/s):         {times['online_throttled']}")
    print(f"  Online (unthrottled, 1B/s):       {times['online_unthrottled']}")
    print(f"  Offline (fast hash, 1T/s):        {times['offline_fast']}")
    print(f"  Offline (specialized, 100B/s):    {times['offline_specialized']}")
    print(f"  Offline (slow hash, 10k/s):       {times['offline_slow']}")


if __name__ == "__main__":
    print("Password Strength Meter (Improved) using Start‑End Markov Model")
    print("Based on research from zxcvbn, passwd‑strength, and KeePass.\n")

    if not os.path.exists("common_passwords.txt"):
        print("Note: 'common_passwords.txt' not found. Using built‑in common password list.")
        print("      Download a larger list from https://github.com/danielmiessler/SecLists for better coverage.\n")

    while True:
        pw = input("Enter password (or 'quit'): ")
        if pw.lower() == 'quit':
            break
        analyse_password(pw, CORPUS_MODEL)