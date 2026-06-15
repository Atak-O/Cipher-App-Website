"""Heuristic cipher analysis for the CipherLab AI Assistant."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from cipher_methods import (
    ENGLISH_ALPHABET,
    TURKISH_ALPHABET,
    affine_decrypt,
    atbash_cipher,
    base64_decode,
    binary_to_text,
    caesar_cipher,
    gcd,
    morse_decode,
    rail_fence_decrypt,
    vigenere_cipher,
)

COMMON_WORDS = [
    "THE", "AND", "YOU", "THAT", "HAVE", "FOR", "WITH", "HELLO", "WORLD", "SECRET",
    "MERHABA", "DUNYA", "BEN", "SEN", "BIR", "VE", "BU", "ILE", "ICIN", "SIFRE", "GIZLI",
    "OKUL", "MATEMATIK", "PYTHON", "PROJE", "CIPHER", "LAB",
]

COMMON_VIGENERE_KEYS = [
    "DUNYA", "GIZ", "GIZEM", "KEDI", "ANAHTAR", "SIFRE", "OKUL", "PYTHON", "PROJE",
    "CIPHER", "LAB", "SECRET", "WORLD", "HELLO", "MATH", "AI",
]


@dataclass
class AnalysisCandidate:
    cipher: str
    confidence: int
    parameters: str
    plaintext: str
    explanation: str


def clean_letters(text: str, alphabet: str = ENGLISH_ALPHABET) -> str:
    return "".join(ch.upper() for ch in text if ch.upper() in alphabet)


def language_score(text: str) -> float:
    upper = text.upper()
    if not upper.strip():
        return -999

    printable = sum(1 for ch in text if ch.isprintable()) / max(len(text), 1)
    letters = sum(1 for ch in upper if ch.isalpha())
    spaces = upper.count(" ")
    vowels = sum(1 for ch in upper if ch in "AEIİOÖUÜ")
    bad_symbols = sum(1 for ch in upper if not (ch.isalnum() or ch.isspace() or ch in ".,!?;:'\"-_/()"))

    score = printable * 10
    score += min(spaces, 12) * 1.7
    if letters:
        vowel_ratio = vowels / letters
        score += max(0, 1 - abs(vowel_ratio - 0.38)) * 12
    for word in COMMON_WORDS:
        if word in upper:
            score += 12 + min(len(word), 8)
    score -= bad_symbols * 5
    return score


def confidence_from_score(score: float, base: int = 40) -> int:
    return max(1, min(99, int(base + score * 0.8)))


def index_of_coincidence(text: str, alphabet: str = ENGLISH_ALPHABET) -> float:
    letters = clean_letters(text, alphabet)
    n = len(letters)
    if n < 2:
        return 0.0
    total = 0
    for ch in alphabet:
        f = letters.count(ch)
        total += f * (f - 1)
    return total / (n * (n - 1))


def guess_vigenere_key_length(text: str, alphabet: str = ENGLISH_ALPHABET, max_len: int = 12) -> int:
    letters = clean_letters(text, alphabet)
    if len(letters) < 12:
        return 0
    best_len = 1
    best_ioc = 0.0
    for key_len in range(1, min(max_len, len(letters)) + 1):
        groups = [letters[i::key_len] for i in range(key_len)]
        avg_ioc = sum(index_of_coincidence(group, alphabet) for group in groups) / key_len
        if avg_ioc > best_ioc:
            best_ioc = avg_ioc
            best_len = key_len
    return best_len


def analyze_morse(text: str) -> AnalysisCandidate | None:
    stripped = text.strip()
    morse_chars = set(".-/ ")
    if stripped and all(ch in morse_chars for ch in stripped) and any(ch in ".-" for ch in stripped):
        decoded = morse_decode(stripped)
        unknowns = decoded.count("?")
        return AnalysisCandidate(
            "Morse Code",
            max(60, 98 - unknowns * 8),
            "Dots, dashes, spaces, and slash separators",
            decoded,
            "The character set strongly matches Morse notation.",
        )
    return None


def analyze_binary(text: str) -> AnalysisCandidate | None:
    compact = text.replace(" ", "").strip()
    if compact and re.fullmatch(r"[01]+", compact) and len(compact) % 8 == 0:
        try:
            decoded = binary_to_text(text)
            return AnalysisCandidate(
                "Binary / ASCII",
                97,
                "8-bit binary blocks",
                decoded,
                "The input contains only binary digits and can be grouped into full bytes.",
            )
        except Exception:
            return AnalysisCandidate(
                "Binary / ASCII",
                72,
                "Binary-like byte stream",
                "Decoding failed",
                "The shape matches binary, but UTF-8 conversion did not produce readable text.",
            )
    return None


def analyze_base64(text: str) -> AnalysisCandidate | None:
    stripped = text.strip()
    if len(stripped) < 4 or len(stripped) % 4 != 0:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", stripped):
        return None
    try:
        decoded = base64_decode(stripped)
        score = language_score(decoded)
        return AnalysisCandidate(
            "Base64",
            88 if score > 5 else 70,
            "Valid Base64 alphabet and padding",
            decoded,
            "The input length, padding, and character set match Base64 encoding. Base64 is encoding, not encryption.",
        )
    except Exception:
        return None


def analyze_rot13(text: str) -> AnalysisCandidate | None:
    decoded = caesar_cipher(text, 13, ENGLISH_ALPHABET)
    score = language_score(decoded)
    if score > 10:
        return AnalysisCandidate(
            "ROT13",
            confidence_from_score(score, 52),
            "Fixed shift: 13",
            decoded,
            "A ROT13 transform produced readable language-like text.",
        )
    return None


def analyze_caesar(text: str) -> AnalysisCandidate | None:
    best = None
    for alphabet in (ENGLISH_ALPHABET, TURKISH_ALPHABET):
        for shift in range(1, len(alphabet)):
            decoded = caesar_cipher(text, shift, alphabet, decrypt=True)
            score = language_score(decoded)
            if best is None or score > best[0]:
                best = (score, alphabet, shift, decoded)
    if not best:
        return None
    score, alphabet, shift, decoded = best
    if score < 8:
        return None
    return AnalysisCandidate(
        "Caesar Cipher",
        confidence_from_score(score, 48),
        f"Detected shift: +{shift}; alphabet length: {len(alphabet)}",
        decoded,
        f"Letter frequency and readability were strongest when decrypting with a backward shift of {shift}.",
    )


def analyze_atbash(text: str) -> AnalysisCandidate | None:
    candidates = []
    for alphabet in (ENGLISH_ALPHABET, TURKISH_ALPHABET):
        decoded = atbash_cipher(text, alphabet)
        candidates.append((language_score(decoded), alphabet, decoded))
    score, alphabet, decoded = max(candidates, key=lambda x: x[0])
    if score > 8:
        return AnalysisCandidate(
            "Atbash Cipher",
            confidence_from_score(score, 45),
            f"Reversed alphabet length: {len(alphabet)}",
            decoded,
            "Reversing the alphabet produced the most readable candidate text.",
        )
    return None


def analyze_vigenere(text: str) -> AnalysisCandidate | None:
    best = None
    for alphabet in (ENGLISH_ALPHABET, TURKISH_ALPHABET):
        for key in COMMON_VIGENERE_KEYS:
            try:
                decoded = vigenere_cipher(text, key, alphabet, decrypt=True)
                score = language_score(decoded)
                if best is None or score > best[0]:
                    best = (score, alphabet, key, decoded)
            except Exception:
                pass
    if not best:
        return None
    score, alphabet, key, decoded = best
    key_len = guess_vigenere_key_length(text, alphabet)
    if score > 12:
        parameters = f"Possible key: {key}"
        if key_len:
            parameters += f"; likely key length: {key_len}"
        return AnalysisCandidate(
            "Vigenère Cipher",
            confidence_from_score(score, 40),
            parameters,
            decoded,
            "Dictionary key trials and repeated-pattern analysis produced a readable candidate.",
        )
    if key_len >= 3:
        return AnalysisCandidate(
            "Vigenère Cipher",
            54,
            f"Likely key length: {key_len}",
            "More ciphertext is needed for a stronger key guess.",
            "Index of coincidence suggests a repeating-key substitution may be present.",
        )
    return None


def analyze_rail_fence(text: str) -> AnalysisCandidate | None:
    best = None
    for rails in range(2, 7):
        try:
            decoded = rail_fence_decrypt(text, rails)
            score = language_score(decoded)
            if best is None or score > best[0]:
                best = (score, rails, decoded)
        except Exception:
            pass
    if best and best[0] > 9:
        score, rails, decoded = best
        return AnalysisCandidate(
            "Rail Fence Cipher",
            confidence_from_score(score, 38),
            f"Detected rails: {rails}",
            decoded,
            "Trying common rail counts produced a readable zigzag transposition candidate.",
        )
    return None


def analyze_affine(text: str) -> AnalysisCandidate | None:
    best = None
    for alphabet in (ENGLISH_ALPHABET, TURKISH_ALPHABET):
        m = len(alphabet)
        for a in range(1, m):
            if gcd(a, m) != 1:
                continue
            for b in range(m):
                try:
                    decoded = affine_decrypt(text, a, b, alphabet)
                    score = language_score(decoded)
                    if best is None or score > best[0]:
                        best = (score, alphabet, a, b, decoded)
                except Exception:
                    pass
    if best and best[0] > 12:
        score, alphabet, a, b, decoded = best
        return AnalysisCandidate(
            "Affine Cipher",
            confidence_from_score(score, 36),
            f"a={a}, b={b}, mod={len(alphabet)}",
            decoded,
            "Affine parameter brute-force found a candidate with the strongest language score.",
        )
    return None


def analyze_xor_shape(text: str) -> AnalysisCandidate | None:
    stripped = text.strip()
    if len(stripped) >= 8 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", stripped):
        return AnalysisCandidate(
            "XOR Cipher",
            35,
            "CipherLab stores XOR output as Base64",
            "A key or known plaintext clue is required.",
            "The text could be XOR output, but XOR cannot be reliably decrypted without the key.",
        )
    return None


def run_cipher_ai_analysis(text: str) -> list[dict]:
    analyzers = [
        analyze_morse,
        analyze_binary,
        analyze_base64,
        analyze_rot13,
        analyze_caesar,
        analyze_atbash,
        analyze_vigenere,
        analyze_rail_fence,
        analyze_affine,
        analyze_xor_shape,
    ]
    results: list[AnalysisCandidate] = []
    seen = set()
    for analyzer in analyzers:
        candidate = analyzer(text)
        if candidate and candidate.cipher not in seen:
            results.append(candidate)
            seen.add(candidate.cipher)
    return [asdict(item) for item in sorted(results, key=lambda item: item.confidence, reverse=True)]
