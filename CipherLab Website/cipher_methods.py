"""Reusable cipher implementations for CipherLab Web Edition."""

from __future__ import annotations

import base64
import re

TURKISH_ALPHABET = "ABCÇDEFGĞHIİJKLMNOÖPRSŞTUÜVYZ"
ENGLISH_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

MORSE_CODE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---", "3": "...--",
    "4": "....-", "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
    ".": ".-.-.-", ",": "--..--", "?": "..--..", "!": "-.-.--", ":": "---...",
    "'": ".----.", '"': ".-..-.", "(": "-.--.", ")": "-.--.-", "&": ".-...",
    ";": "-.-.-.", "=": "-...-", "+": ".-.-.", "-": "-....-", "_": "..--.-",
    "/": "-..-.", "@": ".--.-.", " ": "/",
}

REVERSE_MORSE = {value: key for key, value in MORSE_CODE.items()}


def get_alphabet(name: str = "english") -> str:
    return TURKISH_ALPHABET if name == "turkish" else ENGLISH_ALPHABET


def preserve_case(original: str, encrypted: str) -> str:
    return encrypted.lower() if original.islower() else encrypted


def caesar_cipher(text: str, shift: int, alphabet: str, decrypt: bool = False) -> str:
    if decrypt:
        shift = -shift
    result = []
    for char in text:
        upper = char.upper()
        if upper in alphabet:
            new_index = (alphabet.index(upper) + shift) % len(alphabet)
            result.append(preserve_case(char, alphabet[new_index]))
        else:
            result.append(char)
    return "".join(result)


def vigenere_cipher(text: str, key: str, alphabet: str, decrypt: bool = False) -> str:
    clean_key = "".join(ch.upper() for ch in key if ch.upper() in alphabet)
    if not clean_key:
        raise ValueError("The key must include at least one letter from the selected alphabet.")

    result = []
    key_index = 0
    for char in text:
        upper = char.upper()
        if upper in alphabet:
            shift = alphabet.index(clean_key[key_index % len(clean_key)])
            if decrypt:
                shift = -shift
            new_index = (alphabet.index(upper) + shift) % len(alphabet)
            result.append(preserve_case(char, alphabet[new_index]))
            key_index += 1
        else:
            result.append(char)
    return "".join(result)


def atbash_cipher(text: str, alphabet: str) -> str:
    reversed_alphabet = alphabet[::-1]
    result = []
    for char in text:
        upper = char.upper()
        if upper in alphabet:
            result.append(preserve_case(char, reversed_alphabet[alphabet.index(upper)]))
        else:
            result.append(char)
    return "".join(result)


def morse_encode(text: str) -> str:
    encoded = []
    for char in text.upper():
        encoded.append(MORSE_CODE.get(char, char))
    return " ".join(encoded)


def morse_decode(code: str) -> str:
    words = code.strip().split(" / ")
    decoded_words = []
    for word in words:
        letters = word.split()
        decoded_words.append("".join(REVERSE_MORSE.get(letter, "?") for letter in letters))
    return " ".join(decoded_words)


def base64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("utf-8")


def base64_decode(encoded: str) -> str:
    try:
        return base64.b64decode(encoded.encode("utf-8"), validate=True).decode("utf-8")
    except Exception as exc:
        raise ValueError("Enter a valid Base64 value.") from exc


def text_to_binary(text: str) -> str:
    return " ".join(format(byte, "08b") for byte in text.encode("utf-8"))


def binary_to_text(binary: str) -> str:
    compact = binary.replace(" ", "")
    if len(compact) % 8 != 0 or not re.fullmatch(r"[01]+", compact):
        raise ValueError("Binary input must contain only 0/1 and be divisible into 8-bit blocks.")
    data = bytes(int(compact[i:i + 8], 2) for i in range(0, len(compact), 8))
    return data.decode("utf-8")


def xor_cipher(text: str, key: str) -> str:
    if not key:
        raise ValueError("XOR key cannot be empty.")
    key_bytes = key.encode("utf-8")
    encrypted_bytes = bytes(
        char ^ key_bytes[i % len(key_bytes)]
        for i, char in enumerate(text.encode("utf-8"))
    )
    return base64.b64encode(encrypted_bytes).decode("utf-8")


def xor_decipher(encoded: str, key: str) -> str:
    if not key:
        raise ValueError("XOR key cannot be empty.")
    try:
        encrypted_bytes = base64.b64decode(encoded.encode("utf-8"), validate=True)
        key_bytes = key.encode("utf-8")
        decrypted = bytes(byte ^ key_bytes[i % len(key_bytes)] for i, byte in enumerate(encrypted_bytes))
        return decrypted.decode("utf-8")
    except Exception as exc:
        raise ValueError("XOR decryption failed. The text or key may be incorrect.") from exc


def rail_fence_encrypt(text: str, rails: int) -> str:
    if rails < 2:
        raise ValueError("Rail count must be at least 2.")
    fence = ["" for _ in range(rails)]
    rail = 0
    direction = 1
    for char in text:
        fence[rail] += char
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    return "".join(fence)


def rail_fence_decrypt(cipher: str, rails: int) -> str:
    if rails < 2:
        raise ValueError("Rail count must be at least 2.")
    pattern = []
    rail = 0
    direction = 1
    for _ in cipher:
        pattern.append(rail)
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1

    rail_lengths = [pattern.count(r) for r in range(rails)]
    rails_text = []
    index = 0
    for length in rail_lengths:
        rails_text.append(list(cipher[index:index + length]))
        index += length

    result = []
    rail_positions = [0] * rails
    for r in pattern:
        result.append(rails_text[r][rail_positions[r]])
        rail_positions[r] += 1
    return "".join(result)


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def mod_inverse(a: int, m: int) -> int:
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("The selected 'a' value has no modular inverse.")


def affine_encrypt(text: str, a: int, b: int, alphabet: str) -> str:
    m = len(alphabet)
    if gcd(a, m) != 1:
        raise ValueError(f"'a' must be coprime with the alphabet length ({m}).")
    result = []
    for char in text:
        upper = char.upper()
        if upper in alphabet:
            x = alphabet.index(upper)
            result.append(preserve_case(char, alphabet[(a * x + b) % m]))
        else:
            result.append(char)
    return "".join(result)


def affine_decrypt(text: str, a: int, b: int, alphabet: str) -> str:
    m = len(alphabet)
    inv = mod_inverse(a, m)
    result = []
    for char in text:
        upper = char.upper()
        if upper in alphabet:
            y = alphabet.index(upper)
            result.append(preserve_case(char, alphabet[(inv * (y - b)) % m]))
        else:
            result.append(char)
    return "".join(result)


def process_cipher(cipher_type: str, mode: str, text: str, params: dict) -> str:
    alphabet = get_alphabet(params.get("alphabet", "english"))
    decrypt = mode == "decrypt"

    if cipher_type == "caesar":
        forward_shift = int(params.get("shift") or 0)
        backward_shift = int(params.get("back") or 0)
        return caesar_cipher(text, forward_shift - backward_shift, alphabet, decrypt)
    if cipher_type == "vigenere":
        return vigenere_cipher(text, params.get("key", ""), alphabet, decrypt)
    if cipher_type == "atbash":
        return atbash_cipher(text, alphabet)
    if cipher_type == "rot13":
        return caesar_cipher(text, 13, ENGLISH_ALPHABET)
    if cipher_type == "morse":
        return morse_decode(text) if decrypt else morse_encode(text)
    if cipher_type == "base64":
        return base64_decode(text) if decrypt else base64_encode(text)
    if cipher_type == "binary":
        return binary_to_text(text) if decrypt else text_to_binary(text)
    if cipher_type == "xor":
        key = params.get("key", "")
        return xor_decipher(text, key) if decrypt else xor_cipher(text, key)
    if cipher_type == "rail_fence":
        rails = int(params.get("rails") or 3)
        return rail_fence_decrypt(text, rails) if decrypt else rail_fence_encrypt(text, rails)
    if cipher_type == "affine":
        a = int(params.get("a") or 5)
        b = int(params.get("b") or 8)
        return affine_decrypt(text, a, b, alphabet) if decrypt else affine_encrypt(text, a, b, alphabet)

    raise ValueError("Unsupported cipher type.")
