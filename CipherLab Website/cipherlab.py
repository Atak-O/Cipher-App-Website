"""
CipherLab - Terminal Encryption Toolkit
Developed by Atakan Özden

Features:
- Caesar Cipher
- Vigenere Cipher
- Atbash Cipher
- ROT13
- Morse Code
- Base64 Encode/Decode
- Binary / ASCII Encode/Decode
- XOR Cipher
- Rail Fence Cipher
- Affine Cipher

Recommended:
    pip install rich

Run:
    python cipherlab.py
"""

from __future__ import annotations

import base64
import os
import re
import sys
from dataclasses import dataclass
from typing import Callable

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, IntPrompt
    from rich.text import Text
    from rich.align import Align
except ImportError:
    print("CipherLab için 'rich' kütüphanesi gerekli.")
    print("Kurulum: pip install rich")
    sys.exit(1)

console = Console()

# -----------------------------
# Design / UX settings
# Palette:
# cyan: primary action
# magenta: brand accent
# green: success
# yellow: warning
# red: error
# dim: helper text
# -----------------------------

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
    "/": "-..-.", "@": ".--.-.", " ": "/"
}
REVERSE_MORSE = {value: key for key, value in MORSE_CODE.items()}


@dataclass
class ToolItem:
    number: int
    name: str
    description: str
    action: Callable[[], None]


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def show_logo() -> None:
    logo = r"""
  ______ _       _               _          _     
 / _____(_)     | |             | |        | |    
| /     _ ____  | |__   _____  _| |     ___| |__  
| |    | |  _ \ | '_ \ / _ \ \/ / |    / _ \ '_ \ 
| \____| | |_) || | | |  __/>  <| |___|  __/ |_) |
 \_____)_|  __/ |_| |_|\___/_/\_\_____/\___|_.__/ 
         | |                                      
         |_|                                      
"""
    console.print(Panel.fit(
        Align.center(Text(logo, style="bold cyan") + Text("\nTerminal Encryption Toolkit", style="bold magenta")),
        border_style="cyan",
        padding=(1, 2),
    ))


def pause() -> None:
    console.print()
    Prompt.ask("[dim]Devam etmek için Enter'a bas[/dim]", default="")


def result_panel(title: str, result: str) -> None:
    console.print()
    console.print(Panel(
        Text(result, style="bold green"),
        title=f"[bold cyan]{title}[/bold cyan]",
        border_style="green",
        padding=(1, 2),
    ))


def error(message: str) -> None:
    console.print(Panel(f"[bold red]{message}[/bold red]", title="Hata", border_style="red"))


def ask_text(label: str = "Metin") -> str:
    while True:
        text = Prompt.ask(f"[bold cyan]{label}[/bold cyan]")
        if text.strip():
            return text
        error("Boş metin girilemez.")


def choose_alphabet() -> str:
    console.print("\n[bold cyan]Alfabe seç[/bold cyan]")
    console.print("[cyan]1[/cyan] Türkçe alfabe  [dim](ABCÇ...ÜVYZ)[/dim]")
    console.print("[cyan]2[/cyan] İngilizce alfabe [dim](A-Z)[/dim]")
    choice = Prompt.ask("Seçim", choices=["1", "2"], default="1")
    return TURKISH_ALPHABET if choice == "1" else ENGLISH_ALPHABET


def preserve_case(original: str, encrypted: str) -> str:
    return encrypted.lower() if original.islower() else encrypted


# -----------------------------
# Ciphers
# -----------------------------

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
        raise ValueError("Anahtar, seçilen alfabeden en az bir harf içermeli.")

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
    unsupported = []
    for char in text.upper():
        if char in MORSE_CODE:
            encoded.append(MORSE_CODE[char])
        elif char in "ÇĞİÖŞÜ":
            unsupported.append(char)
        else:
            encoded.append(char)
    if unsupported:
        console.print(f"[yellow]Uyarı:[/yellow] Morse sözlüğünde bazı Türkçe karakterler yok: {', '.join(sorted(set(unsupported)))}")
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
        raise ValueError("Geçerli bir Base64 metni girilmedi.") from exc


def text_to_binary(text: str) -> str:
    return " ".join(format(byte, "08b") for byte in text.encode("utf-8"))


def binary_to_text(binary: str) -> str:
    compact = binary.replace(" ", "")
    if len(compact) % 8 != 0 or not re.fullmatch(r"[01]+", compact):
        raise ValueError("Binary metin sadece 0/1 içermeli ve 8'in katı uzunlukta olmalı.")
    data = bytes(int(compact[i:i + 8], 2) for i in range(0, len(compact), 8))
    return data.decode("utf-8")


def xor_cipher(text: str, key: str) -> str:
    if not key:
        raise ValueError("XOR anahtarı boş olamaz.")
    encrypted_bytes = bytes(
        char ^ key.encode("utf-8")[i % len(key.encode("utf-8"))]
        for i, char in enumerate(text.encode("utf-8"))
    )
    return base64.b64encode(encrypted_bytes).decode("utf-8")


def xor_decipher(encoded: str, key: str) -> str:
    if not key:
        raise ValueError("XOR anahtarı boş olamaz.")
    try:
        encrypted_bytes = base64.b64decode(encoded.encode("utf-8"), validate=True)
        key_bytes = key.encode("utf-8")
        decrypted = bytes(byte ^ key_bytes[i % len(key_bytes)] for i, byte in enumerate(encrypted_bytes))
        return decrypted.decode("utf-8")
    except Exception as exc:
        raise ValueError("XOR çözme başarısız. Metin veya anahtar hatalı olabilir.") from exc


def rail_fence_encrypt(text: str, rails: int) -> str:
    if rails < 2:
        raise ValueError("Rail sayısı en az 2 olmalı.")
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
        raise ValueError("Rail sayısı en az 2 olmalı.")
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
    raise ValueError("a değerinin modüler tersi yok. Başka bir a seç.")


def affine_encrypt(text: str, a: int, b: int, alphabet: str) -> str:
    m = len(alphabet)
    if gcd(a, m) != 1:
        raise ValueError(f"a ile alfabe uzunluğu aralarında asal olmalı. Alfabe uzunluğu: {m}")
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


# -----------------------------
# UX wrappers
# -----------------------------

def show_tool_header(name: str, desc: str) -> None:
    clear_screen()
    show_logo()
    console.print(Panel(f"[bold magenta]{name}[/bold magenta]\n[dim]{desc}[/dim]", border_style="magenta"))


def action_caesar() -> None:
    show_tool_header("Caesar Cipher", "Harfleri belirli bir sayı kadar kaydırır.")
    alphabet = choose_alphabet()
    mode = Prompt.ask("İşlem", choices=["şifrele", "çöz"], default="şifrele")
    text = ask_text()
    shift = IntPrompt.ask("Kaydırma miktarı", default=3)
    result = caesar_cipher(text, shift, alphabet, decrypt=(mode == "çöz"))
    result_panel("Sonuç", result)
    pause()


def action_vigenere() -> None:
    show_tool_header("Vigenère Cipher", "Anahtar kelimeyle her harfi farklı miktarda kaydırır.")
    alphabet = choose_alphabet()
    mode = Prompt.ask("İşlem", choices=["şifrele", "çöz"], default="şifrele")
    text = ask_text()
    key = ask_text("Anahtar")
    try:
        result = vigenere_cipher(text, key, alphabet, decrypt=(mode == "çöz"))
        result_panel("Sonuç", result)
    except ValueError as exc:
        error(str(exc))
    pause()


def action_atbash() -> None:
    show_tool_header("Atbash Cipher", "Alfabeyi ters çevirir: A ↔ Z gibi.")
    alphabet = choose_alphabet()
    text = ask_text()
    result_panel("Sonuç", atbash_cipher(text, alphabet))
    pause()


def action_rot13() -> None:
    show_tool_header("ROT13", "İngilizce alfabede 13 kaydırmalı özel Caesar türü.")
    text = ask_text()
    result_panel("Sonuç", caesar_cipher(text, 13, ENGLISH_ALPHABET))
    pause()


def action_morse() -> None:
    show_tool_header("Morse Code", "Metni nokta ve çizgilere çevirir veya geri çözer.")
    mode = Prompt.ask("İşlem", choices=["şifrele", "çöz"], default="şifrele")
    text = ask_text("Morse kodu" if mode == "çöz" else "Metin")
    result = morse_decode(text) if mode == "çöz" else morse_encode(text)
    result_panel("Sonuç", result)
    pause()


def action_base64() -> None:
    show_tool_header("Base64", "Metni güvenli taşınabilir kod biçimine çevirir. Gerçek şifreleme değildir.")
    mode = Prompt.ask("İşlem", choices=["kodla", "çöz"], default="kodla")
    text = ask_text("Base64 metni" if mode == "çöz" else "Metin")
    try:
        result = base64_decode(text) if mode == "çöz" else base64_encode(text)
        result_panel("Sonuç", result)
    except ValueError as exc:
        error(str(exc))
    pause()


def action_binary() -> None:
    show_tool_header("Binary / ASCII", "Metni 0 ve 1'lere çevirir veya geri çözer.")
    mode = Prompt.ask("İşlem", choices=["kodla", "çöz"], default="kodla")
    text = ask_text("Binary" if mode == "çöz" else "Metin")
    try:
        result = binary_to_text(text) if mode == "çöz" else text_to_binary(text)
        result_panel("Sonuç", result)
    except ValueError as exc:
        error(str(exc))
    pause()


def action_xor() -> None:
    show_tool_header("XOR Cipher", "Anahtar ile byte seviyesinde şifreleme yapar. Sonuç Base64 olarak gösterilir.")
    mode = Prompt.ask("İşlem", choices=["şifrele", "çöz"], default="şifrele")
    text = ask_text("Şifreli Base64 metni" if mode == "çöz" else "Metin")
    key = ask_text("Anahtar")
    try:
        result = xor_decipher(text, key) if mode == "çöz" else xor_cipher(text, key)
        result_panel("Sonuç", result)
    except ValueError as exc:
        error(str(exc))
    pause()


def action_rail_fence() -> None:
    show_tool_header("Rail Fence Cipher", "Metni zikzak ray sistemine göre yer değiştirerek şifreler.")
    mode = Prompt.ask("İşlem", choices=["şifrele", "çöz"], default="şifrele")
    text = ask_text()
    rails = IntPrompt.ask("Ray sayısı", default=3)
    try:
        result = rail_fence_decrypt(text, rails) if mode == "çöz" else rail_fence_encrypt(text, rails)
        result_panel("Sonuç", result)
    except ValueError as exc:
        error(str(exc))
    pause()


def action_affine() -> None:
    show_tool_header("Affine Cipher", "Matematiksel formül kullanır: E(x) = (a*x + b) mod m.")
    alphabet = choose_alphabet()
    mode = Prompt.ask("İşlem", choices=["şifrele", "çöz"], default="şifrele")
    text = ask_text()
    console.print("[dim]İpucu: İngilizce alfabe için a=5, b=8 klasik bir örnektir.[/dim]")
    a = IntPrompt.ask("a değeri", default=5)
    b = IntPrompt.ask("b değeri", default=8)
    try:
        result = affine_decrypt(text, a, b, alphabet) if mode == "çöz" else affine_encrypt(text, a, b, alphabet)
        result_panel("Sonuç", result)
    except ValueError as exc:
        error(str(exc))
    pause()


# -----------------------------
# CipherLab AI Assistant
# Heuristic cryptanalysis system
# -----------------------------

COMMON_WORDS = [
    "THE", "AND", "YOU", "THAT", "HAVE", "FOR", "WITH", "HELLO", "WORLD", "SECRET",
    "MERHABA", "DUNYA", "BEN", "SEN", "BIR", "VE", "BU", "ILE", "ICIN", "SIFRE", "GIZLI",
    "OKUL", "MATEMATIK", "PYTHON", "PROJE", "CIPHER", "LAB"
]

COMMON_VIGENERE_KEYS = [
    "DUNYA", "GIZ", "GIZEM", "KEDI", "ANAHTAR", "SIFRE", "OKUL", "PYTHON", "PROJE",
    "CIPHER", "LAB", "SECRET", "WORLD", "HELLO", "MATH", "AI"
]


@dataclass
class AnalysisCandidate:
    cipher: str
    confidence: int
    details: str
    preview: str


def clean_letters(text: str, alphabet: str = ENGLISH_ALPHABET) -> str:
    return "".join(ch.upper() for ch in text if ch.upper() in alphabet)


def language_score(text: str) -> float:
    """Simple readability score for Turkish/English-like plaintext."""
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
    return max(1, min(99, int(base + score * 2.2)))


def preview(text: str, limit: int = 120) -> str:
    text = text.replace("\n", " ").strip()
    return text if len(text) <= limit else text[:limit] + "..."


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
    best_ioc = 0
    for key_len in range(1, min(max_len, len(letters)) + 1):
        groups = [letters[i::key_len] for i in range(key_len)]
        avg_ioc = sum(index_of_coincidence(group, alphabet) for group in groups) / key_len
        if avg_ioc > best_ioc:
            best_ioc = avg_ioc
            best_len = key_len
    return best_len


def analyze_morse(text: str) -> AnalysisCandidate | None:
    stripped = text.strip()
    if not stripped:
        return None
    morse_chars = set(".-/ ")
    if all(ch in morse_chars for ch in stripped) and any(ch in ".-" for ch in stripped):
        decoded = morse_decode(stripped)
        unknowns = decoded.count("?")
        confidence = max(60, 98 - unknowns * 8)
        return AnalysisCandidate("Morse Code", confidence, "Metin sadece nokta, çizgi, boşluk ve / karakterlerinden oluşuyor.", decoded)
    return None


def analyze_binary(text: str) -> AnalysisCandidate | None:
    compact = text.replace(" ", "").strip()
    if compact and re.fullmatch(r"[01]+", compact) and len(compact) % 8 == 0:
        try:
            decoded = binary_to_text(text)
            return AnalysisCandidate("Binary / ASCII", 97, "Metin yalnızca 0 ve 1 içeriyor ve 8 bitlik bloklara ayrılabiliyor.", decoded)
        except Exception:
            return AnalysisCandidate("Binary / ASCII", 72, "Binary formatına benziyor ama UTF-8 metne çevrilirken sorun oluştu.", "Çözüm başarısız")
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
        confidence = 88 if score > 5 else 70
        return AnalysisCandidate("Base64", confidence, "Karakter seti ve uzunluk Base64 formatına uyuyor. Not: Base64 şifreleme değil, kodlamadır.", decoded)
    except Exception:
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
    direction = f"-{shift} geri" if shift else "0"
    return AnalysisCandidate(
        "Caesar Cipher",
        confidence_from_score(score, 48),
        f"En anlamlı çözüm {len(alphabet)} harfli alfabe ile {direction} kaydırmada bulundu. Şifreleme yönü muhtemelen +{shift} ileri.",
        decoded,
    )


def analyze_rot13(text: str) -> AnalysisCandidate | None:
    decoded = caesar_cipher(text, 13, ENGLISH_ALPHABET)
    score = language_score(decoded)
    if score > 10:
        return AnalysisCandidate("ROT13", confidence_from_score(score, 52), "ROT13, Caesar Cipher'ın 13 kaydırmalı özel halidir.", decoded)
    return None


def analyze_atbash(text: str) -> AnalysisCandidate | None:
    candidates = []
    for alphabet in (ENGLISH_ALPHABET, TURKISH_ALPHABET):
        decoded = atbash_cipher(text, alphabet)
        candidates.append((language_score(decoded), alphabet, decoded))
    score, alphabet, decoded = max(candidates, key=lambda x: x[0])
    if score > 8:
        return AnalysisCandidate("Atbash Cipher", confidence_from_score(score, 45), f"Alfabe tersleme denemesi anlamlı çıktı. Kullanılan alfabe uzunluğu: {len(alphabet)}.", decoded)
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
        return AnalysisCandidate("Rail Fence Cipher", confidence_from_score(score, 38), f"Zikzak çözüm denemelerinde en iyi sonuç {rails} ray ile bulundu.", decoded)
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
        return AnalysisCandidate("Affine Cipher", confidence_from_score(score, 36), f"En iyi matematiksel çözüm: a={a}, b={b}, mod={len(alphabet)}.", decoded)
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
        extra = f"Tahmini anahtar: {key}."
        if key_len:
            extra += f" Metindeki tekrar yapısına göre olası anahtar uzunluğu: {key_len}."
        return AnalysisCandidate("Vigenère Cipher", confidence_from_score(score, 40), extra, decoded)
    if key_len >= 3:
        return AnalysisCandidate("Vigenère Cipher", 54, f"Kesin anahtar bulunamadı; tekrar yapısı Vigenère'e benzeyebilir. Olası anahtar uzunluğu: {key_len}.", "Daha uzun metin verilirse anahtar tahmini güçlenir.")
    return None


def analyze_xor_shape(text: str) -> AnalysisCandidate | None:
    stripped = text.strip()
    if len(stripped) >= 8 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", stripped):
        return AnalysisCandidate("XOR Cipher", 35, "XOR çıktısı bu programda Base64 olarak saklanır. Anahtar bilinmeden güvenilir çözüm yapmak zordur.", "Anahtar tahmini için bilinen kelime/ipuçları gerekir.")
    return None


def run_cipher_ai_analysis(text: str) -> list[AnalysisCandidate]:
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
    return sorted(results, key=lambda item: item.confidence, reverse=True)


def show_ai_result(results: list[AnalysisCandidate]) -> None:
    if not results:
        console.print(Panel(
            "[yellow]Belirgin bir şifreleme türü yakalanamadı.[/yellow]\n\n"
            "Daha uzun bir metin verirsen Caesar/Vigenère gibi yöntemlerde tahmin çok daha iyi çalışır.",
            title="AI Assistant Sonucu",
            border_style="yellow",
        ))
        return

    best = results[0]
    console.print(Panel(
        f"[bold green]Muhtemel tür:[/bold green] {best.cipher}\n"
        f"[bold green]Güven skoru:[/bold green] %{best.confidence}\n"
        f"[bold green]Tahmin detayı:[/bold green] {best.details}\n\n"
        f"[bold cyan]Olası çözüm / yorum:[/bold cyan]\n{best.preview}",
        title="CipherLab AI Assistant",
        border_style="green",
        padding=(1, 2),
    ))

    if len(results) > 1:
        table = Table(title="Diğer Olasılıklar", border_style="cyan", header_style="bold magenta")
        table.add_column("Sıra", justify="center", style="cyan", width=5)
        table.add_column("Tür")
        table.add_column("Güven", justify="center")
        table.add_column("Kısa Önizleme")
        for index, item in enumerate(results[1:5], start=2):
            table.add_row(str(index), item.cipher, f"%{item.confidence}", preview(item.preview, 55))
        console.print(table)


def show_ai_explainer() -> None:
    console.print(Panel(
        "[bold cyan]Bu mod ne yapar?[/bold cyan]\n"
        "Şifreli metindeki karakter yapısı, tekrarlar, olası çözümler ve okunabilirlik skorunu inceler.\n\n"
        "[bold yellow]Önemli:[/bold yellow] Bu bir kriptanaliz asistanıdır; her zaman kesin sonuç vermez. "
        "Özellikle Vigenère'de anahtar tahmini için metnin uzun olması gerekir.",
        title="Nasıl Çalışır?",
        border_style="cyan",
    ))


def action_ai_assistant() -> None:
    while True:
        clear_screen()
        show_logo()
        console.print(Panel(
            "[bold magenta]CipherLab AI Assistant[/bold magenta]\n"
            "Şifreli metni analiz eder, olası yöntemi ve varsa anahtar/kaydırma değerini tahmin eder.",
            border_style="magenta",
        ))

        table = Table(title="AI Assistant Menü", border_style="cyan", header_style="bold magenta")
        table.add_column("No", justify="center", style="bold cyan", width=5)
        table.add_column("İşlem", style="bold white")
        table.add_column("Açıklama", style="dim")
        table.add_row("1", "Şifreleme Türünü Tahmin Et", "Metni analiz edip en olası yöntemi bulur")
        table.add_row("2", "Nasıl Çalışır?", "Kısaca mantığını açıklar")
        table.add_row("0", "Ana Menüye Dön", "CipherLab ana menüsüne geri döner")
        console.print(table)

        choice = Prompt.ask("[bold cyan]Seçimin[/bold cyan]", choices=["1", "2", "0"], default="1")
        if choice == "0":
            return
        if choice == "2":
            show_ai_explainer()
            pause()
            continue

        encrypted_text = ask_text("Şifrelenmiş metin")
        console.print("\n[dim]Analiz ediliyor: biçim, frekans, okunabilirlik ve olası anahtarlar kontrol ediliyor...[/dim]")
        results = run_cipher_ai_analysis(encrypted_text)
        show_ai_result(results)
        pause()


def show_about() -> None:
    clear_screen()
    show_logo()
    about = """
[bold cyan]CipherLab[/bold cyan], klasik şifreleme yöntemlerini öğrenmek ve denemek için hazırlanmış terminal tabanlı bir araçtır.

[bold yellow]Not:[/bold yellow] Caesar, Vigenère, Atbash, Rail Fence ve Affine gibi yöntemler eğitim amaçlıdır.
Gerçek hayatta güvenli mesajlaşma için modern kriptografi gerekir.

[bold green]UX hedefleri:[/bold green]
- Net menü
- Anlaşılır hata mesajları
- Tekrarlanabilir akış
- Tutarlı renk paleti
- Kolay geri dönüş
"""
    console.print(Panel(about.strip(), title="Hakkında", border_style="cyan"))
    pause()


def main_menu() -> None:
    tools = [
        ToolItem(1, "Caesar Cipher", "Harf kaydırma", action_caesar),
        ToolItem(2, "Vigenère Cipher", "Anahtarlı harf kaydırma", action_vigenere),
        ToolItem(3, "Atbash Cipher", "Alfabe tersleme", action_atbash),
        ToolItem(4, "ROT13", "13 kaydırmalı Caesar", action_rot13),
        ToolItem(5, "CipherLab AI Assistant", "Şifreleme türü, anahtar ve kaydırma tahmini", action_ai_assistant),
        ToolItem(6, "Morse Code", "Nokta ve çizgi kodlama", action_morse),
        ToolItem(7, "Base64", "Metin kodlama", action_base64),
        ToolItem(8, "Binary / ASCII", "0 ve 1 dönüşümü", action_binary),
        ToolItem(9, "XOR Cipher", "Anahtarlı byte işlemi", action_xor),
        ToolItem(10, "Rail Fence Cipher", "Zikzak yer değiştirme", action_rail_fence),
        ToolItem(11, "Affine Cipher", "Matematiksel şifreleme", action_affine),
    ]

    while True:
        clear_screen()
        show_logo()
        console.print("[dim]Bir araç seç, metnini gir, sonucu al. Gereksiz karmaşa yok; kriptoloji zaten yeterince Matrix.[/dim]\n")

        table = Table(title="CipherLab Menü", border_style="cyan", header_style="bold magenta")
        table.add_column("No", justify="center", style="bold cyan", width=5)
        table.add_column("Araç", style="bold white")
        table.add_column("Açıklama", style="dim")

        for tool in tools:
            table.add_row(str(tool.number), tool.name, tool.description)
        table.add_row("99", "Hakkında", "Proje bilgisi ve notlar")
        table.add_row("0", "Çıkış", "Programı kapat")

        console.print(table)
        choice = Prompt.ask("[bold cyan]Seçimin[/bold cyan]", default="1")

        if choice == "0":
            console.print("\n[bold green]CipherLab kapatıldı. Şifreler çözüldü, sırlar şimdilik güvende.[/bold green]")
            break
        if choice == "99":
            show_about()
            continue

        selected = next((tool for tool in tools if str(tool.number) == choice), None)
        if selected:
            selected.action()
        else:
            error("Geçersiz seçim. Menüdeki numaralardan birini seç.")
            pause()


if __name__ == "__main__":
    main_menu()
