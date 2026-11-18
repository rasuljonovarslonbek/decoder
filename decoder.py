#!/usr/bin/env python3
import sys
import base64
import binascii
import codecs
import urllib.parse
import string

# ANSI Color Codes for terminal styling
CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BOLD = '\033[1m'
DIM = '\033[2m'
RESET = '\033[0m'

BANNER = f"""{CYAN}{BOLD}
 ███████╗███████╗██╗  ██╗
 ╚══███╔╝██╔════╝██║  ██║
   ███╔╝ ███████╗███████║
  ███╔╝  ╚════██║██╔══██║
 ███████╗███████║██║  ██║
 ╚══════╝╚══════╝╚═╝  ╚═╝
{YELLOW}  >> CTF Multi-Decoder & Cipher Identifier <<{RESET}
"""

def is_mostly_printable(text, threshold=0.85):
    """Checks if the decoded output is readable ASCII text."""
    if not text:
        return False
    printable_chars = set(string.printable)
    printable_count = sum(1 for c in text if c in printable_chars)
    return (printable_count / len(text)) >= threshold

def highlight_flag(text):
    """Highlights common CTF flag patterns if detected."""
    lower = text.lower()
    keywords = ['flag{', 'ctf{', 'htb{', 'thm{', 'picoctf{', 'zsh{']
    for kw in keywords:
        if kw in lower:
            return f"{GREEN}{BOLD}[FLAG DETECTED]{RESET} {GREEN}{text}{RESET}"
    return text

def try_base64(data):
    try:
        padded = data + '=' * ((4 - len(data) % 4) % 4)
        res = base64.b64decode(padded, validate=False).decode('utf-8', errors='ignore')
        if res and res != data and is_mostly_printable(res):
            return ("Base64", "64-character radix encoding (A-Z, a-z, 0-9, +, /)", res)
    except Exception:
        pass
    return None

def try_base32(data):
    try:
        clean = data.upper().replace(' ', '')
        padded = clean + '=' * ((8 - len(clean) % 8) % 8)
        res = base64.b32decode(padded).decode('utf-8', errors='ignore')
        if res and is_mostly_printable(res):
            return ("Base32", "32-character radix encoding (A-Z and 2-7)", res)
    except Exception:
        pass
    return None

def try_base85(data):
    results = []
    # Try Ascii85
    try:
        res = base64.a85decode(data).decode('utf-8', errors='ignore')
        if res and is_mostly_printable(res):
            results.append(("Base85 (ASCII85)", "High-density 85-character ASCII encoding", res))
    except Exception:
        pass
    # Try standard b85
    try:
        res = base64.b85decode(data).decode('utf-8', errors='ignore')
        if res and is_mostly_printable(res):
            results.append(("Base85 (RFC 1924)", "Base85 encoding commonly used in Git/CTF payloads", res))
    except Exception:
        pass
    return results

def try_hex(data):
    try:
        clean = data.replace(' ', '').replace('0x', '').replace('\\x', '').replace(':', '')
        if all(c in string.hexdigits for c in clean) and len(clean) % 2 == 0 and len(clean) >= 4:
            res = bytes.fromhex(clean).decode('utf-8', errors='ignore')
            if res and is_mostly_printable(res):
                return ("Hexadecimal (Base16)", "Byte representation using characters 0-9 and A-F", res)
    except Exception:
        pass
    return None

def try_binary(data):
    try:
        clean = data.replace(' ', '')
        if set(clean).issubset({'0', '1'}) and len(clean) >= 8 and len(clean) % 8 == 0:
            chars = [chr(int(clean[i:i+8], 2)) for i in range(0, len(clean), 8)]
            res = ''.join(chars)
            if is_mostly_printable(res):
                return ("Binary (8-bit ASCII)", "Base-2 bit stream grouped into 8-bit bytes", res)
    except Exception:
        pass
    return None

def try_decimal_octal(data):
    results = []
    parts = data.strip().split()
    if len(parts) > 1:
        # Decimal check
        if all(p.isdigit() for p in parts):
            try:
                res = ''.join(chr(int(p)) for p in parts)
                if is_mostly_printable(res):
                    results.append(("Decimal ASCII", "Space-separated Base-10 ASCII character codes", res))
            except Exception:
                pass
        # Octal check
        if all(all(c in '01234567' for c in p) for p in parts):
            try:
                res = ''.join(chr(int(p, 8)) for p in parts)
                if is_mostly_printable(res):
                    results.append(("Octal ASCII", "Space-separated Base-8 ASCII character codes", res))
            except Exception:
                pass
    return results

def try_url(data):
    if '%' in data or '+' in data:
        res = urllib.parse.unquote_plus(data)
        if res != data and is_mostly_printable(res):
            return ("URL Encoding", "Percent-encoded characters used in HTTP URIs", res)
    return None

def try_rot13(data):
    if any(c.isalpha() for c in data):
        res = codecs.decode(data, 'rot_13')
        if res != data:
            return ("ROT13", "Caesar cipher substitution shifted by 13 positions", res)
    return None

def try_rot47(data):
    res = []
    for char in data:
        code = ord(char)
        if 33 <= code <= 126:
            res.append(chr(33 + ((code + 14) % 94)))
        else:
            res.append(char)
    decoded = ''.join(res)
    if decoded != data:
        return ("ROT47", "ASCII shift by 47 positions covering symbols, numbers, and letters", decoded)
    return None

def try_atbash(data):
    if any(c.isalpha() for c in data):
        res = []
        for char in data:
            if char.isupper():
                res.append(chr(90 - (ord(char) - 65)))
            elif char.islower():
                res.append(chr(122 - (ord(char) - 97)))
            else:
                res.append(char)
        return ("Atbash Cipher", "Monoalphabetic substitution reversing the alphabet (A<->Z)", ''.join(res))
    return None

def try_morse(data):
    MORSE_DICT = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
        '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
        '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
        '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
        '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
        '---..': '8', '----.': '9', '/': ' ', '-.-.--': '!', '.-.-.-': '.', '--..--': ','
    }
    allowed = {'.', '-', ' ', '/'}
    if set(data.strip()).issubset(allowed) and ('.' in data or '-' in data):
        tokens = data.strip().split(' ')
        res = ''.join(MORSE_DICT.get(t, '?') for t in tokens if t)
        return ("Morse Code", "Telecommunication encoding using dots (.) and dashes (-)", res)
    return None

def caesar_bruteforce(data):
    results = []
    if not any(c.isalpha() for c in data):
        return results
    for shift in range(1, 26):
        if shift == 13:
            continue  # Already covered by ROT13
        shifted = []
        for char in data:
            if char.isupper():
                shifted.append(chr((ord(char) - 65 - shift) % 26 + 65))
            elif char.islower():
                shifted.append(chr((ord(char) - 97 - shift) % 26 + 97))
            else:
                shifted.append(char)
        results.append((f"ROT-{shift:02d}", ''.join(shifted)))
    return results

def analyze_payload(payload):
    print(BANNER)
    print(f"{BOLD}Input Payload:{RESET} {YELLOW}{payload}{RESET}\n")
    print(f"{CYAN}{'='*65}{RESET}")
    print(f"{BOLD}[+] DIRECT ENCODING & CIPHER MATCHES{RESET}")
    print(f"{CYAN}{'='*65}{RESET}")

    detectors = [
        try_base64, try_base32, try_hex, try_binary,
        try_url, try_morse, try_rot13, try_rot47, try_atbash
    ]

    matches = []
    for detector in detectors:
        res = detector(payload)
        if res:
            matches.append(res)

    for multi_detector in (try_base85, try_decimal_octal):
        res_list = multi_detector(payload)
        if res_list:
            matches.extend(res_list)

    # Always append Reverse String
    if len(payload) > 1:
        matches.append(("Reverse String", "Payload character order reversed backwards", payload[::-1]))

    for name, info, output in matches:
        print(f"\n{GREEN}{BOLD}[*] Type:{RESET} {BOLD}{name}{RESET}")
        print(f"    {DIM}Info:{RESET} {info}")
        print(f"    {CYAN}Out :{RESET} {highlight_flag(output)}")

    # Caesar Cipher Bruteforce Table
    caesar_list = caesar_bruteforce(payload)
    if caesar_list:
        print(f"\n{CYAN}{'='*65}{RESET}")
        print(f"{BOLD}[+] CAESAR / ROT BRUTE-FORCE (SHIFTS 1-25){RESET}")
        print(f"{CYAN}{'='*65}{RESET}")
        for rot_name, res in caesar_list:
            flagged = highlight_flag(res)
            # Only print all shifts, highlighting any that trigger flag detection
            print(f"  {YELLOW}{rot_name}{RESET} : {flagged}")

    print(f"\n{CYAN}{'='*65}{RESET}\n")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        user_input = " ".join(sys.argv[1:])
    else:
        print(BANNER)
        try:
            user_input = input(f"{BOLD}Enter CTF code/cipher to decode > {RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)

    if user_input:
        analyze_payload(user_input)
    else:
        print(f"{RED}[!] Error: No input provided.{RESET}")