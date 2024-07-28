from functools import lru_cache
import re

# Combine all algorithms into a single dictionary
ALL_ALGORITHMS = {
    "encryption": {
        "AES": r"AES",
        "CHACHA20": r"CHACHA20",
        "3DES": r"3DES|DES-EDE3",
        "CAMELLIA": r"CAMELLIA",
        "ARIA": r"ARIA",
        "SEED": r"SEED",
        "SM4": r"SM4",
        "IDEA": r"IDEA",
        "RC4": r"RC4",
    },
    "key_exchange": {
        "ECDHE": r"ECDHE|EECDH",
        "DHE": r"DHE|EDH",
        "ECDH": r"ECDH",
        "DH": r"DH",
        "RSA": r"RSA",
        "PSK": r"PSK",
        "SRP": r"SRP",
        "GOST": r"GOST",
        "ECCPWD": r"ECCPWD",
        "SM2": r"SM2",
    },
    "mac": {
        "SHA384": r"SHA384",
        "SHA256": r"SHA256",
        "SHA224": r"SHA224",
        "SHA": r"SHA1?",
        "MD5": r"MD5",
        "POLY1305": r"POLY1305",
        "AEAD": r"GCM|CCM|OCB",
        "GOST": r"GOST28147|GOST34\.11",
        "SM3": r"SM3",
    },
}

# Compile all regular expressions
for category in ALL_ALGORITHMS.values():
    for alg, pattern in category.items():
        category[alg] = re.compile(pattern)


@lru_cache(maxsize=128)
def parse_cipher_suite(cipher_suite):
    result = {"encryption": "Unknown", "key_exchange": "Unknown", "mac": "Unknown"}

    for category, algorithms in ALL_ALGORITHMS.items():
        for alg, pattern in algorithms.items():
            if pattern.search(cipher_suite):
                result[category] = alg
                break

    return result
