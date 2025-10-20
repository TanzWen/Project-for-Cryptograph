"""
RSA Algorithm Implementation
SC6104 - Introduction to Cryptography

This module implements the core RSA algorithm including:
- Helper functions (primality testing, GCD, modular inverse)
- Key generation
- Encryption and decryption
"""

import random
from typing import Tuple, Optional


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def is_prime(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin primality test.

    Args:
        n: Number to test for primality
        k: Number of rounds (higher = more accurate)

    Returns:
        True if n is probably prime, False if composite
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def gcd(a: int, b: int) -> int:
    """
    Compute the greatest common divisor using Euclidean algorithm.

    Args:
        a: First integer
        b: Second integer

    Returns:
        GCD of a and b
    """
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean algorithm.

    Returns (gcd, x, y) such that a*x + b*y = gcd
    """
    if a == 0:
        return b, 0, 1

    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1

    return gcd_val, x, y


def mod_inverse(a: int, m: int) -> Optional[int]:
    """
    Compute modular multiplicative inverse of a modulo m.

    Args:
        a: The number to invert
        m: The modulus

    Returns:
        x such that (a * x) % m == 1, or None if inverse doesn't exist
    """
    gcd_val, x, _ = extended_gcd(a, m)

    if gcd_val != 1:
        return None  # Modular inverse doesn't exist

    return (x % m + m) % m


def generate_prime(bits: int) -> int:
    """
    Generate a random prime number with specified bit length.

    Args:
        bits: Desired bit length of the prime

    Returns:
        A prime number of approximately 'bits' length
    """
    while True:
        # Generate random odd number in range
        n = random.getrandbits(bits)
        # Ensure it's odd and has the right bit length
        n |= (1 << bits - 1) | 1

        if is_prime(n):
            return n

def str2num(s: str) -> int:
    """
    Convert a string to an integer representation.

    Args:
        s: Input string

    Returns:
        Integer representation of the string
    """
    return int.from_bytes(s.encode('utf-8'), 'big')

def num2str(n: int) -> str:
    """
    Convert an integer back to a string representation.

    Args:
        n: Input integer

    Returns:
        String representation of the integer
    """
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, 'big').decode('utf-8')
# ============================================================================
# CORE RSA FUNCTIONS
# ============================================================================

def generate_keypair(bits: int = 1024) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    Generate an RSA keypair.

    Args:
        bits: Bit length for each prime (total modulus will be ~2*bits)

    Returns:
        ((e, n), (d, n)) - public key and private key
    """
    # Generate two distinct primes
    p = generate_prime(bits)
    q = generate_prime(bits)
    while p == q:
        q = generate_prime(bits)

    # Compute modulus
    n = p * q

    # Compute Euler's totient
    phi_n = (p - 1) * (q - 1)

    # Choose public exponent (commonly 65537)
    e = 65537
    while gcd(e, phi_n) != 1:
        e = random.randrange(3, phi_n, 2)

    # Compute private exponent
    d = mod_inverse(e, phi_n)

    return ((e, n), (d, n))


def encrypt(message: int, public_key: Tuple[int, int]) -> int:
    """
    Encrypt a message using RSA public key.

    Args:
        message: Integer message (must be < n)
        public_key: (e, n)

    Returns:
        Ciphertext c = m^e mod n
    """
    e, n = public_key
    return pow(message, e, n)


def decrypt(ciphertext: int, private_key: Tuple[int, int]) -> int:
    """
    Decrypt a ciphertext using RSA private key.

    Args:
        ciphertext: Encrypted message
        private_key: (d, n)

    Returns:
        Plaintext m = c^d mod n
    """
    d, n = private_key
    return pow(ciphertext, d, n)


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    print("RSA Algorithm Demo")
    print("=" * 80)
    # input("Press Enter to generate a new RSA keypair...")
    message = input("Enter a message to encrypt: ")
    bits = int(input("Enter key size in bits (e.g., 1024, 2048): "))
    print("*" * 80)
    print("*"+" "*78+"*")
    print("*"+" "*28+"Generating RSA keypair"+" "*28+"*")
    print("*"+" "*78+"*")
    print("*" * 80)
    # Generate keypair
    public_key, private_key = generate_keypair(bits)
    e, n = public_key
    d, _ = private_key

    print(f"Public key (e, n):")
    print(f"  e = {e}")
    print(f"  n = {n}")
    print(f"\nPrivate key (d, n):")
    print(f"  d = {d}")
    print()
    print("*" * 80)
    print("*"+" "*78+"*")
    print("*"+" "*30+"Encrypting message"+" "*30+"*")
    print("*"+" "*78+"*")
    print("*" * 80)
    # Test message
    print(f"Original message: {message}")
    message_num = str2num(message)
    print(f"Message as number: {message_num}")

    # Encrypt
    ciphertext = encrypt(message_num, public_key)
    print(f"Encrypted: {ciphertext}")
    print()
    print("*" * 80)
    print("*"+" "*78+"*")
    print("*"+" "*30+"decrypting message"+" "*30+"*")
    print("*"+" "*78+"*")
    print("*" * 80)
    # Decrypt
    decrypted_num = decrypt(ciphertext, private_key)
    decrypted = num2str(decrypted_num)
    print(f"Decrypted number: {decrypted_num}")
    print(f"Decrypted: {decrypted}")

    assert message == decrypted, "Decryption failed!"
    print("\n✓ Encryption/Decryption successful!")
