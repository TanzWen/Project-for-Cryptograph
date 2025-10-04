"""
RSA Algorithm Implementation

This module implements the RSA cryptosystem from scratch, including:
- Prime number generation
- Key pair generation
- Encryption and decryption

Author: Educational demonstration for cryptography study
"""

import random
import math


def is_prime(n, k=5):
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


def generate_prime(bits):
    """
    Generate a random prime number of specified bit length.

    Args:
        bits: Desired bit length of the prime

    Returns:
        A prime number of approximately 'bits' bits
    """
    while True:
        # Generate random odd number of desired bit length
        candidate = random.getrandbits(bits)
        # Ensure it has the correct bit length (MSB set)
        candidate |= (1 << bits - 1) | 1

        if is_prime(candidate):
            return candidate


def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm.

    Finds x, y such that ax + by = gcd(a, b)

    Args:
        a, b: Integers

    Returns:
        Tuple (gcd, x, y)
    """
    if a == 0:
        return b, 0, 1

    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1

    return gcd, x, y


def mod_inverse(e, phi):
    """
    Calculate modular multiplicative inverse of e modulo phi.

    Finds d such that (e * d) ≡ 1 (mod phi)

    Args:
        e: Public exponent
        phi: Euler's totient of n

    Returns:
        Private exponent d
    """
    gcd, x, _ = extended_gcd(e, phi)

    if gcd != 1:
        raise ValueError("Modular inverse does not exist")

    return x % phi


def generate_keypair(bits=512):
    """
    Generate an RSA public/private key pair.

    Args:
        bits: Bit length for each prime (total key size will be 2*bits)

    Returns:
        Tuple ((n, e), (n, d)) where:
            (n, e) is the public key
            (n, d) is the private key
    """
    # Generate two large distinct prime numbers
    print(f"Generating two {bits}-bit primes...")
    p = generate_prime(bits)
    q = generate_prime(bits)

    # Ensure p and q are distinct
    while p == q:
        q = generate_prime(bits)

    # Calculate modulus n = p * q
    n = p * q

    # Calculate Euler's totient: phi(n) = (p-1)(q-1)
    phi = (p - 1) * (q - 1)

    # Choose public exponent e (commonly 65537)
    # e must be coprime to phi
    e = 65537
    if math.gcd(e, phi) != 1:
        # Fallback to finding a suitable e
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2

    # Calculate private exponent d
    # d is the modular multiplicative inverse of e mod phi
    d = mod_inverse(e, phi)

    # Public key: (n, e)
    # Private key: (n, d)
    return (n, e), (n, d)


def generate_weak_keypair(bits=512):
    """
    Generate a WEAK RSA key pair where p and q are close together.

    This makes the key vulnerable to Fermat's factorization attack.

    Args:
        bits: Bit length for the primes

    Returns:
        Tuple ((n, e), (n, d), p, q) where:
            (n, e) is the public key
            (n, d) is the private key
            p, q are the prime factors (returned for verification)
    """
    print(f"Generating WEAK key with close primes (for demonstration)...")

    # Start from a random number and find consecutive primes
    base = random.getrandbits(bits) | (1 << bits - 1) | 1

    # Find first prime
    p = base
    while not is_prime(p):
        p += 2

    # Find next prime close to p
    q = p + 2
    while not is_prime(q):
        q += 2

    print(f"Prime p has {p.bit_length()} bits")
    print(f"Prime q has {q.bit_length()} bits")
    print(f"Difference |p - q| = {abs(p - q)}")

    # Calculate n and phi
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e and calculate d
    e = 65537
    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2

    d = mod_inverse(e, phi)

    return (n, e), (n, d), p, q


def encrypt(public_key, message):
    """
    Encrypt a message using RSA public key.

    Args:
        public_key: Tuple (n, e)
        message: Integer message (must be < n)

    Returns:
        Ciphertext c = m^e mod n
    """
    n, e = public_key

    if message >= n:
        raise ValueError("Message must be smaller than modulus n")

    # c = m^e mod n
    ciphertext = pow(message, e, n)
    return ciphertext


def decrypt(private_key, ciphertext):
    """
    Decrypt a ciphertext using RSA private key.

    Args:
        private_key: Tuple (n, d)
        ciphertext: Encrypted message

    Returns:
        Original message m = c^d mod n
    """
    n, d = private_key

    # m = c^d mod n
    message = pow(ciphertext, d, n)
    return message


if __name__ == "__main__":
    # Simple demonstration of RSA encryption/decryption
    print("="*60)
    print("RSA Algorithm Demonstration")
    print("="*60)

    # Generate keypair
    public_key, private_key = generate_keypair(bits=1024)
    n, e = public_key
    _, d = private_key

    print(f"\nPublic Key (n, e):")
    print(f"  n = {n}")
    print(f"  e = {e}")
    print(f"\nPrivate Key (n, d):")
    print(f"  d = {d}")

    # Encrypt a message
    message = 123456789
    print(f"\nOriginal message: {message}")

    ciphertext = encrypt(public_key, message)
    print(f"Encrypted ciphertext: {ciphertext}")

    # Decrypt the message
    decrypted = decrypt(private_key, ciphertext)
    print(f"Decrypted message: {decrypted}")
    print(f"\nDecryption successful: {decrypted == message}")
