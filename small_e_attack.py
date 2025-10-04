"""
Small Public Exponent Attack on RSA

This module demonstrates how RSA can be broken when the public exponent e
is too small and the message m is small enough that m^e < n.

In this case, no modular reduction occurs during encryption, so we can
simply take the e-th root of the ciphertext to recover the message.

Author: Educational demonstration for cryptography study
"""

import math
from rsa import encrypt, decrypt, generate_keypair, mod_inverse, generate_prime


def integer_nth_root(x, n):
    """
    Calculate the integer n-th root of x using binary search.

    Returns the largest integer r such that r^n <= x

    Args:
        x: The number to take the root of
        n: The root degree

    Returns:
        Integer n-th root of x
    """
    if x < 0:
        raise ValueError("Cannot take even root of negative number")
    if x == 0 or x == 1:
        return x

    # Binary search for the n-th root
    low, high = 0, x

    while low <= high:
        mid = (low + high) // 2
        mid_n = mid ** n

        if mid_n == x:
            return mid
        elif mid_n < x:
            low = mid + 1
        else:
            high = mid - 1

    return high


def newton_nth_root(x, n, precision=100):
    """
    Calculate the n-th root of x using Newton's method.

    Newton's formula: r_{k+1} = ((n-1)*r_k + x/r_k^(n-1)) / n

    Args:
        x: The number to take the root of
        n: The root degree
        precision: Number of iterations

    Returns:
        Integer n-th root of x
    """
    if x == 0:
        return 0

    # Initial guess
    r = x

    for _ in range(precision):
        # Newton's iteration
        r_new = ((n - 1) * r + x // (r ** (n - 1))) // n

        if r_new >= r:
            break
        r = r_new

    # Verify and adjust if necessary
    while r ** n > x:
        r -= 1
    while (r + 1) ** n <= x:
        r += 1

    return r


def generate_small_e_keypair(bits=512, e=3):
    """
    Generate RSA key pair with a small public exponent.

    Args:
        bits: Bit length for each prime
        e: Small public exponent (typically 3, 5, or 7)

    Returns:
        Tuple ((n, e), (n, d)) where:
            (n, e) is the public key
            (n, d) is the private key
    """
    print(f"Generating RSA key with small exponent e = {e}...")

    # Generate primes such that gcd(e, phi) = 1
    while True:
        p = generate_prime(bits)
        q = generate_prime(bits)

        while p == q:
            q = generate_prime(bits)

        phi = (p - 1) * (q - 1)

        if math.gcd(e, phi) == 1:
            break

    n = p * q
    d = mod_inverse(e, phi)

    print(f"Key generated with {n.bit_length()} bit modulus")
    print(f"Public exponent e = {e}")

    return (n, e), (n, d)


def attack_small_e(public_key, ciphertext, max_k=100):
    """
    Attack RSA with small public exponent when m^e < n.

    If the plaintext m is small enough that m^e < n, then the encryption
    is just c = m^e (no modular reduction). We can recover m by computing
    the e-th root of c.

    For slightly larger messages, we try c + k*n for small values of k.

    Args:
        public_key: Tuple (n, e)
        ciphertext: The encrypted message
        max_k: Maximum value of k to try (for m^e = c + k*n case)

    Returns:
        Recovered message m if successful, None otherwise
    """
    n, e = public_key

    print("\n" + "="*60)
    print("ATTACKING RSA WITH SMALL PUBLIC EXPONENT")
    print("="*60)

    print(f"\nPublic exponent e = {e}")
    print(f"Attempting to recover message by computing {e}-th root...")

    # Try c + k*n for k = 0, 1, 2, ...
    for k in range(max_k):
        # Calculate m^e = c + k*n
        target = ciphertext + k * n

        # Compute e-th root using Newton's method
        m = newton_nth_root(target, e)

        # Verify if m^e equals target
        if m ** e == target:
            print(f"\n✓ Successfully recovered message!")
            print(f"  Found at k = {k}")
            print(f"  m^{e} = c + {k}*n")
            print(f"  Recovered message m = {m}")

            print("\n" + "="*60)
            print("ATTACK SUCCESSFUL - MESSAGE RECOVERED!")
            print("="*60)

            return m

    print("\n✗ Attack failed: Could not find valid root")
    print(f"  (Tried k from 0 to {max_k-1})")
    return None


def main():
    """
    Demonstration of the small public exponent attack.
    """
    print("="*60)
    print("RSA SMALL PUBLIC EXPONENT ATTACK DEMONSTRATION")
    print("="*60)
    print()
    print("This script demonstrates how RSA can be broken when:")
    print("1. The public exponent e is small (e.g., e=3)")
    print("2. The message m is small enough that m^e < n")
    print()

    # Part 1: Generate key with small e
    print("\n" + "-"*60)
    print("PART 1: Generating RSA Key with Small Exponent")
    print("-"*60)

    # Use small e (3 is common but vulnerable)
    public_key, private_key = generate_small_e_keypair(bits=256, e=3)
    n, e = public_key

    print(f"\nGenerated Public Key:")
    print(f"  n = {n}")
    print(f"  e = {e}")

    # Part 2: Encrypt a small message
    print("\n" + "-"*60)
    print("PART 2: Encrypting a Small Message")
    print("-"*60)

    # Use a small message to ensure m^3 < n
    message = 12345678901234567890  # Small compared to n
    print(f"\nOriginal message: {message}")
    print(f"Message has {message.bit_length()} bits")

    # Check if m^e < n
    m_to_e = message ** e
    print(f"\nm^{e} = {m_to_e}")
    print(f"n = {n}")
    print(f"m^{e} < n: {m_to_e < n}")

    ciphertext = encrypt(public_key, message)
    print(f"\nEncrypted ciphertext: {ciphertext}")

    # Verify normal decryption
    decrypted = decrypt(private_key, ciphertext)
    print(f"Decrypted (using private key): {decrypted}")
    print(f"Decryption successful: {decrypted == message}")

    # Part 3: Attack with small e
    print("\n" + "-"*60)
    print("PART 3: Attacking with Small Exponent")
    print("-"*60)

    recovered_message = attack_small_e(public_key, ciphertext, max_k=10)

    if recovered_message is not None:
        print(f"\nOriginal message:  {message}")
        print(f"Recovered message: {recovered_message}")
        print(f"Messages match: {recovered_message == message}")

        print("\n" + "="*60)
        print("CONCLUSION")
        print("="*60)
        print("The attack was successful! The message was recovered by")
        print(f"simply computing the {e}-th root of the ciphertext.")
        print("\nLESSON: Never use small public exponents with small messages!")
        print("- Use padding schemes like OAEP to ensure m^e >= n")
        print("- Or use larger public exponents (e.g., e=65537)")
        print("="*60)


if __name__ == "__main__":
    main()
