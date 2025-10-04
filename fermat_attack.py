"""
Fermat's Factorization Attack on Weak RSA

This module demonstrates how RSA can be broken when the prime factors
p and q are chosen too close together using Fermat's factorization method.

Author: Educational demonstration for cryptography study
"""

import math
from rsa import generate_weak_keypair, encrypt, decrypt, mod_inverse


def fermat_factorization(n, max_iterations=100000):
    """
    Fermat's factorization method for breaking RSA with close primes.

    This attack exploits the fact that if p and q are close, then n = p*q
    can be expressed as a difference of squares: n = a^2 - b^2 = (a-b)(a+b)

    Algorithm:
    1. Start with a = ceil(sqrt(n))
    2. Calculate b^2 = a^2 - n
    3. If b^2 is a perfect square, we found the factorization
    4. Otherwise, increment a and repeat

    Args:
        n: RSA modulus to factor
        max_iterations: Maximum attempts before giving up

    Returns:
        Tuple (p, q) if successful, None otherwise
    """
    # Start with a = ceil(sqrt(n))
    a = math.isqrt(n)
    if a * a < n:
        a += 1

    for _ in range(max_iterations):
        # Calculate b^2 = a^2 - n
        b_squared = a * a - n

        # Check if b_squared is a perfect square
        b = math.isqrt(b_squared)

        if b * b == b_squared:
            # Found the factorization!
            # n = a^2 - b^2 = (a - b)(a + b)
            p = a - b
            q = a + b
            return p, q

        # Try next value of a
        a += 1

    return None


def attack_weak_rsa(public_key):
    """
    Attack RSA with weak parameters (close primes) using Fermat's method.

    Args:
        public_key: Tuple (n, e)

    Returns:
        Recovered private key (n, d) if successful, None otherwise
    """
    n, e = public_key

    print("\n" + "="*60)
    print("ATTACKING RSA WITH FERMAT'S FACTORIZATION")
    print("="*60)

    print(f"\nAttempting to factor n (modulus has {n.bit_length()} bits)...")

    # Try to factor n using Fermat's method
    result = fermat_factorization(n)

    if result is None:
        print("Attack failed: Could not factor n")
        print("(Primes may not be close enough)")
        return None

    p, q = result
    print(f"\n✓ Successfully factored n!")
    print(f"  p = {p}")
    print(f"  q = {q}")
    print(f"  Verification: p * q = {p * q}")
    print(f"  Matches n: {p * q == n}")

    # Calculate phi
    phi = (p - 1) * (q - 1)
    print(f"\n✓ Calculated phi(n) = (p-1)(q-1)")

    # Calculate private exponent d
    d = mod_inverse(e, phi)
    print(f"✓ Recovered private exponent d")

    print("\n" + "="*60)
    print("ATTACK SUCCESSFUL - PRIVATE KEY RECOVERED!")
    print("="*60)

    return (n, d)


def main():
    """
    Demonstration of the Fermat factorization attack on weak RSA.
    """
    print("="*60)
    print("RSA WEAK PARAMETER ATTACK DEMONSTRATION")
    print("="*60)
    print()
    print("This script demonstrates how RSA can be broken when the")
    print("prime factors p and q are chosen too close together.")
    print()

    # Part 1: Generate a weak RSA key pair
    print("\n" + "-"*60)
    print("PART 1: Generating Weak RSA Key Pair")
    print("-"*60)

    # Use smaller bit size for demonstration (makes attack faster)
    public_key, private_key, p, q = generate_weak_keypair(bits=64)
    n, e = public_key
    _, d = private_key

    print(f"\nGenerated Public Key:")
    print(f"  n = {n}")
    print(f"  e = {e}")
    print(f"\nOriginal Private Key:")
    print(f"  d = {d}")
    print(f"\nActual primes (for verification):")
    print(f"  p = {p}")
    print(f"  q = {q}")

    # Part 2: Encrypt a message
    print("\n" + "-"*60)
    print("PART 2: Encrypting a Message")
    print("-"*60)

    message = 42424242
    print(f"\nOriginal message: {message}")

    ciphertext = encrypt(public_key, message)
    print(f"Encrypted ciphertext: {ciphertext}")

    # Verify decryption works with original key
    decrypted = decrypt(private_key, ciphertext)
    print(f"Decrypted (using original private key): {decrypted}")
    print(f"Decryption successful: {decrypted == message}")

    # Part 3: Attack the weak key
    print("\n" + "-"*60)
    print("PART 3: Attacking the Weak RSA Key")
    print("-"*60)

    recovered_private_key = attack_weak_rsa(public_key)

    if recovered_private_key:
        _, d_recovered = recovered_private_key
        print(f"\nRecovered Private Key:")
        print(f"  d = {d_recovered}")
        print(f"\nPrivate key matches original: {d_recovered == d}")

        # Part 4: Decrypt with recovered key
        print("\n" + "-"*60)
        print("PART 4: Decrypting with Recovered Key")
        print("-"*60)

        decrypted_by_attacker = decrypt(recovered_private_key, ciphertext)
        print(f"\nCiphertext: {ciphertext}")
        print(f"Decrypted (using RECOVERED key): {decrypted_by_attacker}")
        print(f"Decryption successful: {decrypted_by_attacker == message}")

        print("\n" + "="*60)
        print("CONCLUSION")
        print("="*60)
        print("The attack was successful! The private key was recovered")
        print("and used to decrypt the message, all from just the public key.")
        print("\nLESSON: Never use RSA primes that are close together!")
        print("In practice, p and q should be randomly chosen large primes")
        print("with significant distance between them.")
        print("="*60)


if __name__ == "__main__":
    main()
