"""
Fermat's Factorization Attack
SC6104 - Introduction to Cryptography

This module implements Fermat's factorization attack on RSA.
Efficient when p and q are close to each other.
Based on the identity: n = a^2 - b^2 = (a-b)(a+b)
"""

import math
from typing import Optional
from rsa import mod_inverse


def attack_fermat_factorization(e: int, n: int, max_iterations: int = 100000) -> Optional[int]:
    """
    Attack 3: Fermat's factorization attack.

    Efficient when p and q are close to each other.
    Based on the identity: n = a^2 - b^2 = (a-b)(a+b)

    Args:
        e: Public exponent
        n: Modulus
        max_iterations: Maximum iterations to try

    Returns:
        Private exponent d, or None if attack fails
    """
    # Start with a = ceil(sqrt(n))
    a = math.isqrt(n)
    if a * a < n:
        a += 1

    for _ in range(max_iterations):
        b_squared = a * a - n

        # Check if b_squared is a perfect square
        b = math.isqrt(b_squared)

        if b * b == b_squared:
            # Found factors
            p = a - b
            q = a + b

            if p * q == n and p > 1 and q > 1:
                print(f"[Fermat Attack] Found factors: p={p}, q={q}")

                # Compute phi(n) and private exponent
                phi_n = (p - 1) * (q - 1)
                d = mod_inverse(e, phi_n)

                return d

        a += 1

    return None


if __name__ == "__main__":
    from rsa import generate_prime, is_prime, mod_inverse

    print("Fermat's Factorization Attack Demo")
    print("=" * 80)

    # Generate primes that are close to each other
    base = 10**10
    p = base + 1
    q = base + 3

    # Find actual primes near base
    while not is_prime(p):
        p += 2

    q = p + 10  # Start searching near p
    while not is_prime(q):
        q += 2

    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537
    d_actual = mod_inverse(e, phi_n)

    print(f"Weak parameters (close primes):")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"n = {n}")

    d_recovered = attack_fermat_factorization(e, n)
    print(f"Recovered d={d_recovered}")
    print(f"Success: {d_recovered == d_actual}")
