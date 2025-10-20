"""
Wiener's Attack
SC6104 - Introduction to Cryptography

This module implements Wiener's attack on RSA with small private exponent.
Applicable when d < (1/3) * n^(1/4).
Uses continued fraction expansion of e/n to find convergents k/d.
"""

import math
from typing import Optional


def attack_wiener(e: int, n: int) -> Optional[int]:
    """
    Attack 4: Wiener's attack on small private exponent.

    Applicable when d < (1/3) * n^(1/4).
    Uses continued fraction expansion of e/n to find convergents k/d.

    Args:
        e: Public exponent
        n: Modulus

    Returns:
        Private exponent d, or None if attack fails
    """
    def continued_fraction(numerator: int, denominator: int):
        """Generate continued fraction expansion."""
        while denominator:
            quotient = numerator // denominator
            yield quotient
            numerator, denominator = denominator, numerator - quotient * denominator

    def convergents(cf):
        """Generate convergents from continued fraction."""
        p0, p1 = 0, 1
        q0, q1 = 1, 0

        for a in cf:
            p = a * p1 + p0
            q = a * q1 + q0
            yield (p, q)
            p0, p1 = p1, p
            q0, q1 = q1, q

    # Generate continued fraction of e/n
    cf = list(continued_fraction(e, n))

    # Test each convergent
    for k, d in convergents(iter(cf)):
        if k == 0:
            continue

        # Check if this is a valid private key
        # For valid key: e*d ≡ 1 (mod phi(n))
        # So: e*d = 1 + k*phi(n)
        # Therefore: phi(n) = (e*d - 1) / k

        if (e * d - 1) % k != 0:
            continue

        phi_n = (e * d - 1) // k

        # Try to factor n using phi(n)
        # We know: phi(n) = (p-1)(q-1) = n - (p+q) + 1
        # So: p + q = n - phi(n) + 1

        p_plus_q = n - phi_n + 1

        # Solve: p + q = p_plus_q and p*q = n
        # This gives: x^2 - (p+q)*x + n = 0

        discriminant = p_plus_q * p_plus_q - 4 * n

        if discriminant < 0:
            continue

        sqrt_discriminant = math.isqrt(discriminant)

        if sqrt_discriminant * sqrt_discriminant != discriminant:
            continue

        p = (p_plus_q + sqrt_discriminant) // 2
        q = (p_plus_q - sqrt_discriminant) // 2

        if p * q == n and p > 1 and q > 1:
            print(f"[Wiener Attack] Found factors: p={p}, q={q}")
            print(f"[Wiener Attack] Recovered private exponent: d={d}")
            return d

    return None


if __name__ == "__main__":
    import random
    from rsa import generate_prime, mod_inverse, gcd

    print("Wiener's Attack Demo")
    print("=" * 80)

    # Generate a keypair with intentionally small d
    p = generate_prime(256)
    q = generate_prime(256)
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Choose small d
    d = random.randint(1, int(n**0.25 / 3))

    # Make sure d is coprime to phi_n
    while gcd(d, phi_n) != 1:
        d += 1

    # Compute corresponding e
    e = mod_inverse(d, phi_n)

    print(f"Weak parameters (small d):")
    print(f"n = {n}")
    print(f"e = {e}")
    print(f"Actual d = {d}")

    d_recovered = attack_wiener(e, n)
    print(f"Success: {d_recovered == d}")
