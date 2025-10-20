"""
Small Modulus Factorization Attack
SC6104 - Introduction to Cryptography

This module implements attack on small RSA modulus using trial division.
If n is small enough, we can factor it directly and recover the private key d.
"""

import math
from typing import Optional
from rsa import is_prime, mod_inverse


def attack_small_modulus(e: int, n: int, max_trial: int = 1000000) -> Optional[int]:
    """
    Attack 1: Factor small modulus using trial division.

    If n is small enough, we can factor it directly and recover d.

    Args:
        e: Public exponent
        n: Modulus
        max_trial: Maximum number to try in trial division

    Returns:
        Private exponent d, or None if attack fails
    """
    # Try to factor n by trial division
    for i in range(2, min(max_trial, int(math.sqrt(n)) + 1)):
        if n % i == 0:
            p = i
            q = n // i

            # Verify it's a valid factorization
            if p * q == n and is_prime(p) and is_prime(q):
                print(f"[Small Modulus Attack] Found factors: p={p}, q={q}")

                # Compute phi(n) and private exponent
                phi_n = (p - 1) * (q - 1)
                d = mod_inverse(e, phi_n)

                return d

    return None


if __name__ == "__main__":
    from rsa import mod_inverse

    print("Small Modulus Attack Demo")
    print("=" * 80)

    # Example: Small modulus attack
    p, q = 61, 53
    n = p * q
    e = 17
    phi_n = (p - 1) * (q - 1)
    d_actual = mod_inverse(e, phi_n)
    print(f"Weak key: n={n}, e={e}")
    d_recovered = attack_small_modulus(e, n)
    print(f"Recovered d={d_recovered}, Actual d={d_actual}")
    print(f"Success: {d_recovered == d_actual}")
