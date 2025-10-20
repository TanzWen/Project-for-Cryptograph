"""
Low Public Exponent Attack
SC6104 - Introduction to Cryptography

This module implements the low public exponent attack on RSA.
If e is small and m^e < n, then c = m^e (no modular reduction).
We can recover m by computing the e-th root of c.
"""

from typing import Optional


def attack_low_public_exponent(c: int, e: int, n: int) -> Optional[int]:
    """
    Attack 2: Low public exponent attack.

    If e is small and m^e < n, then c = m^e (no modular reduction).
    We can recover m by computing the e-th root of c.

    Args:
        c: Ciphertext
        e: Public exponent (should be small, e.g., 3)
        n: Modulus

    Returns:
        Recovered plaintext m, or None if attack fails
    """
    # Try to compute the e-th root of c
    # Using binary search to find integer e-th root

    def nth_root(x: int, n: int) -> Optional[int]:
        """Compute integer n-th root of x using binary search."""
        if x < 0:
            return None
        if x == 0:
            return 0

        # Binary search
        low, high = 0, x
        while low <= high:
            mid = (low + high) // 2
            mid_pow = mid ** n

            if mid_pow == x:
                return mid
            elif mid_pow < x:
                low = mid + 1
            else:
                high = mid - 1

        return None

    m = nth_root(c, e)

    if m is not None:
        # Verify the result
        if pow(m, e, n) == c:
            print(f"[Low Exponent Attack] Successfully recovered message: m={m}")
            return m

    return None


if __name__ == "__main__":
    from rsa import generate_prime

    print("Low Public Exponent Attack Demo")
    print("=" * 80)

    # Example: Low exponent attack
    e = 3
    p = generate_prime(256)
    q = generate_prime(256)
    n = p * q
    message = 1000
    ciphertext = pow(message, e, n)
    print(f"Message: {message}, Ciphertext: {ciphertext}")
    m_recovered = attack_low_public_exponent(ciphertext, e, n)
    print(f"Recovered message: {m_recovered}")
    print(f"Success: {m_recovered == message}")
