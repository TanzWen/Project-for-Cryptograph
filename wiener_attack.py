"""
Wiener's Attack on RSA (Small Private Exponent)

This module demonstrates Wiener's attack on RSA when the private exponent d
is too small. Wiener proved that if d < (1/3) * n^(1/4), then d can be
efficiently recovered using continued fractions.

The attack exploits the relationship: e*d ≡ 1 (mod φ(n))
This can be rewritten as: e*d = 1 + k*φ(n) for some integer k
Therefore: k/d ≈ e/φ(n) ≈ e/n

We use continued fraction expansion of e/n to find k/d.

Author: Educational demonstration for cryptography study
"""

import math
from rsa import encrypt, decrypt, generate_prime, mod_inverse


def continued_fraction_expansion(numerator, denominator):
    """
    Compute the continued fraction expansion of numerator/denominator.

    A continued fraction is represented as [a0; a1, a2, a3, ...]
    where the value equals a0 + 1/(a1 + 1/(a2 + 1/(a3 + ...)))

    Args:
        numerator: Numerator of the fraction
        denominator: Denominator of the fraction

    Returns:
        List of continued fraction coefficients
    """
    cf = []

    while denominator != 0:
        # Integer part
        q = numerator // denominator
        cf.append(q)

        # Update for next iteration
        numerator, denominator = denominator, numerator - q * denominator

    return cf


def convergents_from_cf(cf):
    """
    Calculate convergents from a continued fraction expansion.

    Convergents are the rational approximations obtained by truncating
    the continued fraction at each step.

    Args:
        cf: List of continued fraction coefficients

    Returns:
        List of (numerator, denominator) tuples representing convergents
    """
    convergents = []

    # p_{-1} = 1, p_0 = cf[0]
    # q_{-1} = 0, q_0 = 1
    p_prev2, p_prev1 = 1, cf[0]
    q_prev2, q_prev1 = 0, 1

    convergents.append((cf[0], 1))

    for i in range(1, len(cf)):
        # Recurrence relation:
        # p_i = cf[i] * p_{i-1} + p_{i-2}
        # q_i = cf[i] * q_{i-1} + q_{i-2}
        p_curr = cf[i] * p_prev1 + p_prev2
        q_curr = cf[i] * q_prev1 + q_prev2

        convergents.append((p_curr, q_curr))

        p_prev2, p_prev1 = p_prev1, p_curr
        q_prev2, q_prev1 = q_prev1, q_curr

    return convergents


def is_perfect_square(n):
    """
    Check if n is a perfect square.

    Args:
        n: Integer to check

    Returns:
        True if n is a perfect square, False otherwise
    """
    if n < 0:
        return False

    root = math.isqrt(n)
    return root * root == n


def solve_quadratic(a, b, c):
    """
    Solve quadratic equation ax^2 + bx + c = 0.

    Args:
        a, b, c: Coefficients of the quadratic equation

    Returns:
        Tuple (x1, x2) of solutions if they exist and are integers,
        None otherwise
    """
    # Calculate discriminant
    discriminant = b * b - 4 * a * c

    if discriminant < 0:
        return None

    if not is_perfect_square(discriminant):
        return None

    sqrt_discriminant = math.isqrt(discriminant)

    # Check if solutions are integers
    if (- b + sqrt_discriminant) % (2 * a) != 0:
        return None

    x1 = (- b + sqrt_discriminant) // (2 * a)
    x2 = (- b - sqrt_discriminant) // (2 * a)

    return (x1, x2)


def recover_prime_factors(n, phi):
    """
    Recover prime factors p and q from n and φ(n).

    We know:
    - n = p * q
    - φ(n) = (p-1)(q-1) = n - (p+q) + 1

    So: p + q = n - φ(n) + 1

    We can solve:
    - p + q = s (where s = n - φ(n) + 1)
    - p * q = n

    Using the quadratic formula on: x^2 - s*x + n = 0

    Args:
        n: RSA modulus
        phi: Euler's totient of n

    Returns:
        Tuple (p, q) if successful, None otherwise
    """
    # p + q = n - phi + 1
    sum_pq = n - phi + 1

    # Solve x^2 - sum_pq * x + n = 0
    roots = solve_quadratic(1, -sum_pq, n)

    if roots is None:
        return None

    p, q = roots

    # Verify the factorization
    if p * q == n and p > 1 and q > 1:
        return (p, q)

    return None


def wiener_attack(public_key):
    """
    Wiener's attack on RSA with small private exponent.

    The attack works when d < (1/3) * n^(1/4).

    Algorithm:
    1. Compute continued fraction expansion of e/n
    2. For each convergent k/d:
       a. Check if k is non-zero
       b. Compute φ = (e*d - 1) / k
       c. Try to factor n using n and φ
       d. If successful, recover private key

    Args:
        public_key: Tuple (n, e)

    Returns:
        Recovered private key (n, d) if successful, None otherwise
    """
    n, e = public_key

    print("\n" + "="*60)
    print("WIENER'S ATTACK ON RSA (Small Private Exponent)")
    print("="*60)

    print(f"\nPublic key:")
    print(f"  n = {n}")
    print(f"  e = {e}")
    print(f"  n has {n.bit_length()} bits")

    # Compute continued fraction expansion of e/n
    print(f"\nComputing continued fraction expansion of e/n...")
    cf = continued_fraction_expansion(e, n)
    print(f"Continued fraction has {len(cf)} terms")

    # Get all convergents
    convergents = convergents_from_cf(cf)
    print(f"Testing {len(convergents)} convergents...")

    # Try each convergent
    for i, (k, d) in enumerate(convergents):
        # Skip if k is zero
        if k == 0:
            continue

        # Check if (e*d - 1) is divisible by k
        if (e * d - 1) % k != 0:
            continue

        # Compute potential φ(n)
        phi = (e * d - 1) // k

        # Try to factor n using phi
        factors = recover_prime_factors(n, phi)

        if factors is not None:
            p, q = factors
            print(f"\n✓ Found valid convergent at index {i}!")
            print(f"  k/d = {k}/{d}")
            print(f"  Recovered φ(n) = {phi}")
            print(f"  Factored n into p = {p}, q = {q}")
            print(f"  Verification: p * q = {p * q}")
            print(f"  Recovered private exponent d = {d}")

            # Verify d is correct
            if (e * d) % phi == 1:
                print(f"  Verification: (e * d) mod φ(n) = 1 ✓")

                print("\n" + "="*60)
                print("ATTACK SUCCESSFUL - PRIVATE KEY RECOVERED!")
                print("="*60)

                return (n, d)

    print("\n✗ Attack failed: Could not find valid convergent")
    print("  (Private exponent may not be small enough)")
    return None


def generate_weak_d_keypair(bits=256):
    """
    Generate RSA key pair with a SMALL private exponent (vulnerable to Wiener).

    For demonstration, we create d to be small (around n^0.25).

    Args:
        bits: Bit length for the modulus

    Returns:
        Tuple ((n, e), (n, d), p, q) where:
            (n, e) is the public key
            (n, d) is the private key
            p, q are the prime factors
    """
    print(f"Generating RSA key with SMALL private exponent...")

    # Generate primes
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)

    while p == q:
        q = generate_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose a small d (around n^0.25 for vulnerability)
    # For Wiener's attack to work: d < (1/3) * n^0.25
    target_d_bits = n.bit_length() // 4 - 2  # Make it smaller than threshold
    d = generate_prime(target_d_bits)

    # Make sure gcd(d, phi) = 1
    while math.gcd(d, phi) != 1:
        d = generate_prime(target_d_bits)

    # Calculate e from d
    e = mod_inverse(d, phi)

    print(f"Generated key:")
    print(f"  n has {n.bit_length()} bits")
    print(f"  d has {d.bit_length()} bits")
    print(f"  Wiener threshold: n^0.25 ≈ {int(n ** 0.25).bit_length()} bits")
    print(f"  d < (1/3) * n^0.25: {d < (n ** 0.25) / 3}")

    return (n, e), (n, d), p, q


def main():
    """
    Demonstration of Wiener's attack on RSA with small private exponent.
    """
    print("="*60)
    print("WIENER'S ATTACK DEMONSTRATION")
    print("="*60)
    print()
    print("This script demonstrates Wiener's attack on RSA when:")
    print("- The private exponent d is too small")
    print("- Specifically, when d < (1/3) * n^(1/4)")
    print()

    # Part 1: Generate weak key with small d
    print("\n" + "-"*60)
    print("PART 1: Generating RSA Key with Small Private Exponent")
    print("-"*60)

    public_key, private_key, p, q = generate_weak_d_keypair(bits=256)
    n, e = public_key
    _, d = private_key

    print(f"\nGenerated Public Key:")
    print(f"  n = {n}")
    print(f"  e = {e}")
    print(f"\nOriginal Private Key:")
    print(f"  d = {d}")

    # Part 2: Encrypt a message
    print("\n" + "-"*60)
    print("PART 2: Encrypting a Message")
    print("-"*60)

    message = 1234567890
    print(f"\nOriginal message: {message}")

    ciphertext = encrypt(public_key, message)
    print(f"Encrypted ciphertext: {ciphertext}")

    # Verify normal decryption
    decrypted = decrypt(private_key, ciphertext)
    print(f"Decrypted (using private key): {decrypted}")
    print(f"Decryption successful: {decrypted == message}")

    # Part 3: Wiener's attack
    print("\n" + "-"*60)
    print("PART 3: Executing Wiener's Attack")
    print("-"*60)

    recovered_private_key = wiener_attack(public_key)

    if recovered_private_key is not None:
        _, d_recovered = recovered_private_key
        print(f"\nOriginal private exponent:  {d}")
        print(f"Recovered private exponent: {d_recovered}")
        print(f"Private keys match: {d_recovered == d}")

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
        print("using continued fractions, all from just the public key.")
        print("\nLESSON: Never use small private exponents!")
        print("- Ensure d > n^0.25")
        print("- Use proper key generation procedures")
        print("- Follow cryptographic standards (e.g., FIPS 186-4)")
        print("="*60)


if __name__ == "__main__":
    main()
