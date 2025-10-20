# RSA Algorithm and Attack Implementations

**SC6104 - Introduction to Cryptography**

This project implements the RSA cryptosystem and demonstrates five common attacks on weak RSA parameters.

## Project Structure

```
.
├── rsa.py         # Core RSA algorithm implementation
├── attacks.py     # Attack implementations
├── demo.py        # Demonstration scripts
└── README.md      # This file
```

## Files Overview

### 1. `rsa.py` - Core RSA Implementation

Contains the fundamental RSA algorithm components:

**Helper Functions:**
- `is_prime(n, k)` - Miller-Rabin primality test
- `gcd(a, b)` - Greatest common divisor (Euclidean algorithm)
- `extended_gcd(a, b)` - Extended Euclidean algorithm
- `mod_inverse(a, m)` - Modular multiplicative inverse
- `generate_prime(bits)` - Random prime number generation

**RSA Functions:**
- `generate_keypair(bits)` - Generate RSA public/private keypair
- `encrypt(message, public_key)` - Encrypt integer message
- `decrypt(ciphertext, private_key)` - Decrypt ciphertext

**Usage:**
```python
from rsa import generate_keypair, encrypt, decrypt

# Generate keys
public_key, private_key = generate_keypair(bits=1024)

# Encrypt
message = 12345
ciphertext = encrypt(message, public_key)

# Decrypt
plaintext = decrypt(ciphertext, private_key)
```

Run standalone:
```bash
python3 rsa.py
```

### 2. `attacks.py` - RSA Attack Implementations

Implements five attacks on weak RSA parameters:

**Attack 1: Small Modulus Attack**
- `attack_small_modulus(e, n, max_trial)`
- Exploits: Modulus n is too small
- Method: Trial division factorization
- Recovers: Private key d

**Attack 2: Low Public Exponent Attack**
- `attack_low_public_exponent(c, e, n)`
- Exploits: Small e and small message (m^e < n)
- Method: Integer e-th root extraction
- Recovers: Plaintext message m

**Attack 3: Fermat's Factorization Attack**
- `attack_fermat_factorization(e, n, max_iterations)`
- Exploits: Primes p and q are close to each other
- Method: Fermat's difference of squares
- Recovers: Private key d

**Attack 4: Common Factor Attack**
- `attack_common_factor(e1, n1, e2, n2)`
- Exploits: Two moduli share a common prime factor
- Method: GCD of two moduli
- Recovers: Both private keys d1 and d2

**Attack 5: Wiener's Attack**
- `attack_wiener(e, n)`
- Exploits: Private exponent d is too small (d < n^0.25 / 3)
- Method: Continued fraction expansion
- Recovers: Private key d

**Usage:**
```python
from attacks import attack_small_modulus

# Attack a weak key
e = 17
n = 3233  # Small modulus
d = attack_small_modulus(e, n)
print(f"Recovered private key: {d}")
```

Run standalone:
```bash
python3 attacks.py
```

### 3. `demo.py` - Complete Demonstrations

Demonstrates all attacks with vulnerable keypairs:

- `demo_standard_rsa()` - Standard RSA usage
- `demo_attack_small_modulus()` - Attack 1 demo
- `demo_attack_low_exponent()` - Attack 2 demo
- `demo_attack_fermat()` - Attack 3 demo
- `demo_attack_common_factor()` - Attack 4 demo
- `demo_attack_wiener()` - Attack 5 demo

**Run all demonstrations:**
```bash
python3 demo.py
```

## Quick Start

1. **Test basic RSA:**
   ```bash
   python3 rsa.py
   ```

2. **Test attacks:**
   ```bash
   python3 attacks.py
   ```

3. **Run full demonstration:**
   ```bash
   python3 demo.py
   ```

## Attack Summaries

| Attack | Weakness | Condition | Complexity |
|--------|----------|-----------|------------|
| Small Modulus | n too small | n < 10^20 | O(√n) |
| Low Exponent | e small, m small | m^e < n | O(log n) |
| Fermat | p, q close | \|p-q\| small | O(p-q) |
| Common Factor | Shared prime | gcd(n1, n2) > 1 | O(log n) |
| Wiener | d too small | d < n^0.25/3 | O(log^2 n) |

## Security Recommendations

To avoid these attacks:

1. **Use large moduli**: At least 2048 bits (preferably 3072-4096 bits)
2. **Use standard e**: e = 65537 is recommended
3. **Generate distinct primes**: Ensure |p - q| is large
4. **Never reuse primes**: Each keypair must use unique primes
5. **Use large private key**: Ensure d is sufficiently large
6. **Use padding schemes**: OAEP for encryption, PSS for signatures

## Educational Purpose

This implementation is for **educational purposes only**. It demonstrates:
- How RSA works mathematically
- Common implementation mistakes
- How cryptographic attacks exploit weaknesses

**Do not use in production systems!** Use established libraries like:
- Python: `cryptography`, `pycryptodome`
- OpenSSL, GPG for practical applications

## Requirements

- Python 3.6+
- No external dependencies (uses only standard library)

## Author

SC6104 - Introduction to Cryptography
Nanyang Technological University

## License

Educational use only.
