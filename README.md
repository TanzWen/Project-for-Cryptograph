# RSA Algorithm and Attack Implementations

**SC6104 - Introduction to Cryptography**

This project implements the RSA cryptosystem and demonstrates four common attacks on weak RSA parameters. The project follows a modular design with each attack implemented in a separate file.

## Project Structure

```
.
├── rsa.py                      # Core RSA algorithm implementation
├── small_modulus_attack.py     # Attack 1: Small modulus factorization
├── low_exponent_attack.py      # Attack 2: Low public exponent attack
├── fermat_attack.py            # Attack 3: Fermat's factorization
├── wiener_attack.py            # Attack 4: Wiener's attack (small d)
├── README.md                   # This file (English)
└── README_zh.md                # Chinese documentation
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

**RSA Core Functions:**
- `generate_keypair(bits)` - Generate RSA public/private keypair
- `encrypt(message, public_key)` - Encrypt integer message
- `decrypt(ciphertext, private_key)` - Decrypt ciphertext

**Usage Example:**
```python
from rsa import generate_keypair, encrypt, decrypt

# Generate keypair
public_key, private_key = generate_keypair(bits=1024)
e, n = public_key
d, _ = private_key

# Encrypt message
message = 12345
ciphertext = encrypt(message, public_key)
print(f"Ciphertext: {ciphertext}")

# Decrypt ciphertext
plaintext = decrypt(ciphertext, private_key)
print(f"Plaintext: {plaintext}")
assert message == plaintext
```

**Run standalone test:**
```bash
python3 rsa.py
```

---

### 2. `small_modulus_attack.py` - Small Modulus Factorization Attack

**Function:** `attack_small_modulus(e, n, max_trial=1000000)`

**Attack Principle:**
- Exploits: Modulus n is too small and can be factored by brute force
- Method: Trial division to factor n = p × q
- Recovers: Private key d

**Applicable Conditions:**
- n < 10^20 (approximately, depending on computing power)
- Time complexity: O(√n)

**Code Example:**
```python
from small_modulus_attack import attack_small_modulus

# Vulnerable parameters
e = 17
n = 3233  # n = 61 × 53, too small!

# Execute attack
d = attack_small_modulus(e, n)
print(f"Recovered private key: {d}")
```

**Run standalone test:**
```bash
python3 small_modulus_attack.py
```

**Defense:**
- Use at least 2048-bit modulus (preferably 3072-4096 bits)

---

### 3. `low_exponent_attack.py` - Low Public Exponent Attack

**Function:** `attack_low_public_exponent(c, e, n)`

**Attack Principle:**
- Exploits: Public exponent e is small (e.g., e=3) and message m is also small
- Key condition: When m^e < n, encryption doesn't involve modular reduction
- Method: Compute the e-th integer root of ciphertext c
- Recovers: Plaintext message m

**Applicable Conditions:**
- e is small (typically e = 3)
- m^e < n (message is sufficiently small)
- Time complexity: O(log n)

**Code Example:**
```python
from low_exponent_attack import attack_low_public_exponent
from rsa import generate_prime

# Vulnerable parameters
e = 3
p = generate_prime(512)
q = generate_prime(512)
n = p * q

# Small message
message = 1000  # 1000^3 might be less than n
ciphertext = pow(message, e, n)

# Execute attack
recovered_message = attack_low_public_exponent(ciphertext, e, n)
print(f"Original message: {message}")
print(f"Recovered message: {recovered_message}")
```

**Run standalone test:**
```bash
python3 low_exponent_attack.py
```

**Defense:**
- Use larger public exponent (recommended e = 65537)
- Use padding scheme (e.g., OAEP) to ensure m^e > n

---

### 4. `fermat_attack.py` - Fermat's Factorization Attack

**Function:** `attack_fermat_factorization(e, n, max_iterations=100000)`

**Attack Principle:**
- Exploits: The two primes p and q are too close to each other
- Mathematical basis: n = a² - b² = (a-b)(a+b)
- Method: Start from a = ⌈√n⌉ and search until a² - n is a perfect square
- Recovers: Private key d

**Applicable Conditions:**
- |p - q| is small
- Time complexity: O(|p - q|)

**Code Example:**
```python
from fermat_attack import attack_fermat_factorization
from rsa import is_prime, mod_inverse

# Generate close primes
base = 10**10
p = base + 1
while not is_prime(p):
    p += 2

q = p + 10  # q is very close to p
while not is_prime(q):
    q += 2

n = p * q
e = 65537

# Execute Fermat attack
d = attack_fermat_factorization(e, n)
print(f"Successfully recovered private key: {d}")
```

**Run standalone test:**
```bash
python3 fermat_attack.py
```

**Defense:**
- Ensure |p - q| is sufficiently large
- Don't generate p and q from close starting values

---

### 5. `wiener_attack.py` - Wiener's Attack (Small Private Key)

**Function:** `attack_wiener(e, n)`

**Attack Principle:**
- Exploits: Private key d is too small (d < n^(1/4) / 3)
- Mathematical basis: Use continued fraction expansion of e/n to approximate k/d
- Method: Test each convergent to see if it's a valid private key
- Recovers: Private key d

**Applicable Conditions:**
- d < n^0.25 / 3
- Time complexity: O(log² n)

**Code Example:**
```python
from wiener_attack import attack_wiener
from rsa import generate_prime, mod_inverse, gcd
import random

# Generate vulnerable key (small d)
p = generate_prime(256)
q = generate_prime(256)
n = p * q
phi_n = (p - 1) * (q - 1)

# Choose small d
d = random.randint(1, int(n**0.25 / 3))
while gcd(d, phi_n) != 1:
    d += 1

# Compute corresponding e
e = mod_inverse(d, phi_n)

print(f"Original private key d: {d}")
print(f"Satisfies Wiener condition: d < n^0.25/3 = {int(n**0.25/3)}")

# Execute Wiener attack
recovered_d = attack_wiener(e, n)
print(f"Recovered private key d: {recovered_d}")
print(f"Attack successful: {d == recovered_d}")
```

**Run standalone test:**
```bash
python3 wiener_attack.py
```

**Defense:**
- Ensure d is sufficiently large (typically d ≈ φ(n))
- Use standard key generation methods

---

## Quick Start

### 1. Test Basic RSA Encryption/Decryption
```bash
python3 rsa.py
```

### 2. Test Individual Attack Modules

```bash
# Test small modulus attack
python3 small_modulus_attack.py

# Test low exponent attack
python3 low_exponent_attack.py

# Test Fermat factorization attack
python3 fermat_attack.py

# Test Wiener's attack
python3 wiener_attack.py
```

### 3. Use in Your Own Code

```python
# Import RSA core functionality
from rsa import generate_keypair, encrypt, decrypt

# Import attack modules
from small_modulus_attack import attack_small_modulus
from low_exponent_attack import attack_low_public_exponent
from fermat_attack import attack_fermat_factorization
from wiener_attack import attack_wiener

# Use the functions...
```

---

## Attack Comparison Summary

| Attack Type | Target Weakness | Attack Condition | Time Complexity | Recovers |
|------------|----------------|------------------|-----------------|----------|
| Small Modulus | n too small | n < 10^20 | O(√n) | Private key d |
| Low Exponent | e small, m small | m^e < n | O(log n) | Plaintext m |
| Fermat | p, q close | \|p-q\| small | O(\|p-q\|) | Private key d |
| Wiener | d too small | d < n^0.25/3 | O(log² n) | Private key d |

---

## RSA Security Best Practices

To avoid these attacks in real applications:

### Key Generation
1. **Modulus Size**: At least 2048 bits (preferably 3072-4096 bits)
2. **Public Exponent**: Use standard value e = 65537
3. **Prime Generation**:
   - Ensure p and q have the same bit length
   - Ensure |p - q| is sufficiently large
   - Never reuse primes across different keypairs
4. **Private Key Size**: Ensure d is sufficiently large (close to φ(n))

### Encryption/Signing
5. **Padding Schemes**:
   - Encryption: Use OAEP (Optimal Asymmetric Encryption Padding)
   - Signing: Use PSS (Probabilistic Signature Scheme)
6. **Message Handling**: Never encrypt raw data directly, always use padding

### Key Management
7. **Key Storage**: Use secure key storage mechanisms
8. **Key Rotation**: Regularly update keys
9. **Key Length**: Upgrade key length as computing power increases

---

## System Requirements

- **Python Version**: Python 3.6+
- **External Dependencies**: None (uses only standard library)

---

## Educational Purpose Statement

⚠️ **IMPORTANT: This implementation is for educational purposes only!**

This project demonstrates:
- The mathematical principles and working mechanisms of RSA
- Common cryptographic implementation mistakes
- How cryptanalytic attacks exploit weak parameters

**Do NOT use in production systems!** This implementation lacks many security features:
- No padding schemes (OAEP, PSS)
- No side-channel attack protection
- No timing attack protection
- Insufficient random number generation
- No security audit

### Use Mature Cryptographic Libraries in Practice

**Recommended Python Library:**
```python
# Use the cryptography library (recommended)
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Generate keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

# Encrypt (with OAEP padding)
ciphertext = public_key.encrypt(
    b"secret message",
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Decrypt
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
```

**Other Recommended Tools:**
- Python: `pycryptodome`
- Command-line: OpenSSL, GPG
- Enterprise: HSM (Hardware Security Module)

---

## Learning Path

### Stage 1: Understand RSA Basics
1. Run `python3 rsa.py` to understand basic encryption/decryption
2. Read code to understand prime generation, modular inverse, etc.
3. Try modifying parameters and observe results

### Stage 2: Learn Attack Principles
1. Run each attack module's test code
2. Understand the mathematical principles of each attack
3. Analyze attack conditions and time complexity

### Stage 3: Hands-on Exploration
1. Modify attack parameters, observe success/failure boundaries
2. Try optimizing attack algorithms
3. Combine different attack methods

### Stage 4: Deep Dive
1. Read related academic papers (see References)
2. Study modern RSA security practices and standards
3. Learn about post-quantum cryptography developments

---

## Frequently Asked Questions (FAQ)

### Q1: Why can't this be used in production?
**A:** This is a simplified educational implementation lacking critical security features:
- No padding scheme protection
- No protection against side-channel attacks (timing, power analysis, etc.)
- Insufficient random number generation
- No rigorous security audit
- Code not optimized for performance and security

### Q2: What key lengths are recommended?
**A:** Depends on security requirements:
- **Current standard (2025)**: At least 2048 bits
- **Long-term security**: 3072-4096 bits
- **Highly sensitive data**: 4096 bits
- **Quantum threat**: Consider post-quantum cryptography algorithms (e.g., Kyber, Dilithium)

### Q3: Why is e = 65537 the standard choice?
**A:** Because 65537 = 2^16 + 1:
- Large enough to prevent low exponent attacks
- Binary representation is 10000000000000001 (only two 1s)
- Enables fast modular exponentiation (17 squarings)
- Is prime and satisfies coprimality with φ(n)

### Q4: How to verify RSA key security?
**A:** Check the following:
- [ ] n is at least 2048 bits
- [ ] e = 65537
- [ ] p and q have similar bit lengths
- [ ] |p - q| is sufficiently large (resistant to Fermat attack)
- [ ] d is sufficiently large (resistant to Wiener attack)
- [ ] p and q are truly randomly generated primes

### Q5: How common are these attacks in reality?
**A:**
- **Small modulus attack**: Early systems (e.g., 512-bit keys) have been deprecated
- **Low exponent attack**: Modern systems use padding schemes, mostly unaffected
- **Fermat attack**: Standard key generation algorithms avoid this issue
- **Wiener attack**: Correct implementations don't produce small d

However, incorrect implementations or configurations can still introduce these vulnerabilities!

### Q6: Quantum computing threat to RSA?
**A:**
- **Shor's algorithm**: Quantum computers can factor large integers in polynomial time
- **Timeline**: Practical quantum computers may emerge within 10-20 years
- **Response**: Research and deploy post-quantum cryptography algorithms (NIST has begun standardization)

---

## Technical Deep Dive

### Attack 1: Small Modulus Attack - Mathematical Principle

Given public key (e, n), if n is sufficiently small:

1. Find factors of n by trial division:
   ```
   for i from 2 to √n:
       if n % i == 0:
           p = i, q = n / i
   ```

2. Compute φ(n) = (p-1)(q-1)

3. Compute d = e^(-1) mod φ(n)

**Complexity**: O(√n), feasible for n < 2^64

---

### Attack 2: Low Exponent Attack - Mathematical Principle

When e is small (e.g., e=3) and message m is also small:

1. Encryption: c = m^e mod n
2. If m^e < n, then c = m^e (no modular reduction)
3. Attack: Directly compute m = ∛c (integer cube root)

**Example**:
```
e = 3, m = 1000
c = 1000^3 = 1,000,000,000
m = ∛1,000,000,000 = 1000
```

---

### Attack 3: Fermat Factorization - Mathematical Principle

Based on the identity: n = a² - b² = (a-b)(a+b)

1. Let a = ⌈√n⌉
2. Compute b² = a² - n
3. Check if b² is a perfect square
4. If yes, then p = a-b, q = a+b
5. If no, a++, go back to step 2

When p ≈ q, the algorithm converges quickly!

---

### Attack 4: Wiener's Attack - Mathematical Principle

Based on continued fraction theory:

1. e·d ≡ 1 (mod φ(n)), i.e., e·d = 1 + k·φ(n)
2. Therefore e/n ≈ k/d (when d is small)
3. Compute continued fraction expansion of e/n
4. Test each convergent k/d to see if:
   - (e·d - 1) % k == 0
   - Can recover p and q from φ(n) = (e·d-1)/k

**Theoretical guarantee**: When d < n^0.25/3, k/d must be a convergent of e/n

---

## References

### Academic Papers

1. **RSA Original Paper**
   - Rivest, R., Shamir, A., & Adleman, L. (1978). "A Method for Obtaining Digital Signatures and Public-Key Cryptosystems". *Communications of the ACM*, 21(2), 120-126.

2. **Wiener's Attack**
   - Wiener, M. (1990). "Cryptanalysis of Short RSA Secret Exponents". *IEEE Transactions on Information Theory*, 36(3), 553-558.

3. **Improved Wiener Attack**
   - Boneh, D., & Durfee, G. (2000). "Cryptanalysis of RSA with Private Key d Less Than N^0.292". *IEEE Transactions on Information Theory*, 46(4), 1339-1349.

4. **Fermat Factorization Method**
   - McKee, J. (1999). "Speeding Fermat's Factoring Method". *Mathematics of Computation*, 68(228), 1729-1737.

### Standards

- **PKCS #1 v2.2**: RSA Cryptography Standard
- **FIPS 186-5**: Digital Signature Standard (DSS)
- **NIST SP 800-57**: Recommendation for Key Management
- **RFC 8017**: PKCS #1: RSA Cryptography Specifications Version 2.2

### Online Resources

- [Cryptopals Crypto Challenges](https://cryptopals.com/) - Hands-on cryptography challenges
- [Khan Academy - Cryptography](https://www.khanacademy.org/computing/computer-science/cryptography) - Basic cryptography course
- [Applied Cryptography by Bruce Schneier](https://www.schneier.com/books/applied-cryptography/) - Classic cryptography textbook

---

## Author

**Course**: SC6104 - Introduction to Cryptography
**Institution**: Nanyang Technological University
**Year**: 2024-2025

---

## License

Educational use only.

---

## Acknowledgments

Thanks to all scholars and developers who have contributed to cryptographic research and education.

---

**Final Reminder**: Cryptography is a complex field. In real applications, always use well-tested and audited professional libraries. This project helps understand principles but should not be used to protect real data!
