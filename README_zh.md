# RSA 算法与攻击实现

**SC6104 - 密码学导论**

本项目实现了 RSA 密码系统，并演示了针对弱 RSA 参数的四种常见攻击。项目采用模块化设计，每种攻击都在独立的文件中实现。

## 项目结构

```
.
├── rsa.py                      # RSA 核心算法实现
├── small_modulus_attack.py     # 攻击 1：小模数分解攻击
├── low_exponent_attack.py      # 攻击 2：低公钥指数攻击
├── fermat_attack.py            # 攻击 3：费马分解攻击
├── wiener_attack.py            # 攻击 4：维纳攻击（小私钥）
├── README.md                   # 英文说明文档
└── README_zh.md                # 中文说明文档（本文件）
```

## 文件概览

### 1. `rsa.py` - RSA 核心实现

包含 RSA 算法的基础组件：

**辅助函数：**
- `is_prime(n, k)` - Miller-Rabin 素性测试
- `gcd(a, b)` - 最大公约数（欧几里得算法）
- `extended_gcd(a, b)` - 扩展欧几里得算法
- `mod_inverse(a, m)` - 模逆元计算
- `generate_prime(bits)` - 随机素数生成

**RSA 核心函数：**
- `generate_keypair(bits)` - 生成 RSA 公钥/私钥对
- `encrypt(message, public_key)` - 加密整数消息
- `decrypt(ciphertext, private_key)` - 解密密文

**使用示例：**
```python
from rsa import generate_keypair, encrypt, decrypt

# 生成密钥对
public_key, private_key = generate_keypair(bits=1024)
e, n = public_key
d, _ = private_key

# 加密消息
message = 12345
ciphertext = encrypt(message, public_key)
print(f"密文: {ciphertext}")

# 解密密文
plaintext = decrypt(ciphertext, private_key)
print(f"明文: {plaintext}")
assert message == plaintext
```

**独立运行测试：**
```bash
python3 rsa.py
```

---

### 2. `small_modulus_attack.py` - 小模数分解攻击

**函数：** `attack_small_modulus(e, n, max_trial=1000000)`

**攻击原理：**
- 利用漏洞：模数 n 过小，可以通过暴力分解
- 攻击方法：试除法分解 n = p × q
- 恢复内容：私钥 d

**适用条件：**
- n < 10^20 左右（取决于计算能力）
- 时间复杂度：O(√n)

**代码示例：**
```python
from small_modulus_attack import attack_small_modulus

# 脆弱参数
e = 17
n = 3233  # n = 61 × 53，过小！

# 执行攻击
d = attack_small_modulus(e, n)
print(f"恢复的私钥: {d}")
```

**独立运行测试：**
```bash
python3 small_modulus_attack.py
```

**防御措施：**
- 使用至少 2048 位的模数（推荐 3072-4096 位）

---

### 3. `low_exponent_attack.py` - 低公钥指数攻击

**函数：** `attack_low_public_exponent(c, e, n)`

**攻击原理：**
- 利用漏洞：公钥指数 e 很小（如 e=3）且消息 m 也很小
- 关键条件：当 m^e < n 时，加密不涉及模运算
- 攻击方法：直接计算密文 c 的 e 次整数根
- 恢复内容：明文消息 m

**适用条件：**
- e 较小（通常 e = 3）
- m^e < n（消息足够小）
- 时间复杂度：O(log n)

**代码示例：**
```python
from low_exponent_attack import attack_low_public_exponent
from rsa import generate_prime

# 脆弱参数
e = 3
p = generate_prime(512)
q = generate_prime(512)
n = p * q

# 小消息
message = 1000  # 1000^3 可能小于 n
ciphertext = pow(message, e, n)

# 执行攻击
recovered_message = attack_low_public_exponent(ciphertext, e, n)
print(f"原始消息: {message}")
print(f"恢复消息: {recovered_message}")
```

**独立运行测试：**
```bash
python3 low_exponent_attack.py
```

**防御措施：**
- 使用较大的公钥指数（推荐 e = 65537）
- 使用填充方案（如 OAEP）确保 m^e > n

---

### 4. `fermat_attack.py` - 费马分解攻击

**函数：** `attack_fermat_factorization(e, n, max_iterations=100000)`

**攻击原理：**
- 利用漏洞：两个素数 p 和 q 彼此过于接近
- 数学基础：n = a² - b² = (a-b)(a+b)
- 攻击方法：从 a = ⌈√n⌉ 开始搜索，直到 a² - n 是完全平方数
- 恢复内容：私钥 d

**适用条件：**
- |p - q| 很小
- 时间复杂度：O(|p - q|)

**代码示例：**
```python
from fermat_attack import attack_fermat_factorization
from rsa import is_prime, mod_inverse

# 生成接近的素数
base = 10**10
p = base + 1
while not is_prime(p):
    p += 2

q = p + 10  # q 和 p 非常接近
while not is_prime(q):
    q += 2

n = p * q
e = 65537

# 执行费马攻击
d = attack_fermat_factorization(e, n)
print(f"成功恢复私钥: {d}")
```

**独立运行测试：**
```bash
python3 fermat_attack.py
```

**防御措施：**
- 确保 |p - q| 足够大
- 不要从接近的值开始生成 p 和 q

---

### 5. `wiener_attack.py` - 维纳攻击（小私钥）

**函数：** `attack_wiener(e, n)`

**攻击原理：**
- 利用漏洞：私钥 d 过小（d < n^(1/4) / 3）
- 数学基础：利用 e/n 的连分数展开来逼近 k/d
- 攻击方法：测试每个收敛项是否为有效的私钥
- 恢复内容：私钥 d

**适用条件：**
- d < n^0.25 / 3
- 时间复杂度：O(log² n)

**代码示例：**
```python
from wiener_attack import attack_wiener
from rsa import generate_prime, mod_inverse, gcd
import random

# 生成脆弱密钥（小 d）
p = generate_prime(256)
q = generate_prime(256)
n = p * q
phi_n = (p - 1) * (q - 1)

# 选择小的 d
d = random.randint(1, int(n**0.25 / 3))
while gcd(d, phi_n) != 1:
    d += 1

# 计算对应的 e
e = mod_inverse(d, phi_n)

print(f"原始私钥 d: {d}")
print(f"满足维纳条件: d < n^0.25/3 = {int(n**0.25/3)}")

# 执行维纳攻击
recovered_d = attack_wiener(e, n)
print(f"恢复私钥 d: {recovered_d}")
print(f"攻击成功: {d == recovered_d}")
```

**独立运行测试：**
```bash
python3 wiener_attack.py
```

**防御措施：**
- 确保 d 足够大（通常 d ≈ φ(n)）
- 使用标准的密钥生成方法

---

## 快速开始

### 1. 测试基本 RSA 加密/解密
```bash
python3 rsa.py
```

### 2. 测试各个攻击模块

```bash
# 测试小模数攻击
python3 small_modulus_attack.py

# 测试低指数攻击
python3 low_exponent_attack.py

# 测试费马分解攻击
python3 fermat_attack.py

# 测试维纳攻击
python3 wiener_attack.py
```

### 3. 在自己的代码中使用

```python
# 导入 RSA 核心功能
from rsa import generate_keypair, encrypt, decrypt

# 导入攻击模块
from small_modulus_attack import attack_small_modulus
from low_exponent_attack import attack_low_public_exponent
from fermat_attack import attack_fermat_factorization
from wiener_attack import attack_wiener

# 使用相应的函数...
```

---

## 攻击对比总结

| 攻击类型 | 目标弱点 | 攻击条件 | 时间复杂度 | 恢复内容 |
|---------|---------|---------|-----------|---------|
| 小模数攻击 | n 过小 | n < 10^20 | O(√n) | 私钥 d |
| 低指数攻击 | e 小，m 小 | m^e < n | O(log n) | 明文 m |
| 费马分解 | p、q 接近 | \|p-q\| 小 | O(\|p-q\|) | 私钥 d |
| 维纳攻击 | d 过小 | d < n^0.25/3 | O(log² n) | 私钥 d |

---

## RSA 安全实践建议

为了避免这些攻击，在实际应用中应当：

### 密钥生成
1. **模数大小**：至少 2048 位（推荐 3072-4096 位）
2. **公钥指数**：使用标准值 e = 65537
3. **素数生成**：
   - 确保 p 和 q 的位长度相同
   - 确保 |p - q| 足够大
   - 永不在不同密钥对间重用素数
4. **私钥大小**：确保 d 足够大（接近 φ(n)）

### 加密/签名
5. **填充方案**：
   - 加密：使用 OAEP (Optimal Asymmetric Encryption Padding)
   - 签名：使用 PSS (Probabilistic Signature Scheme)
6. **消息处理**：永不直接加密原始数据，务必使用填充

### 密钥管理
7. **密钥存储**：使用安全的密钥存储机制
8. **密钥轮换**：定期更新密钥
9. **密钥长度**：随着计算能力提升，及时升级密钥长度

---

## 系统要求

- **Python 版本**：Python 3.6+
- **外部依赖**：无（仅使用标准库）

---

## 教育用途声明

⚠️ **重要提示：本实现仅用于教育目的！**

本项目用于演示：
- RSA 的数学原理和工作机制
- 常见的密码学实现错误
- 密码分析攻击如何利用弱参数

**请勿在生产系统中使用！** 本实现缺少许多安全特性：
- 无填充方案（OAEP、PSS）
- 无侧信道攻击防护
- 无时间攻击防护
- 缺少完善的随机数生成器
- 未经过安全审计

### 实际应用请使用成熟的密码学库

**Python 推荐库：**
```python
# 使用 cryptography 库（推荐）
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# 生成密钥
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

# 加密（使用 OAEP 填充）
ciphertext = public_key.encrypt(
    b"secret message",
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# 解密
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
```

**其他推荐工具：**
- Python: `pycryptodome`
- 命令行: OpenSSL, GPG
- 企业级: HSM (硬件安全模块)

---

## 学习路径建议

### 第一阶段：理解 RSA 基础
1. 运行 `python3 rsa.py` 了解基本加密/解密流程
2. 阅读代码理解素数生成、模逆元等数学基础
3. 尝试修改参数，观察运行结果

### 第二阶段：学习攻击原理
1. 逐个运行各攻击模块的测试代码
2. 理解每种攻击的数学原理
3. 分析攻击的适用条件和时间复杂度

### 第三阶段：实践探索
1. 修改攻击参数，观察成功/失败的边界条件
2. 尝试优化攻击算法
3. 组合使用不同的攻击方法

### 第四阶段：深入研究
1. 阅读相关学术论文（见参考资料）
2. 研究现代 RSA 的安全实践和标准
3. 了解后量子密码学的发展

---

## 常见问题 FAQ

### Q1: 为什么不能用于生产环境？
**A:** 本实现是教学简化版，缺少关键安全特性：
- 无填充方案保护
- 未防范侧信道攻击（时间攻击、功耗分析等）
- 随机数生成不够安全
- 未经过严格的安全审计
- 代码未针对性能和安全性优化

### Q2: 实际推荐的密钥长度？
**A:** 根据不同的安全需求：
- **当前标准（2025年）**：至少 2048 位
- **长期安全**：3072-4096 位
- **高度敏感数据**：4096 位
- **面对量子威胁**：考虑后量子密码学算法（如 Kyber、Dilithium）

### Q3: e = 65537 为什么是标准选择？
**A:** 因为 65537 = 2^16 + 1：
- 足够大，可防范低指数攻击
- 二进制表示为 10000000000000001（仅两个1）
- 快速模幂运算（平方17次）
- 是素数，满足与 φ(n) 互质的要求

### Q4: 如何验证 RSA 密钥的安全性？
**A:** 检查以下要点：
- [ ] n 至少 2048 位
- [ ] e = 65537
- [ ] p 和 q 长度相近
- [ ] |p - q| 足够大（不易受费马攻击）
- [ ] d 足够大（不易受维纳攻击）
- [ ] p 和 q 是真随机生成的素数

### Q5: 这些攻击在现实中有多常见？
**A:**
- **小模数攻击**：早期系统（如512位密钥）已被淘汰
- **低指数攻击**：现代系统使用填充方案，基本不受影响
- **费马攻击**：标准密钥生成算法已避免此问题
- **维纳攻击**：正确的实现不会产生小 d

然而，错误的实现或配置仍可能引入这些漏洞！

### Q6: 量子计算对 RSA 的威胁？
**A:**
- **Shor 算法**：量子计算机可以在多项式时间内分解大整数
- **时间表**：实用量子计算机可能在10-20年内出现
- **应对**：研究和部署后量子密码学算法（NIST 已开始标准化）

---

## 技术深入解析

### 攻击 1：小模数攻击的数学原理

给定公钥 (e, n)，如果 n 足够小：

1. 通过试除法找到 n 的因子：
   ```
   for i from 2 to √n:
       if n % i == 0:
           p = i, q = n / i
   ```

2. 计算 φ(n) = (p-1)(q-1)

3. 计算 d = e^(-1) mod φ(n)

**复杂度**：O(√n)，对于 n < 2^64 是可行的

---

### 攻击 2：低指数攻击的数学原理

当 e 很小（如 e=3）且消息 m 也很小时：

1. 加密：c = m^e mod n
2. 如果 m^e < n，则 c = m^e（无模运算）
3. 攻击：直接计算 m = ∛c（整数立方根）

**例子**：
```
e = 3, m = 1000
c = 1000^3 = 1,000,000,000
m = ∛1,000,000,000 = 1000
```

---

### 攻击 3：费马分解的数学原理

基于恒等式：n = a² - b² = (a-b)(a+b)

1. 令 a = ⌈√n⌉
2. 计算 b² = a² - n
3. 检查 b² 是否为完全平方数
4. 若是，则 p = a-b, q = a+b
5. 若否，a++，回到步骤2

当 p ≈ q 时，算法快速收敛！

---

### 攻击 4：维纳攻击的数学原理

基于连分数理论：

1. e·d ≡ 1 (mod φ(n))，即 e·d = 1 + k·φ(n)
2. 因此 e/n ≈ k/d（当 d 很小时）
3. 计算 e/n 的连分数展开
4. 测试每个收敛项 k/d 是否满足：
   - (e·d - 1) % k == 0
   - 从 φ(n) = (e·d-1)/k 可以恢复 p 和 q

**理论保证**：当 d < n^0.25/3 时，k/d 必定是 e/n 的某个收敛项

---

## 参考资料

### 学术论文

1. **RSA 原始论文**
   - Rivest, R., Shamir, A., & Adleman, L. (1978). "A Method for Obtaining Digital Signatures and Public-Key Cryptosystems". *Communications of the ACM*, 21(2), 120-126.

2. **维纳攻击**
   - Wiener, M. (1990). "Cryptanalysis of Short RSA Secret Exponents". *IEEE Transactions on Information Theory*, 36(3), 553-558.

3. **改进的维纳攻击**
   - Boneh, D., & Durfee, G. (2000). "Cryptanalysis of RSA with Private Key d Less Than N^0.292". *IEEE Transactions on Information Theory*, 46(4), 1339-1349.

4. **费马分解方法**
   - McKee, J. (1999). "Speeding Fermat's Factoring Method". *Mathematics of Computation*, 68(228), 1729-1737.

### 标准文档

- **PKCS #1 v2.2**: RSA Cryptography Standard
- **FIPS 186-5**: Digital Signature Standard (DSS)
- **NIST SP 800-57**: Recommendation for Key Management
- **RFC 8017**: PKCS #1: RSA Cryptography Specifications Version 2.2

### 在线资源

- [Cryptopals Crypto Challenges](https://cryptopals.com/) - 实战密码学挑战
- [Khan Academy - Cryptography](https://www.khanacademy.org/computing/computer-science/cryptography) - 密码学基础教程
- [Applied Cryptography by Bruce Schneier](https://www.schneier.com/books/applied-cryptography/) - 经典密码学教材

---

## 项目作者

**课程**: SC6104 - Introduction to Cryptography
**学校**: 南洋理工大学 (Nanyang Technological University)
**年份**: 2024-2025

---

## 许可证

本项目仅供教育和学习使用。

---

## 致谢

感谢所有为密码学研究和教育做出贡献的学者和开发者。

---

**最后提醒**：密码学是一个复杂的领域，在实际应用中务必使用经过充分测试和审计的专业库。本项目帮助理解原理，但不应用于保护真实数据！
