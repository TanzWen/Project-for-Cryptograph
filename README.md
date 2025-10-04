# RSA算法实现与多种参数弱点攻击演示

本项目实现了完整的RSA加密算法，并演示了三种主要的RSA参数选择不当导致的攻击方法：
1. **Fermat分解攻击** - 当p和q过于接近时
2. **小公钥指数攻击** - 当e太小且m^e < n时
3. **Wiener攻击** - 当私钥指数d太小时

## 📁 项目结构

```
.
├── rsa.py              # RSA算法核心实现
├── fermat_attack.py    # Fermat分解攻击演示
├── small_e_attack.py   # 小公钥指数攻击演示
├── wiener_attack.py    # Wiener攻击演示（连分数算法）
├── all_attacks_demo.py # 综合演示程序（所有攻击）
└── README.md           # 项目说明文档
```

## 📚 RSA算法概述

RSA是一种非对称加密算法，基于大整数分解的困难性。其安全性依赖于：
- 将大合数n = p × q分解为两个素因数p和q在计算上是困难的
- 但是，如果参数选择不当，这个假设可能被打破

### RSA关键步骤

1. **密钥生成**
   - 选择两个大素数 p 和 q
   - 计算模数 n = p × q
   - 计算欧拉函数 φ(n) = (p-1)(q-1)
   - 选择公钥指数 e（通常为65537）
   - 计算私钥指数 d ≡ e⁻¹ (mod φ(n))

2. **加密**
   - 密文 c = m^e mod n

3. **解密**
   - 明文 m = c^d mod n

## 🎯 三种攻击原理

### 攻击1：Fermat分解法（p和q太接近）

**攻击目标**：当RSA的两个素因子p和q过于接近时，可以快速分解模数n

**数学原理**：

如果 p 和 q 很接近，设 p < q，则：
- n = p × q
- 令 a = ⌈√n⌉（n的平方根向上取整）
- 如果 p 和 q 接近，则存在 a 和 b 使得：
  ```
  n = a² - b² = (a-b)(a+b)
  ```
  其中 p = a-b，q = a+b

**算法流程**：
1. 从 a = ⌈√n⌉ 开始
2. 计算 b² = a² - n
3. 检查 b² 是否为完全平方数
4. 如果是，则找到分解：p = a-b，q = a+b
5. 如果不是，令 a = a+1，重复步骤2

**时间复杂度**：
- 如果 |p-q| 很小，算法在 O(|p-q|) 时间内完成
- 远快于通用分解算法的指数时间

**完整攻击链**：
```
获取公钥 (n, e)
   ↓
使用Fermat分解法分解n → 找到 p 和 q
   ↓
计算欧拉函数 φ(n) = (p-1)(q-1)
   ↓
恢复私钥指数 d ≡ e⁻¹ (mod φ(n))
   ↓
使用恢复的私钥解密消息 m = c^d mod n
```

---

### 攻击2：小公钥指数攻击（e太小）

**攻击目标**：当公钥指数e很小（如e=3）且消息m满足 m^e < n 时

**数学原理**：

- 正常RSA加密：c = m^e mod n
- 如果 m^e < n，则没有发生模约减
- 因此：c = m^e（普通整数运算，非模运算）
- 恢复明文：m = c^(1/e)（计算e次方根）

**算法流程**：
1. 尝试对密文c计算e次方根
2. 如果 m^e = c，则找到明文m
3. 如果不成功，尝试 m^e = c + k*n（k为小整数）
4. 使用二分搜索或牛顿法计算整数e次方根

**攻击条件**：
- e必须很小（通常e=3, 5, 7等）
- 消息m必须足够小，使得 m^e < n
- 或者稍大的消息，m^e = c + k*n，k为小整数

**完整攻击链**：
```
获取公钥 (n, e) 和密文 c
   ↓
检查 e 是否很小（如 e=3）
   ↓
对 c 或 c+k*n 计算 e 次方根
   ↓
验证 m^e 是否等于原始值
   ↓
成功恢复明文 m
```

---

### 攻击3：Wiener攻击（d太小）

**攻击目标**：当私钥指数d < (1/3) × n^(1/4) 时

**数学原理**：

- RSA关系式：e × d ≡ 1 (mod φ(n))
- 改写为：e × d = 1 + k × φ(n)，其中k为某个整数
- 因此：k/d ≈ e/φ(n) ≈ e/n（因为φ(n)接近n）
- 使用连分数展开e/n可以找到k/d

**连分数算法**：

1. 计算e/n的连分数展开：[a₀; a₁, a₂, a₃, ...]
2. 计算所有收敛项（convergents）k/d
3. 对每个收敛项：
   - 检查 (e×d - 1) 是否能被 k 整除
   - 如果可以，计算 φ = (e×d - 1) / k
   - 尝试用n和φ恢复p和q
   - 使用二次方程：x² - (n-φ+1)x + n = 0
4. 如果成功分解，则d即为私钥指数

**时间复杂度**：
- 连分数展开：O(log n)
- 收敛项数量：O(log n)
- 总体：多项式时间

**完整攻击链**：
```
获取公钥 (n, e)
   ↓
计算 e/n 的连分数展开
   ↓
获取所有收敛项 k/d
   ↓
对每个收敛项尝试恢复 φ(n)
   ↓
用 φ(n) 分解 n 得到 p 和 q
   ↓
成功恢复私钥指数 d
```

## 🚀 使用方法

### 方法1: 综合演示（推荐）

运行 `all_attacks_demo.py` 查看所有攻击的交互式演示：

```bash
python all_attacks_demo.py
```

**交互菜单**：
```
请选择演示模式:
  [1] 演示 Fermat分解攻击
  [2] 演示 小公钥指数攻击
  [3] 演示 Wiener攻击
  [4] 演示所有攻击（按顺序）
  [0] 退出
```

---

### 方法2: 单独运行各个攻击

#### 1. RSA基本功能演示

```bash
python rsa.py
```

演示标准RSA加密/解密流程。

#### 2. Fermat分解攻击

```bash
python fermat_attack.py
```

演示当p和q过于接近时的攻击过程。

#### 3. 小公钥指数攻击

```bash
python small_e_attack.py
```

演示当e=3且消息较小时的攻击过程。

#### 4. Wiener攻击

```bash
python wiener_attack.py
```

演示当私钥指数d太小时使用连分数算法的攻击过程。

---

### 方法3: 作为模块导入

```python
from rsa import generate_keypair, encrypt, decrypt
from fermat_attack import attack_weak_rsa
from small_e_attack import attack_small_e
from wiener_attack import wiener_attack

# 生成并攻击弱密钥
from fermat_attack import generate_weak_keypair
public_key, private_key, p, q = generate_weak_keypair(bits=64)
recovered_key = attack_weak_rsa(public_key)

# 小e攻击
from small_e_attack import generate_small_e_keypair
pub_key, priv_key = generate_small_e_keypair(bits=256, e=3)
message = 12345678
ciphertext = encrypt(pub_key, message)
recovered_msg = attack_small_e(pub_key, ciphertext)

# Wiener攻击
from wiener_attack import generate_weak_d_keypair
pub_key, priv_key, p, q = generate_weak_d_keypair(bits=256)
recovered_key = wiener_attack(pub_key)
```

## 🔍 代码功能详解

### `rsa.py` 核心函数

| 函数 | 功能 | 输入 | 输出 |
|------|------|------|------|
| `is_prime(n, k)` | Miller-Rabin素性测试 | n: 待测数字<br>k: 测试轮数 | True/False |
| `generate_prime(bits)` | 生成指定位数的素数 | bits: 位数 | 素数p |
| `mod_inverse(e, phi)` | 计算模逆元 | e: 公钥指数<br>phi: 欧拉函数值 | d: 私钥指数 |
| `generate_keypair(bits)` | 生成安全的RSA密钥对 | bits: 每个素数的位数 | (公钥, 私钥) |
| `generate_weak_keypair(bits)` | 生成弱RSA密钥对（p≈q） | bits: 素数位数 | (公钥, 私钥, p, q) |
| `encrypt(public_key, m)` | RSA加密 | public_key: (n,e)<br>m: 明文 | 密文c |
| `decrypt(private_key, c)` | RSA解密 | private_key: (n,d)<br>c: 密文 | 明文m |

### `fermat_attack.py` 核心函数

| 函数 | 功能 | 输入 | 输出 |
|------|------|------|------|
| `fermat_factorization(n)` | Fermat分解算法 | n: RSA模数 | (p, q) 或 None |
| `attack_weak_rsa(public_key)` | 完整Fermat攻击流程 | public_key: (n,e) | 恢复的私钥(n,d) |

### `small_e_attack.py` 核心函数

| 函数 | 功能 | 输入 | 输出 |
|------|------|------|------|
| `integer_nth_root(x, n)` | 二分搜索计算n次方根 | x: 数值<br>n: 次数 | 整数根 |
| `newton_nth_root(x, n)` | 牛顿法计算n次方根 | x: 数值<br>n: 次数 | 整数根 |
| `generate_small_e_keypair(bits, e)` | 生成小e的密钥对 | bits: 位数<br>e: 小指数 | (公钥, 私钥) |
| `attack_small_e(public_key, c)` | 完整小e攻击流程 | public_key: (n,e)<br>c: 密文 | 恢复的明文m |

### `wiener_attack.py` 核心函数

| 函数 | 功能 | 输入 | 输出 |
|------|------|------|------|
| `continued_fraction_expansion(a, b)` | 连分数展开 | a: 分子<br>b: 分母 | 连分数系数列表 |
| `convergents_from_cf(cf)` | 计算收敛项 | cf: 连分数系数 | [(k, d), ...] |
| `recover_prime_factors(n, phi)` | 从n和φ恢复p和q | n: 模数<br>phi: 欧拉函数 | (p, q) 或 None |
| `generate_weak_d_keypair(bits)` | 生成小d的密钥对 | bits: 位数 | (公钥, 私钥, p, q) |
| `wiener_attack(public_key)` | 完整Wiener攻击流程 | public_key: (n,e) | 恢复的私钥(n,d) |

## 📊 攻击效果对比

### 攻击条件与复杂度

| 攻击类型 | 弱点参数 | 攻击条件 | 时间复杂度 | 成功率 |
|---------|---------|---------|-----------|-------|
| **Fermat分解** | p ≈ q | \|p-q\| 很小 | O(\|p-q\|) | 高（当条件满足） |
| **小公钥指数** | e 小 | e小 且 m^e < n | O(log n) | 高（当条件满足） |
| **Wiener攻击** | d 小 | d < (1/3)n^0.25 | O(log² n) | 高（当条件满足） |

### 实际攻击时间示例

**Fermat分解攻击**：

| 素数位数 | \|p-q\| 范围 | 攻击时间 | 攻击难度 |
|---------|----------|---------|---------|
| 32位 | < 1000 | < 1秒 | 极易 |
| 64位 | < 10000 | < 5秒 | 容易 |
| 128位 | < 100000 | < 1分钟 | 中等 |
| 256位 | < 1000000 | < 10分钟 | 较难 |

**小公钥指数攻击**：

| 模数位数 | e值 | 消息大小 | 攻击时间 | 攻击难度 |
|---------|-----|---------|---------|---------|
| 256位 | 3 | m < n^(1/3) | < 1秒 | 极易 |
| 512位 | 3 | m < n^(1/3) | < 2秒 | 极易 |
| 1024位 | 5 | m < n^(1/5) | < 5秒 | 容易 |

**Wiener攻击**：

| 模数位数 | d的位数 | 攻击时间 | 攻击难度 |
|---------|---------|---------|---------|
| 256位 | < 32位 | < 1秒 | 极易 |
| 512位 | < 64位 | < 2秒 | 容易 |
| 1024位 | < 128位 | < 5秒 | 容易 |

## 🛡️ 安全建议

### RSA参数选择的最佳实践

#### 1. 素数选择（防Fermat攻击）
- ✅ 使用密码学安全的随机数生成器独立选择 p 和 q
- ✅ 确保 |p-q| 足够大（至少相差 2^(n/2-100) 数量级）
- ✅ p 和 q 的位数应该相近但不相同
- ❌ 不要使用连续素数或相近素数
- ❌ 不要从相同的种子生成 p 和 q

#### 2. 公钥指数选择（防小e攻击）
- ✅ 使用标准公钥指数 e = 65537（常用且安全）
- ✅ 必须使用填充方案（OAEP、PKCS#1 v2.0）
- ✅ 填充确保 m^e >= n
- ❌ 避免使用 e = 3（除非有适当填充）
- ❌ 不要对小消息直接加密

#### 3. 私钥指数选择（防Wiener攻击）
- ✅ 确保 d > n^0.25（安全边界）
- ✅ 实践中 d 通常接近 φ(n)，自然满足此条件
- ✅ 使用标准密钥生成过程
- ❌ 不要人为减小 d 的大小
- ❌ 不要使用"快速解密"变体

#### 4. 密钥长度
- ✅ 现代标准：至少 2048 位（p 和 q 各 1024 位）
- ✅ 高安全需求：3072 位或 4096 位
- ✅ 2030年后建议：最少 3072 位
- ❌ 不要使用小于 2048 位的密钥

#### 5. 其他安全措施
- ✅ 使用经过验证的密码库（OpenSSL、cryptography等）
- ✅ 定期更新密钥（密钥轮换）
- ✅ 安全存储私钥（硬件安全模块HSM）
- ✅ 实施密钥管理策略
- ✅ 遵循密码学标准（FIPS 186-4、NIST SP 800-57）

### 防御总结表

| 攻击类型 | 防御措施 | 标准参数 |
|---------|---------|---------|
| Fermat分解 | 独立随机选择p和q，确保差距大 | \|p-q\| > 2^(n/2-100) |
| 小e攻击 | 使用填充方案，或使用e=65537 | OAEP填充 + e=65537 |
| Wiener攻击 | 确保d足够大 | d > n^0.25 |
| 通用 | 使用足够长的密钥 | n >= 2048 bits |

## 📖 参考资料

### 学术论文
- **RSA算法**：Rivest, R., Shamir, A., & Adleman, L. (1978). "A Method for Obtaining Digital Signatures and Public-Key Cryptosystems"
- **Fermat分解法**：Fermat's factorization method (数论经典算法)
- **Wiener攻击**：Wiener, M. (1990). "Cryptanalysis of Short RSA Secret Exponents"
- **小e攻击**：Coppersmith, D. (1996). "Finding a Small Root of a Univariate Modular Equation"

### 标准与指南
- **NIST SP 800-57**：Key Management Recommendations
- **FIPS 186-4**：Digital Signature Standard (DSS)
- **PKCS#1 v2.2**：RSA Cryptography Specifications
- **RFC 8017**：PKCS#1: RSA Cryptography Specifications Version 2.2

### 在线资源
- [RSA Laboratories](https://www.rsa.com/)
- [Cryptography Stack Exchange](https://crypto.stackexchange.com/)
- [NIST Cryptographic Standards](https://csrc.nist.gov/)

## 🎓 学习要点

通过本项目，您将深入学习：

### 1. 密码学基础
- 模运算和数论基础
- 素性测试算法（Miller-Rabin）
- 模逆元计算（扩展欧几里得算法）
- 欧拉函数与费马小定理

### 2. RSA算法
- 密钥生成完整流程
- 加密/解密数学原理
- 安全性假设与条件
- 参数选择的重要性

### 3. 密码分析技术
- **因数分解方法**
  - Fermat分解法
  - 试除法vs特殊分解法

- **代数攻击**
  - 小指数攻击原理
  - 整数开方算法

- **数论攻击**
  - 连分数理论
  - 丢番图逼近
  - Wiener攻击数学基础

### 4. 安全工程实践
- 参数弱点识别
- 安全参数选择标准
- 密钥管理最佳实践
- 风险评估方法

## 💡 扩展练习

### 1. 实现其他攻击
- [ ] Pollard's p-1 分解算法
- [ ] Pollard's rho 分解算法
- [ ] 共模攻击（Common Modulus Attack）
- [ ] 低解密指数攻击（Low Decryption Exponent）
- [ ] Håstad's 广播攻击

### 2. 性能优化
- [ ] 优化素数生成速度（使用筛法预处理）
- [ ] 实现中国剩余定理（CRT）加速解密
- [ ] 蒙哥马利模乘优化
- [ ] 并行化大整数运算

### 3. 安全加固
- [ ] 实现 OAEP 填充方案
- [ ] 实现 PSS 签名方案
- [ ] 添加密钥长度安全检查
- [ ] 实现密钥强度评估

### 4. 对比分析
- [ ] 比较不同素数间距下的Fermat攻击效率
- [ ] 分析不同e值对安全性的影响
- [ ] 测量不同位数密钥的攻击时间
- [ ] 生成攻击成功率统计图表

### 5. 可视化
- [ ] 创建Fermat分解过程动画
- [ ] 可视化连分数收敛过程
- [ ] 绘制安全参数空间图
- [ ] 创建交互式Web演示

## ⚠️ 免责声明

**本项目仅用于教育目的，演示密码学中的参数选择弱点**

- ✅ 用于学习RSA的数学原理
- ✅ 用于理解密码分析技术
- ✅ 用于认识安全参数的重要性
- ❌ **不得**在生产环境使用本代码
- ❌ **不得**用于攻击真实系统
- ❌ **不得**用于任何非法目的

使用本项目代码造成的任何后果由使用者自行承担。

---

## 📝 总结

本项目展示了RSA加密算法在参数选择不当时的三种主要弱点：

| 攻击 | 弱点 | 教训 |
|-----|------|------|
| 🔸 **Fermat分解** | p和q太接近 | 素数必须独立随机选择，差距要大 |
| 🔸 **小公钥指数** | e太小且无填充 | 必须使用填充方案或较大的e |
| 🔸 **Wiener攻击** | d太小 | 私钥指数必须足够大 |

**核心原则**：密码系统的安全性不仅取决于算法本身，更依赖于参数的正确选择和实现细节。

---

**作者**：密码学学习项目
**版本**：2.0
**更新日期**：2024
**目的**：教育和研究
**许可**：仅供学习使用
