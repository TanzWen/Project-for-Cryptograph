"""
Comprehensive RSA Attacks Demonstration

This script demonstrates all three major RSA parameter weakness attacks:
1. Fermat's Factorization (p and q too close)
2. Small Public Exponent Attack (e too small, m^e < n)
3. Wiener's Attack (d too small)

Author: Educational demonstration for cryptography study
"""

import sys
from rsa import encrypt, decrypt

# Import attack modules
from fermat_attack import generate_weak_keypair, attack_weak_rsa as fermat_attack
from small_e_attack import generate_small_e_keypair, attack_small_e
from wiener_attack import generate_weak_d_keypair, wiener_attack


def print_header(title):
    """Print a formatted header."""
    print("\n" + "="*70)
    print(title.center(70))
    print("="*70)


def print_section(title):
    """Print a formatted section header."""
    print("\n" + "-"*70)
    print(title)
    print("-"*70)


def demonstrate_fermat_attack():
    """Demonstrate Fermat's factorization attack on close primes."""
    print_header("ATTACK 1: FERMAT'S FACTORIZATION (p and q too close)")

    print("\n攻击原理：")
    print("当RSA的两个素因子p和q过于接近时，可以使用Fermat分解法快速分解n")
    print("算法利用 n = a² - b² = (a-b)(a+b) 的形式来寻找p和q")

    print_section("Step 1: 生成弱密钥（p和q接近）")
    public_key, private_key, p, q = generate_weak_keypair(bits=64)
    n, e = public_key
    _, d = private_key

    print(f"\n公钥: (n, e)")
    print(f"  n = {n}")
    print(f"  e = {e}")
    print(f"\n素因子信息:")
    print(f"  p = {p}")
    print(f"  q = {q}")
    print(f"  差值 |p-q| = {abs(p-q)}")

    print_section("Step 2: 加密消息")
    message = 123456789
    print(f"\n原始消息: {message}")

    ciphertext = encrypt(public_key, message)
    print(f"密文: {ciphertext}")

    print_section("Step 3: 执行Fermat分解攻击")
    recovered_private_key = fermat_attack(public_key)

    if recovered_private_key:
        print_section("Step 4: 使用恢复的私钥解密")
        decrypted = decrypt(recovered_private_key, ciphertext)
        print(f"\n解密消息: {decrypted}")
        print(f"攻击成功: {decrypted == message} ✓")

    return recovered_private_key is not None


def demonstrate_small_e_attack():
    """Demonstrate small public exponent attack."""
    print_header("ATTACK 2: SMALL PUBLIC EXPONENT (e too small)")

    print("\n攻击原理：")
    print("当公钥指数e很小（如e=3）且消息m满足 m^e < n 时")
    print("加密过程不会发生模约减，可以直接对密文开e次方根恢复明文")

    print_section("Step 1: 生成小公钥指数的密钥")
    public_key, private_key = generate_small_e_keypair(bits=256, e=3)
    n, e = public_key

    print(f"\n公钥: (n, e)")
    print(f"  n = {n}")
    print(f"  e = {e} (very small!)")

    print_section("Step 2: 加密小消息")
    message = 12345678901234567890
    print(f"\n原始消息: {message}")
    print(f"消息位数: {message.bit_length()} bits")

    # Check vulnerability condition
    m_to_e = message ** e
    print(f"\n漏洞检查:")
    print(f"  m^{e} = {m_to_e}")
    print(f"  m^{e} < n: {m_to_e < n} {'(vulnerable!)' if m_to_e < n else ''}")

    ciphertext = encrypt(public_key, message)
    print(f"\n密文: {ciphertext}")

    print_section("Step 3: 执行小公钥指数攻击")
    recovered_message = attack_small_e(public_key, ciphertext, max_k=10)

    if recovered_message is not None:
        print(f"\n原始消息:  {message}")
        print(f"恢复消息: {recovered_message}")
        print(f"攻击成功: {recovered_message == message} ✓")

    return recovered_message is not None


def demonstrate_wiener_attack():
    """Demonstrate Wiener's attack on small private exponent."""
    print_header("ATTACK 3: WIENER'S ATTACK (d too small)")

    print("\n攻击原理：")
    print("当私钥指数d < (1/3) * n^(1/4) 时，可以通过连分数展开e/n来恢复d")
    print("利用关系式 k/d ≈ e/n，其中 e*d ≡ 1 (mod φ(n))")

    print_section("Step 1: 生成小私钥指数的密钥")
    public_key, private_key, p, q = generate_weak_d_keypair(bits=256)
    n, e = public_key
    _, d = private_key

    print(f"\n公钥: (n, e)")
    print(f"  n = {n}")
    print(f"  e = {e}")

    threshold = int((n ** 0.25) / 3)
    print(f"\n私钥信息:")
    print(f"  d = {d}")
    print(f"  d的位数: {d.bit_length()} bits")
    print(f"  Wiener阈值: (1/3)*n^0.25 ≈ {threshold.bit_length()} bits")
    print(f"  满足攻击条件: {d < threshold} {'✓' if d < threshold else '✗'}")

    print_section("Step 2: 加密消息")
    message = 9876543210
    print(f"\n原始消息: {message}")

    ciphertext = encrypt(public_key, message)
    print(f"密文: {ciphertext}")

    print_section("Step 3: 执行Wiener攻击")
    recovered_private_key = wiener_attack(public_key)

    if recovered_private_key:
        print_section("Step 4: 使用恢复的私钥解密")
        decrypted = decrypt(recovered_private_key, ciphertext)
        print(f"\n解密消息: {decrypted}")
        print(f"攻击成功: {decrypted == message} ✓")

    return recovered_private_key is not None


def main():
    """Main demonstration program."""
    print_header("RSA参数弱点攻击 - 综合演示")

    print("""
本程序演示三种主要的RSA参数选择不当导致的攻击：

1️⃣  Fermat分解法攻击
   - 条件: p和q过于接近
   - 方法: 利用差分平方分解

2️⃣  小公钥指数攻击
   - 条件: e太小 且 m^e < n
   - 方法: 直接开e次方根

3️⃣  Wiener攻击
   - 条件: d < (1/3)*n^(1/4)
   - 方法: 连分数展开算法
""")

    # Menu for attack selection
    print("\n请选择演示模式:")
    print("  [1] 演示 Fermat分解攻击")
    print("  [2] 演示 小公钥指数攻击")
    print("  [3] 演示 Wiener攻击")
    print("  [4] 演示所有攻击（按顺序）")
    print("  [0] 退出")

    try:
        choice = input("\n请输入选项 (0-4): ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n\n程序退出。")
        sys.exit(0)

    attacks_success = []

    if choice == '1':
        success = demonstrate_fermat_attack()
        attacks_success.append(("Fermat分解攻击", success))

    elif choice == '2':
        success = demonstrate_small_e_attack()
        attacks_success.append(("小公钥指数攻击", success))

    elif choice == '3':
        success = demonstrate_wiener_attack()
        attacks_success.append(("Wiener攻击", success))

    elif choice == '4':
        print("\n开始依次演示所有攻击...\n")

        success1 = demonstrate_fermat_attack()
        attacks_success.append(("Fermat分解攻击", success1))

        input("\n按Enter继续下一个攻击...")

        success2 = demonstrate_small_e_attack()
        attacks_success.append(("小公钥指数攻击", success2))

        input("\n按Enter继续下一个攻击...")

        success3 = demonstrate_wiener_attack()
        attacks_success.append(("Wiener攻击", success3))

    elif choice == '0':
        print("\n程序退出。")
        sys.exit(0)

    else:
        print("\n无效选项！")
        sys.exit(1)

    # Summary
    if attacks_success:
        print_header("攻击演示总结")
        print("\n攻击结果:")
        for attack_name, success in attacks_success:
            status = "✓ 成功" if success else "✗ 失败"
            print(f"  {attack_name}: {status}")

        print("\n" + "="*70)
        print("重要教训".center(70))
        print("="*70)
        print("""
1. 素数选择: p和q必须有足够大的差距，随机独立生成
2. 公钥指数: 不要使用过小的e，或使用填充方案(如OAEP)
3. 私钥指数: 确保d足够大，d > n^0.25
4. 密钥长度: 使用至少2048位的模数
5. 使用标准: 遵循NIST/FIPS等密码学标准

⚠️  本演示仅用于教育目的，切勿用于非法用途！
        """)
        print("="*70)


if __name__ == "__main__":
    main()
