Response:
Let's break down the thought process for analyzing the provided Go code snippet for `crypto/rsa/rsa.go`.

**1. Initial Reading and High-Level Understanding:**

* **Purpose from the Package Comment:**  The very first thing I notice is the package comment. It clearly states that this package implements RSA encryption and signatures according to PKCS #1 and RFC 8017. It highlights the two main use cases: public-key encryption/decryption and public-key signatures/verification. It also mentions the difference between v1.5 and v2 (OAEP/PSS) algorithms. This immediately gives a strong foundation.
* **Key Data Structures:** I scan the code for the main data structures: `PublicKey` and `PrivateKey`. I see their fields: `N` (modulus), `E` (public exponent) for `PublicKey`, and the addition of `D` (private exponent), `Primes`, and `Precomputed` for `PrivateKey`. This tells me the fundamental components of an RSA key.
* **Import Statements:**  The import statements provide clues about dependencies and functionalities used. `crypto`, `crypto/rand`, `crypto/subtle`, `math/big`, `io` are all relevant to cryptographic operations, randomness, and big integer arithmetic, which are expected for RSA. The presence of `crypto/internal/boring` and `crypto/internal/fips140/*` hints at potential integration with BoringSSL or FIPS 140 compliance.
* **Core Functionality:** I look for functions that perform the core RSA operations. I spot methods like `Sign`, `Decrypt` on `PrivateKey`, and functions like `GenerateKey`, `SignPKCS1v15`, `SignPSS`, `DecryptPKCS1v15`, `decryptOAEP`. These are the workhorses of the package.

**2. Detailed Analysis - Function by Function (or Concept):**

* **`PublicKey` and `PrivateKey`:**  I note the `Size()` and `Equal()` methods for both structures. `Size()` returns the key size in bytes, and `Equal()` checks for value equality. The comment about `N` being secret regarding timing side-channels but `E` and bit size not being protected is important for security considerations.
* **`OAEPOptions`:** I recognize this as a struct for configuring OAEP decryption, noting the `Hash`, `MGFHash`, and `Label` fields.
* **`Sign` and `Decrypt` (methods on `PrivateKey`):**  These are the core interface implementations (`crypto.Signer`, `crypto.Decrypter`). I see how they delegate to specific signing/decrypting functions based on the `opts` parameter (PSS or PKCS#1 v1.5 for signing, OAEP or PKCS#1 v1.5 for decryption).
* **`PrecomputedValues` and `CRTValue`:**  I understand that these structures are for optimizing private key operations using the Chinese Remainder Theorem (CRT). The comment mentioning the historical accident with the first two primes is an interesting detail. The deprecation note for `CRTValues` in multi-prime RSA is also important.
* **`Validate`:** This function is for basic key sanity checks. The comment about it being faster after `Precompute` makes sense.
* **`GenerateKey` and `GenerateMultiPrimeKey`:**  These are crucial for creating RSA key pairs. I pay attention to the minimum key size check (1024 bits) and the `GODEBUG` setting to bypass it. The warnings about `GenerateMultiPrimeKey` regarding security, compatibility, and performance are significant.
* **Error Variables:**  `ErrMessageTooLong`, `ErrDecryption`, `ErrVerification` provide standard error indications.
* **`Precompute` and `precompute`:**  These functions handle the precomputation logic. The separate `precomputeLegacy` function suggests handling older key formats or multi-prime cases.
* **`fipsPublicKey` and `fipsPrivateKey`:** These functions suggest interaction with a FIPS-compliant implementation, likely the `crypto/internal/fips140/rsa` package.

**3. Identifying Key Functionalities and Providing Examples:**

Based on the function analysis, I can now list the functionalities:

* Key Generation
* Encryption/Decryption (PKCS#1 v1.5 and OAEP)
* Signing/Verification (PKCS#1 v1.5 and PSS)
* Key Validation
* Precomputation for optimization

Then I construct simple Go code examples for each of these. For example, for key generation, I'd show the basic usage of `GenerateKey`. For encryption, I'd demonstrate `EncryptOAEP` and `DecryptOAEP`.

**4. Code Reasoning with Hypothetical Inputs/Outputs:**

For more complex functions like `Sign` or `Decrypt`, I think about what input parameters are expected (e.g., `rand`, `PrivateKey`, `digest`, `opts` for `Sign`). I'd then imagine a simple scenario and what the output would look like (e.g., a signature as a byte slice). This helps in understanding the function's behavior.

**5. Command-Line Arguments (Not Applicable):**

I carefully read the code and realize there are no functions that directly parse command-line arguments. The code primarily deals with in-memory key representations and cryptographic operations. So, I explicitly state that there's no command-line argument processing in this specific snippet.

**6. Common Mistakes:**

I look for potential pitfalls based on the code and comments. The minimum key size is a clear candidate. Using the wrong options for decryption (e.g., using `nil` for OAEP) is another. The deprecation of `GenerateMultiPrimeKey` and its implications are also important.

**7. Language and Formatting:**

Finally, I ensure the answer is in Chinese as requested and format it clearly with headings and code blocks for readability.

**Self-Correction/Refinement During the Process:**

* **Initial Overlook:** I might initially miss the nuances of the `PrecomputedValues` and its relation to FIPS. Going back and rereading the comments helps clarify this.
* **Ambiguity in Examples:**  If my initial code examples are too vague, I refine them to be more concrete, including necessary imports and clearer variable names.
* **Missing Error Handling:**  I double-check if my examples include basic error handling, as is good practice in Go.

By following this structured thought process, I can thoroughly analyze the code snippet and provide a comprehensive and accurate answer to the user's request.
这段代码是 Go 语言 `crypto/rsa` 包中关于 RSA 加密算法实现的一部分核心代码。它定义了 RSA 密钥的结构体，并实现了与密钥相关的基本操作和接口。

以下是这段代码的主要功能：

1. **定义 RSA 密钥结构体：**
   - `PublicKey`: 表示 RSA 公钥，包含模数 `N` 和公钥指数 `E`。
   - `PrivateKey`: 表示 RSA 私钥，嵌入了 `PublicKey`，并额外包含私钥指数 `D` 和模数 `N` 的素数因子 `Primes`。还包含用于加速运算的预计算值 `Precomputed`。

2. **实现密钥的基本方法：**
   - `PublicKey.Size()`: 返回模数的大小（以字节为单位）。这决定了使用此公钥加密或签名的原始数据或密文的大小。
   - `PublicKey.Equal(crypto.PublicKey)`: 判断两个公钥是否相等。
   - `PrivateKey.Public()`: 返回私钥对应的公钥。
   - `PrivateKey.Equal(crypto.PrivateKey)`: 判断两个私钥是否相等（忽略预计算值）。
   - `bigIntEqual(a, b *big.Int)`: 以常量时间比较两个大整数是否相等，防止时序攻击泄露信息。

3. **实现 `crypto.Signer` 和 `crypto.Decrypter` 接口：**
   - `PrivateKey.Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts)`: 使用私钥对摘要进行签名。根据 `opts` 的类型，可以选择使用 PKCS #1 v1.5 或 PSS 算法。
   - `PrivateKey.Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts)`: 使用私钥解密密文。根据 `opts` 的类型，可以选择使用 PKCS #1 v1.5 或 OAEP 算法。

4. **定义 OAEP 解密选项结构体：**
   - `OAEPOptions`: 用于传递 OAEP 解密所需的选项，包括哈希函数 (`Hash` 和 `MGFHash`) 和标签 (`Label`)。

5. **定义预计算值结构体：**
   - `PrecomputedValues`: 包含加速 RSA 私钥操作的预计算值，例如 `Dp`、`Dq` 和 `Qinv`，这些值用于中国剩余定理（CRT）加速计算。还包含 `fips` 字段，可能用于 FIPS 认证的实现。
   - `CRTValue`: 包含用于多素数 RSA 的 CRT 值的结构体（虽然代码中注释说明多素数 RSA 的 CRT 优化已被弃用）。

6. **实现密钥的校验和生成：**
   - `PrivateKey.Validate()`: 对私钥进行基本健全性检查。

7. **实现密钥生成功能：**
   - `GenerateKey(random io.Reader, bits int)`: 生成指定位数的随机 RSA 私钥。如果位数小于 1024，则会返回错误，除非设置了 `GODEBUG` 环境变量 `rsa1024min=0`。
   - `GenerateMultiPrimeKey(random io.Reader, nprimes int, bits int)`: 生成多素数 RSA 密钥对（已弃用，不推荐使用）。

8. **定义错误类型：**
   - `ErrMessageTooLong`: 当尝试加密或签名的消息对于密钥大小来说太长时返回。
   - `ErrDecryption`: 解密失败时返回的错误。
   - `ErrVerification`: 签名验证失败时返回的错误。

9. **实现私钥预计算功能：**
   - `PrivateKey.Precompute()`: 执行一些计算来加速未来的私钥操作。

10. **内部辅助函数：**
    - `checkKeySize(size int)`: 检查密钥大小是否满足最低安全要求。
    - `checkPublicKeySize(k *PublicKey)`: 检查公钥的模数是否存在以及大小是否满足最低安全要求。
    - `precompute()`, `precomputeLegacy()`: 内部的预计算实现。
    - `fipsPublicKey(pub *PublicKey)`, `fipsPrivateKey(priv *PrivateKey)`:  可能用于与 FIPS 认证相关的密钥转换。

**它是什么 Go 语言功能的实现？**

这段代码实现了 **RSA 公钥加密和数字签名** 的功能。它提供了生成密钥对、加密数据、解密数据、签名数据和验证签名的能力。它遵循了 PKCS #1 和 RFC 8017 标准，并支持不同的填充方案（PKCS #1 v1.5, OAEP, PSS）。

**Go 代码示例说明：**

以下是一些使用 `crypto/rsa` 包进行常见 RSA 操作的示例：

**示例 1：生成 RSA 密钥对**

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
)

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	publicKey := &privateKey.PublicKey

	fmt.Printf("Generated RSA key pair:\n")
	fmt.Printf("Public Key (N): %X\n", publicKey.N)
	fmt.Printf("Public Key (E): %d\n", publicKey.E)
	// 私钥信息通常不直接打印，这里仅作演示
	// fmt.Printf("Private Key (D): %X\n", privateKey.D)
}
```

**假设输入与输出：**

* **输入：** 无（依赖于 `rand.Reader` 提供的随机性）
* **输出：** 将会打印生成的 RSA 公钥的模数 `N` (一个十六进制表示的大整数) 和公钥指数 `E` (通常为 65537)。私钥信息（`D`）在示例中被注释掉，因为通常不应直接打印或泄露。

**示例 2：使用 OAEP 加密和解密**

```go
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"log"
)

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	publicKey := &privateKey.PublicKey

	plaintext := []byte("这是一个需要加密的消息")
	label := []byte("OAEP Label")

	// 加密
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, label)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Ciphertext: %X\n", ciphertext)

	// 解密
	decryptedPlaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, label)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Decrypted Plaintext: %s\n", string(decryptedPlaintext))
}
```

**假设输入与输出：**

* **输入：** 字符串 "这是一个需要加密的消息"
* **输出：**
    * `Ciphertext`:  一段十六进制表示的加密后的数据，每次运行结果会因为随机性而不同。
    * `Decrypted Plaintext`: 字符串 "这是一个需要加密的消息"。

**示例 3：使用 PSS 签名和验证**

```go
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"log"
)

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	publicKey := &privateKey.PublicKey

	message := []byte("需要签名的消息")
	hashed := sha256.Sum256(message)

	// 签名
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed[:], nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Signature: %X\n", signature)

	// 验证
	err = rsa.VerifyPSS(publicKey, crypto.SHA256, hashed[:], signature, nil)
	if err != nil {
		log.Fatalf("Verification error: %v", err)
	}
	fmt.Println("Signature verified successfully.")
}
```

**假设输入与输出：**

* **输入：** 字符串 "需要签名的消息"
* **输出：**
    * `Signature`: 一段十六进制表示的签名数据，每次运行结果会因为随机性而不同。
    * "Signature verified successfully."

**命令行参数的具体处理：**

这段代码本身**不涉及**直接处理命令行参数。`crypto/rsa` 包主要提供 RSA 算法的底层实现，它依赖于其他包（例如 `flag` 包）来处理命令行输入。如果你想编写一个使用 RSA 进行加密或签名的命令行工具，你需要自己解析命令行参数，并将解析后的参数传递给 `crypto/rsa` 包提供的函数。

**使用者易犯错的点：**

1. **使用过小的密钥长度：**  代码中明确指出，小于 1024 位的密钥是不安全的，`GenerateKey` 默认会返回错误。使用者可能会忽略这个警告，或者为了测试方便设置 `GODEBUG=rsa1024min=0`，但在生产环境中这样做是危险的。

   ```go
   // 错误示例：尝试生成不安全的密钥
   privateKey, _ := rsa.GenerateKey(rand.Reader, 512) // 这通常会返回错误
   ```

2. **不正确的填充模式：**  RSA 加密和签名需要使用合适的填充模式（例如 PKCS #1 v1.5, OAEP, PSS）。如果加密和解密或签名和验证使用了不匹配的填充模式，会导致操作失败。

   ```go
   // 错误示例：使用 PKCS1v15 解密 OAEP 加密的数据
   // 假设 ciphertext 是用 OAEP 加密的
   decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext) // 这会失败
   ```

3. **混淆公钥和私钥的使用：**  加密应该使用公钥，解密应该使用私钥。签名应该使用私钥，验证应该使用公钥。混淆使用会导致操作失败或安全问题。

   ```go
   // 错误示例：使用私钥加密数据
   // 这不是标准的 RSA 用法
   // ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, privateKey, plaintext)
   ```

4. **在签名时使用原始消息而不是摘要：**  RSA 签名通常是对消息的哈希值（摘要）进行签名，而不是直接对原始消息签名。如果直接对原始消息签名，可能会超出密钥长度限制，或者存在安全风险。

   ```go
   // 错误示例：直接对消息签名（可能导致错误）
   // signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, message) // message 可能过长
   ```

5. **不处理错误：**  所有涉及加密和签名的操作都可能返回错误。使用者应该始终检查并妥善处理这些错误，而不是简单地忽略它们。

   ```go
   ciphertext, err := rsa.EncryptOAEP(...)
   if err != nil {
       log.Fatalf("Encryption failed: %v", err)
   }
   ```

理解这些常见的错误可以帮助使用者更安全有效地使用 `crypto/rsa` 包。

### 提示词
```
这是路径为go/src/crypto/rsa/rsa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package rsa implements RSA encryption as specified in PKCS #1 and RFC 8017.
//
// RSA is a single, fundamental operation that is used in this package to
// implement either public-key encryption or public-key signatures.
//
// The original specification for encryption and signatures with RSA is PKCS #1
// and the terms "RSA encryption" and "RSA signatures" by default refer to
// PKCS #1 version 1.5. However, that specification has flaws and new designs
// should use version 2, usually called by just OAEP and PSS, where
// possible.
//
// Two sets of interfaces are included in this package. When a more abstract
// interface isn't necessary, there are functions for encrypting/decrypting
// with v1.5/OAEP and signing/verifying with v1.5/PSS. If one needs to abstract
// over the public key primitive, the PrivateKey type implements the
// Decrypter and Signer interfaces from the crypto package.
//
// Operations involving private keys are implemented using constant-time
// algorithms, except for [GenerateKey] and for some operations involving
// deprecated multi-prime keys.
//
// # Minimum key size
//
// [GenerateKey] returns an error if a key of less than 1024 bits is requested,
// and all Sign, Verify, Encrypt, and Decrypt methods return an error if used
// with a key smaller than 1024 bits. Such keys are insecure and should not be
// used.
//
// The `rsa1024min=0` GODEBUG setting suppresses this error, but we recommend
// doing so only in tests, if necessary. Tests can use [testing.T.Setenv] or
// include `//go:debug rsa1024min=0` in a `_test.go` source file to set it.
//
// Alternatively, see the [GenerateKey (TestKey)] example for a pregenerated
// test-only 2048-bit key.
//
// [GenerateKey (TestKey)]: #example-GenerateKey-TestKey
package rsa

import (
	"crypto"
	"crypto/internal/boring"
	"crypto/internal/boring/bbig"
	"crypto/internal/fips140/bigmod"
	"crypto/internal/fips140/rsa"
	"crypto/internal/fips140only"
	"crypto/internal/randutil"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"internal/godebug"
	"io"
	"math"
	"math/big"
)

var bigOne = big.NewInt(1)

// A PublicKey represents the public part of an RSA key.
//
// The value of the modulus N is considered secret by this library and protected
// from leaking through timing side-channels. However, neither the value of the
// exponent E nor the precise bit size of N are similarly protected.
type PublicKey struct {
	N *big.Int // modulus
	E int      // public exponent
}

// Any methods implemented on PublicKey might need to also be implemented on
// PrivateKey, as the latter embeds the former and will expose its methods.

// Size returns the modulus size in bytes. Raw signatures and ciphertexts
// for or by this public key will have the same size.
func (pub *PublicKey) Size() int {
	return (pub.N.BitLen() + 7) / 8
}

// Equal reports whether pub and x have the same value.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey)
	if !ok {
		return false
	}
	return bigIntEqual(pub.N, xx.N) && pub.E == xx.E
}

// OAEPOptions is an interface for passing options to OAEP decryption using the
// crypto.Decrypter interface.
type OAEPOptions struct {
	// Hash is the hash function that will be used when generating the mask.
	Hash crypto.Hash

	// MGFHash is the hash function used for MGF1.
	// If zero, Hash is used instead.
	MGFHash crypto.Hash

	// Label is an arbitrary byte string that must be equal to the value
	// used when encrypting.
	Label []byte
}

// A PrivateKey represents an RSA key
type PrivateKey struct {
	PublicKey            // public part.
	D         *big.Int   // private exponent
	Primes    []*big.Int // prime factors of N, has >= 2 elements.

	// Precomputed contains precomputed values that speed up RSA operations,
	// if available. It must be generated by calling PrivateKey.Precompute and
	// must not be modified.
	Precomputed PrecomputedValues
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

// Equal reports whether priv and x have equivalent values. It ignores
// Precomputed values.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	if !priv.PublicKey.Equal(&xx.PublicKey) || !bigIntEqual(priv.D, xx.D) {
		return false
	}
	if len(priv.Primes) != len(xx.Primes) {
		return false
	}
	for i := range priv.Primes {
		if !bigIntEqual(priv.Primes[i], xx.Primes[i]) {
			return false
		}
	}
	return true
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
	return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}

// Sign signs digest with priv, reading randomness from rand. If opts is a
// *[PSSOptions] then the PSS algorithm will be used, otherwise PKCS #1 v1.5 will
// be used. digest must be the result of hashing the input message using
// opts.HashFunc().
//
// This method implements [crypto.Signer], which is an interface to support keys
// where the private part is kept in, for example, a hardware module. Common
// uses should use the Sign* functions in this package directly.
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if pssOpts, ok := opts.(*PSSOptions); ok {
		return SignPSS(rand, priv, pssOpts.Hash, digest, pssOpts)
	}

	return SignPKCS1v15(rand, priv, opts.HashFunc(), digest)
}

// Decrypt decrypts ciphertext with priv. If opts is nil or of type
// *[PKCS1v15DecryptOptions] then PKCS #1 v1.5 decryption is performed. Otherwise
// opts must have type *[OAEPOptions] and OAEP decryption is done.
func (priv *PrivateKey) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	if opts == nil {
		return DecryptPKCS1v15(rand, priv, ciphertext)
	}

	switch opts := opts.(type) {
	case *OAEPOptions:
		if opts.MGFHash == 0 {
			return decryptOAEP(opts.Hash.New(), opts.Hash.New(), priv, ciphertext, opts.Label)
		} else {
			return decryptOAEP(opts.Hash.New(), opts.MGFHash.New(), priv, ciphertext, opts.Label)
		}

	case *PKCS1v15DecryptOptions:
		if l := opts.SessionKeyLen; l > 0 {
			plaintext = make([]byte, l)
			if _, err := io.ReadFull(rand, plaintext); err != nil {
				return nil, err
			}
			if err := DecryptPKCS1v15SessionKey(rand, priv, ciphertext, plaintext); err != nil {
				return nil, err
			}
			return plaintext, nil
		} else {
			return DecryptPKCS1v15(rand, priv, ciphertext)
		}

	default:
		return nil, errors.New("crypto/rsa: invalid options for Decrypt")
	}
}

type PrecomputedValues struct {
	Dp, Dq *big.Int // D mod (P-1) (or mod Q-1)
	Qinv   *big.Int // Q^-1 mod P

	// CRTValues is used for the 3rd and subsequent primes. Due to a
	// historical accident, the CRT for the first two primes is handled
	// differently in PKCS #1 and interoperability is sufficiently
	// important that we mirror this.
	//
	// Deprecated: These values are still filled in by Precompute for
	// backwards compatibility but are not used. Multi-prime RSA is very rare,
	// and is implemented by this package without CRT optimizations to limit
	// complexity.
	CRTValues []CRTValue

	fips *rsa.PrivateKey
}

// CRTValue contains the precomputed Chinese remainder theorem values.
type CRTValue struct {
	Exp   *big.Int // D mod (prime-1).
	Coeff *big.Int // R·Coeff ≡ 1 mod Prime.
	R     *big.Int // product of primes prior to this (inc p and q).
}

// Validate performs basic sanity checks on the key.
// It returns nil if the key is valid, or else an error describing a problem.
//
// It runs faster on valid keys if run after [Precompute].
func (priv *PrivateKey) Validate() error {
	// We can operate on keys based on d alone, but it isn't possible to encode
	// with [crypto/x509.MarshalPKCS1PrivateKey], which unfortunately doesn't
	// return an error.
	if len(priv.Primes) < 2 {
		return errors.New("crypto/rsa: missing primes")
	}
	// If Precomputed.fips is set, then the key has been validated by
	// [rsa.NewPrivateKey] or [rsa.NewPrivateKeyWithoutCRT].
	if priv.Precomputed.fips != nil {
		return nil
	}
	_, err := priv.precompute()
	return err
}

// rsa1024min is a GODEBUG that re-enables weak RSA keys if set to "0".
// See https://go.dev/issue/68762.
var rsa1024min = godebug.New("rsa1024min")

func checkKeySize(size int) error {
	if size >= 1024 {
		return nil
	}
	if rsa1024min.Value() == "0" {
		rsa1024min.IncNonDefault()
		return nil
	}
	return fmt.Errorf("crypto/rsa: %d-bit keys are insecure (see https://go.dev/pkg/crypto/rsa#hdr-Minimum_key_size)", size)
}

func checkPublicKeySize(k *PublicKey) error {
	if k.N == nil {
		return errors.New("crypto/rsa: missing public modulus")
	}
	return checkKeySize(k.N.BitLen())
}

// GenerateKey generates a random RSA private key of the given bit size.
//
// If bits is less than 1024, [GenerateKey] returns an error. See the "[Minimum
// key size]" section for further details.
//
// Most applications should use [crypto/rand.Reader] as rand. Note that the
// returned key does not depend deterministically on the bytes read from rand,
// and may change between calls and/or between versions.
//
// [Minimum key size]: #hdr-Minimum_key_size
func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	if err := checkKeySize(bits); err != nil {
		return nil, err
	}

	if boring.Enabled && random == boring.RandReader &&
		(bits == 2048 || bits == 3072 || bits == 4096) {
		bN, bE, bD, bP, bQ, bDp, bDq, bQinv, err := boring.GenerateKeyRSA(bits)
		if err != nil {
			return nil, err
		}
		N := bbig.Dec(bN)
		E := bbig.Dec(bE)
		D := bbig.Dec(bD)
		P := bbig.Dec(bP)
		Q := bbig.Dec(bQ)
		Dp := bbig.Dec(bDp)
		Dq := bbig.Dec(bDq)
		Qinv := bbig.Dec(bQinv)
		e64 := E.Int64()
		if !E.IsInt64() || int64(int(e64)) != e64 {
			return nil, errors.New("crypto/rsa: generated key exponent too large")
		}

		key := &PrivateKey{
			PublicKey: PublicKey{
				N: N,
				E: int(e64),
			},
			D:      D,
			Primes: []*big.Int{P, Q},
			Precomputed: PrecomputedValues{
				Dp:        Dp,
				Dq:        Dq,
				Qinv:      Qinv,
				CRTValues: make([]CRTValue, 0), // non-nil, to match Precompute
			},
		}
		return key, nil
	}

	if fips140only.Enabled && bits < 2048 {
		return nil, errors.New("crypto/rsa: use of keys smaller than 2048 bits is not allowed in FIPS 140-only mode")
	}
	if fips140only.Enabled && bits%2 == 1 {
		return nil, errors.New("crypto/rsa: use of keys with odd size is not allowed in FIPS 140-only mode")
	}
	if fips140only.Enabled && !fips140only.ApprovedRandomReader(random) {
		return nil, errors.New("crypto/rsa: only crypto/rand.Reader is allowed in FIPS 140-only mode")
	}

	k, err := rsa.GenerateKey(random, bits)
	if err != nil {
		return nil, err
	}
	N, e, d, p, q, dP, dQ, qInv := k.Export()
	key := &PrivateKey{
		PublicKey: PublicKey{
			N: new(big.Int).SetBytes(N),
			E: e,
		},
		D: new(big.Int).SetBytes(d),
		Primes: []*big.Int{
			new(big.Int).SetBytes(p),
			new(big.Int).SetBytes(q),
		},
		Precomputed: PrecomputedValues{
			fips:      k,
			Dp:        new(big.Int).SetBytes(dP),
			Dq:        new(big.Int).SetBytes(dQ),
			Qinv:      new(big.Int).SetBytes(qInv),
			CRTValues: make([]CRTValue, 0), // non-nil, to match Precompute
		},
	}
	return key, nil
}

// GenerateMultiPrimeKey generates a multi-prime RSA keypair of the given bit
// size and the given random source.
//
// Table 1 in "[On the Security of Multi-prime RSA]" suggests maximum numbers of
// primes for a given bit size.
//
// Although the public keys are compatible (actually, indistinguishable) from
// the 2-prime case, the private keys are not. Thus it may not be possible to
// export multi-prime private keys in certain formats or to subsequently import
// them into other code.
//
// This package does not implement CRT optimizations for multi-prime RSA, so the
// keys with more than two primes will have worse performance.
//
// Deprecated: The use of this function with a number of primes different from
// two is not recommended for the above security, compatibility, and performance
// reasons. Use [GenerateKey] instead.
//
// [On the Security of Multi-prime RSA]: http://www.cacr.math.uwaterloo.ca/techreports/2006/cacr2006-16.pdf
func GenerateMultiPrimeKey(random io.Reader, nprimes int, bits int) (*PrivateKey, error) {
	if nprimes == 2 {
		return GenerateKey(random, bits)
	}
	if fips140only.Enabled {
		return nil, errors.New("crypto/rsa: multi-prime RSA is not allowed in FIPS 140-only mode")
	}

	randutil.MaybeReadByte(random)

	priv := new(PrivateKey)
	priv.E = 65537

	if nprimes < 2 {
		return nil, errors.New("crypto/rsa: GenerateMultiPrimeKey: nprimes must be >= 2")
	}

	if bits < 64 {
		primeLimit := float64(uint64(1) << uint(bits/nprimes))
		// pi approximates the number of primes less than primeLimit
		pi := primeLimit / (math.Log(primeLimit) - 1)
		// Generated primes start with 11 (in binary) so we can only
		// use a quarter of them.
		pi /= 4
		// Use a factor of two to ensure that key generation terminates
		// in a reasonable amount of time.
		pi /= 2
		if pi <= float64(nprimes) {
			return nil, errors.New("crypto/rsa: too few primes of given length to generate an RSA key")
		}
	}

	primes := make([]*big.Int, nprimes)

NextSetOfPrimes:
	for {
		todo := bits
		// crypto/rand should set the top two bits in each prime.
		// Thus each prime has the form
		//   p_i = 2^bitlen(p_i) × 0.11... (in base 2).
		// And the product is:
		//   P = 2^todo × α
		// where α is the product of nprimes numbers of the form 0.11...
		//
		// If α < 1/2 (which can happen for nprimes > 2), we need to
		// shift todo to compensate for lost bits: the mean value of 0.11...
		// is 7/8, so todo + shift - nprimes * log2(7/8) ~= bits - 1/2
		// will give good results.
		if nprimes >= 7 {
			todo += (nprimes - 2) / 5
		}
		for i := 0; i < nprimes; i++ {
			var err error
			primes[i], err = rand.Prime(random, todo/(nprimes-i))
			if err != nil {
				return nil, err
			}
			todo -= primes[i].BitLen()
		}

		// Make sure that primes is pairwise unequal.
		for i, prime := range primes {
			for j := 0; j < i; j++ {
				if prime.Cmp(primes[j]) == 0 {
					continue NextSetOfPrimes
				}
			}
		}

		n := new(big.Int).Set(bigOne)
		totient := new(big.Int).Set(bigOne)
		pminus1 := new(big.Int)
		for _, prime := range primes {
			n.Mul(n, prime)
			pminus1.Sub(prime, bigOne)
			totient.Mul(totient, pminus1)
		}
		if n.BitLen() != bits {
			// This should never happen for nprimes == 2 because
			// crypto/rand should set the top two bits in each prime.
			// For nprimes > 2 we hope it does not happen often.
			continue NextSetOfPrimes
		}

		priv.D = new(big.Int)
		e := big.NewInt(int64(priv.E))
		ok := priv.D.ModInverse(e, totient)

		if ok != nil {
			priv.Primes = primes
			priv.N = n
			break
		}
	}

	priv.Precompute()
	if err := priv.Validate(); err != nil {
		return nil, err
	}

	return priv, nil
}

// ErrMessageTooLong is returned when attempting to encrypt or sign a message
// which is too large for the size of the key. When using [SignPSS], this can also
// be returned if the size of the salt is too large.
var ErrMessageTooLong = errors.New("crypto/rsa: message too long for RSA key size")

// ErrDecryption represents a failure to decrypt a message.
// It is deliberately vague to avoid adaptive attacks.
var ErrDecryption = errors.New("crypto/rsa: decryption error")

// ErrVerification represents a failure to verify a signature.
// It is deliberately vague to avoid adaptive attacks.
var ErrVerification = errors.New("crypto/rsa: verification error")

// Precompute performs some calculations that speed up private key operations
// in the future. It is safe to run on non-validated private keys.
func (priv *PrivateKey) Precompute() {
	if priv.Precomputed.fips != nil {
		return
	}

	precomputed, err := priv.precompute()
	if err != nil {
		// We don't have a way to report errors, so just leave the key
		// unmodified. Validate will re-run precompute.
		return
	}
	priv.Precomputed = precomputed
}

func (priv *PrivateKey) precompute() (PrecomputedValues, error) {
	var precomputed PrecomputedValues

	if priv.N == nil {
		return precomputed, errors.New("crypto/rsa: missing public modulus")
	}
	if priv.D == nil {
		return precomputed, errors.New("crypto/rsa: missing private exponent")
	}
	if len(priv.Primes) != 2 {
		return priv.precomputeLegacy()
	}
	if priv.Primes[0] == nil {
		return precomputed, errors.New("crypto/rsa: prime P is nil")
	}
	if priv.Primes[1] == nil {
		return precomputed, errors.New("crypto/rsa: prime Q is nil")
	}

	// If the CRT values are already set, use them.
	if priv.Precomputed.Dp != nil && priv.Precomputed.Dq != nil && priv.Precomputed.Qinv != nil {
		k, err := rsa.NewPrivateKeyWithPrecomputation(priv.N.Bytes(), priv.E, priv.D.Bytes(),
			priv.Primes[0].Bytes(), priv.Primes[1].Bytes(),
			priv.Precomputed.Dp.Bytes(), priv.Precomputed.Dq.Bytes(), priv.Precomputed.Qinv.Bytes())
		if err != nil {
			return precomputed, err
		}
		precomputed = priv.Precomputed
		precomputed.fips = k
		precomputed.CRTValues = make([]CRTValue, 0)
		return precomputed, nil
	}

	k, err := rsa.NewPrivateKey(priv.N.Bytes(), priv.E, priv.D.Bytes(),
		priv.Primes[0].Bytes(), priv.Primes[1].Bytes())
	if err != nil {
		return precomputed, err
	}

	precomputed.fips = k
	_, _, _, _, _, dP, dQ, qInv := k.Export()
	precomputed.Dp = new(big.Int).SetBytes(dP)
	precomputed.Dq = new(big.Int).SetBytes(dQ)
	precomputed.Qinv = new(big.Int).SetBytes(qInv)
	precomputed.CRTValues = make([]CRTValue, 0)
	return precomputed, nil
}

func (priv *PrivateKey) precomputeLegacy() (PrecomputedValues, error) {
	var precomputed PrecomputedValues

	k, err := rsa.NewPrivateKeyWithoutCRT(priv.N.Bytes(), priv.E, priv.D.Bytes())
	if err != nil {
		return precomputed, err
	}
	precomputed.fips = k

	if len(priv.Primes) < 2 {
		return precomputed, nil
	}

	// Ensure the Mod and ModInverse calls below don't panic.
	for _, prime := range priv.Primes {
		if prime == nil {
			return precomputed, errors.New("crypto/rsa: prime factor is nil")
		}
		if prime.Cmp(bigOne) <= 0 {
			return precomputed, errors.New("crypto/rsa: prime factor is <= 1")
		}
	}

	precomputed.Dp = new(big.Int).Sub(priv.Primes[0], bigOne)
	precomputed.Dp.Mod(priv.D, precomputed.Dp)

	precomputed.Dq = new(big.Int).Sub(priv.Primes[1], bigOne)
	precomputed.Dq.Mod(priv.D, precomputed.Dq)

	precomputed.Qinv = new(big.Int).ModInverse(priv.Primes[1], priv.Primes[0])
	if precomputed.Qinv == nil {
		return precomputed, errors.New("crypto/rsa: prime factors are not relatively prime")
	}

	r := new(big.Int).Mul(priv.Primes[0], priv.Primes[1])
	precomputed.CRTValues = make([]CRTValue, len(priv.Primes)-2)
	for i := 2; i < len(priv.Primes); i++ {
		prime := priv.Primes[i]
		values := &precomputed.CRTValues[i-2]

		values.Exp = new(big.Int).Sub(prime, bigOne)
		values.Exp.Mod(priv.D, values.Exp)

		values.R = new(big.Int).Set(r)
		values.Coeff = new(big.Int).ModInverse(r, prime)
		if values.Coeff == nil {
			return precomputed, errors.New("crypto/rsa: prime factors are not relatively prime")
		}

		r.Mul(r, prime)
	}

	return precomputed, nil
}

func fipsPublicKey(pub *PublicKey) (*rsa.PublicKey, error) {
	N, err := bigmod.NewModulus(pub.N.Bytes())
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{N: N, E: pub.E}, nil
}

func fipsPrivateKey(priv *PrivateKey) (*rsa.PrivateKey, error) {
	if priv.Precomputed.fips != nil {
		return priv.Precomputed.fips, nil
	}
	precomputed, err := priv.precompute()
	if err != nil {
		return nil, err
	}
	return precomputed.fips, nil
}
```