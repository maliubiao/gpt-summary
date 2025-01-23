Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The primary request is to understand the *functionality* of the provided Go code, which is a part of the `crypto/rsa` package and specifically the `fips.go` file. This immediately suggests a focus on FIPS 140 compliance.

2. **Initial Scan for Clues:**  A quick read-through reveals several key terms and concepts:
    * `fips`: This appears in the filename and several function/variable names. This is a strong indicator of FIPS 140-3 related functionality.
    * `PSS`, `OAEP`, `PKCS1v15`: These are well-known RSA signature and encryption schemes.
    * `crypto.Hash`:  Indicates cryptographic hashing is involved.
    * `io.Reader`:  Suggests the need for a source of randomness.
    * `PrivateKey`, `PublicKey`:  Clearly deals with RSA key pairs.
    * `fips140only`: This package name pops up repeatedly, reinforcing the FIPS theme.
    * `boring`:  This suggests potential integration with BoringSSL, a FIPS-certified library.
    * Error handling (`errors.New`, `fipsError`): Standard Go error handling.

3. **Identify Core Functions:** The code defines several top-level functions like `SignPSS`, `VerifyPSS`, `EncryptOAEP`, `DecryptOAEP`, `SignPKCS1v15`, and `VerifyPKCS1v15`. These are the main entry points and represent the core functionalities provided by this file.

4. **Analyze Function by Function:**  Take each core function and try to understand its purpose:

    * **`SignPSS`**:  The name strongly suggests it's for generating PSS signatures. Look for keywords like "signing," "digest," "salt." The code checks FIPS mode, hash function validity, and uses `rsa.SignPSS` under the hood.

    * **`VerifyPSS`**:  Likely for verifying PSS signatures. Look for "verifies," "signature," "digest." Similar FIPS checks are present.

    * **`EncryptOAEP`**:  Handles RSA-OAEP encryption. Look for "encrypts," "message," "label." Again, FIPS mode and hash checks are there.

    * **`DecryptOAEP`**: Decrypts using RSA-OAEP. Look for "decrypts," "ciphertext," "label."

    * **`SignPKCS1v15`**: Implements PKCS#1 v1.5 signing. Look for "signature," "hashed."

    * **`VerifyPKCS1v15`**: Verifies PKCS#1 v1.5 signatures.

5. **Examine Supporting Structures and Functions:**

    * **`PSSOptions`**:  This struct clearly holds parameters specific to PSS signing and verification (e.g., `SaltLength`, `Hash`). The `saltLength()` method provides a helper for retrieving the salt length.

    * **Constants (`PSSSaltLengthAuto`, `PSSSaltLengthEqualsHash`)**: These define special values for the `SaltLength` option, offering flexibility in salt management.

    * **`fipsError`, `fipsError2`**: These functions seem to wrap errors returned by the underlying FIPS implementation, translating them to the `crypto/rsa` package's error types.

    * **`checkFIPS140OnlyPublicKey`, `checkFIPS140OnlyPrivateKey`**:  These functions enforce FIPS 140-3 requirements on key sizes and formats.

6. **Identify the "Why":**  The consistent presence of `fips140only` and the checks within the functions strongly suggest this file is a FIPS 140-3 compliant implementation of RSA cryptographic operations. The presence of `boring` hints at a dual implementation strategy where, in some cases, the work might be delegated to BoringSSL.

7. **Construct the Explanation:** Now, organize the findings into a clear and structured answer:

    * **Start with a high-level summary:** State that the code implements RSA functionalities in a FIPS 140-3 compliant manner.
    * **List the core functionalities:** Clearly enumerate the signing and encryption/decryption functions.
    * **Explain each function in detail:**  Describe its purpose, key parameters, and how it relates to FIPS compliance (e.g., hash restrictions, randomness source).
    * **Provide Go code examples:** Illustrate the usage of key functions like `SignPSS` and `EncryptOAEP`, including input and output (or potential error). This makes the explanation more concrete.
    * **Address command-line arguments (if applicable):** In this specific code, there aren't direct command-line arguments being processed, so state that explicitly.
    * **Identify potential pitfalls:**  Think about common mistakes users might make, especially related to FIPS compliance (e.g., incorrect hash functions, non-compliant randomness).
    * **Use clear and concise language:**  Avoid jargon where possible and explain technical terms when necessary.

8. **Review and Refine:** Read through the generated answer to ensure accuracy, completeness, and clarity. Are there any ambiguities? Is the explanation logical and easy to follow?  For instance, initially, I might have missed the subtleties of `PSSSaltLengthAuto` and `PSSSaltLengthEqualsHash`, but a closer look at the code would reveal their purpose.

This iterative process of scanning, identifying, analyzing, and organizing information allows for a comprehensive understanding of the code and the generation of a detailed and helpful explanation.
这段Go语言代码是 `crypto/rsa` 包的一部分，专门用于在**FIPS 140-3 模式**下执行 RSA 加密和签名操作。它提供了一组符合 FIPS 标准的函数，用于执行 PSS 签名、OAEP 加密/解密以及 PKCS#1 v1.5 签名/校验。

**核心功能列举:**

1. **PSS 签名 (`SignPSS`):**  使用概率签名方案 (Probabilistic Signature Scheme, PSS) 对消息摘要进行签名。它允许设置盐值的长度，并强制在 FIPS 模式下使用批准的哈希算法（SHA-2 或 SHA-3）。
2. **PSS 签名校验 (`VerifyPSS`):** 验证 PSS 签名是否与给定的公钥和消息摘要匹配。
3. **OAEP 加密 (`EncryptOAEP`):** 使用最优非对称加密填充 (Optimal Asymmetric Encryption Padding, OAEP) 方案加密消息。它需要指定一个哈希函数作为随机预言机，并允许包含一个可选的标签。同样，FIPS 模式下限制了可用的哈希算法。
4. **OAEP 解密 (`DecryptOAEP`):** 使用 OAEP 方案解密密文。
5. **PKCS#1 v1.5 签名 (`SignPKCS1v15`):** 使用 RSA PKCS #1 v1.5 标准进行签名。可以对已哈希的消息进行签名，也可以直接对消息进行签名（不建议，除非为了互操作性）。
6. **PKCS#1 v1.5 签名校验 (`VerifyPKCS1v15`):** 验证 RSA PKCS #1 v1.5 签名。

**它是什么Go语言功能的实现？**

这段代码是 Go 语言标准库 `crypto/rsa` 包中针对 **FIPS 140-3 合规性** 的特定实现。  FIPS 140-3 是一项美国政府标准，用于验证加密模块的安全性。当 Go 程序以 FIPS 模式运行时（通常通过构建标签或环境变量控制），会调用此文件中的函数，而不是 `rsa` 包中默认的实现。

**Go 代码举例说明:**

以下代码演示了如何使用 `SignPSS` 函数在 FIPS 模式下进行签名：

```go
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"os"
)

func main() {
	// 假设我们已经有一个 RSA 私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating private key:", err)
		os.Exit(1)
	}

	message := []byte("这是一个需要签名的消息")
	hashed := sha256.Sum256(message)

	// 设置 PSSOptions，使用默认的盐值长度
	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	}

	// 在 FIPS 模式下，SignPSS 会被调用
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed[:], opts)
	if err != nil {
		fmt.Println("Error signing:", err)
		os.Exit(1)
	}

	fmt.Printf("签名结果: %x\n", signature)

	// 验证签名 (假设公钥已知)
	err = rsa.VerifyPSS(&privateKey.PublicKey, crypto.SHA256, hashed[:], signature, opts)
	if err != nil {
		fmt.Println("Error verifying signature:", err)
		os.Exit(1)
	}

	fmt.Println("签名验证成功！")
}
```

**假设的输入与输出:**

* **输入 (对于 `SignPSS`):**
    * `rand.Reader`:  一个安全的随机数生成器。
    * `privateKey`: 一个 `*rsa.PrivateKey` 类型的 RSA 私钥。
    * `crypto.SHA256`:  用于哈希消息的哈希算法。
    * `hashed[:]`:  消息的 SHA256 哈希值的字节切片。
    * `opts`:  `&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}`。

* **输出 (对于 `SignPSS`):**
    * `signature`:  一个字节切片，包含生成的 PSS 签名。例如：`[...byte array...]`
    * `err`:  如果签名成功，则为 `nil`，否则包含错误信息。

**代码推理:**

这段代码的核心逻辑在于根据是否启用了 FIPS 模式，选择调用不同的底层实现。

* **FIPS 模式启用时 (`fips140only.Enabled` 为 `true`)**:  会调用 `crypto/internal/fips140/rsa` 包中的函数（例如 `rsa.SignPSS`, `rsa.EncryptOAEP` 等）。这些函数是经过 FIPS 认证的实现。同时，代码会进行严格的检查，例如：
    * 密钥长度必须至少为 2048 位，且为偶数。
    * 公钥指数不能小于等于 2<sup>16</sup> 且为奇数。
    * 只能使用批准的哈希算法（SHA-2 或 SHA-3）。
    * 只能使用 `crypto/rand.Reader` 作为随机数源。
    * PSS 签名的盐值长度不能超过所用哈希算法的输出长度。

* **FIPS 模式未启用时**:  如果 `boring.Enabled` 为 `true`，则会尝试调用 BoringSSL 提供的实现。否则，可能使用 `crypto/rsa` 包中的默认实现（虽然这段 `fips.go` 文件本身就是 FIPS 模式下的实现）。

**命令行参数的具体处理:**

这段代码本身**不直接处理命令行参数**。  FIPS 模式的启用通常是通过 Go 编译器的构建标签或者运行时环境变量来控制的。

* **构建标签:**  编译时可以使用 `-tags fips` 标签来启用 FIPS 模式，例如：
  ```bash
  go build -tags fips myapp.go
  ```
* **环境变量:**  某些环境可能会使用环境变量来指示 FIPS 模式，但这通常是底层库或操作系统级别的配置，而不是这段 Go 代码直接处理的。

**使用者易犯错的点:**

1. **使用了不被 FIPS 批准的哈希算法:** 在 FIPS 模式下，尝试使用像 MD5 或 SHA1 这样的哈希算法会导致错误。

   ```go
   // 错误示例（FIPS 模式下）
   opts := &rsa.PSSOptions{
       SaltLength: rsa.PSSSaltLengthAuto,
       Hash:       crypto.MD5, // MD5 在 FIPS 模式下不被允许
   }
   ```

   **错误信息示例:** `crypto/rsa: use of hash functions other than SHA-2 or SHA-3 is not allowed in FIPS 140-only mode`

2. **使用了不符合 FIPS 要求的密钥长度:**  尝试使用过短的 RSA 密钥（例如 1024 位）会失败。

   ```go
   // 错误示例（FIPS 模式下）
   privateKey, _ := rsa.GenerateKey(rand.Reader, 1024)
   ```

   **错误信息示例:** `crypto/rsa: use of keys smaller than 2048 bits is not allowed in FIPS 140-only mode`

3. **在 FIPS 模式下使用了非 `crypto/rand.Reader` 的随机数源:**  FIPS 模式要求使用经过认证的随机数生成器，而 `crypto/rand.Reader` 是 Go 标准库中提供的符合要求的实现。

   ```go
   // 错误示例（FIPS 模式下）
   myRand := &MyInsecureRandom{} // 假设这是一个不安全的随机数生成器
   signature, err := rsa.SignPSS(myRand, privateKey, crypto.SHA256, hashed[:], opts)
   ```

   **错误信息示例:** `crypto/rsa: only crypto/rand.Reader is allowed in FIPS 140-only mode`

4. **PSS 签名中使用了过长的盐值:**  在 FIPS 模式下，PSS 签名的盐值长度不能超过所用哈希算法的输出长度。

   ```go
   // 错误示例（FIPS 模式下，假设 SHA256 输出为 32 字节）
   opts := &rsa.PSSOptions{
       SaltLength: 33, // 超过 SHA256 的输出长度
       Hash:       crypto.SHA256,
   }
   ```

   **错误信息示例:** `crypto/rsa: use of PSS salt longer than the hash is not allowed in FIPS 140-only mode`

总而言之，这段代码是 Go 语言在需要满足 FIPS 140-3 安全标准时，进行 RSA 加密和签名操作的关键实现。使用者需要特别注意 FIPS 模式下的限制，包括哈希算法的选择、密钥长度以及随机数生成器的使用。

### 提示词
```
这是路径为go/src/crypto/rsa/fips.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto"
	"crypto/internal/boring"
	"crypto/internal/fips140/rsa"
	"crypto/internal/fips140only"
	"errors"
	"hash"
	"io"
)

const (
	// PSSSaltLengthAuto causes the salt in a PSS signature to be as large
	// as possible when signing, and to be auto-detected when verifying.
	//
	// When signing in FIPS 140-3 mode, the salt length is capped at the length
	// of the hash function used in the signature.
	PSSSaltLengthAuto = 0
	// PSSSaltLengthEqualsHash causes the salt length to equal the length
	// of the hash used in the signature.
	PSSSaltLengthEqualsHash = -1
)

// PSSOptions contains options for creating and verifying PSS signatures.
type PSSOptions struct {
	// SaltLength controls the length of the salt used in the PSS signature. It
	// can either be a positive number of bytes, or one of the special
	// PSSSaltLength constants.
	SaltLength int

	// Hash is the hash function used to generate the message digest. If not
	// zero, it overrides the hash function passed to SignPSS. It's required
	// when using PrivateKey.Sign.
	Hash crypto.Hash
}

// HashFunc returns opts.Hash so that [PSSOptions] implements [crypto.SignerOpts].
func (opts *PSSOptions) HashFunc() crypto.Hash {
	return opts.Hash
}

func (opts *PSSOptions) saltLength() int {
	if opts == nil {
		return PSSSaltLengthAuto
	}
	return opts.SaltLength
}

// SignPSS calculates the signature of digest using PSS.
//
// digest must be the result of hashing the input message using the given hash
// function. The opts argument may be nil, in which case sensible defaults are
// used. If opts.Hash is set, it overrides hash.
//
// The signature is randomized depending on the message, key, and salt size,
// using bytes from rand. Most applications should use [crypto/rand.Reader] as
// rand.
func SignPSS(rand io.Reader, priv *PrivateKey, hash crypto.Hash, digest []byte, opts *PSSOptions) ([]byte, error) {
	if err := checkPublicKeySize(&priv.PublicKey); err != nil {
		return nil, err
	}
	if err := checkFIPS140OnlyPrivateKey(priv); err != nil {
		return nil, err
	}
	if fips140only.Enabled && !fips140only.ApprovedHash(hash.New()) {
		return nil, errors.New("crypto/rsa: use of hash functions other than SHA-2 or SHA-3 is not allowed in FIPS 140-only mode")
	}
	if fips140only.Enabled && !fips140only.ApprovedRandomReader(rand) {
		return nil, errors.New("crypto/rsa: only crypto/rand.Reader is allowed in FIPS 140-only mode")
	}

	if opts != nil && opts.Hash != 0 {
		hash = opts.Hash
	}

	if boring.Enabled && rand == boring.RandReader {
		bkey, err := boringPrivateKey(priv)
		if err != nil {
			return nil, err
		}
		return boring.SignRSAPSS(bkey, hash, digest, opts.saltLength())
	}
	boring.UnreachableExceptTests()

	k, err := fipsPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	h := hash.New()

	saltLength := opts.saltLength()
	if fips140only.Enabled && saltLength > hash.Size() {
		return nil, errors.New("crypto/rsa: use of PSS salt longer than the hash is not allowed in FIPS 140-only mode")
	}
	switch saltLength {
	case PSSSaltLengthAuto:
		saltLength, err = rsa.PSSMaxSaltLength(k.PublicKey(), h)
		if err != nil {
			return nil, fipsError(err)
		}
	case PSSSaltLengthEqualsHash:
		saltLength = hash.Size()
	default:
		// If we get here saltLength is either > 0 or < -1, in the
		// latter case we fail out.
		if saltLength <= 0 {
			return nil, errors.New("crypto/rsa: invalid PSS salt length")
		}
	}

	return fipsError2(rsa.SignPSS(rand, k, h, digest, saltLength))
}

// VerifyPSS verifies a PSS signature.
//
// A valid signature is indicated by returning a nil error. digest must be the
// result of hashing the input message using the given hash function. The opts
// argument may be nil, in which case sensible defaults are used. opts.Hash is
// ignored.
//
// The inputs are not considered confidential, and may leak through timing side
// channels, or if an attacker has control of part of the inputs.
func VerifyPSS(pub *PublicKey, hash crypto.Hash, digest []byte, sig []byte, opts *PSSOptions) error {
	if err := checkPublicKeySize(pub); err != nil {
		return err
	}
	if err := checkFIPS140OnlyPublicKey(pub); err != nil {
		return err
	}
	if fips140only.Enabled && !fips140only.ApprovedHash(hash.New()) {
		return errors.New("crypto/rsa: use of hash functions other than SHA-2 or SHA-3 is not allowed in FIPS 140-only mode")
	}

	if boring.Enabled {
		bkey, err := boringPublicKey(pub)
		if err != nil {
			return err
		}
		if err := boring.VerifyRSAPSS(bkey, hash, digest, sig, opts.saltLength()); err != nil {
			return ErrVerification
		}
		return nil
	}

	k, err := fipsPublicKey(pub)
	if err != nil {
		return err
	}

	saltLength := opts.saltLength()
	if fips140only.Enabled && saltLength > hash.Size() {
		return errors.New("crypto/rsa: use of PSS salt longer than the hash is not allowed in FIPS 140-only mode")
	}
	switch saltLength {
	case PSSSaltLengthAuto:
		return fipsError(rsa.VerifyPSS(k, hash.New(), digest, sig))
	case PSSSaltLengthEqualsHash:
		return fipsError(rsa.VerifyPSSWithSaltLength(k, hash.New(), digest, sig, hash.Size()))
	default:
		return fipsError(rsa.VerifyPSSWithSaltLength(k, hash.New(), digest, sig, saltLength))
	}
}

// EncryptOAEP encrypts the given message with RSA-OAEP.
//
// OAEP is parameterised by a hash function that is used as a random oracle.
// Encryption and decryption of a given message must use the same hash function
// and sha256.New() is a reasonable choice.
//
// The random parameter is used as a source of entropy to ensure that
// encrypting the same message twice doesn't result in the same ciphertext.
// Most applications should use [crypto/rand.Reader] as random.
//
// The label parameter may contain arbitrary data that will not be encrypted,
// but which gives important context to the message. For example, if a given
// public key is used to encrypt two types of messages then distinct label
// values could be used to ensure that a ciphertext for one purpose cannot be
// used for another by an attacker. If not required it can be empty.
//
// The message must be no longer than the length of the public modulus minus
// twice the hash length, minus a further 2.
func EncryptOAEP(hash hash.Hash, random io.Reader, pub *PublicKey, msg []byte, label []byte) ([]byte, error) {
	if err := checkPublicKeySize(pub); err != nil {
		return nil, err
	}
	if err := checkFIPS140OnlyPublicKey(pub); err != nil {
		return nil, err
	}
	if fips140only.Enabled && !fips140only.ApprovedHash(hash) {
		return nil, errors.New("crypto/rsa: use of hash functions other than SHA-2 or SHA-3 is not allowed in FIPS 140-only mode")
	}
	if fips140only.Enabled && !fips140only.ApprovedRandomReader(random) {
		return nil, errors.New("crypto/rsa: only crypto/rand.Reader is allowed in FIPS 140-only mode")
	}

	defer hash.Reset()

	if boring.Enabled && random == boring.RandReader {
		hash.Reset()
		k := pub.Size()
		if len(msg) > k-2*hash.Size()-2 {
			return nil, ErrMessageTooLong
		}
		bkey, err := boringPublicKey(pub)
		if err != nil {
			return nil, err
		}
		return boring.EncryptRSAOAEP(hash, hash, bkey, msg, label)
	}
	boring.UnreachableExceptTests()

	k, err := fipsPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return fipsError2(rsa.EncryptOAEP(hash, hash, random, k, msg, label))
}

// DecryptOAEP decrypts ciphertext using RSA-OAEP.
//
// OAEP is parameterised by a hash function that is used as a random oracle.
// Encryption and decryption of a given message must use the same hash function
// and sha256.New() is a reasonable choice.
//
// The random parameter is legacy and ignored, and it can be nil.
//
// The label parameter must match the value given when encrypting. See
// [EncryptOAEP] for details.
func DecryptOAEP(hash hash.Hash, random io.Reader, priv *PrivateKey, ciphertext []byte, label []byte) ([]byte, error) {
	defer hash.Reset()
	return decryptOAEP(hash, hash, priv, ciphertext, label)
}

func decryptOAEP(hash, mgfHash hash.Hash, priv *PrivateKey, ciphertext []byte, label []byte) ([]byte, error) {
	if err := checkPublicKeySize(&priv.PublicKey); err != nil {
		return nil, err
	}
	if err := checkFIPS140OnlyPrivateKey(priv); err != nil {
		return nil, err
	}
	if fips140only.Enabled {
		if !fips140only.ApprovedHash(hash) || !fips140only.ApprovedHash(mgfHash) {
			return nil, errors.New("crypto/rsa: use of hash functions other than SHA-2 or SHA-3 is not allowed in FIPS 140-only mode")
		}
	}

	if boring.Enabled {
		k := priv.Size()
		if len(ciphertext) > k ||
			k < hash.Size()*2+2 {
			return nil, ErrDecryption
		}
		bkey, err := boringPrivateKey(priv)
		if err != nil {
			return nil, err
		}
		out, err := boring.DecryptRSAOAEP(hash, mgfHash, bkey, ciphertext, label)
		if err != nil {
			return nil, ErrDecryption
		}
		return out, nil
	}

	k, err := fipsPrivateKey(priv)
	if err != nil {
		return nil, err
	}

	return fipsError2(rsa.DecryptOAEP(hash, mgfHash, k, ciphertext, label))
}

// SignPKCS1v15 calculates the signature of hashed using
// RSASSA-PKCS1-V1_5-SIGN from RSA PKCS #1 v1.5.  Note that hashed must
// be the result of hashing the input message using the given hash
// function. If hash is zero, hashed is signed directly. This isn't
// advisable except for interoperability.
//
// The random parameter is legacy and ignored, and it can be nil.
//
// This function is deterministic. Thus, if the set of possible
// messages is small, an attacker may be able to build a map from
// messages to signatures and identify the signed messages. As ever,
// signatures provide authenticity, not confidentiality.
func SignPKCS1v15(random io.Reader, priv *PrivateKey, hash crypto.Hash, hashed []byte) ([]byte, error) {
	var hashName string
	if hash != crypto.Hash(0) {
		if len(hashed) != hash.Size() {
			return nil, errors.New("crypto/rsa: input must be hashed message")
		}
		hashName = hash.String()
	}

	if err := checkPublicKeySize(&priv.PublicKey); err != nil {
		return nil, err
	}
	if err := checkFIPS140OnlyPrivateKey(priv); err != nil {
		return nil, err
	}
	if fips140only.Enabled && !fips140only.ApprovedHash(hash.New()) {
		return nil, errors.New("crypto/rsa: use of hash functions other than SHA-2 or SHA-3 is not allowed in FIPS 140-only mode")
	}

	if boring.Enabled {
		bkey, err := boringPrivateKey(priv)
		if err != nil {
			return nil, err
		}
		return boring.SignRSAPKCS1v15(bkey, hash, hashed)
	}

	k, err := fipsPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return fipsError2(rsa.SignPKCS1v15(k, hashName, hashed))
}

// VerifyPKCS1v15 verifies an RSA PKCS #1 v1.5 signature.
// hashed is the result of hashing the input message using the given hash
// function and sig is the signature. A valid signature is indicated by
// returning a nil error. If hash is zero then hashed is used directly. This
// isn't advisable except for interoperability.
//
// The inputs are not considered confidential, and may leak through timing side
// channels, or if an attacker has control of part of the inputs.
func VerifyPKCS1v15(pub *PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error {
	if err := checkPublicKeySize(pub); err != nil {
		return err
	}
	if err := checkFIPS140OnlyPublicKey(pub); err != nil {
		return err
	}
	if fips140only.Enabled && !fips140only.ApprovedHash(hash.New()) {
		return errors.New("crypto/rsa: use of hash functions other than SHA-2 or SHA-3 is not allowed in FIPS 140-only mode")
	}

	if boring.Enabled {
		bkey, err := boringPublicKey(pub)
		if err != nil {
			return err
		}
		if err := boring.VerifyRSAPKCS1v15(bkey, hash, hashed, sig); err != nil {
			return ErrVerification
		}
		return nil
	}

	k, err := fipsPublicKey(pub)
	if err != nil {
		return err
	}
	var hashName string
	if hash != crypto.Hash(0) {
		if len(hashed) != hash.Size() {
			return errors.New("crypto/rsa: input must be hashed message")
		}
		hashName = hash.String()
	}
	return fipsError(rsa.VerifyPKCS1v15(k, hashName, hashed, sig))
}

func fipsError(err error) error {
	switch err {
	case rsa.ErrDecryption:
		return ErrDecryption
	case rsa.ErrVerification:
		return ErrVerification
	case rsa.ErrMessageTooLong:
		return ErrMessageTooLong
	}
	return err
}

func fipsError2[T any](x T, err error) (T, error) {
	return x, fipsError(err)
}

func checkFIPS140OnlyPublicKey(pub *PublicKey) error {
	if !fips140only.Enabled {
		return nil
	}
	if pub.N == nil {
		return errors.New("crypto/rsa: public key missing N")
	}
	if pub.N.BitLen() < 2048 {
		return errors.New("crypto/rsa: use of keys smaller than 2048 bits is not allowed in FIPS 140-only mode")
	}
	if pub.N.BitLen()%2 == 1 {
		return errors.New("crypto/rsa: use of keys with odd size is not allowed in FIPS 140-only mode")
	}
	if pub.E <= 1<<16 {
		return errors.New("crypto/rsa: use of public exponent <= 2¹⁶ is not allowed in FIPS 140-only mode")
	}
	if pub.E&1 == 0 {
		return errors.New("crypto/rsa: use of even public exponent is not allowed in FIPS 140-only mode")
	}
	return nil
}

func checkFIPS140OnlyPrivateKey(priv *PrivateKey) error {
	if !fips140only.Enabled {
		return nil
	}
	if err := checkFIPS140OnlyPublicKey(&priv.PublicKey); err != nil {
		return err
	}
	if len(priv.Primes) != 2 {
		return errors.New("crypto/rsa: use of multi-prime keys is not allowed in FIPS 140-only mode")
	}
	if priv.Primes[0] == nil || priv.Primes[1] == nil || priv.Primes[0].BitLen() != priv.Primes[1].BitLen() {
		return errors.New("crypto/rsa: use of primes of different sizes is not allowed in FIPS 140-only mode")
	}
	return nil
}
```