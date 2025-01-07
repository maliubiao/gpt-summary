Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the Go code, its purpose within the broader Go ecosystem, illustrative examples, and potential pitfalls for users. The file path `go/src/crypto/internal/fips140/rsa/rsa.go` is a major clue – this is RSA implementation within a FIPS 140 context, suggesting security and compliance are key concerns.

2. **Initial Code Scan (Keywords and Structure):**  Quickly scan the code for key terms and structural elements:
    * `package rsa`:  Confirms this is the RSA package.
    * `import`:  Notes dependencies on `crypto/internal/fips140` and `crypto/internal/fips140/bigmod`. These are internal packages, suggesting a lower-level implementation focused on FIPS compliance and potentially optimized big integer arithmetic.
    * `struct PublicKey`, `struct PrivateKey`: Identifies the core data structures for RSA keys. The fields within these structs (e.g., `N`, `E`, `d`, `p`, `q`, `dP`, `dQ`, `qInv`) are standard components of RSA key representation, especially when considering CRT optimization.
    * Function names like `Size`, `PublicKey`, `NewPrivateKey`, `Export`, `Encrypt`, `DecryptWithoutCheck`, `DecryptWithCheck`, `checkPrivateKey`, `checkPublicKey`:  These strongly suggest the common operations associated with RSA cryptography.

3. **Deep Dive into Key Structures and Functions:**

    * **`PublicKey`:**  `N` (modulus) and `E` (public exponent) are the essential components. The `Size()` method is straightforward – calculating the size of the modulus in bytes.
    * **`PrivateKey`:** This is more complex, containing the public key (`pub`), the private exponent `d`, and crucially, the CRT parameters: `p`, `q`, `dP`, `dQ`, `qInv`. The comment about multi-prime keys being deprecated and FIPS mode requiring CRT is significant. The `PublicKey()` method simply returns a pointer to the embedded public key.
    * **`NewPrivateKey` variants:** The existence of `NewPrivateKey`, `NewPrivateKeyWithPrecomputation`, and `NewPrivateKeyWithoutCRT` points to different ways of constructing private keys, likely with varying performance implications (precomputation) and compliance levels (CRT). Notice the byte slice inputs, indicating the raw representation of the key parameters.
    * **`Export()`:**  The opposite of the `NewPrivateKey` functions, returning the key components as byte slices. The conditional return based on `priv.dP` being nil reinforces the CRT vs. non-CRT distinction.
    * **`checkPrivateKey` and `checkPublicKey`:** These are crucial for security. They validate the key parameters according to FIPS standards (bit length, primality checks, relationships between parameters, etc.). The Pairwise Consistency Test (PCT) within `checkPrivateKey` is a strong indicator of FIPS compliance testing.
    * **`Encrypt` and `Decrypt` variants:**  Standard RSA encryption and decryption operations. The `WithoutCheck` and `WithCheck` versions of `Decrypt` are interesting. The comment within `decrypt` explains the check against CRT errors.
    * **`encrypt` and `decrypt` (lowercase):** These are the internal, core implementations of the encryption and decryption algorithms, likely using the `bigmod` package for modular arithmetic.

4. **Inferring Functionality and Go Language Features:**

    * **RSA Cryptography:** The code clearly implements RSA public-key cryptography, including key generation (though the provided snippet doesn't show the generation function), encryption, and decryption.
    * **FIPS 140 Compliance:** The package path and the checks within the code strongly suggest this implementation is designed to meet FIPS 140 standards for cryptographic modules.
    * **Big Integer Arithmetic:** The use of the `bigmod` package indicates the need for arbitrary-precision integer arithmetic, which is essential for RSA due to the large numbers involved.
    * **Chinese Remainder Theorem (CRT):** The presence of `p`, `q`, `dP`, `dQ`, and `qInv` and the conditional logic in `decrypt` clearly demonstrates the implementation of CRT for optimized private key operations.
    * **Error Handling:** The functions return `error` values, a standard Go practice for indicating failures. The specific error types (e.g., `ErrMessageTooLong`, `ErrDecryption`, `ErrVerification`) provide more context.

5. **Constructing Examples:** Based on the identified functionalities, create simple Go code examples. Focus on demonstrating key operations like creating keys, encryption, and decryption. Make sure to include plausible input data and expected output (or at least the *type* of output).

6. **Identifying Potential Pitfalls:** Think about common mistakes users might make when using this kind of cryptographic library:
    * **Using `WithoutCheck` decryption inappropriately:** Emphasize the security implications.
    * **Incorrect key parameter handling:** Highlight the importance of using the correct `NewPrivateKey` function based on the available parameters.
    * **Misunderstanding FIPS compliance:** Explain that certain key types or operations might not be FIPS-compliant.

7. **Command-Line Arguments:** Since the code snippet doesn't directly handle command-line arguments, acknowledge this and explain *why* it's not present (it's a library, not an executable).

8. **Structuring the Answer:** Organize the findings logically, using headings and bullet points for clarity. Start with a high-level summary of functionality and then delve into specifics. Use code blocks for examples and clearly label inputs and outputs.

9. **Review and Refine:**  Read through the generated answer to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas where further explanation might be needed. For example, initially, I might not have emphasized the significance of the internal packages as much. Reviewing the code and the request would prompt me to highlight that.
这段代码是 Go 语言 `crypto/internal/fips140/rsa` 包的一部分，它实现了 RSA 公钥和私钥的结构体以及创建、导出和基本的加密解密功能。由于其路径包含 `fips140`，可以推断出这个实现是为了满足 FIPS 140 标准，这是一个美国政府对密码模块的安全标准。

**功能列举:**

1. **定义 RSA 公钥结构体 `PublicKey`:**  包含模数 `N` 和公钥指数 `E`。
2. **定义 RSA 私钥结构体 `PrivateKey`:** 包含公钥 `pub`，私钥指数 `d`，以及用于 CRT（中国剩余定理）加速计算的参数 `p`, `q`, `dP`, `dQ`, `qInv`。还包含一个布尔值 `fipsApproved` 标识该密钥是否符合 FIPS 标准。
3. **`PublicKey` 的 `Size()` 方法:** 返回公钥模数的大小（字节数），这决定了该公钥加密或生成的签名的长度。
4. **`PrivateKey` 的 `PublicKey()` 方法:** 返回私钥对应的公钥。
5. **`NewPrivateKey` 系列函数:**
   - `NewPrivateKey(N []byte, e int, d, P, Q []byte)`:  从给定的模数、公钥指数、私钥指数以及素数因子 `P` 和 `Q` 创建一个新的 RSA 私钥。
   - `newPrivateKey(n *bigmod.Modulus, e int, d *bigmod.Nat, p, q *bigmod.Modulus)`: 内部使用的创建私钥的函数，参数类型为 `bigmod.Modulus` 和 `bigmod.Nat`。
   - `NewPrivateKeyWithPrecomputation(N []byte, e int, d, P, Q, dP, dQ, qInv []byte)`:  从给定的所有参数（包括预计算的 CRT 值）创建 RSA 私钥。
   - `NewPrivateKeyWithoutCRT(N []byte, e int, d []byte)`:  创建一个不包含 CRT 参数的私钥，这通常用于旧的或不符合 FIPS 标准的多素数密钥。
6. **`PrivateKey` 的 `Export()` 方法:**  将私钥的参数（模数、公钥指数、私钥指数、素数因子、CRT 参数）以大端字节切片的形式导出。如果密钥是通过 `NewPrivateKeyWithoutCRT` 创建的，则 `P`, `Q`, `dP`, `dQ`, `qInv` 可能为 `nil`。
7. **`checkPrivateKey(priv *PrivateKey)` 函数:**  用于检查私钥的有效性，包括与公钥的一致性、素数因子的关系、CRT 参数的正确性等。这个函数还会设置 `priv.fipsApproved` 的值。
8. **`checkPublicKey(pub *PublicKey)` 函数:**  用于检查公钥的有效性，例如模数的奇偶性、大小以及公钥指数的合理性。
9. **`Encrypt(pub *PublicKey, plaintext []byte)` 函数:** 使用 RSA 公钥加密给定的明文。
10. **内部函数 `encrypt(pub *PublicKey, plaintext []byte)`:**  实际执行 RSA 加密操作。
11. **`DecryptWithoutCheck(priv *PrivateKey, ciphertext []byte)` 函数:** 使用 RSA 私钥解密给定的密文，但不进行额外的 CRT 计算错误检查。
12. **`DecryptWithCheck(priv *PrivateKey, ciphertext []byte)` 函数:** 使用 RSA 私钥解密给定的密文，并进行额外的 CRT 计算错误检查以提高安全性。
13. **内部函数 `decrypt(priv *PrivateKey, ciphertext []byte, check bool)`:**  实际执行 RSA 解密操作，`check` 参数决定是否进行额外的验证。

**它是什么 Go 语言功能的实现？**

这段代码实现了 **RSA 公钥密码算法** 的核心数据结构和基本操作。RSA 是一种非对称加密算法，广泛用于安全通信和数字签名。

**Go 代码举例说明:**

假设我们已经有了 RSA 密钥的参数（通常从文件或网络中加载）：

```go
package main

import (
	"crypto/internal/fips140/rsa"
	"fmt"
	"encoding/base64"
	"log"
)

func main() {
	// 假设我们有以下密钥参数（实际应用中应安全加载）
	nBytes, _ := base64.StdEncoding.DecodeString("oR6Oty/otv0jRwJ+Lz/s9n8a7n1+j6o0PjL4vP/z2fxruc/v6PqjQ+Mvi8//PZ/Gu5z+/o+qND4y+Lz/89n8a7nM=")
	e := 65537
	dBytes, _ := base64.StdEncoding.DecodeString("ZkT+Pj/9/f7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+")
	pBytes, _ := base64.StdEncoding.DecodeString("4f7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+")
	qBytes, _ := base64.StdEncoding.DecodeString("6vf+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+")

	// 创建私钥
	privateKey, err := rsa.NewPrivateKey(nBytes, e, dBytes, pBytes, qBytes)
	if err != nil {
		log.Fatal(err)
	}

	// 获取公钥
	publicKey := privateKey.PublicKey()

	// 要加密的数据
	plaintext := []byte("Hello, RSA!")

	// 使用公钥加密
	ciphertext, err := rsa.Encrypt(publicKey, plaintext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Ciphertext: %x\n", ciphertext)

	// 使用私钥解密 (不进行额外检查)
	decryptedPlaintext, err := rsa.DecryptWithoutCheck(privateKey, ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Decrypted Plaintext (WithoutCheck): %s\n", decryptedPlaintext)

	// 使用私钥解密 (进行额外检查)
	decryptedPlaintextWithCheck, err := rsa.DecryptWithCheck(privateKey, ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Decrypted Plaintext (WithCheck): %s\n", decryptedPlaintextWithCheck)
}
```

**假设的输入与输出:**

* **输入 (在代码中硬编码，实际应用中会加载):**
    * `nBytes`:  RSA 模数 `N` 的字节表示。
    * `e`: RSA 公钥指数 `E` (通常是 65537)。
    * `dBytes`: RSA 私钥指数 `d` 的字节表示。
    * `pBytes`: RSA 素数因子 `p` 的字节表示。
    * `qBytes`: RSA 素数因子 `q` 的字节表示。
    * `plaintext`:  要加密的字符串 "Hello, RSA!"。

* **输出:**
    * `Ciphertext`:  加密后的密文的十六进制表示 (例如: `Ciphertext: ...`)。由于 RSA 加密的随机性，每次运行的密文会不同，但长度应该与模数大小一致。
    * `Decrypted Plaintext (WithoutCheck)`:  解密后的明文字符串 "Hello, RSA!"。
    * `Decrypted Plaintext (WithCheck)`:  解密后的明文字符串 "Hello, RSA!"。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。它是一个库，用于提供 RSA 加密解密的功能。如果需要在命令行中使用 RSA 加密解密，你需要编写一个使用这个库的可执行程序，并在该程序中解析命令行参数。

例如，你可以使用 `flag` 包来处理命令行参数，像这样：

```go
package main

import (
	"crypto/internal/fips140/rsa"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
)

func main() {
	keyFile := flag.String("key", "", "Path to the private key file (base64 encoded parameters)")
	message := flag.String("message", "", "Message to encrypt")
	flag.Parse()

	if *keyFile == "" || *message == "" {
		flag.Usage()
		return
	}

	keyData, err := ioutil.ReadFile(*keyFile)
	if err != nil {
		log.Fatalf("Failed to read key file: %v", err)
	}

	// 假设密钥文件包含 base64 编码的 N, e, d, P, Q，用特定格式分隔
	// (这里只是一个简化的例子，实际应用中需要更严谨的密钥格式处理)
	var nBytes, dBytes, pBytes, qBytes []byte
	var e int
	_, err = fmt.Sscanf(string(keyData), "%s\n%d\n%s\n%s\n%s",
		&nBytes, &e, &dBytes, &pBytes, &qBytes)
	if err != nil {
		log.Fatalf("Failed to parse key file: %v", err)
	}
	// ... (解码 base64 字符串) ...

	privateKey, err := rsa.NewPrivateKey(nBytes, e, dBytes, pBytes, qBytes)
	if err != nil {
		log.Fatal(err)
	}
	publicKey := privateKey.PublicKey()

	ciphertext, err := rsa.Encrypt(publicKey, []byte(*message))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Ciphertext: %x\n", ciphertext)
}
```

在这个例子中，使用了 `-key` 和 `-message` 两个命令行参数来指定密钥文件和要加密的消息。

**使用者易犯错的点:**

1. **混淆 `DecryptWithoutCheck` 和 `DecryptWithCheck` 的使用场景:**  `DecryptWithoutCheck` 效率稍高，但在某些情况下可能无法检测到 CRT 计算中的错误，这在理论上可能导致安全问题。除非有非常明确的性能需求，否则 **强烈建议使用 `DecryptWithCheck`** 以获得更高的安全性。

   ```go
   // 错误的做法 (除非有特殊理由)
   decrypted, _ := rsa.DecryptWithoutCheck(privateKey, ciphertext)

   // 推荐的做法
   decrypted, err := rsa.DecryptWithCheck(privateKey, ciphertext)
   if err != nil {
       // 处理解密错误
   }
   ```

2. **不理解 FIPS 模式的限制:**  `fips140` 包下的代码通常会有更严格的限制，例如密钥长度、算法选择等。直接使用此包可能会遇到不符合 FIPS 标准的错误，如果你的应用不需要满足 FIPS 140，可能应该使用 `crypto/rsa` 包。

3. **密钥参数处理不当:**  `NewPrivateKey` 系列函数需要正确的密钥参数。如果提供的参数不一致（例如 `N` 不是 `P` 和 `Q` 的乘积），会导致密钥创建失败。

4. **直接操作 `PrivateKey` 结构体:**  应该通过提供的构造函数 (`NewPrivateKey` 等) 创建私钥，而不是直接初始化 `PrivateKey` 结构体。因为构造函数内部会进行必要的验证和初始化。

5. **忽略错误处理:**  加密和解密操作都可能失败，例如，要解密的数据不是用对应的公钥加密的。必须检查并妥善处理返回的 `error`。

总而言之，这段代码提供了 FIPS 140 标准下的 RSA 加密解密功能实现，使用者需要理解 RSA 算法的原理和 FIPS 标准的要求，并注意正确使用提供的 API 和处理潜在的错误。

Prompt: 
```
这是路径为go/src/crypto/internal/fips140/rsa/rsa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsa

import (
	"bytes"
	"crypto/internal/fips140"
	"crypto/internal/fips140/bigmod"
	"errors"
)

type PublicKey struct {
	N *bigmod.Modulus
	E int
}

// Size returns the modulus size in bytes. Raw signatures and ciphertexts
// for or by this public key will have the same size.
func (pub *PublicKey) Size() int {
	return (pub.N.BitLen() + 7) / 8
}

type PrivateKey struct {
	// pub has already been checked with checkPublicKey.
	pub PublicKey
	d   *bigmod.Nat
	// The following values are not set for deprecated multi-prime keys.
	//
	// Since they are always set for keys in FIPS mode, for SP 800-56B Rev. 2
	// purposes we always use the Chinese Remainder Theorem (CRT) format.
	p, q *bigmod.Modulus // p × q = n
	// dP and dQ are used as exponents, so we store them as big-endian byte
	// slices to be passed to [bigmod.Nat.Exp].
	dP   []byte      // d mod (p - 1)
	dQ   []byte      // d mod (q - 1)
	qInv *bigmod.Nat // qInv = q⁻¹ mod p
	// fipsApproved is false if this key does not comply with FIPS 186-5 or
	// SP 800-56B Rev. 2.
	fipsApproved bool
}

func (priv *PrivateKey) PublicKey() *PublicKey {
	return &priv.pub
}

// NewPrivateKey creates a new RSA private key from the given parameters.
//
// All values are in big-endian byte slice format, and may have leading zeros
// or be shorter if leading zeroes were trimmed.
func NewPrivateKey(N []byte, e int, d, P, Q []byte) (*PrivateKey, error) {
	n, err := bigmod.NewModulus(N)
	if err != nil {
		return nil, err
	}
	p, err := bigmod.NewModulus(P)
	if err != nil {
		return nil, err
	}
	q, err := bigmod.NewModulus(Q)
	if err != nil {
		return nil, err
	}
	dN, err := bigmod.NewNat().SetBytes(d, n)
	if err != nil {
		return nil, err
	}
	return newPrivateKey(n, e, dN, p, q)
}

func newPrivateKey(n *bigmod.Modulus, e int, d *bigmod.Nat, p, q *bigmod.Modulus) (*PrivateKey, error) {
	pMinusOne := p.Nat().SubOne(p)
	pMinusOneMod, err := bigmod.NewModulus(pMinusOne.Bytes(p))
	if err != nil {
		return nil, err
	}
	dP := bigmod.NewNat().Mod(d, pMinusOneMod).Bytes(pMinusOneMod)

	qMinusOne := q.Nat().SubOne(q)
	qMinusOneMod, err := bigmod.NewModulus(qMinusOne.Bytes(q))
	if err != nil {
		return nil, err
	}
	dQ := bigmod.NewNat().Mod(d, qMinusOneMod).Bytes(qMinusOneMod)

	// Constant-time modular inversion with prime modulus by Fermat's Little
	// Theorem: qInv = q⁻¹ mod p = q^(p-2) mod p.
	if p.Nat().IsOdd() == 0 {
		// [bigmod.Nat.Exp] requires an odd modulus.
		return nil, errors.New("crypto/rsa: p is even")
	}
	pMinusTwo := p.Nat().SubOne(p).SubOne(p).Bytes(p)
	qInv := bigmod.NewNat().Mod(q.Nat(), p)
	qInv.Exp(qInv, pMinusTwo, p)

	pk := &PrivateKey{
		pub: PublicKey{
			N: n, E: e,
		},
		d: d, p: p, q: q,
		dP: dP, dQ: dQ, qInv: qInv,
	}
	if err := checkPrivateKey(pk); err != nil {
		return nil, err
	}
	return pk, nil
}

// NewPrivateKeyWithPrecomputation creates a new RSA private key from the given
// parameters, which include precomputed CRT values.
func NewPrivateKeyWithPrecomputation(N []byte, e int, d, P, Q, dP, dQ, qInv []byte) (*PrivateKey, error) {
	n, err := bigmod.NewModulus(N)
	if err != nil {
		return nil, err
	}
	p, err := bigmod.NewModulus(P)
	if err != nil {
		return nil, err
	}
	q, err := bigmod.NewModulus(Q)
	if err != nil {
		return nil, err
	}
	dN, err := bigmod.NewNat().SetBytes(d, n)
	if err != nil {
		return nil, err
	}
	qInvNat, err := bigmod.NewNat().SetBytes(qInv, p)
	if err != nil {
		return nil, err
	}

	pk := &PrivateKey{
		pub: PublicKey{
			N: n, E: e,
		},
		d: dN, p: p, q: q,
		dP: dP, dQ: dQ, qInv: qInvNat,
	}
	if err := checkPrivateKey(pk); err != nil {
		return nil, err
	}
	return pk, nil
}

// NewPrivateKeyWithoutCRT creates a new RSA private key from the given parameters.
//
// This is meant for deprecated multi-prime keys, and is not FIPS 140 compliant.
func NewPrivateKeyWithoutCRT(N []byte, e int, d []byte) (*PrivateKey, error) {
	n, err := bigmod.NewModulus(N)
	if err != nil {
		return nil, err
	}
	dN, err := bigmod.NewNat().SetBytes(d, n)
	if err != nil {
		return nil, err
	}
	pk := &PrivateKey{
		pub: PublicKey{
			N: n, E: e,
		},
		d: dN,
	}
	if err := checkPrivateKey(pk); err != nil {
		return nil, err
	}
	return pk, nil
}

// Export returns the key parameters in big-endian byte slice format.
//
// P, Q, dP, dQ, and qInv may be nil if the key was created with
// NewPrivateKeyWithoutCRT.
func (priv *PrivateKey) Export() (N []byte, e int, d, P, Q, dP, dQ, qInv []byte) {
	N = priv.pub.N.Nat().Bytes(priv.pub.N)
	e = priv.pub.E
	d = priv.d.Bytes(priv.pub.N)
	if priv.dP == nil {
		return
	}
	P = priv.p.Nat().Bytes(priv.p)
	Q = priv.q.Nat().Bytes(priv.q)
	dP = bytes.Clone(priv.dP)
	dQ = bytes.Clone(priv.dQ)
	qInv = priv.qInv.Bytes(priv.p)
	return
}

// checkPrivateKey is called by the NewPrivateKey and GenerateKey functions, and
// is allowed to modify priv.fipsApproved.
func checkPrivateKey(priv *PrivateKey) error {
	priv.fipsApproved = true

	if fipsApproved, err := checkPublicKey(&priv.pub); err != nil {
		return err
	} else if !fipsApproved {
		priv.fipsApproved = false
	}

	if priv.dP == nil {
		// Legacy and deprecated multi-prime keys.
		priv.fipsApproved = false
		return nil
	}

	N := priv.pub.N
	p := priv.p
	q := priv.q

	// FIPS 186-5, Section 5.1 requires "that p and q be of the same bit length."
	if p.BitLen() != q.BitLen() {
		priv.fipsApproved = false
	}

	// Check that pq ≡ 1 mod N (and that p < N and q < N).
	pN := bigmod.NewNat().ExpandFor(N)
	if _, err := pN.SetBytes(p.Nat().Bytes(p), N); err != nil {
		return errors.New("crypto/rsa: invalid prime")
	}
	qN := bigmod.NewNat().ExpandFor(N)
	if _, err := qN.SetBytes(q.Nat().Bytes(q), N); err != nil {
		return errors.New("crypto/rsa: invalid prime")
	}
	if pN.Mul(qN, N).IsZero() != 1 {
		return errors.New("crypto/rsa: p * q != n")
	}

	// Check that de ≡ 1 mod p-1, and de ≡ 1 mod q-1.
	//
	// This implies that e is coprime to each p-1 as e has a multiplicative
	// inverse. Therefore e is coprime to lcm(p-1,q-1,r-1,...) = exponent(ℤ/nℤ).
	// It also implies that a^de ≡ a mod p as a^(p-1) ≡ 1 mod p. Thus a^de ≡ a
	// mod n for all a coprime to n, as required.
	//
	// This checks dP, dQ, and e. We don't check d because it is not actually
	// used in the RSA private key operation.
	pMinus1, err := bigmod.NewModulus(p.Nat().SubOne(p).Bytes(p))
	if err != nil {
		return errors.New("crypto/rsa: invalid prime")
	}
	dP, err := bigmod.NewNat().SetBytes(priv.dP, pMinus1)
	if err != nil {
		return errors.New("crypto/rsa: invalid CRT exponent")
	}
	de := bigmod.NewNat()
	de.SetUint(uint(priv.pub.E)).ExpandFor(pMinus1)
	de.Mul(dP, pMinus1)
	if de.IsOne() != 1 {
		return errors.New("crypto/rsa: invalid CRT exponent")
	}

	qMinus1, err := bigmod.NewModulus(q.Nat().SubOne(q).Bytes(q))
	if err != nil {
		return errors.New("crypto/rsa: invalid prime")
	}
	dQ, err := bigmod.NewNat().SetBytes(priv.dQ, qMinus1)
	if err != nil {
		return errors.New("crypto/rsa: invalid CRT exponent")
	}
	de.SetUint(uint(priv.pub.E)).ExpandFor(qMinus1)
	de.Mul(dQ, qMinus1)
	if de.IsOne() != 1 {
		return errors.New("crypto/rsa: invalid CRT exponent")
	}

	// Check that qInv * q ≡ 1 mod p.
	qP, err := bigmod.NewNat().SetOverflowingBytes(q.Nat().Bytes(q), p)
	if err != nil {
		// q >= 2^⌈log2(p)⌉
		qP = bigmod.NewNat().Mod(q.Nat(), p)
	}
	if qP.Mul(priv.qInv, p).IsOne() != 1 {
		return errors.New("crypto/rsa: invalid CRT coefficient")
	}

	// Check that |p - q| > 2^(nlen/2 - 100).
	//
	// If p and q are very close to each other, then N=pq can be trivially
	// factored using Fermat's factorization method. Broken RSA implementations
	// do generate such keys. See Hanno Böck, Fermat Factorization in the Wild,
	// https://eprint.iacr.org/2023/026.pdf.
	diff := bigmod.NewNat()
	if qP, err := bigmod.NewNat().SetBytes(q.Nat().Bytes(q), p); err != nil {
		// q > p
		pQ, err := bigmod.NewNat().SetBytes(p.Nat().Bytes(p), q)
		if err != nil {
			return errors.New("crypto/rsa: p == q")
		}
		// diff = 0 - p mod q = q - p
		diff.ExpandFor(q).Sub(pQ, q)
	} else {
		// p > q
		// diff = 0 - q mod p = p - q
		diff.ExpandFor(p).Sub(qP, p)
	}
	// A tiny bit of leakage is acceptable because it's not adaptive, an
	// attacker only learns the magnitude of p - q.
	if diff.BitLenVarTime() <= N.BitLen()/2-100 {
		return errors.New("crypto/rsa: |p - q| too small")
	}

	// Check that d > 2^(nlen/2).
	//
	// See section 3 of https://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf
	// for more details about attacks on small d values.
	//
	// Likewise, the leakage of the magnitude of d is not adaptive.
	if priv.d.BitLenVarTime() <= N.BitLen()/2 {
		return errors.New("crypto/rsa: d too small")
	}

	// If the key is still in scope for FIPS mode, perform a Pairwise
	// Consistency Test.
	if priv.fipsApproved {
		if err := fips140.PCT("RSA sign and verify PCT", func() error {
			hash := []byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
			}
			sig, err := signPKCS1v15(priv, "SHA-256", hash)
			if err != nil {
				return err
			}
			return verifyPKCS1v15(priv.PublicKey(), "SHA-256", hash, sig)
		}); err != nil {
			return err
		}
	}

	return nil
}

func checkPublicKey(pub *PublicKey) (fipsApproved bool, err error) {
	fipsApproved = true
	if pub.N == nil {
		return false, errors.New("crypto/rsa: missing public modulus")
	}
	if pub.N.Nat().IsOdd() == 0 {
		return false, errors.New("crypto/rsa: public modulus is even")
	}
	// FIPS 186-5, Section 5.1: "This standard specifies the use of a modulus
	// whose bit length is an even integer and greater than or equal to 2048
	// bits."
	if pub.N.BitLen() < 2048 {
		fipsApproved = false
	}
	if pub.N.BitLen()%2 == 1 {
		fipsApproved = false
	}
	if pub.E < 2 {
		return false, errors.New("crypto/rsa: public exponent too small or negative")
	}
	// e needs to be coprime with p-1 and q-1, since it must be invertible
	// modulo λ(pq). Since p and q are prime, this means e needs to be odd.
	if pub.E&1 == 0 {
		return false, errors.New("crypto/rsa: public exponent is even")
	}
	// FIPS 186-5, Section 5.5(e): "The exponent e shall be an odd, positive
	// integer such that 2¹⁶ < e < 2²⁵⁶."
	if pub.E <= 1<<16 {
		fipsApproved = false
	}
	// We require pub.E to fit into a 32-bit integer so that we
	// do not have different behavior depending on whether
	// int is 32 or 64 bits. See also
	// https://www.imperialviolet.org/2012/03/16/rsae.html.
	if pub.E > 1<<31-1 {
		return false, errors.New("crypto/rsa: public exponent too large")
	}
	return fipsApproved, nil
}

// Encrypt performs the RSA public key operation.
func Encrypt(pub *PublicKey, plaintext []byte) ([]byte, error) {
	fips140.RecordNonApproved()
	if _, err := checkPublicKey(pub); err != nil {
		return nil, err
	}
	return encrypt(pub, plaintext)
}

func encrypt(pub *PublicKey, plaintext []byte) ([]byte, error) {
	m, err := bigmod.NewNat().SetBytes(plaintext, pub.N)
	if err != nil {
		return nil, err
	}
	return bigmod.NewNat().ExpShortVarTime(m, uint(pub.E), pub.N).Bytes(pub.N), nil
}

var ErrMessageTooLong = errors.New("crypto/rsa: message too long for RSA key size")
var ErrDecryption = errors.New("crypto/rsa: decryption error")
var ErrVerification = errors.New("crypto/rsa: verification error")

const withCheck = true
const noCheck = false

// DecryptWithoutCheck performs the RSA private key operation.
func DecryptWithoutCheck(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	fips140.RecordNonApproved()
	return decrypt(priv, ciphertext, noCheck)
}

// DecryptWithCheck performs the RSA private key operation and checks the
// result to defend against errors in the CRT computation.
func DecryptWithCheck(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	fips140.RecordNonApproved()
	return decrypt(priv, ciphertext, withCheck)
}

// decrypt performs an RSA decryption of ciphertext into out. If check is true,
// m^e is calculated and compared with ciphertext, in order to defend against
// errors in the CRT computation.
func decrypt(priv *PrivateKey, ciphertext []byte, check bool) ([]byte, error) {
	if !priv.fipsApproved {
		fips140.RecordNonApproved()
	}

	var m *bigmod.Nat
	N, E := priv.pub.N, priv.pub.E

	c, err := bigmod.NewNat().SetBytes(ciphertext, N)
	if err != nil {
		return nil, ErrDecryption
	}

	if priv.dP == nil {
		// Legacy codepath for deprecated multi-prime keys.
		fips140.RecordNonApproved()
		m = bigmod.NewNat().Exp(c, priv.d.Bytes(N), N)

	} else {
		P, Q := priv.p, priv.q
		t0 := bigmod.NewNat()
		// m = c ^ Dp mod p
		m = bigmod.NewNat().Exp(t0.Mod(c, P), priv.dP, P)
		// m2 = c ^ Dq mod q
		m2 := bigmod.NewNat().Exp(t0.Mod(c, Q), priv.dQ, Q)
		// m = m - m2 mod p
		m.Sub(t0.Mod(m2, P), P)
		// m = m * Qinv mod p
		m.Mul(priv.qInv, P)
		// m = m * q mod N
		m.ExpandFor(N).Mul(t0.Mod(Q.Nat(), N), N)
		// m = m + m2 mod N
		m.Add(m2.ExpandFor(N), N)
	}

	if check {
		c1 := bigmod.NewNat().ExpShortVarTime(m, uint(E), N)
		if c1.Equal(c) != 1 {
			return nil, ErrDecryption
		}
	}

	return m.Bytes(N), nil
}

"""



```