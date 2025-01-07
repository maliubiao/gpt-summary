Response:
Let's break down the thought process for analyzing the provided Go code snippet for `go/src/crypto/cipher/gcm.go`.

**1. Initial Scan and Keyword Spotting:**

The first step is to quickly scan the code for keywords and structural elements. I'm looking for:

* **Package Declaration:** `package cipher` -  Tells me the scope of the code.
* **Imports:**  `crypto/internal/fips140/aes`, `crypto/subtle`, `errors`, etc. These give hints about the functionality. Specifically, the `fips140` imports are a strong indicator of cryptographic operations with potential compliance requirements.
* **Constants:** `gcmBlockSize`, `gcmStandardNonceSize`, `gcmTagSize`, `gcmMinimumTagSize`. These define important parameters for the GCM algorithm.
* **Functions:** `NewGCM`, `NewGCMWithNonceSize`, `NewGCMWithTagSize`, `newGCM`, `NewGCMWithRandomNonce`, `Seal`, `Open`, `newGCMFallback`, `deriveCounter`, `gcmCounterCryptGeneric`, `gcmInc32`, `gcmAuth`, `sliceForAppend`. These are the building blocks of the code's behavior.
* **Types/Structs:** `gcmWithRandomNonce`, `gcmFallback`. These define data structures used in the implementation.
* **Error Variables:** `errOpen`. This indicates a specific error condition.
* **Comments:**  Especially the initial copyright and license information, as well as the comments explaining the purpose of functions.

**2. Understanding the Core Functionality:**

The filename `gcm.go` and the function names like `NewGCM`, `Seal`, and `Open` strongly suggest that this code implements the Galois/Counter Mode (GCM) of operation for block ciphers. The comments confirm this.

**3. Analyzing Key Functions:**

* **`NewGCM`, `NewGCMWithNonceSize`, `NewGCMWithTagSize`:** These are clearly factory functions for creating `AEAD` (Authenticated Encryption with Associated Data) instances using GCM. They allow the user to customize the nonce size and tag size. The FIPS 140 checks are interesting and suggest a security compliance aspect.
* **`NewGCMWithRandomNonce`:** This variant stands out. It automatically handles nonce generation, simplifying usage but imposing a limit on the number of encryptions with the same key.
* **`Seal`:** This function performs the encryption and authentication, producing the ciphertext and authentication tag. The `gcmWithRandomNonce` version prepends the generated nonce.
* **`Open`:** This function performs decryption and tag verification. The `gcmWithRandomNonce` version extracts the prepended nonce.
* **`newGCM` and `newGCMFallback`:** These seem to handle the underlying implementation, potentially switching between optimized (likely hardware-accelerated AES) and generic implementations.
* **Helper Functions (`deriveCounter`, `gcmCounterCryptGeneric`, `gcmAuth`):** These are likely the core GCM algorithm steps: counter generation, encryption/decryption, and authentication tag calculation.

**4. Identifying Go Feature Implementations:**

Based on the analysis, the primary Go feature being implemented is the **Authenticated Encryption with Associated Data (AEAD) interface** from the `crypto/cipher` package. GCM is a specific mode of operation that fulfills the requirements of AEAD.

**5. Constructing Examples:**

To demonstrate the usage, I need to show how to:

* Create a GCM cipher using different `NewGCM` variants.
* Encrypt data using `Seal`.
* Decrypt data using `Open`.
* Highlight the difference when using `NewGCMWithRandomNonce`.

I need to choose a concrete block cipher, and AES is the most obvious choice, especially given the internal imports. The examples should include plaintext, associated data, and a key. For `NewGCMWithRandomNonce`, I need to show that the `nonce` parameter in `Seal` and `Open` is ignored.

**6. Code Reasoning (with Hypothetical Input/Output):**

Consider the `Seal` and `Open` functions in `gcmWithRandomNonce`.

* **Hypothetical `Seal` Input:**
    * `dst`: `nil` (or an empty slice)
    * `nonce`: `[]byte{}` (empty)
    * `plaintext`: `[]byte("secret message")`
    * `additionalData`: `[]byte("metadata")`
    * **Assumption:** `gcmWithRandomNonce`'s `GCM` field is properly initialized with an AES cipher.

* **Reasoning:**  `Seal` will generate a random 12-byte nonce, prepend it to the ciphertext, encrypt the plaintext, calculate the authentication tag, and append the tag.

* **Hypothetical `Seal` Output:**  (Example - actual output will be different due to randomness)
    * `ret`:  A byte slice like `[nonce][ciphertext][tag]`, where `nonce` is 12 random bytes, `ciphertext` is the encrypted "secret message", and `tag` is the 16-byte authentication tag.

* **Hypothetical `Open` Input:**
    * `dst`: `nil`
    * `nonce`: `[]byte{}` (empty)
    * `ciphertext`: The output from the previous `Seal` call (e.g., `[nonce][ciphertext][tag]`)
    * `additionalData`: `[]byte("metadata")` (must be the same as in `Seal`)

* **Reasoning:** `Open` will extract the first 12 bytes as the nonce, decrypt the remaining data (excluding the last 16 bytes), verify the tag against the decrypted data and associated data.

* **Hypothetical `Open` Output:**
    * `ret`: `[]byte("secret message")`
    * `err`: `nil` (if authentication succeeds) or `errOpen` (if authentication fails).

**7. Identifying Potential Pitfalls:**

The code itself points out some potential errors:

* **Incorrect nonce length:** The `Seal` and `Open` functions in `gcmFallback` explicitly check for the correct nonce size.
* **Incorrect tag size:** The `newGCMFallback` function checks for valid tag sizes.
* **Reusing nonces (especially with `NewGCM`):** This is a critical security vulnerability. The documentation for `NewGCMWithRandomNonce` also warns about key reuse limits.
* **Buffer Overlaps:** The code includes checks for invalid buffer overlaps, which could lead to unexpected behavior or security issues.

**8. Structuring the Answer:**

Finally, I organize the findings into a clear and structured answer, covering the requested aspects: functionality, Go feature implementation, code examples (with inputs/outputs), and common mistakes. Using clear headings and formatting makes the information easier to understand.
这段代码是 Go 语言标准库 `crypto/cipher` 包中关于 Galois/Counter Mode (GCM) 加密模式的实现。GCM 是一种广泛使用的认证加密算法，它提供保密性（加密）和完整性（认证）。

**功能列举:**

1. **`NewGCM(cipher Block) (AEAD, error)`:**  创建一个新的 GCM 对象。它接收一个实现了 `Block` 接口的 128 位块密码（通常是 AES），并将其包装在 GCM 模式下。此函数使用标准的 12 字节 nonce 长度和 16 字节的认证标签大小。在启用了 FIPS 140 模式下，如果尝试使用此函数，会返回错误，因为 FIPS 140 模式下不允许使用任意 IV。

2. **`NewGCMWithNonceSize(cipher Block, size int) (AEAD, error)`:** 创建一个新的 GCM 对象，允许指定 nonce 的长度。这个函数主要用于需要兼容使用非标准 nonce 长度的现有加密系统。通常情况下，建议使用 `NewGCM`。同样，在 FIPS 140 模式下会返回错误。

3. **`NewGCMWithTagSize(cipher Block, tagSize int) (AEAD, error)`:** 创建一个新的 GCM 对象，允许指定认证标签的长度。允许的标签大小在 12 到 16 字节之间。此函数主要用于需要兼容使用非标准标签长度的现有加密系统。通常情况下，建议使用 `NewGCM`。同样，在 FIPS 140 模式下会返回错误。

4. **`NewGCMWithRandomNonce(cipher Block) (AEAD, error)`:** 创建一个新的 GCM 对象，它会自动生成随机 nonce。 传递给此函数的 `cipher` 必须是由 `aes.NewCipher` 创建的 AES 密码。 使用此模式时，`Seal` 方法会自动生成一个 96 位的随机 nonce 并将其添加到密文的前面。`Open` 方法会从密文中提取这个 nonce。此模式下，`AEAD` 的 `NonceSize()` 返回 0，而 `Overhead()` 返回 28 字节（nonce 大小 12 字节 + 标签大小 16 字节）。 为了降低随机 nonce 碰撞的风险，对于给定的密钥，加密的消息数量不应超过 2^32。

5. **`Seal(dst, nonce, plaintext, additionalData []byte) []byte` (在 `gcmWithRandomNonce` 中):**  实现加密和认证。当使用 `NewGCMWithRandomNonce` 创建的 GCM 对象时，`nonce` 参数会被忽略，因为 nonce 是自动生成的并添加到输出中。`plaintext` 是要加密的数据，`additionalData` 是需要进行认证但不加密的额外数据。 输出 `dst` 包含 nonce、密文和认证标签。

6. **`Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)` (在 `gcmWithRandomNonce` 中):** 实现解密和认证。 当使用 `NewGCMWithRandomNonce` 创建的 GCM 对象时，`nonce` 参数会被忽略，因为 nonce 期望在 `ciphertext` 的开头。 它会验证认证标签，如果验证成功，则返回解密后的明文；否则返回错误。

7. **`newGCM(cipher Block, nonceSize, tagSize int) (AEAD, error)`:** 内部函数，根据传入的 `Block` 类型选择合适的 GCM 实现。 如果 `cipher` 是 `*aes.Block` 类型，则尝试使用优化的硬件加速的 GCM 实现 (`gcm.New`)。

8. **`newGCMFallback(cipher Block, nonceSize, tagSize int) (AEAD, error)`:** 内部函数，用于处理非 AES 密码的情况，提供一个通用的 GCM 实现。

9. **`NonceSize() int` 和 `Overhead() int`:**  `AEAD` 接口的方法，用于获取 nonce 的大小和认证标签的开销。

10. **`Seal(dst, nonce, plaintext, additionalData []byte) []byte` (在 `gcmFallback` 中):**  通用 GCM 实现的加密和认证过程。

11. **`Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)` (在 `gcmFallback` 中):** 通用 GCM 实现的解密和认证过程。

12. **`deriveCounter(H, counter *[gcmBlockSize]byte, nonce []byte)`:**  根据 nonce 推导出初始的计数器块。

13. **`gcmCounterCryptGeneric(b Block, out, src []byte, counter *[gcmBlockSize]byte)`:**  使用计数器模式对数据进行加密或解密。

14. **`gcmInc32(counterBlock *[gcmBlockSize]byte)`:**  递增计数器块的后 32 位。

15. **`gcmAuth(out []byte, H, tagMask *[gcmBlockSize]byte, ciphertext, additionalData []byte)`:** 计算 GCM 的认证标签。

16. **`sliceForAppend(in []byte, n int) (head, tail []byte)`:**  一个辅助函数，用于高效地扩展切片以容纳额外的字节。

**Go 语言功能实现推理 (AEAD 接口):**

这段代码主要实现了 `crypto/cipher` 包中的 `AEAD` (Authenticated Encryption with Associated Data) 接口。`AEAD` 接口定义了提供认证加密的密码操作。GCM 是一种实现了 `AEAD` 接口的加密模式。

**Go 代码举例说明:**

```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
)

func main() {
	key := make([]byte, 32) // AES-256 密钥
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		log.Fatal(err)
	}

	plaintext := []byte("这是一段需要加密和认证的消息")
	additionalData := []byte("附加认证数据")

	// 使用 NewGCM 创建 GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	// 创建 nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
	}

	// 加密并认证
	ciphertext := gcm.Seal(nil, nonce, plaintext, additionalData)
	fmt.Printf("密文 (包括标签): %x\n", ciphertext)

	// 解密和认证
	decryptedPlaintext, err := gcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("解密后的明文: %s\n", string(decryptedPlaintext))

	fmt.Println("---------------- 使用 NewGCMWithRandomNonce ----------------")

	// 使用 NewGCMWithRandomNonce 创建 GCM cipher
	gcmRandomNonce, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		log.Fatal(err)
	}

	// 加密并认证 (注意 nonce 参数为空)
	ciphertextRandomNonce := gcmRandomNonce.Seal(nil, nil, plaintext, additionalData)
	fmt.Printf("密文 (包括 nonce 和标签): %x\n", ciphertextRandomNonce)

	// 解密和认证 (注意 nonce 参数为空)
	decryptedPlaintextRandomNonce, err := gcmRandomNonce.Open(nil, nil, ciphertextRandomNonce, additionalData)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("解密后的明文: %s\n", string(decryptedPlaintextRandomNonce))
}
```

**假设的输入与输出:**

对于 `NewGCM` 的例子:

* **假设输入:**
    * `key`:  `[]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}`
    * `plaintext`: `"这是一段需要加密和认证的消息"`
    * `additionalData`: `"附加认证数据"`
    * `nonce`:  `[]byte{100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111}` (假设的随机 nonce)

* **假设输出 (密文和标签的具体值会因加密算法而异):**
    * `ciphertext`:  类似于 `[随机 nonce][加密后的数据][认证标签]` 的十六进制表示。例如: `6465666768696a6b6c6d6e6fcafebabefacefadecadecafe加密后的数据的十六进制表示abcdefabcdefabcdefabcdef`

对于 `NewGCMWithRandomNonce` 的例子:

* **假设输入:**
    * `key`: 同上
    * `plaintext`: 同上
    * `additionalData`: 同上

* **假设输出:**
    * `ciphertextRandomNonce`: 类似于 `[随机生成的 nonce][加密后的数据][认证标签]` 的十六进制表示。例如: `[随机生成的12字节nonce的十六进制表示]cafebabefacefadecadecafe加密后的数据的十六进制表示abcdefabcdefabcdefabcdef`

**使用者易犯错的点:**

1. **Nonce 重复使用:**  对于相同的密钥，绝对不能使用相同的 nonce 来加密不同的消息。这会完全破坏 GCM 的安全性。 使用 `NewGCM` 时，开发者需要负责生成和管理唯一的 nonce。

   ```go
   // 错误示例：重复使用 nonce
   nonce := make([]byte, gcm.NonceSize())
   io.ReadFull(rand.Reader, nonce) // 首次生成 nonce

   ciphertext1 := gcm.Seal(nil, nonce, plaintext1, additionalData)
   ciphertext2 := gcm.Seal(nil, nonce, plaintext2, additionalData) // 错误！使用了相同的 nonce
   ```

2. **`NewGCMWithRandomNonce` 的密钥重用限制:**  虽然 `NewGCMWithRandomNonce` 简化了 nonce 的管理，但文档明确指出，对于给定的密钥，加密的消息数量不应超过 2^32。超出此限制会增加随机 nonce 碰撞的风险，从而可能危及安全性。

3. **错误的 `additionalData`:**  解密时提供的 `additionalData` 必须与加密时使用的完全相同。任何差异都会导致认证失败。

   ```go
   // 错误示例：解密时使用错误的 additionalData
   decryptedPlaintext, err := gcm.Open(nil, nonce, ciphertext, []byte("错误的附加认证数据"))
   if err != nil {
       fmt.Println("解密失败:", err) // 很可能会因为认证失败而报错
   }
   ```

4. **不理解 `NewGCMWithRandomNonce` 的 Nonce 处理:** 使用 `NewGCMWithRandomNonce` 时，传递给 `Seal` 和 `Open` 的 `nonce` 参数应该为空（`nil` 或空切片）。 因为 nonce 是由函数内部自动处理的。

   ```go
   // 错误示例：在使用 NewGCMWithRandomNonce 时传递 nonce
   nonce := make([]byte, 12)
   io.ReadFull(rand.Reader, nonce)
   ciphertext := gcmRandomNonce.Seal(nil, nonce, plaintext, additionalData) // 错误！nonce 参数应该为空
   ```

这段代码通过提供多种创建 GCM cipher 对象的方式，并区分了需要开发者管理 nonce 和自动管理 nonce 的场景，为 Go 开发者提供了灵活且安全的认证加密工具。理解这些不同的方法以及它们的适用场景和潜在的陷阱对于正确使用 GCM 至关重要。

Prompt: 
```
这是路径为go/src/crypto/cipher/gcm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import (
	"crypto/internal/fips140/aes"
	"crypto/internal/fips140/aes/gcm"
	"crypto/internal/fips140/alias"
	"crypto/internal/fips140only"
	"crypto/subtle"
	"errors"
	"internal/byteorder"
)

const (
	gcmBlockSize         = 16
	gcmStandardNonceSize = 12
	gcmTagSize           = 16
	gcmMinimumTagSize    = 12 // NIST SP 800-38D recommends tags with 12 or more bytes.
)

// NewGCM returns the given 128-bit, block cipher wrapped in Galois Counter Mode
// with the standard nonce length.
//
// In general, the GHASH operation performed by this implementation of GCM is not constant-time.
// An exception is when the underlying [Block] was created by aes.NewCipher
// on systems with hardware support for AES. See the [crypto/aes] package documentation for details.
func NewGCM(cipher Block) (AEAD, error) {
	if fips140only.Enabled {
		return nil, errors.New("crypto/cipher: use of GCM with arbitrary IVs is not allowed in FIPS 140-only mode, use NewGCMWithRandomNonce")
	}
	return newGCM(cipher, gcmStandardNonceSize, gcmTagSize)
}

// NewGCMWithNonceSize returns the given 128-bit, block cipher wrapped in Galois
// Counter Mode, which accepts nonces of the given length. The length must not
// be zero.
//
// Only use this function if you require compatibility with an existing
// cryptosystem that uses non-standard nonce lengths. All other users should use
// [NewGCM], which is faster and more resistant to misuse.
func NewGCMWithNonceSize(cipher Block, size int) (AEAD, error) {
	if fips140only.Enabled {
		return nil, errors.New("crypto/cipher: use of GCM with arbitrary IVs is not allowed in FIPS 140-only mode, use NewGCMWithRandomNonce")
	}
	return newGCM(cipher, size, gcmTagSize)
}

// NewGCMWithTagSize returns the given 128-bit, block cipher wrapped in Galois
// Counter Mode, which generates tags with the given length.
//
// Tag sizes between 12 and 16 bytes are allowed.
//
// Only use this function if you require compatibility with an existing
// cryptosystem that uses non-standard tag lengths. All other users should use
// [NewGCM], which is more resistant to misuse.
func NewGCMWithTagSize(cipher Block, tagSize int) (AEAD, error) {
	if fips140only.Enabled {
		return nil, errors.New("crypto/cipher: use of GCM with arbitrary IVs is not allowed in FIPS 140-only mode, use NewGCMWithRandomNonce")
	}
	return newGCM(cipher, gcmStandardNonceSize, tagSize)
}

func newGCM(cipher Block, nonceSize, tagSize int) (AEAD, error) {
	c, ok := cipher.(*aes.Block)
	if !ok {
		if fips140only.Enabled {
			return nil, errors.New("crypto/cipher: use of GCM with non-AES ciphers is not allowed in FIPS 140-only mode")
		}
		return newGCMFallback(cipher, nonceSize, tagSize)
	}
	// We don't return gcm.New directly, because it would always return a non-nil
	// AEAD interface value with type *gcm.GCM even if the *gcm.GCM is nil.
	g, err := gcm.New(c, nonceSize, tagSize)
	if err != nil {
		return nil, err
	}
	return g, nil
}

// NewGCMWithRandomNonce returns the given cipher wrapped in Galois Counter
// Mode, with randomly-generated nonces. The cipher must have been created by
// [aes.NewCipher].
//
// It generates a random 96-bit nonce, which is prepended to the ciphertext by Seal,
// and is extracted from the ciphertext by Open. The NonceSize of the AEAD is zero,
// while the Overhead is 28 bytes (the combination of nonce size and tag size).
//
// A given key MUST NOT be used to encrypt more than 2^32 messages, to limit the
// risk of a random nonce collision to negligible levels.
func NewGCMWithRandomNonce(cipher Block) (AEAD, error) {
	c, ok := cipher.(*aes.Block)
	if !ok {
		return nil, errors.New("cipher: NewGCMWithRandomNonce requires aes.Block")
	}
	g, err := gcm.New(c, gcmStandardNonceSize, gcmTagSize)
	if err != nil {
		return nil, err
	}
	return gcmWithRandomNonce{g}, nil
}

type gcmWithRandomNonce struct {
	*gcm.GCM
}

func (g gcmWithRandomNonce) NonceSize() int {
	return 0
}

func (g gcmWithRandomNonce) Overhead() int {
	return gcmStandardNonceSize + gcmTagSize
}

func (g gcmWithRandomNonce) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != 0 {
		panic("crypto/cipher: non-empty nonce passed to GCMWithRandomNonce")
	}

	ret, out := sliceForAppend(dst, gcmStandardNonceSize+len(plaintext)+gcmTagSize)
	if alias.InexactOverlap(out, plaintext) {
		panic("crypto/cipher: invalid buffer overlap of output and input")
	}
	if alias.AnyOverlap(out, additionalData) {
		panic("crypto/cipher: invalid buffer overlap of output and additional data")
	}
	nonce = out[:gcmStandardNonceSize]
	ciphertext := out[gcmStandardNonceSize:]

	// The AEAD interface allows using plaintext[:0] or ciphertext[:0] as dst.
	//
	// This is kind of a problem when trying to prepend or trim a nonce, because the
	// actual AES-GCTR blocks end up overlapping but not exactly.
	//
	// In Open, we write the output *before* the input, so unless we do something
	// weird like working through a chunk of block backwards, it works out.
	//
	// In Seal, we could work through the input backwards or intentionally load
	// ahead before writing.
	//
	// However, the crypto/internal/fips140/aes/gcm APIs also check for exact overlap,
	// so for now we just do a memmove if we detect overlap.
	//
	//     ┌───────────────────────────┬ ─ ─
	//     │PPPPPPPPPPPPPPPPPPPPPPPPPPP│    │
	//     └▽─────────────────────────▲┴ ─ ─
	//       ╲ Seal                    ╲
	//        ╲                    Open ╲
	//     ┌───▼─────────────────────────△──┐
	//     │NN|CCCCCCCCCCCCCCCCCCCCCCCCCCC|T│
	//     └────────────────────────────────┘
	//
	if alias.AnyOverlap(out, plaintext) {
		copy(ciphertext, plaintext)
		plaintext = ciphertext[:len(plaintext)]
	}

	gcm.SealWithRandomNonce(g.GCM, nonce, ciphertext, plaintext, additionalData)
	return ret
}

func (g gcmWithRandomNonce) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != 0 {
		panic("crypto/cipher: non-empty nonce passed to GCMWithRandomNonce")
	}
	if len(ciphertext) < gcmStandardNonceSize+gcmTagSize {
		return nil, errOpen
	}

	ret, out := sliceForAppend(dst, len(ciphertext)-gcmStandardNonceSize-gcmTagSize)
	if alias.InexactOverlap(out, ciphertext) {
		panic("crypto/cipher: invalid buffer overlap of output and input")
	}
	if alias.AnyOverlap(out, additionalData) {
		panic("crypto/cipher: invalid buffer overlap of output and additional data")
	}
	// See the discussion in Seal. Note that if there is any overlap at this
	// point, it's because out = ciphertext, so out must have enough capacity
	// even if we sliced the tag off. Also note how [AEAD] specifies that "the
	// contents of dst, up to its capacity, may be overwritten".
	if alias.AnyOverlap(out, ciphertext) {
		nonce = make([]byte, gcmStandardNonceSize)
		copy(nonce, ciphertext)
		copy(out[:len(ciphertext)], ciphertext[gcmStandardNonceSize:])
		ciphertext = out[:len(ciphertext)-gcmStandardNonceSize]
	} else {
		nonce = ciphertext[:gcmStandardNonceSize]
		ciphertext = ciphertext[gcmStandardNonceSize:]
	}

	_, err := g.GCM.Open(out[:0], nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// gcmAble is an interface implemented by ciphers that have a specific optimized
// implementation of GCM. crypto/aes doesn't use this anymore, and we'd like to
// eventually remove it.
type gcmAble interface {
	NewGCM(nonceSize, tagSize int) (AEAD, error)
}

func newGCMFallback(cipher Block, nonceSize, tagSize int) (AEAD, error) {
	if tagSize < gcmMinimumTagSize || tagSize > gcmBlockSize {
		return nil, errors.New("cipher: incorrect tag size given to GCM")
	}
	if nonceSize <= 0 {
		return nil, errors.New("cipher: the nonce can't have zero length")
	}
	if cipher, ok := cipher.(gcmAble); ok {
		return cipher.NewGCM(nonceSize, tagSize)
	}
	if cipher.BlockSize() != gcmBlockSize {
		return nil, errors.New("cipher: NewGCM requires 128-bit block cipher")
	}
	return &gcmFallback{cipher: cipher, nonceSize: nonceSize, tagSize: tagSize}, nil
}

// gcmFallback is only used for non-AES ciphers, which regrettably we
// theoretically support. It's a copy of the generic implementation from
// crypto/internal/fips140/aes/gcm/gcm_generic.go, refer to that file for more details.
type gcmFallback struct {
	cipher    Block
	nonceSize int
	tagSize   int
}

func (g *gcmFallback) NonceSize() int {
	return g.nonceSize
}

func (g *gcmFallback) Overhead() int {
	return g.tagSize
}

func (g *gcmFallback) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != g.nonceSize {
		panic("crypto/cipher: incorrect nonce length given to GCM")
	}
	if g.nonceSize == 0 {
		panic("crypto/cipher: incorrect GCM nonce size")
	}
	if uint64(len(plaintext)) > uint64((1<<32)-2)*gcmBlockSize {
		panic("crypto/cipher: message too large for GCM")
	}

	ret, out := sliceForAppend(dst, len(plaintext)+g.tagSize)
	if alias.InexactOverlap(out, plaintext) {
		panic("crypto/cipher: invalid buffer overlap of output and input")
	}
	if alias.AnyOverlap(out, additionalData) {
		panic("crypto/cipher: invalid buffer overlap of output and additional data")
	}

	var H, counter, tagMask [gcmBlockSize]byte
	g.cipher.Encrypt(H[:], H[:])
	deriveCounter(&H, &counter, nonce)
	gcmCounterCryptGeneric(g.cipher, tagMask[:], tagMask[:], &counter)

	gcmCounterCryptGeneric(g.cipher, out, plaintext, &counter)

	var tag [gcmTagSize]byte
	gcmAuth(tag[:], &H, &tagMask, out[:len(plaintext)], additionalData)
	copy(out[len(plaintext):], tag[:])

	return ret
}

var errOpen = errors.New("cipher: message authentication failed")

func (g *gcmFallback) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != g.nonceSize {
		panic("crypto/cipher: incorrect nonce length given to GCM")
	}
	if g.tagSize < gcmMinimumTagSize {
		panic("crypto/cipher: incorrect GCM tag size")
	}

	if len(ciphertext) < g.tagSize {
		return nil, errOpen
	}
	if uint64(len(ciphertext)) > uint64((1<<32)-2)*gcmBlockSize+uint64(g.tagSize) {
		return nil, errOpen
	}

	ret, out := sliceForAppend(dst, len(ciphertext)-g.tagSize)
	if alias.InexactOverlap(out, ciphertext) {
		panic("crypto/cipher: invalid buffer overlap of output and input")
	}
	if alias.AnyOverlap(out, additionalData) {
		panic("crypto/cipher: invalid buffer overlap of output and additional data")
	}

	var H, counter, tagMask [gcmBlockSize]byte
	g.cipher.Encrypt(H[:], H[:])
	deriveCounter(&H, &counter, nonce)
	gcmCounterCryptGeneric(g.cipher, tagMask[:], tagMask[:], &counter)

	tag := ciphertext[len(ciphertext)-g.tagSize:]
	ciphertext = ciphertext[:len(ciphertext)-g.tagSize]

	var expectedTag [gcmTagSize]byte
	gcmAuth(expectedTag[:], &H, &tagMask, ciphertext, additionalData)
	if subtle.ConstantTimeCompare(expectedTag[:g.tagSize], tag) != 1 {
		// We sometimes decrypt and authenticate concurrently, so we overwrite
		// dst in the event of a tag mismatch. To be consistent across platforms
		// and to avoid releasing unauthenticated plaintext, we clear the buffer
		// in the event of an error.
		clear(out)
		return nil, errOpen
	}

	gcmCounterCryptGeneric(g.cipher, out, ciphertext, &counter)

	return ret, nil
}

func deriveCounter(H, counter *[gcmBlockSize]byte, nonce []byte) {
	if len(nonce) == gcmStandardNonceSize {
		copy(counter[:], nonce)
		counter[gcmBlockSize-1] = 1
	} else {
		lenBlock := make([]byte, 16)
		byteorder.BEPutUint64(lenBlock[8:], uint64(len(nonce))*8)
		J := gcm.GHASH(H, nonce, lenBlock)
		copy(counter[:], J)
	}
}

func gcmCounterCryptGeneric(b Block, out, src []byte, counter *[gcmBlockSize]byte) {
	var mask [gcmBlockSize]byte
	for len(src) >= gcmBlockSize {
		b.Encrypt(mask[:], counter[:])
		gcmInc32(counter)

		subtle.XORBytes(out, src, mask[:])
		out = out[gcmBlockSize:]
		src = src[gcmBlockSize:]
	}
	if len(src) > 0 {
		b.Encrypt(mask[:], counter[:])
		gcmInc32(counter)
		subtle.XORBytes(out, src, mask[:])
	}
}

func gcmInc32(counterBlock *[gcmBlockSize]byte) {
	ctr := counterBlock[len(counterBlock)-4:]
	byteorder.BEPutUint32(ctr, byteorder.BEUint32(ctr)+1)
}

func gcmAuth(out []byte, H, tagMask *[gcmBlockSize]byte, ciphertext, additionalData []byte) {
	lenBlock := make([]byte, 16)
	byteorder.BEPutUint64(lenBlock[:8], uint64(len(additionalData))*8)
	byteorder.BEPutUint64(lenBlock[8:], uint64(len(ciphertext))*8)
	S := gcm.GHASH(H, additionalData, ciphertext, lenBlock)
	subtle.XORBytes(out, S, tagMask[:])
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

"""



```