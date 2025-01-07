Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Core Purpose:** The file path `go/src/crypto/internal/boring/aes.go` immediately suggests this is about AES implementation, likely using "boringcrypto" which implies it's leveraging a specific (and potentially optimized) crypto library. The `internal` package suggests it's not meant for direct public use.

2. **Scan for Key Data Structures and Functions:** Quickly look for `type` definitions and prominent `func` declarations. This gives a high-level overview:
    * `aesKeySizeError`:  A custom error type for invalid key sizes.
    * `aesCipher`: The main structure representing an AES cipher instance, holding the key and potentially internal encryption/decryption states.
    * `extraModes`: An interface hinting at additional modes of operation (CBC, CTR, GCM).
    * `NewAESCipher`:  The constructor for `aesCipher`.
    * `Encrypt`, `Decrypt`: Core AES block encryption/decryption functions.
    * `aesCBC`, `aesCTR`, `aesGCM`: Structures for specific modes of operation.
    * `NewCBCEncrypter`, `NewCBCDecrypter`, `NewCTR`, `NewGCM`: Functions to create instances of these modes.
    * `NewGCMTLS`, `NewGCMTLS13`: TLS-specific GCM constructors.
    * `Seal`, `Open`:  Functions for authenticated encryption/decryption using GCM.

3. **Analyze Key Functionality - Start with the Basics (Block Cipher):**
    * `NewAESCipher`:  This is likely the entry point. Notice the calls to `C._goboringcrypto_AES_set_decrypt_key` and `C._goboringcrypto_AES_set_encrypt_key`. This confirms the usage of a C library (boringcrypto). The return of `aesKeySizeError` suggests validation of the provided key.
    * `Encrypt`, `Decrypt`: These methods take `dst` and `src` byte slices. The calls to `C._goboringcrypto_AES_encrypt` and `C._goboringcrypto_AES_decrypt` are crucial. The `panic` calls for buffer overlap and incomplete blocks are important error handling aspects.

4. **Examine the Modes of Operation:**
    * **CBC:**  `aesCBC`, `NewCBCEncrypter`, `NewCBCDecrypter`, `CryptBlocks`. The `iv` field and the `C._goboringcrypto_AES_cbc_encrypt` function are key. The `mode` field (`C.GO_AES_ENCRYPT` or `C.GO_AES_DECRYPT`) is used to specify the operation.
    * **CTR:** `aesCTR`, `NewCTR`, `XORKeyStream`. The `iv`, `num`, and `ecount_buf` suggest the state maintained for the counter. `C._goboringcrypto_AES_ctr128_encrypt` performs the actual XORing.
    * **GCM:**  This is more complex. `aesGCM`, `NewGCM`, `NewGCMTLS`, `NewGCMTLS13`, `Seal`, `Open`. The interaction with `C.GO_EVP_AEAD_CTX` and functions like `C._goboringcrypto_EVP_aead_aes_128_gcm` points to the use of an authenticated encryption with associated data (AEAD) mode provided by the underlying library. `Seal` and `Open` perform the encryption and decryption with authentication. The `NonceSize` and `Overhead` methods reveal important parameters of GCM. The `EVP_AEAD_CTX_seal_wrapper` and `EVP_AEAD_CTX_open_wrapper` functions in the C code are interesting – they seem to add a safety check for the output buffer length.

5. **Identify Potential Issues (Error Prone Areas):**
    * **Key Size:** The `aesKeySizeError` clearly indicates that incorrect key lengths will cause errors.
    * **IV Handling (CBC and CTR):**  The `NewCBCEncrypter`, `NewCBCDecrypter`, and `NewCTR` functions require an IV of a specific length. Incorrect IV lengths will cause panics. For CBC, the IV must be unpredictable for each encryption. For CTR, the IV (or nonce) must be unique for each message encrypted with the same key.
    * **Nonce Handling (GCM):** GCM has specific nonce size requirements (typically 12 bytes). Incorrect nonce lengths passed to `Seal` or `Open` will lead to panics. Nonce reuse with the same key is a critical security vulnerability in GCM.
    * **Buffer Overlap:** The code explicitly checks for and panics on "inexact overlap" between source and destination buffers in `Encrypt`, `Decrypt`, `CryptBlocks`, and `XORKeyStream`.
    * **Input/Output Buffer Sizes:**  The block cipher functions (`Encrypt`, `Decrypt`) require full blocks. CBC requires the input to be a multiple of the block size. GCM has limits on plaintext size.
    * **GCM Tag Size:** While the code primarily uses the standard GCM tag size (16 bytes), it acknowledges the possibility of non-standard sizes but falls back to the standard Go library for those cases. This might be confusing to users.

6. **Infer Go Language Features:**
    * **C Interoperability (`import "C"`):** The presence of `import "C"` and `C._goboringcrypto_...` functions signifies the use of cgo to interact with a C library.
    * **Interfaces (`cipher.Block`, `cipher.BlockMode`, `cipher.Stream`, `cipher.AEAD`):** The code implements standard Go crypto interfaces, making it interoperable with other Go crypto components.
    * **Error Handling (`error` interface, custom error types):**  Standard Go error handling practices are used.
    * **Panics:**  Panics are used for conditions that should not occur in normal usage (e.g., buffer overlaps, incorrect buffer sizes), indicating programmer errors.
    * **`unsafe` package:** The use of `unsafe.Pointer` is necessary for interacting with C data structures.
    * **Finalizers (`runtime.SetFinalizer`):**  Used in `aesGCM` to ensure that the underlying C context is cleaned up when the Go object is garbage collected.
    * **Build Constraints (`//go:build ...`):**  These constraints restrict the compilation of this file to specific platforms and build configurations.

7. **Construct Examples:** Based on the identified functionality, create simple Go code examples demonstrating basic encryption/decryption with the block cipher and different modes (CBC, CTR, GCM). Include plausible inputs and expected outputs to illustrate the behavior.

8. **Explain Command-Line Arguments (If Applicable):** In this specific code snippet, there's no direct handling of command-line arguments. It's a library implementation. So, the explanation should reflect this.

9. **Review and Refine:** Read through the generated explanation to ensure clarity, accuracy, and completeness. Check for any ambiguities or areas that could be explained more effectively. Ensure the examples are correct and easy to understand. Make sure the potential pitfalls are clearly highlighted.
这段代码是 Go 语言 `crypto/internal/boring` 包中关于 AES 加密算法的实现。它使用了 BoringSSL 库提供的 AES 功能，并通过 cgo 技术将 C 代码集成到 Go 语言中。

**主要功能:**

1. **AES 加密和解密:**  提供了底层的 AES 加密和解密功能，包括 ECB 模式的基本块加密和解密。
2. **CBC 模式:** 实现了 AES 的 CBC（Cipher Block Chaining）加密和解密模式。
3. **CTR 模式:** 实现了 AES 的 CTR（Counter）加密模式，用于流加密。
4. **GCM 模式:** 实现了 AES 的 GCM（Galois/Counter Mode）认证加密模式，提供数据加密和完整性校验。
5. **与 BoringSSL 集成:** 通过 cgo 调用 BoringSSL 库的 AES 相关函数，利用其高性能和经过安全审计的实现。
6. **错误处理:** 定义了 `aesKeySizeError` 类型用于表示无效的密钥长度错误。
7. **内存安全:** 在 C 代码中使用了 wrapper 函数 (`EVP_AEAD_CTX_seal_wrapper`, `EVP_AEAD_CTX_open_wrapper`) 来分配 C 栈上的内存，并检查输出长度，以避免在 Go 和 C 之间传递指针时可能发生的堆逃逸问题。

**它是什么 Go 语言功能的实现？**

这段代码实现了 Go 语言标准库 `crypto/cipher` 包中 `Block` 和 `AEAD` 接口的一部分，专门针对 AES 算法。这意味着它可以被用作 `crypto/cipher` 中定义的各种加密模式的底层实现。

**Go 代码举例说明:**

```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
)

func main() {
	key := []byte("thisisagoodkey123") // 16 字节密钥，对应 AES-128

	// 创建 AES cipher.Block
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	plaintext := []byte("Hello, world!")

	// ECB 模式加密（不推荐在实际应用中使用，安全性较差）
	ciphertext := make([]byte, len(plaintext))
	block.Encrypt(ciphertext, plaintext)
	fmt.Printf("ECB 加密后: %x\n", ciphertext)

	decryptedtext := make([]byte, len(ciphertext))
	block.Decrypt(decryptedtext, ciphertext)
	fmt.Printf("ECB 解密后: %s\n", decryptedtext)

	// CBC 模式加密
	iv := []byte("thisisaninitvect") // 初始化向量，长度必须等于 BlockSize
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertextCBC := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertextCBC, plaintext)
	fmt.Printf("CBC 加密后: %x\n", ciphertextCBC)

	// CBC 模式解密
	modeDec := cipher.NewCBCDecrypter(block, iv)
	decryptedtextCBC := make([]byte, len(ciphertextCBC))
	modeDec.CryptBlocks(decryptedtextCBC, ciphertextCBC)
	fmt.Printf("CBC 解密后: %s\n", decryptedtextCBC)

	// CTR 模式加密
	ivCTR := []byte("thisisanoncevery") // Nonce，长度必须等于 BlockSize
	stream := cipher.NewCTR(block, ivCTR)
	ciphertextCTR := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertextCTR, plaintext)
	fmt.Printf("CTR 加密后: %x\n", ciphertextCTR)

	// CTR 模式解密 (CTR 加密和解密使用相同的 XORKeyStream)
	streamDec := cipher.NewCTR(block, ivCTR)
	decryptedtextCTR := make([]byte, len(ciphertextCTR))
	streamDec.XORKeyStream(decryptedtextCTR, ciphertextCTR)
	fmt.Printf("CTR 解密后: %s\n", decryptedtextCTR)

	// GCM 模式加密
	nonce := make([]byte, 12) // GCM 推荐 12 字节 nonce
	// 实际应用中 nonce 需要是唯一且不可预测的
	additionalData := []byte("附加数据")
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}
	ciphertextGCM := gcm.Seal(nil, nonce, plaintext, additionalData)
	fmt.Printf("GCM 加密后: %x\n", ciphertextGCM)

	// GCM 模式解密
	plaintextGCM, err := gcm.Open(nil, nonce, ciphertextGCM, additionalData)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("GCM 解密后: %s\n", plaintextGCM)
}
```

**假设的输入与输出:**

假设输入的 `plaintext` 是 `"Hello, world!"`，密钥 `key` 是 `"thisisagoodkey123"`，初始化向量 `iv` 是 `"thisisaninitvect"`，Nonce 是 `"thisisanoncevery"`，附加数据是 `"附加数据"`。

* **ECB 加密后 (ciphertext):**  `注意: ECB 模式对相同明文块加密结果相同，安全性较差，此处仅为演示`  输出会是 16 进制表示的加密后数据，例如: `a5f9...` (实际值会根据 BoringSSL 的实现而定)。
* **ECB 解密后 (decryptedtext):** `Hello, world!`
* **CBC 加密后 (ciphertextCBC):**  输出会是 16 进制表示的加密后数据，例如: `b7c1...` (实际值会根据 BoringSSL 的实现而定)。
* **CBC 解密后 (decryptedtextCBC):** `Hello, world!`
* **CTR 加密后 (ciphertextCTR):** 输出会是 16 进制表示的加密后数据，例如: `1d9a...` (实际值会根据 BoringSSL 的实现而定)。
* **CTR 解密后 (decryptedtextCTR):** `Hello, world!`
* **GCM 加密后 (ciphertextGCM):** 输出会包含密文和认证标签，例如: `8a2b...` (实际值会根据 BoringSSL 的实现而定)。
* **GCM 解密后 (plaintextGCM):** `Hello, world!`

**注意:**  上述输出只是示例，实际的加密结果会根据具体的 BoringSSL 版本和内部实现而有所不同。重要的是理解各种加密模式的工作原理和使用方法。

**命令行参数的具体处理:**

这段代码本身是一个库的实现，不直接处理命令行参数。它提供的功能会被其他使用 `crypto/aes` 和 `crypto/cipher` 包的程序调用。如果一个使用了这个 AES 实现的程序需要处理命令行参数，那么该程序需要自行处理，与这段代码无关。

**使用者易犯错的点:**

1. **密钥长度错误:** `NewAESCipher` 函数会检查密钥长度。AES 支持 128 位、192 位和 256 位密钥（对应 16、24 和 32 字节）。使用错误的密钥长度会导致 `aesKeySizeError`。

   ```go
   key := []byte("invalidkey") // 长度不是 16, 24, 或 32
   _, err := aes.NewCipher(key)
   if err != nil {
       fmt.Println(err) // 输出: crypto/aes: invalid key size 10
   }
   ```

2. **CBC 模式下 IV 的使用:**
   * **IV 长度错误:** CBC 模式的初始化向量（IV）的长度必须等于 AES 的块大小（16 字节）。
   * **IV 重复使用:**  对于相同的密钥，每次加密都必须使用不同的、不可预测的 IV。重复使用相同的 IV 会严重降低 CBC 模式的安全性。

   ```go
   key := []byte("thisisagoodkey123")
   block, _ := aes.NewCipher(key)
   iv := []byte("wronglength") // IV 长度错误
   mode := cipher.NewCBCEncrypter(block, iv) // 这里会 panic: cipher: incorrect length IV
   ```

3. **CTR 模式下 Nonce 的使用:**
   * **Nonce 长度错误:** CTR 模式的 Nonce (有时也叫 IV) 的长度必须等于 AES 的块大小（16 字节）。
   * **Nonce 重复使用:** 对于相同的密钥，每次加密都必须使用不同的 Nonce。重复使用相同的 Nonce 会导致严重的安全性问题，因为相同的密钥流会被用于加密不同的消息。

   ```go
   key := []byte("thisisagoodkey123")
   block, _ := aes.NewCipher(key)
   nonce := []byte("short") // Nonce 长度错误
   stream := cipher.NewCTR(block, nonce) // 这里会 panic: cipher: incorrect length IV
   ```

4. **GCM 模式下 Nonce 的使用:**
   * **Nonce 长度推荐:** GCM 模式推荐使用 12 字节的 Nonce。虽然可以使用其他长度，但不推荐。
   * **Nonce 唯一性:** 对于相同的密钥，Nonce 必须是唯一的。在每次加密时生成一个新的、唯一的 Nonce 是至关重要的。重复使用相同的 Nonce 会完全破坏 GCM 提供的安全性。

   ```go
   key := []byte("thisisagoodkey123")
   block, _ := aes.NewCipher(key)
   nonce := make([]byte, 10) // GCM Nonce 长度不推荐
   gcm, _ := cipher.NewGCM(block)
   _, err := gcm.Seal(nil, nonce, []byte("plaintext"), nil) // 可能导致安全问题或错误
   ```

5. **缓冲区重叠:**  `Encrypt`、`Decrypt`、`CryptBlocks` 和 `XORKeyStream` 方法会检查源缓冲区和目标缓冲区是否重叠。如果发生重叠，会触发 `panic`。这是为了避免在原地加密/解密时可能出现的数据损坏。

   ```go
   key := []byte("thisisagoodkey123")
   block, _ := aes.NewCipher(key)
   plaintext := []byte("this is a test")
   ciphertext := plaintext // 源和目标缓冲区重叠
   block.Encrypt(ciphertext, plaintext) // 这里会 panic: crypto/cipher: invalid buffer overlap
   ```

理解这些易犯错的点对于安全地使用 AES 加密至关重要。在实际应用中，应该仔细选择加密模式，并遵循最佳实践来管理密钥、IV 和 Nonce。对于 GCM 模式，尤其要注意 Nonce 的唯一性。

Prompt: 
```
这是路径为go/src/crypto/internal/boring/aes.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build boringcrypto && linux && (amd64 || arm64) && !android && !msan

package boring

/*

#include "goboringcrypto.h"

// These wrappers allocate out_len on the C stack, and check that it matches the expected
// value, to avoid having to pass a pointer from Go, which would escape to the heap.

int EVP_AEAD_CTX_seal_wrapper(const GO_EVP_AEAD_CTX *ctx, uint8_t *out,
							  size_t exp_out_len,
							  const uint8_t *nonce, size_t nonce_len,
							  const uint8_t *in, size_t in_len,
							  const uint8_t *ad, size_t ad_len) {
	size_t out_len;
	int ok = _goboringcrypto_EVP_AEAD_CTX_seal(ctx, out, &out_len, exp_out_len,
		nonce, nonce_len, in, in_len, ad, ad_len);
	if (out_len != exp_out_len) {
		return 0;
	}
	return ok;
};

int EVP_AEAD_CTX_open_wrapper(const GO_EVP_AEAD_CTX *ctx, uint8_t *out,
							  size_t exp_out_len,
							  const uint8_t *nonce, size_t nonce_len,
							  const uint8_t *in, size_t in_len,
							  const uint8_t *ad, size_t ad_len) {
	size_t out_len;
	int ok = _goboringcrypto_EVP_AEAD_CTX_open(ctx, out, &out_len, exp_out_len,
		nonce, nonce_len, in, in_len, ad, ad_len);
	if (out_len != exp_out_len) {
		return 0;
	}
	return ok;
};

*/
import "C"
import (
	"bytes"
	"crypto/cipher"
	"errors"
	"runtime"
	"strconv"
	"unsafe"
)

type aesKeySizeError int

func (k aesKeySizeError) Error() string {
	return "crypto/aes: invalid key size " + strconv.Itoa(int(k))
}

const aesBlockSize = 16

type aesCipher struct {
	key []byte
	enc C.GO_AES_KEY
	dec C.GO_AES_KEY
}

type extraModes interface {
	// Copied out of crypto/aes/modes.go.
	NewCBCEncrypter(iv []byte) cipher.BlockMode
	NewCBCDecrypter(iv []byte) cipher.BlockMode
	NewCTR(iv []byte) cipher.Stream
	NewGCM(nonceSize, tagSize int) (cipher.AEAD, error)
}

var _ extraModes = (*aesCipher)(nil)

func NewAESCipher(key []byte) (cipher.Block, error) {
	c := &aesCipher{key: bytes.Clone(key)}
	// Note: 0 is success, contradicting the usual BoringCrypto convention.
	if C._goboringcrypto_AES_set_decrypt_key((*C.uint8_t)(unsafe.Pointer(&c.key[0])), C.uint(8*len(c.key)), &c.dec) != 0 ||
		C._goboringcrypto_AES_set_encrypt_key((*C.uint8_t)(unsafe.Pointer(&c.key[0])), C.uint(8*len(c.key)), &c.enc) != 0 {
		return nil, aesKeySizeError(len(key))
	}
	return c, nil
}

func (c *aesCipher) BlockSize() int { return aesBlockSize }

func (c *aesCipher) Encrypt(dst, src []byte) {
	if inexactOverlap(dst, src) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	if len(src) < aesBlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < aesBlockSize {
		panic("crypto/aes: output not full block")
	}
	C._goboringcrypto_AES_encrypt(
		(*C.uint8_t)(unsafe.Pointer(&src[0])),
		(*C.uint8_t)(unsafe.Pointer(&dst[0])),
		&c.enc)
}

func (c *aesCipher) Decrypt(dst, src []byte) {
	if inexactOverlap(dst, src) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	if len(src) < aesBlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < aesBlockSize {
		panic("crypto/aes: output not full block")
	}
	C._goboringcrypto_AES_decrypt(
		(*C.uint8_t)(unsafe.Pointer(&src[0])),
		(*C.uint8_t)(unsafe.Pointer(&dst[0])),
		&c.dec)
}

type aesCBC struct {
	key  *C.GO_AES_KEY
	mode C.int
	iv   [aesBlockSize]byte
}

func (x *aesCBC) BlockSize() int { return aesBlockSize }

func (x *aesCBC) CryptBlocks(dst, src []byte) {
	if inexactOverlap(dst, src) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	if len(src)%aesBlockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	if len(src) > 0 {
		C._goboringcrypto_AES_cbc_encrypt(
			(*C.uint8_t)(unsafe.Pointer(&src[0])),
			(*C.uint8_t)(unsafe.Pointer(&dst[0])),
			C.size_t(len(src)), x.key,
			(*C.uint8_t)(unsafe.Pointer(&x.iv[0])), x.mode)
	}
}

func (x *aesCBC) SetIV(iv []byte) {
	if len(iv) != aesBlockSize {
		panic("cipher: incorrect length IV")
	}
	copy(x.iv[:], iv)
}

func (c *aesCipher) NewCBCEncrypter(iv []byte) cipher.BlockMode {
	x := &aesCBC{key: &c.enc, mode: C.GO_AES_ENCRYPT}
	copy(x.iv[:], iv)
	return x
}

func (c *aesCipher) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	x := &aesCBC{key: &c.dec, mode: C.GO_AES_DECRYPT}
	copy(x.iv[:], iv)
	return x
}

type aesCTR struct {
	key        *C.GO_AES_KEY
	iv         [aesBlockSize]byte
	num        C.uint
	ecount_buf [16]C.uint8_t
}

func (x *aesCTR) XORKeyStream(dst, src []byte) {
	if inexactOverlap(dst, src) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	if len(src) == 0 {
		return
	}
	C._goboringcrypto_AES_ctr128_encrypt(
		(*C.uint8_t)(unsafe.Pointer(&src[0])),
		(*C.uint8_t)(unsafe.Pointer(&dst[0])),
		C.size_t(len(src)), x.key, (*C.uint8_t)(unsafe.Pointer(&x.iv[0])),
		&x.ecount_buf[0], &x.num)
}

func (c *aesCipher) NewCTR(iv []byte) cipher.Stream {
	x := &aesCTR{key: &c.enc}
	copy(x.iv[:], iv)
	return x
}

type aesGCM struct {
	ctx  C.GO_EVP_AEAD_CTX
	aead *C.GO_EVP_AEAD
}

const (
	gcmBlockSize         = 16
	gcmTagSize           = 16
	gcmStandardNonceSize = 12
)

type aesNonceSizeError int

func (n aesNonceSizeError) Error() string {
	return "crypto/aes: invalid GCM nonce size " + strconv.Itoa(int(n))
}

type noGCM struct {
	cipher.Block
}

func (c *aesCipher) NewGCM(nonceSize, tagSize int) (cipher.AEAD, error) {
	if nonceSize != gcmStandardNonceSize && tagSize != gcmTagSize {
		return nil, errors.New("crypto/aes: GCM tag and nonce sizes can't be non-standard at the same time")
	}
	// Fall back to standard library for GCM with non-standard nonce or tag size.
	if nonceSize != gcmStandardNonceSize {
		return cipher.NewGCMWithNonceSize(&noGCM{c}, nonceSize)
	}
	if tagSize != gcmTagSize {
		return cipher.NewGCMWithTagSize(&noGCM{c}, tagSize)
	}
	return c.newGCM(0)
}

const (
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304
)

func NewGCMTLS(c cipher.Block) (cipher.AEAD, error) {
	return c.(*aesCipher).newGCM(VersionTLS12)
}

func NewGCMTLS13(c cipher.Block) (cipher.AEAD, error) {
	return c.(*aesCipher).newGCM(VersionTLS13)
}

func (c *aesCipher) newGCM(tlsVersion uint16) (cipher.AEAD, error) {
	var aead *C.GO_EVP_AEAD
	switch len(c.key) * 8 {
	case 128:
		switch tlsVersion {
		case VersionTLS12:
			aead = C._goboringcrypto_EVP_aead_aes_128_gcm_tls12()
		case VersionTLS13:
			aead = C._goboringcrypto_EVP_aead_aes_128_gcm_tls13()
		default:
			aead = C._goboringcrypto_EVP_aead_aes_128_gcm()
		}
	case 256:
		switch tlsVersion {
		case VersionTLS12:
			aead = C._goboringcrypto_EVP_aead_aes_256_gcm_tls12()
		case VersionTLS13:
			aead = C._goboringcrypto_EVP_aead_aes_256_gcm_tls13()
		default:
			aead = C._goboringcrypto_EVP_aead_aes_256_gcm()
		}
	default:
		// Fall back to standard library for GCM with non-standard key size.
		return cipher.NewGCMWithNonceSize(&noGCM{c}, gcmStandardNonceSize)
	}

	g := &aesGCM{aead: aead}
	if C._goboringcrypto_EVP_AEAD_CTX_init(&g.ctx, aead, (*C.uint8_t)(unsafe.Pointer(&c.key[0])), C.size_t(len(c.key)), C.GO_EVP_AEAD_DEFAULT_TAG_LENGTH, nil) == 0 {
		return nil, fail("EVP_AEAD_CTX_init")
	}
	// Note: Because of the finalizer, any time g.ctx is passed to cgo,
	// that call must be followed by a call to runtime.KeepAlive(g),
	// to make sure g is not collected (and finalized) before the cgo
	// call returns.
	runtime.SetFinalizer(g, (*aesGCM).finalize)
	if g.NonceSize() != gcmStandardNonceSize {
		panic("boringcrypto: internal confusion about nonce size")
	}
	if g.Overhead() != gcmTagSize {
		panic("boringcrypto: internal confusion about tag size")
	}

	return g, nil
}

func (g *aesGCM) finalize() {
	C._goboringcrypto_EVP_AEAD_CTX_cleanup(&g.ctx)
}

func (g *aesGCM) NonceSize() int {
	return int(C._goboringcrypto_EVP_AEAD_nonce_length(g.aead))
}

func (g *aesGCM) Overhead() int {
	return int(C._goboringcrypto_EVP_AEAD_max_overhead(g.aead))
}

// base returns the address of the underlying array in b,
// being careful not to panic when b has zero length.
func base(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func (g *aesGCM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != gcmStandardNonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}
	if uint64(len(plaintext)) > ((1<<32)-2)*aesBlockSize || len(plaintext)+gcmTagSize < len(plaintext) {
		panic("cipher: message too large for GCM")
	}
	if len(dst)+len(plaintext)+gcmTagSize < len(dst) {
		panic("cipher: message too large for buffer")
	}

	// Make room in dst to append plaintext+overhead.
	n := len(dst)
	for cap(dst) < n+len(plaintext)+gcmTagSize {
		dst = append(dst[:cap(dst)], 0)
	}
	dst = dst[:n+len(plaintext)+gcmTagSize]

	// Check delayed until now to make sure len(dst) is accurate.
	if inexactOverlap(dst[n:], plaintext) {
		panic("cipher: invalid buffer overlap")
	}

	outLen := C.size_t(len(plaintext) + gcmTagSize)
	ok := C.EVP_AEAD_CTX_seal_wrapper(
		&g.ctx,
		(*C.uint8_t)(unsafe.Pointer(&dst[n])), outLen,
		base(nonce), C.size_t(len(nonce)),
		base(plaintext), C.size_t(len(plaintext)),
		base(additionalData), C.size_t(len(additionalData)))
	runtime.KeepAlive(g)
	if ok == 0 {
		panic(fail("EVP_AEAD_CTX_seal"))
	}
	return dst[:n+int(outLen)]
}

var errOpen = errors.New("cipher: message authentication failed")

func (g *aesGCM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != gcmStandardNonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}
	if len(ciphertext) < gcmTagSize {
		return nil, errOpen
	}
	if uint64(len(ciphertext)) > ((1<<32)-2)*aesBlockSize+gcmTagSize {
		return nil, errOpen
	}

	// Make room in dst to append ciphertext without tag.
	n := len(dst)
	for cap(dst) < n+len(ciphertext)-gcmTagSize {
		dst = append(dst[:cap(dst)], 0)
	}
	dst = dst[:n+len(ciphertext)-gcmTagSize]

	// Check delayed until now to make sure len(dst) is accurate.
	if inexactOverlap(dst[n:], ciphertext) {
		panic("cipher: invalid buffer overlap")
	}

	outLen := C.size_t(len(ciphertext) - gcmTagSize)
	ok := C.EVP_AEAD_CTX_open_wrapper(
		&g.ctx,
		base(dst[n:]), outLen,
		base(nonce), C.size_t(len(nonce)),
		base(ciphertext), C.size_t(len(ciphertext)),
		base(additionalData), C.size_t(len(additionalData)))
	runtime.KeepAlive(g)
	if ok == 0 {
		return nil, errOpen
	}
	return dst[:n+int(outLen)], nil
}

func anyOverlap(x, y []byte) bool {
	return len(x) > 0 && len(y) > 0 &&
		uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
		uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}

func inexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}
	return anyOverlap(x, y)
}

"""



```