Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Core Purpose:** The `//go:build boringcrypto ...` comment strongly suggests this code is a part of the Go standard library's `crypto/rsa` package but specifically for a build using "boringcrypto". This immediately tells us it's likely an interface to a cryptographic library (BoringSSL in this case).

2. **Scan for Key Data Structures:**  Look for types that seem central to RSA cryptography. `PublicKeyRSA` and `PrivateKeyRSA` are obvious candidates. The `BigInt` type also stands out as representing large numbers, crucial for RSA.

3. **Analyze Function Signatures:**  Examine the functions and their parameters.
    * `GenerateKeyRSA(bits int) ...`:  This clearly generates an RSA key pair. The return types (`N`, `E`, `D`, `P`, `Q`, `Dp`, `Dq`, `Qinv` of type `BigInt`) represent the components of an RSA key.
    * `NewPublicKeyRSA(N, E BigInt) ...`: Constructs a public key from its modulus (N) and public exponent (E).
    * `NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv BigInt) ...`:  Constructs a private key from all its components.
    * Functions like `DecryptRSAOAEP`, `EncryptRSAOAEP`, `DecryptRSAPKCS1`, `EncryptRSAPKCS1`, `SignRSAPSS`, `VerifyRSAPSS`, `SignRSAPKCS1v15`, `VerifyRSAPKCS1v15` strongly indicate cryptographic operations. The names themselves are quite descriptive.

4. **Look for Interactions with C Code:** The presence of `#include "goboringcrypto.h"` and the `import "C"` statement immediately signals that this Go code is interfacing with C code. This confirms the "boringcrypto" aspect and indicates that the actual cryptographic operations are likely happening in the linked C library (BoringSSL). Pay attention to how the Go code interacts with C structures (like `C.GO_RSA`, `C.GO_EVP_PKEY`, `C.GO_EVP_PKEY_CTX`).

5. **Trace the Flow of Data (Example: Key Generation):** In `GenerateKeyRSA`, observe the sequence:
    * `C._goboringcrypto_RSA_new()`:  Allocates a new RSA key structure in C.
    * `C._goboringcrypto_RSA_generate_key_fips(key, C.int(bits), nil)`:  Calls a C function to generate the RSA key with a specified number of bits. The "fips" suggests it adheres to certain security standards.
    * `C._goboringcrypto_RSA_get0_key(...)` and `C._goboringcrypto_RSA_get0_factors(...)` and `C._goboringcrypto_RSA_get0_crt_params(...)`: Retrieve the key components from the C structure.
    * `bnToBig(...)`: Converts the C-style big numbers to the Go `BigInt` type.

6. **Identify Patterns (Example: `withKey`):**  Notice the `withKey` methods in both `PublicKeyRSA` and `PrivateKeyRSA`. This suggests a pattern for safely interacting with the underlying C `GO_RSA` structure, likely related to memory management and finalizers. The comment within `withKey` about `runtime.KeepAlive` confirms this.

7. **Infer Functionality Based on Names and Parameters:**  For the cryptographic operation functions:
    * The names tell you the operation (Encrypt, Decrypt, Sign, Verify).
    * The suffixes (OAEP, PKCS1, PSS, NoPadding, v15) indicate the RSA padding scheme being used.
    * The parameters often include hash functions (`hash.Hash`, `crypto.Hash`), the key (`*PublicKeyRSA`, `*PrivateKeyRSA`), and the data to be processed.

8. **Focus on Error Handling:**  Look for `err error` return values and the use of a `bad` helper function. This indicates proper error handling. The `fail()` function likely creates a more informative error message.

9. **Consider Conditional Compilation:** The `//go:build` line specifies build constraints. This indicates that this code is only used under specific conditions (boringcrypto enabled, Linux, specific architectures, etc.).

10. **Infer Go Language Features:** The code uses:
    * C interop (`import "C"`)
    * Structs and methods
    * Defer statements for resource cleanup
    * Finalizers for managing C memory
    * Error handling
    * Function literals (anonymous functions passed to `withKey`)

11. **Address Specific Questions from the Prompt:** Now, go back to the prompt's requests:
    * **List the features:**  Summarize the identified functionalities.
    * **Infer Go language features:**  List the Go features used.
    * **Code examples:**  Construct simple Go code snippets that demonstrate the usage of the identified functions, making reasonable assumptions about inputs.
    * **Input/Output for code:**  Specify example inputs and expected outputs for the code snippets.
    * **Command-line arguments:**  Since the code doesn't directly handle command-line arguments, state that.
    * **Common mistakes:**  Think about potential pitfalls for users, such as incorrect padding choices or hash function mismatches.

By following these steps, we can systematically analyze the code and extract the requested information, forming a comprehensive understanding of its purpose and functionality. The key is to start with the big picture and then gradually delve into the details, paying close attention to names, signatures, and interactions with external libraries.
这段Go语言代码是 `crypto/internal/boring/rsa.go` 文件的一部分，它的作用是 **提供了使用 BoringSSL 库实现的 RSA 加密和解密以及签名和验签的功能**。BoringSSL 是一个由 Google 维护的 OpenSSL 的分支，Go 语言的 `crypto` 包在某些特定编译条件下会使用 BoringSSL 来提供底层的密码学实现。

以下是代码中主要功能的详细列举：

**1. RSA 密钥生成:**

*   `GenerateKeyRSA(bits int) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error)`:  生成指定位数的 RSA 密钥对。它返回 RSA 密钥的各个组成部分，包括模数 (N)，公钥指数 (E)，私钥指数 (D)，以及用于加速计算的素数因子 (P, Q) 和 CRT 参数 (Dp, Dq, Qinv)。

**2. RSA 公钥和私钥的表示:**

*   `PublicKeyRSA` 结构体：表示 RSA 公钥，包含一个指向 BoringSSL 的 `RSA` 结构体的指针 `_key`。
*   `PrivateKeyRSA` 结构体：表示 RSA 私钥，包含一个指向 BoringSSL 的 `RSA` 结构体的指针 `_key`。

**3. 创建 RSA 公钥和私钥对象:**

*   `NewPublicKeyRSA(N, E BigInt) (*PublicKeyRSA, error)`:  根据给定的模数 `N` 和公钥指数 `E` 创建一个 `PublicKeyRSA` 对象。
*   `NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv BigInt) (*PrivateKeyRSA, error)`: 根据给定的 RSA 密钥的各个组成部分创建一个 `PrivateKeyRSA` 对象。

**4. RSA 加密和解密:**

*   `EncryptRSAOAEP(h, mgfHash hash.Hash, pub *PublicKeyRSA, msg, label []byte) ([]byte, error)`: 使用 RSA-OAEP 填充模式加密消息。需要指定哈希函数 `h`，掩码生成函数使用的哈希函数 `mgfHash`，公钥 `pub`，要加密的消息 `msg`，以及可选的标签 `label`。
*   `DecryptRSAOAEP(h, mgfHash hash.Hash, priv *PrivateKeyRSA, ciphertext, label []byte) ([]byte, error)`: 使用 RSA-OAEP 填充模式解密密文。参数与加密函数类似，但使用私钥 `priv`。
*   `EncryptRSAPKCS1(pub *PublicKeyRSA, msg []byte) ([]byte, error)`: 使用 RSA-PKCS1 v1.5 填充模式加密消息。
*   `DecryptRSAPKCS1(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error)`: 使用 RSA-PKCS1 v1.5 填充模式解密密文。
*   `EncryptRSANoPadding(pub *PublicKeyRSA, msg []byte) ([]byte, error)`:  使用无填充模式加密消息（通常不推荐直接使用）。
*   `DecryptRSANoPadding(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error)`: 使用无填充模式解密密文。

**5. RSA 签名和验签:**

*   `SignRSAPSS(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error)`: 使用 RSA-PSS 签名方案对已哈希的消息进行签名。需要指定哈希算法 `h`，已哈希的消息 `hashed`，以及盐的长度 `saltLen`。
*   `VerifyRSAPSS(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte, saltLen int) error`:  使用 RSA-PSS 签名方案验证签名。
*   `SignRSAPKCS1v15(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte) ([]byte, error)`: 使用 RSA-PKCS1 v1.5 签名方案对消息进行签名。可以指定哈希算法 `h`，如果 `h` 为 0，则直接对 `hashed` 进行签名（不推荐）。
*   `VerifyRSAPKCS1v15(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte) error`: 使用 RSA-PKCS1 v1.5 签名方案验证签名。

**6. 底层与 BoringSSL 的交互:**

*   代码中大量使用了 `C._goboringcrypto_...` 形式的函数调用，这些是 Go 的 cgo 特性，用于调用 BoringSSL 提供的 C 语言函数。
*   `withKey` 方法：这是一个辅助方法，用于确保在调用 BoringSSL 函数时，`PublicKeyRSA` 和 `PrivateKeyRSA` 对象不会被垃圾回收。它使用 `runtime.KeepAlive` 来保持对象的存活。
*   `setupRSA` 函数：用于设置 BoringSSL 的上下文，包括填充模式、哈希函数等，为加密和解密操作做准备。
*   `cryptRSA` 函数：是一个通用的加密/解密函数，接受不同的填充模式和初始化/执行函数。
*   `hashToMD` 和 `cryptoHashToMD` 函数：将 Go 的 `hash.Hash` 和 `crypto.Hash` 类型转换为 BoringSSL 的消息摘要类型。

**推断 Go 语言功能实现并举例说明:**

这段代码是 `crypto/rsa` 包的一部分，专门针对启用了 `boringcrypto` 构建标签的情况。它提供了 RSA 算法的实现，这是 Go 标准库中用于非对称加密和签名的核心功能之一。

**代码示例：RSA-OAEP 加密和解密**

假设我们有以下输入：

*   `bits = 2048` (用于生成 2048 位的 RSA 密钥)
*   `message = []byte("这是一个需要加密的消息")`
*   `hash = crypto.SHA256`

```go
package main

import (
	"crypto"
	"crypto/internal/boring" // 注意：这是 internal 包，通常不直接导入
	"crypto/rand"
	"fmt"
	"hash"
)

func main() {
	// 生成 RSA 密钥对
	n, e, d, p, q, dp, dq, qinv, err := boring.GenerateKeyRSA(2048)
	if err != nil {
		fmt.Println("生成密钥失败:", err)
		return
	}

	privateKey, err := boring.NewPrivateKeyRSA(n, e, d, p, q, dp, dq, qinv)
	if err != nil {
		fmt.Println("创建私钥对象失败:", err)
		return
	}

	publicKey, err := boring.NewPublicKeyRSA(n, e)
	if err != nil {
		fmt.Println("创建公钥对象失败:", err)
		return
	}

	message := []byte("这是一个需要加密的消息")
	var h hash.Hash = crypto.SHA256.New()
	label := []byte("OAEP Label")

	// 使用 RSA-OAEP 加密
	ciphertext, err := boring.EncryptRSAOAEP(h, crypto.SHA256.New(), publicKey, message, label)
	if err != nil {
		fmt.Println("加密失败:", err)
		return
	}
	fmt.Printf("密文: %x\n", ciphertext)

	// 使用 RSA-OAEP 解密
	plaintext, err := boring.DecryptRSAOAEP(h, crypto.SHA256.New(), privateKey, ciphertext, label)
	if err != nil {
		fmt.Println("解密失败:", err)
		return
	}
	fmt.Printf("解密后的明文: %s\n", string(plaintext))
}
```

**假设的输出：**

```
密文: [一串十六进制字符]
解密后的明文: 这是一个需要加密的消息
```

**代码示例：RSA-PSS 签名和验签**

假设我们有以下输入：

*   `bits = 2048`
*   `message = []byte("这是一条需要签名的消息")`
*   `hash = crypto.SHA256`

```go
package main

import (
	"crypto"
	"crypto/internal/boring"
	"fmt"
)

func main() {
	// 生成 RSA 密钥对 (省略，与上面示例相同)
	n, e, d, p, q, dp, dq, qinv, err := boring.GenerateKeyRSA(2048)
	if err != nil {
		fmt.Println("生成密钥失败:", err)
		return
	}

	privateKey, err := boring.NewPrivateKeyRSA(n, e, d, p, q, dp, dq, qinv)
	if err != nil {
		fmt.Println("创建私钥对象失败:", err)
		return
	}

	publicKey, err := boring.NewPublicKeyRSA(n, e)
	if err != nil {
		fmt.Println("创建公钥对象失败:", err)
		return
	}

	message := []byte("这是一条需要签名的消息")
	h := crypto.SHA256
	hashed := make([]byte, h.Size())
	hasher := h.New()
	hasher.Write(message)
	hashed = hasher.Sum(nil)
	saltLen := crypto.SHA256.Size()

	// 使用 RSA-PSS 签名
	signature, err := boring.SignRSAPSS(privateKey, h, hashed, saltLen)
	if err != nil {
		fmt.Println("签名失败:", err)
		return
	}
	fmt.Printf("签名: %x\n", signature)

	// 使用 RSA-PSS 验签
	err = boring.VerifyRSAPSS(publicKey, h, hashed, signature, saltLen)
	if err != nil {
		fmt.Println("验签失败:", err)
		return
	}
	fmt.Println("验签成功!")
}
```

**假设的输出：**

```
签名: [一串十六进制字符]
验签成功!
```

**命令行参数处理：**

这段代码本身并不直接处理命令行参数。它是一个底层的密码学实现，通常由更上层的代码（例如使用了 `crypto/rsa` 包的应用程序或库）来调用和使用。命令行参数的处理逻辑会在调用这些底层函数的应用程序中实现。

**使用者易犯错的点：**

1. **填充模式的选择错误：**  RSA 算法本身需要填充模式来保证安全性。常见的错误是混淆使用不同的填充模式（例如 OAEP 和 PKCS1 v1.5），导致加密的数据无法被正确解密，或者签名无法被正确验证。

    **错误示例：** 使用 `EncryptRSAOAEP` 加密，但尝试使用 `DecryptRSAPKCS1` 解密。

2. **哈希函数的选择不匹配：** 在使用 RSA-OAEP 或 RSA-PSS 时，加密、解密、签名和验签操作必须使用相同的哈希函数。不匹配的哈希函数会导致操作失败。

    **错误示例：** 使用 SHA256 进行 RSA-PSS 签名，但尝试使用 SHA1 进行验签。

3. **盐长度 (Salt Length) 的错误配置：** 在 RSA-PSS 中，盐的长度是一个重要的参数。不正确的盐长度会导致签名验证失败。

    **错误示例：** 签名时使用默认盐长度，但在验证时指定了错误的盐长度。

4. **直接使用 `EncryptRSANoPadding` 或 `DecryptRSANoPadding`：**  无填充模式通常只在特定的协议或场景中使用，直接使用容易引入安全漏洞，例如 Textbook RSA 攻击。对于一般的应用场景，应该使用带填充的模式。

5. **密钥管理的疏忽：** 这段代码涉及密钥的生成和使用。不安全地存储或传输密钥是常见的错误。例如，将私钥硬编码在代码中，或者使用不安全的网络协议传输密钥。

6. **对 `internal` 包的直接依赖：**  虽然上面的示例为了演示目的导入了 `crypto/internal/boring`，但在实际开发中，应该避免直接导入 `internal` 包，因为这些包的 API 可能不稳定，并且不保证向后兼容。应该使用 `crypto/rsa` 包提供的公共 API。

总而言之，这段代码是 Go 语言 `crypto` 包在特定条件下使用 BoringSSL 库实现 RSA 算法的关键部分，提供了密钥生成、加密解密以及签名验签等核心功能。使用者需要理解 RSA 的各种填充模式和参数，并注意密钥的安全管理，才能正确且安全地使用这些功能。

### 提示词
```
这是路径为go/src/crypto/internal/boring/rsa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build boringcrypto && linux && (amd64 || arm64) && !android && !msan

package boring

// #include "goboringcrypto.h"
import "C"
import (
	"crypto"
	"crypto/subtle"
	"errors"
	"hash"
	"runtime"
	"strconv"
	"unsafe"
)

func GenerateKeyRSA(bits int) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
	bad := func(e error) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
		return nil, nil, nil, nil, nil, nil, nil, nil, e
	}

	key := C._goboringcrypto_RSA_new()
	if key == nil {
		return bad(fail("RSA_new"))
	}
	defer C._goboringcrypto_RSA_free(key)

	if C._goboringcrypto_RSA_generate_key_fips(key, C.int(bits), nil) == 0 {
		return bad(fail("RSA_generate_key_fips"))
	}

	var n, e, d, p, q, dp, dq, qinv *C.GO_BIGNUM
	C._goboringcrypto_RSA_get0_key(key, &n, &e, &d)
	C._goboringcrypto_RSA_get0_factors(key, &p, &q)
	C._goboringcrypto_RSA_get0_crt_params(key, &dp, &dq, &qinv)
	return bnToBig(n), bnToBig(e), bnToBig(d), bnToBig(p), bnToBig(q), bnToBig(dp), bnToBig(dq), bnToBig(qinv), nil
}

type PublicKeyRSA struct {
	// _key MUST NOT be accessed directly. Instead, use the withKey method.
	_key *C.GO_RSA
}

func NewPublicKeyRSA(N, E BigInt) (*PublicKeyRSA, error) {
	key := C._goboringcrypto_RSA_new()
	if key == nil {
		return nil, fail("RSA_new")
	}
	if !bigToBn(&key.n, N) ||
		!bigToBn(&key.e, E) {
		return nil, fail("BN_bin2bn")
	}
	k := &PublicKeyRSA{_key: key}
	runtime.SetFinalizer(k, (*PublicKeyRSA).finalize)
	return k, nil
}

func (k *PublicKeyRSA) finalize() {
	C._goboringcrypto_RSA_free(k._key)
}

func (k *PublicKeyRSA) withKey(f func(*C.GO_RSA) C.int) C.int {
	// Because of the finalizer, any time _key is passed to cgo, that call must
	// be followed by a call to runtime.KeepAlive, to make sure k is not
	// collected (and finalized) before the cgo call returns.
	defer runtime.KeepAlive(k)
	return f(k._key)
}

type PrivateKeyRSA struct {
	// _key MUST NOT be accessed directly. Instead, use the withKey method.
	_key *C.GO_RSA
}

func NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv BigInt) (*PrivateKeyRSA, error) {
	key := C._goboringcrypto_RSA_new()
	if key == nil {
		return nil, fail("RSA_new")
	}
	if !bigToBn(&key.n, N) ||
		!bigToBn(&key.e, E) ||
		!bigToBn(&key.d, D) ||
		!bigToBn(&key.p, P) ||
		!bigToBn(&key.q, Q) ||
		!bigToBn(&key.dmp1, Dp) ||
		!bigToBn(&key.dmq1, Dq) ||
		!bigToBn(&key.iqmp, Qinv) {
		return nil, fail("BN_bin2bn")
	}
	k := &PrivateKeyRSA{_key: key}
	runtime.SetFinalizer(k, (*PrivateKeyRSA).finalize)
	return k, nil
}

func (k *PrivateKeyRSA) finalize() {
	C._goboringcrypto_RSA_free(k._key)
}

func (k *PrivateKeyRSA) withKey(f func(*C.GO_RSA) C.int) C.int {
	// Because of the finalizer, any time _key is passed to cgo, that call must
	// be followed by a call to runtime.KeepAlive, to make sure k is not
	// collected (and finalized) before the cgo call returns.
	defer runtime.KeepAlive(k)
	return f(k._key)
}

func setupRSA(withKey func(func(*C.GO_RSA) C.int) C.int,
	padding C.int, h, mgfHash hash.Hash, label []byte, saltLen int, ch crypto.Hash,
	init func(*C.GO_EVP_PKEY_CTX) C.int) (pkey *C.GO_EVP_PKEY, ctx *C.GO_EVP_PKEY_CTX, err error) {
	defer func() {
		if err != nil {
			if pkey != nil {
				C._goboringcrypto_EVP_PKEY_free(pkey)
				pkey = nil
			}
			if ctx != nil {
				C._goboringcrypto_EVP_PKEY_CTX_free(ctx)
				ctx = nil
			}
		}
	}()

	pkey = C._goboringcrypto_EVP_PKEY_new()
	if pkey == nil {
		return pkey, ctx, fail("EVP_PKEY_new")
	}
	if withKey(func(key *C.GO_RSA) C.int {
		return C._goboringcrypto_EVP_PKEY_set1_RSA(pkey, key)
	}) == 0 {
		return pkey, ctx, fail("EVP_PKEY_set1_RSA")
	}
	ctx = C._goboringcrypto_EVP_PKEY_CTX_new(pkey, nil)
	if ctx == nil {
		return pkey, ctx, fail("EVP_PKEY_CTX_new")
	}
	if init(ctx) == 0 {
		return pkey, ctx, fail("EVP_PKEY_operation_init")
	}
	if C._goboringcrypto_EVP_PKEY_CTX_set_rsa_padding(ctx, padding) == 0 {
		return pkey, ctx, fail("EVP_PKEY_CTX_set_rsa_padding")
	}
	if padding == C.GO_RSA_PKCS1_OAEP_PADDING {
		md := hashToMD(h)
		if md == nil {
			return pkey, ctx, errors.New("crypto/rsa: unsupported hash function")
		}
		mgfMD := hashToMD(mgfHash)
		if mgfMD == nil {
			return pkey, ctx, errors.New("crypto/rsa: unsupported hash function")
		}
		if C._goboringcrypto_EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) == 0 {
			return pkey, ctx, fail("EVP_PKEY_set_rsa_oaep_md")
		}
		if C._goboringcrypto_EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgfMD) == 0 {
			return pkey, ctx, fail("EVP_PKEY_set_rsa_mgf1_md")
		}
		// ctx takes ownership of label, so malloc a copy for BoringCrypto to free.
		clabel := (*C.uint8_t)(C._goboringcrypto_OPENSSL_malloc(C.size_t(len(label))))
		if clabel == nil {
			return pkey, ctx, fail("OPENSSL_malloc")
		}
		copy((*[1 << 30]byte)(unsafe.Pointer(clabel))[:len(label)], label)
		if C._goboringcrypto_EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, clabel, C.size_t(len(label))) == 0 {
			return pkey, ctx, fail("EVP_PKEY_CTX_set0_rsa_oaep_label")
		}
	}
	if padding == C.GO_RSA_PKCS1_PSS_PADDING {
		if saltLen != 0 {
			if C._goboringcrypto_EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, C.int(saltLen)) == 0 {
				return pkey, ctx, fail("EVP_PKEY_set_rsa_pss_saltlen")
			}
		}
		md := cryptoHashToMD(ch)
		if md == nil {
			return pkey, ctx, errors.New("crypto/rsa: unsupported hash function")
		}
		if C._goboringcrypto_EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) == 0 {
			return pkey, ctx, fail("EVP_PKEY_set_rsa_mgf1_md")
		}
	}

	return pkey, ctx, nil
}

func cryptRSA(withKey func(func(*C.GO_RSA) C.int) C.int,
	padding C.int, h, mgfHash hash.Hash, label []byte, saltLen int, ch crypto.Hash,
	init func(*C.GO_EVP_PKEY_CTX) C.int,
	crypt func(*C.GO_EVP_PKEY_CTX, *C.uint8_t, *C.size_t, *C.uint8_t, C.size_t) C.int,
	in []byte) ([]byte, error) {

	pkey, ctx, err := setupRSA(withKey, padding, h, mgfHash, label, saltLen, ch, init)
	if err != nil {
		return nil, err
	}
	defer C._goboringcrypto_EVP_PKEY_free(pkey)
	defer C._goboringcrypto_EVP_PKEY_CTX_free(ctx)

	var outLen C.size_t
	if crypt(ctx, nil, &outLen, base(in), C.size_t(len(in))) == 0 {
		return nil, fail("EVP_PKEY_decrypt/encrypt")
	}
	out := make([]byte, outLen)
	if crypt(ctx, base(out), &outLen, base(in), C.size_t(len(in))) == 0 {
		return nil, fail("EVP_PKEY_decrypt/encrypt")
	}
	return out[:outLen], nil
}

func DecryptRSAOAEP(h, mgfHash hash.Hash, priv *PrivateKeyRSA, ciphertext, label []byte) ([]byte, error) {
	return cryptRSA(priv.withKey, C.GO_RSA_PKCS1_OAEP_PADDING, h, mgfHash, label, 0, 0, decryptInit, decrypt, ciphertext)
}

func EncryptRSAOAEP(h, mgfHash hash.Hash, pub *PublicKeyRSA, msg, label []byte) ([]byte, error) {
	return cryptRSA(pub.withKey, C.GO_RSA_PKCS1_OAEP_PADDING, h, mgfHash, label, 0, 0, encryptInit, encrypt, msg)
}

func DecryptRSAPKCS1(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	return cryptRSA(priv.withKey, C.GO_RSA_PKCS1_PADDING, nil, nil, nil, 0, 0, decryptInit, decrypt, ciphertext)
}

func EncryptRSAPKCS1(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	return cryptRSA(pub.withKey, C.GO_RSA_PKCS1_PADDING, nil, nil, nil, 0, 0, encryptInit, encrypt, msg)
}

func DecryptRSANoPadding(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	return cryptRSA(priv.withKey, C.GO_RSA_NO_PADDING, nil, nil, nil, 0, 0, decryptInit, decrypt, ciphertext)
}

func EncryptRSANoPadding(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	return cryptRSA(pub.withKey, C.GO_RSA_NO_PADDING, nil, nil, nil, 0, 0, encryptInit, encrypt, msg)
}

// These dumb wrappers work around the fact that cgo functions cannot be used as values directly.

func decryptInit(ctx *C.GO_EVP_PKEY_CTX) C.int {
	return C._goboringcrypto_EVP_PKEY_decrypt_init(ctx)
}

func decrypt(ctx *C.GO_EVP_PKEY_CTX, out *C.uint8_t, outLen *C.size_t, in *C.uint8_t, inLen C.size_t) C.int {
	return C._goboringcrypto_EVP_PKEY_decrypt(ctx, out, outLen, in, inLen)
}

func encryptInit(ctx *C.GO_EVP_PKEY_CTX) C.int {
	return C._goboringcrypto_EVP_PKEY_encrypt_init(ctx)
}

func encrypt(ctx *C.GO_EVP_PKEY_CTX, out *C.uint8_t, outLen *C.size_t, in *C.uint8_t, inLen C.size_t) C.int {
	return C._goboringcrypto_EVP_PKEY_encrypt(ctx, out, outLen, in, inLen)
}

var invalidSaltLenErr = errors.New("crypto/rsa: invalid PSS salt length")

func SignRSAPSS(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	md := cryptoHashToMD(h)
	if md == nil {
		return nil, errors.New("crypto/rsa: unsupported hash function")
	}

	// A salt length of -2 is valid in BoringSSL, but not in crypto/rsa, so reject
	// it, and lengths < -2, before we convert to the BoringSSL sentinel values.
	if saltLen <= -2 {
		return nil, invalidSaltLenErr
	}

	// BoringSSL uses sentinel salt length values like we do, but the values don't
	// fully match what we use. We both use -1 for salt length equal to hash length,
	// but BoringSSL uses -2 to mean maximal size where we use 0. In the latter
	// case convert to the BoringSSL version.
	if saltLen == 0 {
		saltLen = -2
	}

	var out []byte
	var outLen C.size_t
	if priv.withKey(func(key *C.GO_RSA) C.int {
		out = make([]byte, C._goboringcrypto_RSA_size(key))
		return C._goboringcrypto_RSA_sign_pss_mgf1(key, &outLen, base(out), C.size_t(len(out)),
			base(hashed), C.size_t(len(hashed)), md, nil, C.int(saltLen))
	}) == 0 {
		return nil, fail("RSA_sign_pss_mgf1")
	}

	return out[:outLen], nil
}

func VerifyRSAPSS(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	md := cryptoHashToMD(h)
	if md == nil {
		return errors.New("crypto/rsa: unsupported hash function")
	}

	// A salt length of -2 is valid in BoringSSL, but not in crypto/rsa, so reject
	// it, and lengths < -2, before we convert to the BoringSSL sentinel values.
	if saltLen <= -2 {
		return invalidSaltLenErr
	}

	// BoringSSL uses sentinel salt length values like we do, but the values don't
	// fully match what we use. We both use -1 for salt length equal to hash length,
	// but BoringSSL uses -2 to mean maximal size where we use 0. In the latter
	// case convert to the BoringSSL version.
	if saltLen == 0 {
		saltLen = -2
	}

	if pub.withKey(func(key *C.GO_RSA) C.int {
		return C._goboringcrypto_RSA_verify_pss_mgf1(key, base(hashed), C.size_t(len(hashed)),
			md, nil, C.int(saltLen), base(sig), C.size_t(len(sig)))
	}) == 0 {
		return fail("RSA_verify_pss_mgf1")
	}
	return nil
}

func SignRSAPKCS1v15(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte) ([]byte, error) {
	if h == 0 {
		// No hashing.
		var out []byte
		var outLen C.size_t
		if priv.withKey(func(key *C.GO_RSA) C.int {
			out = make([]byte, C._goboringcrypto_RSA_size(key))
			return C._goboringcrypto_RSA_sign_raw(key, &outLen, base(out), C.size_t(len(out)),
				base(hashed), C.size_t(len(hashed)), C.GO_RSA_PKCS1_PADDING)
		}) == 0 {
			return nil, fail("RSA_sign_raw")
		}
		return out[:outLen], nil
	}

	md := cryptoHashToMD(h)
	if md == nil {
		return nil, errors.New("crypto/rsa: unsupported hash function: " + strconv.Itoa(int(h)))
	}
	nid := C._goboringcrypto_EVP_MD_type(md)
	var out []byte
	var outLen C.uint
	if priv.withKey(func(key *C.GO_RSA) C.int {
		out = make([]byte, C._goboringcrypto_RSA_size(key))
		return C._goboringcrypto_RSA_sign(nid, base(hashed), C.uint(len(hashed)),
			base(out), &outLen, key)
	}) == 0 {
		return nil, fail("RSA_sign")
	}
	return out[:outLen], nil
}

func VerifyRSAPKCS1v15(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte) error {
	if h == 0 {
		var out []byte
		var outLen C.size_t
		if pub.withKey(func(key *C.GO_RSA) C.int {
			out = make([]byte, C._goboringcrypto_RSA_size(key))
			return C._goboringcrypto_RSA_verify_raw(key, &outLen, base(out),
				C.size_t(len(out)), base(sig), C.size_t(len(sig)), C.GO_RSA_PKCS1_PADDING)
		}) == 0 {
			return fail("RSA_verify")
		}
		if subtle.ConstantTimeCompare(hashed, out[:outLen]) != 1 {
			return fail("RSA_verify")
		}
		return nil
	}
	md := cryptoHashToMD(h)
	if md == nil {
		return errors.New("crypto/rsa: unsupported hash function")
	}
	nid := C._goboringcrypto_EVP_MD_type(md)
	if pub.withKey(func(key *C.GO_RSA) C.int {
		return C._goboringcrypto_RSA_verify(nid, base(hashed), C.size_t(len(hashed)),
			base(sig), C.size_t(len(sig)), key)
	}) == 0 {
		return fail("RSA_verify")
	}
	return nil
}
```