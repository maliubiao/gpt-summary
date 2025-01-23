Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request asks for the functionalities of the provided Go code, specifically focusing on its role within the `crypto/rsa` package. It also asks for explanations, code examples, and potential pitfalls.

2. **Identify the Core Package:** The `package rsa_test` and the numerous imports starting with `crypto/` immediately tell us this code is demonstrating and testing RSA functionalities within the Go standard library. The `_test` suffix suggests it's part of the testing framework.

3. **Analyze Each `Example` Function:** The key to understanding the code lies in the `Example` functions. Each `Example` function typically demonstrates a specific way to use a feature of the package. This becomes the primary unit of analysis.

4. **`ExampleGenerateKey()`:**
   - **Purpose:**  The name suggests it's about generating RSA keys.
   - **Code Flow:** It calls `rsa.GenerateKey`, marshals the private key using `x509.MarshalPKCS8PrivateKey`, and then encodes it into PEM format using `pem.EncodeToMemory`.
   - **Functionality:** Generates an RSA private key and encodes it in PEM format.
   - **Go Feature:** Demonstrates RSA key generation.
   - **Code Example (Elaboration):**  To illustrate, I need to show how to *use* this generated key (although the example itself only generates it). This leads to the idea of showing how to save it to a file. This is a practical follow-up.

5. **`ExampleGenerateKey_testKey()`:**
   - **Purpose:** The name suggests it's about a *test* key. The comments explicitly mention its insecurity and suitability for testing.
   - **Code Flow:** It decodes a PEM-encoded string containing a pre-defined RSA private key and parses it.
   - **Functionality:** Demonstrates loading a known, insecure RSA key for testing purposes.
   - **Go Feature:** Shows how to parse an existing RSA private key from PEM format.
   - **Code Example (Elaboration):**  No real elaboration needed as it's primarily for demonstrating loading.

6. **`ExampleDecryptPKCS1v15SessionKey()`:**
   - **Purpose:** Focuses on decrypting a session key encrypted with RSA using PKCS#1 v1.5 padding. The comments highlight the importance of constant-time operations to prevent information leaks.
   - **Code Flow:** It initializes a random "key" buffer, attempts to decrypt using `rsa.DecryptPKCS1v15SessionKey`, and then uses the potentially decrypted key with AES-GCM. It handles potential decryption failures gracefully.
   - **Functionality:** Demonstrates the decryption of a session key using RSA with PKCS#1 v1.5 padding, emphasizing constant-time operations.
   - **Go Feature:** Illustrates `rsa.DecryptPKCS1v15SessionKey` and the hybrid encryption approach.
   - **Code Example (Elaboration):**  To make it more concrete, I need to provide a working example with actual encryption and decryption steps, involving the key generation and encryption of the session key first. This requires defining `rsaPrivateKey` and `rsaCiphertext`.

7. **`ExampleSignPKCS1v15()`:**
   - **Purpose:** Demonstrates signing a message using RSA with PKCS#1 v1.5 padding.
   - **Code Flow:**  Hashes the message using SHA256 and then calls `rsa.SignPKCS1v15`.
   - **Functionality:** Shows how to sign data using RSA with PKCS#1 v1.5 padding.
   - **Go Feature:** Demonstrates the `rsa.SignPKCS1v15` function.
   - **Code Example (Elaboration):** No significant elaboration needed, the example is quite clear.

8. **`ExampleVerifyPKCS1v15()`:**
   - **Purpose:** Shows how to verify a signature created using `SignPKCS1v15`.
   - **Code Flow:**  Hashes the same message and calls `rsa.VerifyPKCS1v15`.
   - **Functionality:** Demonstrates the verification of an RSA signature with PKCS#1 v1.5 padding.
   - **Go Feature:** Illustrates the `rsa.VerifyPKCS1v15` function.
   - **Code Example (Elaboration):**  No significant elaboration needed.

9. **`ExampleEncryptOAEP()`:**
   - **Purpose:** Demonstrates encryption using RSA with OAEP padding.
   - **Code Flow:** Calls `rsa.EncryptOAEP` with a label.
   - **Functionality:** Shows how to encrypt data using RSA with OAEP padding.
   - **Go Feature:** Demonstrates the `rsa.EncryptOAEP` function.
   - **Code Example (Elaboration):**  No significant elaboration needed.

10. **`ExampleDecryptOAEP()`:**
    - **Purpose:** Shows how to decrypt data encrypted with `EncryptOAEP`.
    - **Code Flow:** Calls `rsa.DecryptOAEP` with the same label.
    - **Functionality:** Demonstrates the decryption of data encrypted using RSA with OAEP padding.
    - **Go Feature:** Illustrates the `rsa.DecryptOAEP` function.
    - **Code Example (Elaboration):** No significant elaboration needed.

11. **Identify Common Themes and Potential Pitfalls:**  After analyzing each example, look for recurring themes and common mistakes. The examples themselves often highlight potential issues (like the warning about disclosing decryption success in `DecryptPKCS1v15SessionKey`). Other potential issues might include:
    - **Key Size:** Choosing an appropriate key size.
    - **Padding Schemes:** Understanding the differences and security implications of different padding schemes (PKCS#1 v1.5 vs. OAEP).
    - **Error Handling:** The importance of checking errors.
    - **Storing Private Keys Securely:** Although not explicitly in the examples, it's a crucial practical consideration.

12. **Structure the Answer:** Organize the findings logically. Start with a summary of the overall functionality, then detail each `Example` function, provide code illustrations, and finally, discuss potential pitfalls. Use clear headings and formatting for readability. Use the original `Example` function names to directly link the explanation to the code.

13. **Refine and Review:**  Read through the generated answer, checking for clarity, accuracy, and completeness. Ensure that the code examples are runnable and demonstrate the intended functionality. Make sure the language is precise and avoids jargon where possible, or explains it when necessary. For instance, clarifying what "hybrid encryption" means.这段代码是Go语言标准库 `crypto/rsa` 包的示例代码，用于演示如何使用RSA算法进行密钥生成、加密、解密和签名验签等操作。

**主要功能列举:**

1. **`ExampleGenerateKey()`:** 演示如何生成一个新的RSA私钥和公钥对。生成的私钥会被编码成PEM格式并打印到标准输出。
2. **`ExampleGenerateKey_testKey()`:**  演示如何加载一个预先定义好的、**不安全**的测试用RSA私钥。这个私钥来自 RFC 9500，专门用于测试，**不应该在生产环境中使用**。
3. **`ExampleDecryptPKCS1v15SessionKey()`:** 演示如何使用RSA的PKCS#1 v1.5填充方案来解密一个会话密钥（例如，用于对称加密的AES密钥）。这个例子强调了在解密过程中，即使解密失败，也应该以恒定时间操作，避免泄漏任何关于密钥的信息。
4. **`ExampleSignPKCS1v15()`:** 演示如何使用RSA的PKCS#1 v1.5填充方案来对消息的哈希值进行签名。
5. **`ExampleVerifyPKCS1v15()`:** 演示如何使用RSA公钥来验证使用PKCS#1 v1.5填充方案生成的签名。
6. **`ExampleEncryptOAEP()`:** 演示如何使用RSA的OAEP（Optimal Asymmetric Encryption Padding）填充方案来加密数据。
7. **`ExampleDecryptOAEP()`:** 演示如何使用RSA私钥来解密使用OAEP填充方案加密的数据。

**它是什么Go语言功能的实现？**

这段代码主要演示了 `crypto/rsa` 包提供的以下核心功能：

* **密钥生成:** `rsa.GenerateKey()` 用于生成新的RSA密钥对。
* **密钥的编解码:** `x509.MarshalPKCS8PrivateKey()` 和 `pem.EncodeToMemory()` 用于将私钥编码成PEM格式；`pem.Decode()` 和 `x509.ParsePKCS1PrivateKey()` 用于从PEM格式解码私钥。
* **使用 PKCS#1 v1.5 进行加密/解密:** `rsa.DecryptPKCS1v15SessionKey()` 用于解密会话密钥。注意，这里没有直接的 `EncryptPKCS1v15` 的示例，因为 PKCS#1 v1.5 加密存在安全风险，通常不推荐直接使用。
* **使用 PKCS#1 v1.5 进行签名/验签:** `rsa.SignPKCS1v15()` 用于签名，`rsa.VerifyPKCS1v15()` 用于验签。
* **使用 OAEP 进行加密/解密:** `rsa.EncryptOAEP()` 用于加密，`rsa.DecryptOAEP()` 用于解密。OAEP 是一种更安全的填充方案。

**Go代码举例说明:**

**1. 密钥生成和保存：**

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	// 生成 RSA 私钥，密钥长度为 2048 位
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("生成密钥失败:", err)
		return
	}

	// 将私钥编码为 PKCS#8 DER 格式
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		fmt.Println("编码私钥失败:", err)
		return
	}

	// 将 DER 格式的私钥编码为 PEM 格式
	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	}
	privateKeyPEM := pem.EncodeToMemory(privateKeyBlock)

	// 将 PEM 格式的私钥保存到文件
	err = os.WriteFile("private.pem", privateKeyPEM, 0600)
	if err != nil {
		fmt.Println("保存私钥失败:", err)
		return
	}

	fmt.Println("私钥已保存到 private.pem")

	// 获取公钥
	publicKey := &privateKey.PublicKey

	// 将公钥编码为 SubjectPublicKeyInfo DER 格式
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		fmt.Println("编码公钥失败:", err)
		return
	}

	// 将 DER 格式的公钥编码为 PEM 格式
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}
	publicKeyPEM := pem.EncodeToMemory(publicKeyBlock)

	// 将 PEM 格式的公钥保存到文件
	err = os.WriteFile("public.pem", publicKeyPEM, 0644)
	if err != nil {
		fmt.Println("保存公钥失败:", err)
		return
	}

	fmt.Println("公钥已保存到 public.pem")
}
```

**假设输入与输出：**

运行上述代码后，会在当前目录下生成 `private.pem` 和 `public.pem` 两个文件，分别包含生成的 RSA 私钥和公钥的 PEM 编码。输出到控制台的信息如下：

```
私钥已保存到 private.pem
公钥已保存到 public.pem
```

**2. 使用 OAEP 进行加密和解密：**

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"os"
)

func main() {
	// 假设我们已经有了私钥 (从文件加载或者通过其他方式获取)
	// 这里为了演示，我们简单创建一个临时的私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("生成密钥失败:", err)
		return
	}
	publicKey := &privateKey.PublicKey

	plaintext := []byte("这是一段需要加密的消息")
	label := []byte("my-label") // 可选的标签

	// 加密
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, label)
	if err != nil {
		fmt.Println("加密失败:", err)
		return
	}

	fmt.Printf("加密后的数据 (Hex): %x\n", ciphertext)

	// 解密
	decryptedPlaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, label)
	if err != nil {
		fmt.Println("解密失败:", err)
		return
	}

	fmt.Printf("解密后的数据: %s\n", decryptedPlaintext)
}
```

**假设输入与输出：**

运行上述代码，输出类似以下内容：

```
加密后的数据 (Hex): <一串很长的十六进制字符串>
解密后的数据: 这是一段需要加密的消息
```

加密后的数据每次运行都会不同，因为 RSA 的加密过程是随机的。

**命令行参数的具体处理:**

这段示例代码本身并没有直接处理命令行参数。它主要通过 Go 语言的标准库函数来实现 RSA 的各种功能。如果需要在实际应用中处理命令行参数，可以使用 `flag` 包或者第三方库如 `spf13/cobra` 等。

例如，可以使用 `flag` 包来接收用户提供的公钥或私钥文件路径：

```go
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
)

func main() {
	publicKeyFile := flag.String("pubkey", "", "公钥文件路径")
	flag.Parse()

	if *publicKeyFile == "" {
		fmt.Println("请提供公钥文件路径")
		return
	}

	pubKeyBytes, err := os.ReadFile(*publicKeyFile)
	if err != nil {
		fmt.Println("读取公钥文件失败:", err)
		return
	}

	block, _ := pem.Decode(pubKeyBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		fmt.Println("无法解析公钥")
		return
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Println("解析公钥失败:", err)
		return
	}

	rsaPubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		fmt.Println("不是 RSA 公钥")
		return
	}

	fmt.Println("成功加载 RSA 公钥，模数为:", rsaPubKey.N)
}
```

运行方式：

```bash
go run your_program.go -pubkey public.pem
```

**使用者易犯错的点:**

1. **使用 `ExampleGenerateKey_testKey()` 中的测试密钥用于生产环境。**  这是一个非常严重的安全漏洞，因为该密钥是公开的。
2. **直接使用 `rsa.Encrypt` (或者 `EncryptPKCS1v15`) 加密大量数据。**  RSA 算法本身设计为加密少量数据，通常用于加密对称密钥。对于大量数据，应该使用混合加密方案，即使用 RSA 加密对称密钥，然后使用对称加密算法（如 AES）加密实际数据。
3. **对解密结果的成功与否进行分支操作时，没有注意恒定时间操作的要求（特别是在使用 `DecryptPKCS1v15SessionKey` 时）。** 如果根据解密是否成功来执行不同的逻辑，攻击者可以通过计时攻击来推断出密钥信息。`DecryptPKCS1v15SessionKey` 通过将解密后的密钥复制到一个预先存在的、随机填充的缓冲区中来缓解这个问题。
4. **不理解不同填充方案（PKCS#1 v1.5 和 OAEP）的区别和适用场景。** OAEP 通常被认为是更安全的填充方案，应该优先使用。PKCS#1 v1.5 在新协议中应谨慎使用。
5. **私钥的存储和管理不当。** 私钥应该被安全地存储和保护，避免泄露。
6. **忘记对消息进行哈希后再进行签名 (在使用 `SignPKCS1v15` 等签名函数时)。** RSA 签名通常是对消息的哈希值进行的，而不是直接对消息本身进行签名。
7. **在解密或验签时使用错误的公钥或私钥。** 这会导致解密失败或验签失败。
8. **在 OAEP 加密和解密时使用不同的 `label`。** `label` 必须在加密和解密时保持一致。

希望以上解释能够帮助你理解这段 Go 代码的功能。

### 提示词
```
这是路径为go/src/crypto/rsa/example_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsa_test

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

func ExampleGenerateKey() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating RSA key: %s", err)
		return
	}

	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling RSA private key: %s", err)
		return
	}

	fmt.Printf("%s", pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}))
}

func ExampleGenerateKey_testKey() {
	// This is an insecure, test-only key from RFC 9500, Section 2.1.
	// It can be used in tests to avoid slow key generation.
	block, _ := pem.Decode([]byte(strings.ReplaceAll(
		`-----BEGIN RSA TESTING KEY-----
MIIEowIBAAKCAQEAsPnoGUOnrpiSqt4XynxA+HRP7S+BSObI6qJ7fQAVSPtRkqso
tWxQYLEYzNEx5ZSHTGypibVsJylvCfuToDTfMul8b/CZjP2Ob0LdpYrNH6l5hvFE
89FU1nZQF15oVLOpUgA7wGiHuEVawrGfey92UE68mOyUVXGweJIVDdxqdMoPvNNU
l86BU02vlBiESxOuox+dWmuVV7vfYZ79Toh/LUK43YvJh+rhv4nKuF7iHjVjBd9s
B6iDjj70HFldzOQ9r8SRI+9NirupPTkF5AKNe6kUhKJ1luB7S27ZkvB3tSTT3P59
3VVJvnzOjaA1z6Cz+4+eRvcysqhrRgFlwI9TEwIDAQABAoIBAEEYiyDP29vCzx/+
dS3LqnI5BjUuJhXUnc6AWX/PCgVAO+8A+gZRgvct7PtZb0sM6P9ZcLrweomlGezI
FrL0/6xQaa8bBr/ve/a8155OgcjFo6fZEw3Dz7ra5fbSiPmu4/b/kvrg+Br1l77J
aun6uUAs1f5B9wW+vbR7tzbT/mxaUeDiBzKpe15GwcvbJtdIVMa2YErtRjc1/5B2
BGVXyvlJv0SIlcIEMsHgnAFOp1ZgQ08aDzvilLq8XVMOahAhP1O2A3X8hKdXPyrx
IVWE9bS9ptTo+eF6eNl+d7htpKGEZHUxinoQpWEBTv+iOoHsVunkEJ3vjLP3lyI/
fY0NQ1ECgYEA3RBXAjgvIys2gfU3keImF8e/TprLge1I2vbWmV2j6rZCg5r/AS0u
pii5CvJ5/T5vfJPNgPBy8B/yRDs+6PJO1GmnlhOkG9JAIPkv0RBZvR0PMBtbp6nT
Y3yo1lwamBVBfY6rc0sLTzosZh2aGoLzrHNMQFMGaauORzBFpY5lU50CgYEAzPHl
u5DI6Xgep1vr8QvCUuEesCOgJg8Yh1UqVoY/SmQh6MYAv1I9bLGwrb3WW/7kqIoD
fj0aQV5buVZI2loMomtU9KY5SFIsPV+JuUpy7/+VE01ZQM5FdY8wiYCQiVZYju9X
Wz5LxMNoz+gT7pwlLCsC4N+R8aoBk404aF1gum8CgYAJ7VTq7Zj4TFV7Soa/T1eE
k9y8a+kdoYk3BASpCHJ29M5R2KEA7YV9wrBklHTz8VzSTFTbKHEQ5W5csAhoL5Fo
qoHzFFi3Qx7MHESQb9qHyolHEMNx6QdsHUn7rlEnaTTyrXh3ifQtD6C0yTmFXUIS
CW9wKApOrnyKJ9nI0HcuZQKBgQCMtoV6e9VGX4AEfpuHvAAnMYQFgeBiYTkBKltQ
XwozhH63uMMomUmtSG87Sz1TmrXadjAhy8gsG6I0pWaN7QgBuFnzQ/HOkwTm+qKw
AsrZt4zeXNwsH7QXHEJCFnCmqw9QzEoZTrNtHJHpNboBuVnYcoueZEJrP8OnUG3r
UjmopwKBgAqB2KYYMUqAOvYcBnEfLDmyZv9BTVNHbR2lKkMYqv5LlvDaBxVfilE0
2riO4p6BaAdvzXjKeRrGNEKoHNBpOSfYCOM16NjL8hIZB1CaV3WbT5oY+jp7Mzd5
7d56RZOE+ERK2uz/7JX9VSsM/LbH9pJibd4e8mikDS9ntciqOH/3
-----END RSA TESTING KEY-----`, "TESTING KEY", "PRIVATE KEY")))
	testRSA2048, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	fmt.Println("Private key bit size:", testRSA2048.N.BitLen())
}

// RSA is able to encrypt only a very limited amount of data. In order
// to encrypt reasonable amounts of data a hybrid scheme is commonly
// used: RSA is used to encrypt a key for a symmetric primitive like
// AES-GCM.
//
// Before encrypting, data is “padded” by embedding it in a known
// structure. This is done for a number of reasons, but the most
// obvious is to ensure that the value is large enough that the
// exponentiation is larger than the modulus. (Otherwise it could be
// decrypted with a square-root.)
//
// In these designs, when using PKCS #1 v1.5, it's vitally important to
// avoid disclosing whether the received RSA message was well-formed
// (that is, whether the result of decrypting is a correctly padded
// message) because this leaks secret information.
// DecryptPKCS1v15SessionKey is designed for this situation and copies
// the decrypted, symmetric key (if well-formed) in constant-time over
// a buffer that contains a random key. Thus, if the RSA result isn't
// well-formed, the implementation uses a random key in constant time.
func ExampleDecryptPKCS1v15SessionKey() {
	// The hybrid scheme should use at least a 16-byte symmetric key. Here
	// we read the random key that will be used if the RSA decryption isn't
	// well-formed.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("RNG failure")
	}

	rsaCiphertext, _ := hex.DecodeString("aabbccddeeff")

	if err := rsa.DecryptPKCS1v15SessionKey(nil, rsaPrivateKey, rsaCiphertext, key); err != nil {
		// Any errors that result will be “public” – meaning that they
		// can be determined without any secret information. (For
		// instance, if the length of key is impossible given the RSA
		// public key.)
		fmt.Fprintf(os.Stderr, "Error from RSA decryption: %s\n", err)
		return
	}

	// Given the resulting key, a symmetric scheme can be used to decrypt a
	// larger ciphertext.
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("aes.NewCipher failed: " + err.Error())
	}

	// Since the key is random, using a fixed nonce is acceptable as the
	// (key, nonce) pair will still be unique, as required.
	var zeroNonce [12]byte
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic("cipher.NewGCM failed: " + err.Error())
	}
	ciphertext, _ := hex.DecodeString("00112233445566")
	plaintext, err := aead.Open(nil, zeroNonce[:], ciphertext, nil)
	if err != nil {
		// The RSA ciphertext was badly formed; the decryption will
		// fail here because the AES-GCM key will be incorrect.
		fmt.Fprintf(os.Stderr, "Error decrypting: %s\n", err)
		return
	}

	fmt.Printf("Plaintext: %s\n", plaintext)
}

func ExampleSignPKCS1v15() {
	message := []byte("message to be signed")

	// Only small messages can be signed directly; thus the hash of a
	// message, rather than the message itself, is signed. This requires
	// that the hash function be collision resistant. SHA-256 is the
	// least-strong hash function that should be used for this at the time
	// of writing (2016).
	hashed := sha256.Sum256(message)

	signature, err := rsa.SignPKCS1v15(nil, rsaPrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		return
	}

	fmt.Printf("Signature: %x\n", signature)
}

func ExampleVerifyPKCS1v15() {
	message := []byte("message to be signed")
	signature, _ := hex.DecodeString("ad2766728615cc7a746cc553916380ca7bfa4f8983b990913bc69eb0556539a350ff0f8fe65ddfd3ebe91fe1c299c2fac135bc8c61e26be44ee259f2f80c1530")

	// Only small messages can be signed directly; thus the hash of a
	// message, rather than the message itself, is signed. This requires
	// that the hash function be collision resistant. SHA-256 is the
	// least-strong hash function that should be used for this at the time
	// of writing (2016).
	hashed := sha256.Sum256(message)

	err := rsa.VerifyPKCS1v15(&rsaPrivateKey.PublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from verification: %s\n", err)
		return
	}

	// signature is a valid signature of message from the public key.
}

func ExampleEncryptOAEP() {
	secretMessage := []byte("send reinforcements, we're going to advance")
	label := []byte("orders")

	// crypto/rand.Reader is a good source of entropy for randomizing the
	// encryption function.
	rng := rand.Reader

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &test2048Key.PublicKey, secretMessage, label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
		return
	}

	// Since encryption is a randomized function, ciphertext will be
	// different each time.
	fmt.Printf("Ciphertext: %x\n", ciphertext)
}

func ExampleDecryptOAEP() {
	ciphertext, _ := hex.DecodeString("4d1ee10e8f286390258c51a5e80802844c3e6358ad6690b7285218a7c7ed7fc3a4c7b950fbd04d4b0239cc060dcc7065ca6f84c1756deb71ca5685cadbb82be025e16449b905c568a19c088a1abfad54bf7ecc67a7df39943ec511091a34c0f2348d04e058fcff4d55644de3cd1d580791d4524b92f3e91695582e6e340a1c50b6c6d78e80b4e42c5b4d45e479b492de42bbd39cc642ebb80226bb5200020d501b24a37bcc2ec7f34e596b4fd6b063de4858dbf5a4e3dd18e262eda0ec2d19dbd8e890d672b63d368768360b20c0b6b8592a438fa275e5fa7f60bef0dd39673fd3989cc54d2cb80c08fcd19dacbc265ee1c6014616b0e04ea0328c2a04e73460")
	label := []byte("orders")

	plaintext, err := rsa.DecryptOAEP(sha256.New(), nil, test2048Key, ciphertext, label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from decryption: %s\n", err)
		return
	}

	fmt.Printf("Plaintext: %s\n", plaintext)

	// Remember that encryption only provides confidentiality. The
	// ciphertext should be signed before authenticity is assumed and, even
	// then, consider that messages might be reordered.
}
```