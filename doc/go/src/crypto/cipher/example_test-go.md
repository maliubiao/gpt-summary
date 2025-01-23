Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Understanding the Goal:**

The request asks for the *functionality* of the given Go code. Specifically, it asks for:

* A general description of what the code does.
* Identifying the Go language features it demonstrates.
* Providing code examples (with input/output if applicable).
* Explaining command-line arguments (not applicable here).
* Highlighting potential pitfalls for users.

**2. Initial Scan and Keyword Spotting:**

The first step is a quick skim of the code, looking for keywords and recognizable patterns. Keywords like `import`, `func`, `Example`, `aes`, `cipher`, `NewGCM`, `NewCBCDecrypter`, `NewCBCEncrypter`, `NewCFBDecrypter`, `NewCFBEncrypter`, `NewCTR`, `NewOFB`, `StreamReader`, `StreamWriter`, `encrypt`, `decrypt`, `Seal`, `Open`, `XORKeyStream`, `CryptBlocks` immediately suggest that this code deals with cryptography, specifically encryption and decryption using various cipher modes. The `Example` prefix in function names indicates these are example functions intended for documentation.

**3. Analyzing Each `Example` Function Individually:**

The code is well-structured with separate `Example` functions for different cryptographic operations. This makes it easier to analyze. For each `Example` function, the process is similar:

* **Identify the Core Functionality:** Look at the function name and the main `cipher` package functions being called (e.g., `cipher.NewGCM`, `cipher.NewCBCDecrypter`). This tells you the primary cryptographic operation being demonstrated.
* **Trace the Data Flow:**  Follow the variables. Where does the key come from? Where does the plaintext/ciphertext come from? How is the nonce/IV generated or handled? What are the inputs to the `cipher` functions? What is the output?
* **Look for Standard Practices:** Observe common cryptographic patterns, like the use of `rand.Reader` for nonce/IV generation, the importance of key management (the comments about not using the example key in real-world scenarios), and the handling of potential errors.
* **Understand the Cipher Mode:** If you're familiar with different cipher modes (GCM, CBC, CFB, CTR, OFB), try to connect the code to the properties of that mode. For example, noticing the nonce in GCM, the IV in CBC, and how stream ciphers like CFB, CTR, and OFB use `XORKeyStream`.
* **Infer Input/Output:**  For examples demonstrating encryption, deduce the expected output format (hexadecimal). For decryption, look for the expected plaintext output. The `// Output:` comments are very helpful here.
* **Identify Key Information in Comments:** The comments within the code provide crucial context, explaining the purpose of certain steps, security considerations (like the need for authentication), and the properties of the cipher modes.

**4. Synthesizing the Findings:**

After analyzing each example, group the findings to answer the request's questions:

* **Overall Functionality:**  Summarize that the code demonstrates various ways to encrypt and decrypt data using Go's `crypto/cipher` package.
* **Go Language Features:**  List the prominent Go features used: imports, functions, example functions, working with byte slices, error handling, hexadecimal encoding/decoding, random number generation, and the `io` package for reading/writing.
* **Code Examples:** The provided `Example` functions themselves serve as great code examples. No need to create new ones in most cases, but you might want to pull out specific snippets to highlight a particular feature.
* **Reasoning and Assumptions:** When explaining a specific example (like GCM), state your assumptions about the input (key, plaintext/ciphertext, nonce).
* **Command-Line Arguments:**  Explicitly state that no command-line arguments are involved.
* **Common Mistakes:** Based on the code and your understanding of cryptography, identify potential pitfalls: reusing nonces with GCM, not authenticating ciphertexts (especially with CBC and stream ciphers), and incorrect IV handling.

**5. Structuring the Answer:**

Organize the information clearly using the requested headings: 功能, Go语言功能的实现, 代码举例, 代码推理, 命令行参数, 使用者易犯错的点. Use clear and concise language, explaining technical terms where necessary.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This is just about encryption."  **Correction:** Realize it covers both encryption and decryption and demonstrates different cipher modes.
* **Initial thought:** "Just list the functions." **Correction:**  Explain *what* each function does and *how* it uses the `cipher` package.
* **Initial thought:** "Do I need to run the code?" **Correction:** While running the code could be helpful for confirming outputs, the provided `// Output:` comments are sufficient for this task. Focus on understanding the code logic.
* **Initial thought:**  "Should I explain all the nuances of each cipher mode?" **Correction:** Focus on the *demonstration* in the code, not a comprehensive cryptographic explanation. Mention key properties relevant to the example.

By following these steps, the detailed and accurate answer provided previously can be generated. The key is to systematically break down the code, understand its purpose, and connect it to the concepts it illustrates.
这段Go语言代码文件 `example_test.go` 位于 `go/src/crypto/cipher` 目录下，其主要功能是**展示 `crypto/cipher` 包中各种加密模式的用法示例**。 它通过一系列的 `Example` 函数，演示了如何使用不同的加密算法和模式进行加密和解密操作。

具体来说，它实现了以下功能：

1. **展示了 Galois/Counter Mode (GCM) 的加密和解密:**
   - 使用 `cipher.NewGCM` 创建 GCM cipher。
   - 使用 `aesgcm.Seal` 进行加密。
   - 使用 `aesgcm.Open` 进行解密。
   - **代码推理：** GCM 是一种认证加密模式，它提供了机密性、完整性和身份验证。加密过程需要一个密钥和一个随机 nonce（仅使用一次的数字）。
     ```go
     // 假设输入密钥 key, 待加密的明文 plaintext
     key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
     plaintext := []byte("exampleplaintext")

     block, _ := aes.NewCipher(key)
     aesgcm, _ := cipher.NewGCM(block)
     nonce := make([]byte, 12)
     io.ReadFull(rand.Reader, nonce) // 生成随机 nonce
     ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
     fmt.Printf("%x\n", ciphertext) // 输出加密后的密文 (十六进制)

     // 假设输入密钥 key, 密文 ciphertext, 以及加密时使用的 nonce
     ciphertext, _ := hex.DecodeString("c3aaa29f002ca75870806e44086700f62ce4d43e902b3888e23ceff797a7a471")
     nonce, _ := hex.DecodeString("64a9433eae7ccceee2fc0eda")
     block, _ := aes.NewCipher(key)
     aesgcm, _ := cipher.NewGCM(block)
     decryptedPlaintext, _ := aesgcm.Open(nil, nonce, ciphertext, nil)
     fmt.Printf("%s\n", decryptedPlaintext) // 输出解密后的明文： exampleplaintext
     ```
   - **假设输入：** 一个 32 字节的十六进制密钥字符串，以及字符串 "exampleplaintext"。
   - **输出：** 加密后密文的十六进制字符串，以及解密后的原始字符串 "exampleplaintext"。

2. **展示了 Cipher Block Chaining (CBC) 模式的加密和解密:**
   - 使用 `cipher.NewCBCEncrypter` 创建 CBC 加密器。
   - 使用 `cipher.NewCBCDecrypter` 创建 CBC 解密器。
   - 使用 `mode.CryptBlocks` 执行块加密/解密。
   - **代码推理：** CBC 模式需要一个初始化向量 (IV)，并且加密和解密都以块为单位进行。IV 必须是随机的且对于每次加密都是唯一的，但不要求保密。通常 IV 会附加在密文的开头。
     ```go
     // CBC 加密示例
     key, _ := hex.DecodeString("6368616e676520746869732070617373")
     plaintext := []byte("exampleplaintext")
     block, _ := aes.NewCipher(key)
     ciphertext := make([]byte, aes.BlockSize+len(plaintext))
     iv := ciphertext[:aes.BlockSize]
     io.ReadFull(rand.Reader, iv)
     mode := cipher.NewCBCEncrypter(block, iv)
     mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
     fmt.Printf("%x\n", ciphertext) // 输出加密后的密文 (包含 IV)

     // CBC 解密示例
     ciphertextWithIV, _ := hex.DecodeString("73c86d43a9d700a253a96c85b0f6b03ac9792e0e757f869cca306bd3cba1c62b")
     key, _ := hex.DecodeString("6368616e676520746869732070617373")
     block, _ := aes.NewCipher(key)
     iv := ciphertextWithIV[:aes.BlockSize]
     ciphertext := ciphertextWithIV[aes.BlockSize:]
     mode := cipher.NewCBCDecrypter(block, iv)
     mode.CryptBlocks(ciphertext, ciphertext) // 原地解密
     fmt.Printf("%s\n", ciphertext)        // 输出解密后的明文： exampleplaintext
     ```
   - **假设输入（加密）：** 一个 16 字节的十六进制密钥字符串，以及字符串 "exampleplaintext"。
   - **输出（加密）：** 加密后密文的十六进制字符串，包含随机生成的 IV。
   - **假设输入（解密）：** 一个 16 字节的十六进制密钥字符串，以及一个包含 IV 的十六进制密文字符串。
   - **输出（解密）：** 解密后的原始字符串 "exampleplaintext"。

3. **展示了 Cipher Feedback (CFB) 模式的加密和解密:**
   - 使用 `cipher.NewCFBEncrypter` 创建 CFB 加密器。
   - 使用 `cipher.NewCFBDecrypter` 创建 CFB 解密器。
   - 使用 `stream.XORKeyStream` 执行流加密/解密。
   - **代码推理：** CFB 是一种流密码模式，它将块密码转换为流密码。它也需要一个 IV。
     ```go
     // CFB 加密示例
     key, _ := hex.DecodeString("6368616e676520746869732070617373")
     plaintext := []byte("some plaintext")
     block, _ := aes.NewCipher(key)
     ciphertext := make([]byte, aes.BlockSize+len(plaintext))
     iv := ciphertext[:aes.BlockSize]
     io.ReadFull(rand.Reader, iv)
     stream := cipher.NewCFBEncrypter(block, iv)
     stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
     fmt.Printf("%x\n", ciphertext)

     // CFB 解密示例
     ciphertextWithIV, _ := hex.DecodeString("7dd015f06bec7f1b8f6559dad89f4131da62261786845100056b353194ad")
     key, _ := hex.DecodeString("6368616e676520746869732070617373")
     block, _ := aes.NewCipher(key)
     iv := ciphertextWithIV[:aes.BlockSize]
     ciphertext := ciphertextWithIV[aes.BlockSize:]
     stream := cipher.NewCFBDecrypter(block, iv)
     stream.XORKeyStream(ciphertext, ciphertext)
     fmt.Printf("%s", ciphertext) // 输出： some plaintext
     ```
   - **假设输入（加密）：** 一个 16 字节的十六进制密钥字符串，以及字符串 "some plaintext"。
   - **输出（加密）：** 加密后密文的十六进制字符串，包含随机生成的 IV。
   - **假设输入（解密）：** 一个 16 字节的十六进制密钥字符串，以及一个包含 IV 的十六进制密文字符串。
   - **输出（解密）：** 解密后的原始字符串 "some plaintext"。

4. **展示了 Counter (CTR) 模式的加密和解密:**
   - 使用 `cipher.NewCTR` 创建 CTR 流密码。
   - 使用 `stream.XORKeyStream` 执行加密和解密（CTR 模式的加密和解密操作相同）。
   - **代码推理：** CTR 模式也是一种流密码模式，它将块密码转换为流密码。它使用一个计数器来生成密钥流，因此也需要一个唯一的 IV（通常被称为 nonce）。
     ```go
     // CTR 加密和解密示例
     key, _ := hex.DecodeString("6368616e676520746869732070617373")
     plaintext := []byte("some plaintext")
     block, _ := aes.NewCipher(key)
     ciphertext := make([]byte, aes.BlockSize+len(plaintext))
     iv := ciphertext[:aes.BlockSize]
     io.ReadFull(rand.Reader, iv)
     stream := cipher.NewCTR(block, iv)
     stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
     fmt.Printf("%x\n", ciphertext)

     plaintext2 := make([]byte, len(plaintext))
     stream = cipher.NewCTR(block, iv) // 使用相同的密钥和 IV 进行解密
     stream.XORKeyStream(plaintext2, ciphertext[aes.BlockSize:])
     fmt.Printf("%s\n", plaintext2) // 输出： some plaintext
     ```
   - **假设输入：** 一个 16 字节的十六进制密钥字符串，以及字符串 "some plaintext"。
   - **输出：** 加密后密文的十六进制字符串，包含随机生成的 IV，以及解密后的原始字符串 "some plaintext"。

5. **展示了 Output Feedback (OFB) 模式的加密和解密:**
   - 使用 `cipher.NewOFB` 创建 OFB 流密码。
   - 使用 `stream.XORKeyStream` 执行加密和解密（OFB 模式的加密和解密操作相同）。
   - **代码推理：** OFB 模式是另一种将块密码转换为流密码的模式。它通过将前一个加密块的输出反馈到加密器来生成密钥流，也需要一个 IV。
     ```go
     // OFB 加密和解密示例
     key, _ := hex.DecodeString("6368616e676520746869732070617373")
     plaintext := []byte("some plaintext")
     block, _ := aes.NewCipher(key)
     ciphertext := make([]byte, aes.BlockSize+len(plaintext))
     iv := ciphertext[:aes.BlockSize]
     io.ReadFull(rand.Reader, iv)
     stream := cipher.NewOFB(block, iv)
     stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
     fmt.Printf("%x\n", ciphertext)

     plaintext2 := make([]byte, len(plaintext))
     stream = cipher.NewOFB(block, iv) // 使用相同的密钥和 IV 进行解密
     stream.XORKeyStream(plaintext2, ciphertext[aes.BlockSize:])
     fmt.Printf("%s\n", plaintext2) // 输出： some plaintext
     ```
   - **假设输入：** 一个 16 字节的十六进制密钥字符串，以及字符串 "some plaintext"。
   - **输出：** 加密后密文的十六进制字符串，包含随机生成的 IV，以及解密后的原始字符串 "some plaintext"。

6. **展示了 `cipher.StreamReader` 的用法:**
   - 将一个 `io.Reader` 包装成 `cipher.StreamReader`，用于读取加密数据并进行解密。
   - **代码推理：** `StreamReader` 允许逐字节或逐块地解密数据流。
     ```go
     key, _ := hex.DecodeString("6368616e676520746869732070617373")
     encrypted, _ := hex.DecodeString("cf0495cc6f75dafc23948538e79904a9")
     bReader := bytes.NewReader(encrypted)
     block, _ := aes.NewCipher(key)
     var iv [aes.BlockSize]byte // 使用零 IV
     stream := cipher.NewOFB(block, iv[:])
     reader := &cipher.StreamReader{S: stream, R: bReader}
     io.Copy(os.Stdout, reader) // 将解密后的内容输出到标准输出
     // 输出: some secret text
     ```
   - **假设输入：** 一个 16 字节的十六进制密钥字符串，以及一个十六进制加密字符串。
   - **输出：** 解密后的字符串 "some secret text" 输出到标准输出。

7. **展示了 `cipher.StreamWriter` 的用法:**
   - 将一个 `io.Writer` 包装成 `cipher.StreamWriter`，用于写入数据并进行加密。
   - **代码推理：** `StreamWriter` 允许逐字节或逐块地加密数据流。
     ```go
     key, _ := hex.DecodeString("6368616e6e676520746869732070617373")
     bReader := bytes.NewReader([]byte("some secret text"))
     block, _ := aes.NewCipher(key)
     var iv [aes.BlockSize]byte // 使用零 IV
     stream := cipher.NewOFB(block, iv[:])
     var out bytes.Buffer
     writer := &cipher.StreamWriter{S: stream, W: &out}
     io.Copy(writer, bReader)
     fmt.Printf("%x\n", out.Bytes()) // 输出加密后的密文
     // 输出: cf0495cc6f75dafc23948538e79904a9
     ```
   - **假设输入：** 一个 16 字节的十六进制密钥字符串，以及字符串 "some secret text"。
   - **输出：** 加密后的密文的十六进制字符串。

**Go 语言功能的实现:**

这段代码主要展示了以下 Go 语言功能：

* **包的导入 (`import`)**: 引入了 `bytes`, `crypto/aes`, `crypto/cipher`, `crypto/rand`, `encoding/hex`, `fmt`, `io`, `os` 等标准库包，用于处理字节操作、AES 加密、密码学接口、随机数生成、十六进制编码、格式化输出、IO 操作和操作系统交互。
* **函数定义 (`func`)**: 定义了多个以 `Example` 开头的函数，这些是 Go 的示例函数，用于在文档中展示代码用法。
* **错误处理**: 通过检查返回值中的 `error` 类型来处理可能发生的错误，例如 `aes.NewCipher` 和 `cipher.NewGCM` 等函数可能会返回错误。
* **切片 (`[]byte`)**: 大量使用了字节切片来表示密钥、明文、密文、nonce 和 IV。
* **结构体和接口**: 使用了 `cipher.Block` 接口和 `cipher.AEAD` 接口（例如 GCM）以及具体的结构体类型，如 `aes.Cipher` 和 `cipher.gcm`.
* **随机数生成**: 使用 `rand.Reader` 来生成随机的 nonce 和 IV。
* **十六进制编码/解码**: 使用 `hex.DecodeString` 将十六进制字符串转换为字节切片，使用 `fmt.Printf("%x\n", ...)` 将字节切片格式化为十六进制字符串输出。
* **IO 操作**: 使用 `io.ReadFull` 从随机数生成器读取指定长度的字节，使用 `io.Copy` 在 `StreamReader` 和 `StreamWriter` 的示例中进行数据流的复制。

**命令行参数的具体处理:**

这段代码本身并没有处理任何命令行参数。它是一个测试和示例代码文件，通常不直接作为可执行程序运行。它的目的是为了在 Go 的文档生成工具 `godoc` 中展示 `crypto/cipher` 包的用法。

**使用者易犯错的点:**

1. **重复使用 Nonce 或 IV:**
   - **GCM:**  对于同一个密钥，**绝对不能重复使用 nonce**。重复使用会导致严重的安全性问题。示例代码中强调了这一点。
   - **CBC, CFB, OFB, CTR:**  虽然不需要像 GCM 那样保密，但对于同一个密钥，**IV 应该是唯一的**。重复使用会降低安全性。示例代码中也提到了 IV 的独特性。
   - **示例：** 在 GCM 加密中，如果使用了相同的密钥和 nonce 加密两条不同的消息，攻击者可以计算出这两条消息的 XOR 结果，从而可能恢复原始消息。

2. **未对加密数据进行认证 (Authentication):**
   - **CBC 和流密码模式 (CFB, CTR, OFB):** 这些模式只提供机密性，**不提供数据完整性和身份验证**。攻击者可以修改密文而不被检测到。示例代码中多次强调了需要使用 `crypto/hmac` 等进行认证。
   - **示例：** 使用 CBC 加密后，攻击者可以翻转密文中的某些比特，导致解密后的明文也发生相应的变化，而接收方可能无法察觉。

3. **密钥管理不当:**
   - 示例代码中强调了密钥应该从安全的地方加载并重用，并警告不要使用示例密钥。将密钥硬编码在代码中或者以不安全的方式存储是非常危险的。

4. **CBC 模式下的填充 Oracle 攻击:**
   - 示例代码中提到了 CBC 模式下如果明文长度不是块大小的倍数需要填充，并警告在解密前必须进行身份验证，以避免填充 Oracle 攻击。

总而言之，这个 `example_test.go` 文件是学习和理解 Go 语言 `crypto/cipher` 包中各种加密模式的绝佳资源。通过阅读和运行这些示例，开发者可以更好地掌握如何在 Go 中安全地进行加密操作。

### 提示词
```
这是路径为go/src/crypto/cipher/example_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func ExampleNewGCM_encrypt() {
	// Load your secret key from a safe place and reuse it across multiple
	// Seal/Open calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	// When decoded the key should be 16 bytes (AES-128) or 32 (AES-256).
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	plaintext := []byte("exampleplaintext")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	fmt.Printf("%x\n", ciphertext)
}

func ExampleNewGCM_decrypt() {
	// Load your secret key from a safe place and reuse it across multiple
	// Seal/Open calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	// When decoded the key should be 16 bytes (AES-128) or 32 (AES-256).
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	ciphertext, _ := hex.DecodeString("c3aaa29f002ca75870806e44086700f62ce4d43e902b3888e23ceff797a7a471")
	nonce, _ := hex.DecodeString("64a9433eae7ccceee2fc0eda")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("%s\n", plaintext)
	// Output: exampleplaintext
}

func ExampleNewCBCDecrypter() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	ciphertext, _ := hex.DecodeString("73c86d43a9d700a253a96c85b0f6b03ac9792e0e757f869cca306bd3cba1c62b")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.

	fmt.Printf("%s\n", ciphertext)
	// Output: exampleplaintext
}

func ExampleNewCBCEncrypter() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("exampleplaintext")

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	if len(plaintext)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	fmt.Printf("%x\n", ciphertext)
}

func ExampleNewCFBDecrypter() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	ciphertext, _ := hex.DecodeString("7dd015f06bec7f1b8f6559dad89f4131da62261786845100056b353194ad")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)
	fmt.Printf("%s", ciphertext)
	// Output: some plaintext
}

func ExampleNewCFBEncrypter() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("some plaintext")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.
	fmt.Printf("%x\n", ciphertext)
}

func ExampleNewCTR() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("some plaintext")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	// CTR mode is the same for both encryption and decryption, so we can
	// also decrypt that ciphertext with NewCTR.

	plaintext2 := make([]byte, len(plaintext))
	stream = cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext2, ciphertext[aes.BlockSize:])

	fmt.Printf("%s\n", plaintext2)
	// Output: some plaintext
}

func ExampleNewOFB() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("some plaintext")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	// OFB mode is the same for both encryption and decryption, so we can
	// also decrypt that ciphertext with NewOFB.

	plaintext2 := make([]byte, len(plaintext))
	stream = cipher.NewOFB(block, iv)
	stream.XORKeyStream(plaintext2, ciphertext[aes.BlockSize:])

	fmt.Printf("%s\n", plaintext2)
	// Output: some plaintext
}

func ExampleStreamReader() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")

	encrypted, _ := hex.DecodeString("cf0495cc6f75dafc23948538e79904a9")
	bReader := bytes.NewReader(encrypted)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// If the key is unique for each ciphertext, then it's ok to use a zero
	// IV.
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	reader := &cipher.StreamReader{S: stream, R: bReader}
	// Copy the input to the output stream, decrypting as we go.
	if _, err := io.Copy(os.Stdout, reader); err != nil {
		panic(err)
	}

	// Note that this example is simplistic in that it omits any
	// authentication of the encrypted data. If you were actually to use
	// StreamReader in this manner, an attacker could flip arbitrary bits in
	// the output.

	// Output: some secret text
}

func ExampleStreamWriter() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")

	bReader := bytes.NewReader([]byte("some secret text"))

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// If the key is unique for each ciphertext, then it's ok to use a zero
	// IV.
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	var out bytes.Buffer

	writer := &cipher.StreamWriter{S: stream, W: &out}
	// Copy the input to the output buffer, encrypting as we go.
	if _, err := io.Copy(writer, bReader); err != nil {
		panic(err)
	}

	// Note that this example is simplistic in that it omits any
	// authentication of the encrypted data. If you were actually to use
	// StreamReader in this manner, an attacker could flip arbitrary bits in
	// the decrypted result.

	fmt.Printf("%x\n", out.Bytes())
	// Output: cf0495cc6f75dafc23948538e79904a9
}
```