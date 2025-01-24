Response:
Let's break down the thought process for analyzing this Go code and generating the detailed explanation.

1. **Understand the Goal:** The primary goal is to analyze a Go test file (`rsa_test.go`) and explain its functionality, highlight key concepts, provide code examples, and point out potential pitfalls.

2. **Initial Skim and Keyword Spotting:**  Read through the code quickly, looking for familiar Go testing patterns and relevant package names. Keywords like `Test...`, `Benchmark...`, `crypto/rsa`, `Encrypt`, `Decrypt`, `Sign`, `Verify`, `GenerateKey`, `flag`, `pem`, `x509` immediately jump out. This gives a high-level idea that the file is about testing the RSA cryptography implementation in Go.

3. **Structure Identification:** Notice the file is structured with various test functions (`TestKeyGeneration`, `TestEncryptOAEP`, etc.) and benchmark functions (`BenchmarkDecryptPKCS1v15`). There are also helper functions like `parseKey` and `testingKey`. This structure suggests that the file is organized to test different aspects of the RSA functionality.

4. **Focus on Test Functions:** Each `Test...` function targets a specific feature or scenario. Analyze each test function individually:
    * **`TestKeyGeneration`**:  Tests the generation of RSA keys of different sizes. The `GODEBUG` environment variable interaction is a key point here.
    * **`Test3PrimeKeyGeneration`, `Test4PrimeKeyGeneration`, `TestNPrimeKeyGeneration`**:  Focus on multi-prime RSA key generation.
    * **`TestImpossibleKeyGeneration`**: Tests the robustness of key generation with invalid sizes.
    * **`TestGnuTLSKey`**: Tests key parsing from a specific format.
    * **`testKeyBasics`**: A helper function called by other tests to perform basic encryption/decryption checks. Identify its core logic.
    * **`TestAllocations`**:  Checks the number of memory allocations during decryption.
    * **`TestEverything`**: A comprehensive test covering various RSA operations (encryption, decryption, signing, verification) with different padding schemes. Note the use of the `all` flag.
    * **`TestKeyTooSmall`**: Specifically tests error handling for operations with small, insecure keys.
    * **`TestEncryptOAEP`, `TestDecryptOAEP`, `Test2DecryptOAEP`, `TestEncryptDecryptOAEP`**: Focus on testing the OAEP padding scheme.
    * **`TestPSmallerThanQ`**:  A specific test case for keys where the prime factors have a size difference.

5. **Analyze Benchmark Functions:** `Benchmark...` functions measure the performance of key RSA operations. Note which operations are being benchmarked (encryption, decryption, signing, verification, key generation, key parsing).

6. **Helper Function Analysis:**
    * **`parseKey`**: Understands how to decode PEM-encoded private keys (both PKCS#1 and PKCS#8 formats).
    * **`testingKey`**:  A simple helper to replace "TESTING KEY" with "PRIVATE KEY" in the test key strings.

7. **Identify Core RSA Functionality Tested:** Based on the test function names and the operations performed within them, list the core RSA functionalities being tested:
    * Key generation (various sizes, multi-prime)
    * Key validation
    * Encryption/Decryption (PKCS#1 v1.5, OAEP)
    * Signing/Verification (PKCS#1 v1.5, PSS)
    * Key import/export (PEM encoding, PKCS#8, PKIX)

8. **Look for Command-Line Flags:**  Notice the `flag` package being used. Identify the flags defined (in this case, `-all`). Explain its purpose and how it affects the test execution.

9. **Identify Potential User Mistakes:** Based on the test cases, deduce common errors users might make:
    * Using keys that are too small.
    * Trying to sign unhashed messages with `SignPKCS1v15`.
    * Incorrectly handling or modifying signatures.
    * Not considering key size limitations for encryption.

10. **Provide Code Examples:**  For key functionalities (like key generation, encryption, decryption, signing, verification), create concise, runnable Go code snippets illustrating their usage. Include assumptions about input and expected output.

11. **Structure the Answer:** Organize the findings logically using the prompts provided in the initial request:
    * Overall functionality of the test file.
    * Explanation of key Go language features being tested.
    * Code examples with input/output.
    * Details about command-line flags.
    * Common mistakes users might make.

12. **Refine and Review:** Read through the generated explanation, ensuring clarity, accuracy, and completeness. Check for any missing details or areas that could be explained better. For instance, explicitly mentioning the purpose of `crypto/rand` for secure random number generation would be beneficial. Also, ensuring the code examples are correct and easy to understand is crucial. For example, initially, I might forget to mention the need to import relevant packages in the code examples. Reviewing would catch this.

This systematic approach allows for a comprehensive understanding of the code and the generation of a detailed and informative explanation. It starts broad and then progressively narrows down to specific functionalities and potential issues.
这段代码是 Go 语言标准库中 `crypto/rsa` 包的测试代码，位于 `go/src/crypto/rsa/rsa_test.go`。它的主要功能是 **测试 RSA 加密算法的各种实现细节和功能是否正确**。

以下是它所测试的主要功能点：

1. **密钥生成:**
   - 测试 `GenerateKey` 函数生成不同大小（128, 512, 1024, 2048, 3072, 4096 位）的 RSA 密钥对的功能。
   - 特别测试了在 `GODEBUG` 环境变量未设置时，生成小于 1024 位密钥的情况，预期会失败。
   - 测试 `GenerateMultiPrimeKey` 函数生成多素数 RSA 密钥对 (3 个或更多素数) 的功能。
   - 测试生成不可能大小的密钥是否会进入死循环或 panic。

2. **密钥基本属性验证:**
   - 测试生成的私钥是否能通过 `Validate()` 方法的基本校验。
   - 验证私钥指数 `D` 是否小于模数 `N`。

3. **PKCS#1 v1.5 加密和解密:**
   - 测试 `EncryptPKCS1v15` 函数使用公钥加密消息的功能。
   - 测试 `DecryptPKCS1v15` 函数使用私钥解密消息的功能。
   - 验证加密后再解密的消息是否与原始消息一致。
   - 测试 `DecryptPKCS1v15SessionKey` 函数解密会话密钥的功能。

4. **OAEP 加密和解密:**
   - 测试 `EncryptOAEP` 函数使用公钥和 OAEP 填充模式加密消息的功能。
   - 测试 `DecryptOAEP` 函数使用私钥和 OAEP 填充模式解密消息的功能。
   - 验证加密后再解密的消息是否与原始消息一致。

5. **PKCS#1 v1.5 签名和验证:**
   - 测试 `SignPKCS1v15` 函数使用私钥对已哈希的消息进行签名的功能。
   - 验证只有已哈希的消息才能被签名。
   - 测试 `VerifyPKCS1v15` 函数使用公钥验证签名是否有效的功能。
   - 测试篡改签名和消息后，验证是否会失败。

6. **PSS 签名和验证:**
   - 测试 `SignPSS` 函数使用私钥和 PSS 填充模式对已哈希的消息进行签名的功能。
   - 测试 `VerifyPSS` 函数使用公钥和 PSS 填充模式验证签名是否有效的功能。
   - 测试使用 `PSSSaltLengthAuto` 和 `PSSSaltLengthEqualsHash` 两种盐长度的情况。
   - 测试篡改签名和消息后，验证是否会失败。
   - 测试输入大于模数的签名和密文的处理情况。

7. **密钥的序列化和反序列化:**
   - 测试将私钥序列化为 PKCS#8 格式的 DER 编码，并能成功解析回 `PrivateKey` 对象。
   - 测试将公钥序列化为 PKIX 格式的 DER 编码，并能成功解析回 `PublicKey` 对象。
   - 验证序列化和反序列化后的密钥是否与原始密钥一致。

8. **小密钥的错误处理:**
   - 测试使用小于 1024 位（例如 512 位）的密钥进行加密、解密、签名和验证操作时，是否会返回预期的错误（包含 "insecure" 字符串）。

9. **与其他库生成的密钥的兼容性:**
   - 测试解析由 `certtool` 工具生成的特定格式的私钥 (`TestGnuTLSKey`)。

10. **性能测试 (Benchmark):**
    - 提供了针对 `DecryptPKCS1v15`, `EncryptPKCS1v15`, `DecryptOAEP`, `EncryptOAEP`, `SignPKCS1v15`, `VerifyPKCS1v15`, `SignPSS`, `VerifyPSS`, `GenerateKey`, `ParsePKCS8PrivateKey` 等操作的性能基准测试。

**它是什么 Go 语言功能的实现？**

这段代码主要测试的是 Go 语言标准库 `crypto/rsa` 包中 **RSA 公钥密码算法** 的实现。 RSA 是一种非对称加密算法，广泛用于安全通信和数字签名。

**Go 代码举例说明：**

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
)

func main() {
	// 假设的输入：要加密的消息
	message := []byte("Hello, RSA!")

	// 1. 生成 RSA 密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
		return
	}
	publicKey := &privateKey.PublicKey

	fmt.Println("RSA 密钥对已生成:")
	// 注意：实际应用中不应该直接打印私钥
	// fmt.Printf("私钥: %+v\n", privateKey)
	// fmt.Printf("公钥: %+v\n", publicKey)

	// 2. 使用公钥加密消息 (PKCS#1 v1.5)
	encryptedMessage, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, message)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting message: %v\n", err)
		return
	}
	fmt.Printf("加密后的消息: %x\n", encryptedMessage)

	// 3. 使用私钥解密消息
	decryptedMessage, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedMessage)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting message: %v\n", err)
		return
	}
	fmt.Printf("解密后的消息: %s\n", decryptedMessage)

	// 假设的输入：要签名的消息
	signMessage := []byte("This is a document to sign.")
	hashed := sha256.Sum256(signMessage) // 需要先对消息进行哈希

	// 4. 使用私钥签名消息 (PKCS#1 v1.5)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing message: %v\n", err)
		return
	}
	fmt.Printf("签名: %x\n", signature)

	// 5. 使用公钥验证签名
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error verifying signature: %v\n", err)
		return
	}
	fmt.Println("签名验证成功!")
}
```

**假设的输入与输出：**

* **输入 (加密):** `message := []byte("Hello, RSA!")`
* **输出 (加密):** 加密后的消息是一个十六进制表示的字节数组，例如：`加密后的消息: 3d4a...` (具体内容每次运行都会不同，因为加密过程包含随机性)。
* **输入 (签名):** `signMessage := []byte("This is a document to sign.")`
* **输出 (签名):** 签名也是一个十六进制表示的字节数组，例如： `签名: 9a2b...` (具体内容每次运行都会不同)。
* **输出 (验证):** 如果验证成功，会输出 `签名验证成功!`。

**命令行参数的具体处理：**

该测试文件使用 `flag` 包定义了一个命令行参数：

```go
var allFlag = flag.Bool("all", false, "test all key sizes up to 2048")
```

- **`all`**: 这是一个布尔类型的 flag。
- **`false`**: 默认值为 `false`。
- **`"test all key sizes up to 2048"`**:  这是该 flag 的描述信息。

**作用:**

当在运行测试时，如果加上 `-all` 命令行参数，例如：

```bash
go test -v -all
```

`TestEverything` 函数中的循环会测试从 32 位到 2048 位的各种密钥大小。如果没有使用 `-all` 参数，并且运行的是短测试 (`testing.Short()` 返回 true，通常使用 `go test -short` 运行)，则只会测试预定义的 `test1024Key` 和 `test2048Key` 这两个密钥。

**使用者易犯错的点：**

1. **使用过小的密钥:** 代码中明确测试了使用小于 1024 位的密钥进行操作会返回错误。使用者容易为了方便或者追求“轻量级”而使用过小的密钥，导致安全风险。

   ```go
   // 错误示例：使用 512 位密钥进行加密
   privateKey, _ := rsa.GenerateKey(rand.Reader, 512)
   publicKey := &privateKey.PublicKey
   message := []byte("Secret message")
   _, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, message)
   if err != nil {
       fmt.Println("加密失败:", err) // 预期会输出包含 "insecure" 的错误信息
   }
   ```

2. **直接签名未哈希的消息:** `SignPKCS1v15` 和 `SignPSS` 函数要求输入是已经哈希过的消息。使用者容易忘记或者错误地直接将未哈希的消息传递给签名函数。

   ```go
   // 错误示例：直接签名未哈希的消息
   privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
   message := []byte("Document to sign")
   _, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, message)
   if err != nil {
       fmt.Println("签名失败:", err) // 预期会输出包含 "crypto/rsa: input must be hashed message" 的错误信息
   }
   ```

3. **错误地处理或修改签名:** 在验证签名时，如果签名被篡改，验证会失败。使用者可能在传输或存储过程中意外修改了签名，导致验证错误。

   ```go
   // 错误示例：篡改签名后进行验证
   // ... (生成签名) ...
   signature[0] ^= 0x01 // 篡改签名
   err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
   if err != nil {
       fmt.Println("签名验证失败:", err) // 预期会验证失败
   }
   ```

总而言之，这段测试代码覆盖了 `crypto/rsa` 包中 RSA 算法的各种关键功能，并通过各种测试用例确保其正确性和安全性。它也暗示了使用者在使用 RSA 算法时需要注意的一些关键点，例如密钥大小和正确的签名流程。

### 提示词
```
这是路径为go/src/crypto/rsa/rsa_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package rsa_test

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/internal/boring"
	"crypto/internal/cryptotest"
	"crypto/rand"
	. "crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

func TestKeyGeneration(t *testing.T) {
	sizes := []int{128, 512, 1024, 2048, 3072, 4096}
	if testing.Short() {
		sizes = sizes[:2]
	}
	for _, size := range sizes {
		t.Run(fmt.Sprintf("%d", size), func(t *testing.T) {
			if size < 1024 {
				_, err := GenerateKey(rand.Reader, size)
				if err == nil {
					t.Errorf("GenerateKey(%d) succeeded without GODEBUG", size)
				}
				t.Setenv("GODEBUG", "rsa1024min=0")
			}
			priv, err := GenerateKey(rand.Reader, size)
			if err != nil {
				t.Errorf("GenerateKey(%d): %v", size, err)
			}
			if bits := priv.N.BitLen(); bits != size {
				t.Errorf("key too short (%d vs %d)", bits, size)
			}
			testKeyBasics(t, priv)
		})
	}
}

func Test3PrimeKeyGeneration(t *testing.T) {
	size := 1024
	if testing.Short() {
		t.Setenv("GODEBUG", "rsa1024min=0")
		size = 256
	}

	priv, err := GenerateMultiPrimeKey(rand.Reader, 3, size)
	if err != nil {
		t.Errorf("failed to generate key")
	}
	testKeyBasics(t, priv)
}

func Test4PrimeKeyGeneration(t *testing.T) {
	size := 1024
	if testing.Short() {
		t.Setenv("GODEBUG", "rsa1024min=0")
		size = 256
	}

	priv, err := GenerateMultiPrimeKey(rand.Reader, 4, size)
	if err != nil {
		t.Errorf("failed to generate key")
	}
	testKeyBasics(t, priv)
}

func TestNPrimeKeyGeneration(t *testing.T) {
	t.Setenv("GODEBUG", "rsa1024min=0")
	primeSize := 64
	maxN := 24
	if testing.Short() {
		primeSize = 16
		maxN = 16
	}
	// Test that generation of N-prime keys works for N > 4.
	for n := 5; n < maxN; n++ {
		priv, err := GenerateMultiPrimeKey(rand.Reader, n, 64+n*primeSize)
		if err == nil {
			testKeyBasics(t, priv)
		} else {
			t.Errorf("failed to generate %d-prime key", n)
		}
	}
}

func TestImpossibleKeyGeneration(t *testing.T) {
	// This test ensures that trying to generate or validate toy RSA keys
	// doesn't enter an infinite loop or panic.
	t.Setenv("GODEBUG", "rsa1024min=0")
	for i := 0; i < 32; i++ {
		GenerateKey(rand.Reader, i)
		GenerateMultiPrimeKey(rand.Reader, 3, i)
		GenerateMultiPrimeKey(rand.Reader, 4, i)
		GenerateMultiPrimeKey(rand.Reader, 5, i)
	}
}

func TestGnuTLSKey(t *testing.T) {
	t.Setenv("GODEBUG", "rsa1024min=0")
	// This is a key generated by `certtool --generate-privkey --bits 128`.
	// It's such that de ≢ 1 mod φ(n), but is congruent mod the order of
	// the group.
	priv := parseKey(testingKey(`-----BEGIN RSA TESTING KEY-----
MGECAQACEQDar8EuoZuSosYtE9SeXSyPAgMBAAECEBf7XDET8e6jjTcfO7y/sykC
CQDozXjCjkBzLQIJAPB6MqNbZaQrAghbZTdQoko5LQIIUp9ZiKDdYjMCCCCpqzmX
d8Y7
-----END RSA TESTING KEY-----`))
	testKeyBasics(t, priv)
}

func testKeyBasics(t *testing.T, priv *PrivateKey) {
	if err := priv.Validate(); err != nil {
		t.Errorf("Validate() failed: %s", err)
	}
	if priv.D.Cmp(priv.N) > 0 {
		t.Errorf("private exponent too large")
	}

	msg := []byte("hi!")
	enc, err := EncryptPKCS1v15(rand.Reader, &priv.PublicKey, msg)
	if err != nil {
		t.Errorf("EncryptPKCS1v15: %v", err)
		return
	}

	dec, err := DecryptPKCS1v15(nil, priv, enc)
	if err != nil {
		t.Errorf("DecryptPKCS1v15: %v", err)
		return
	}
	if !bytes.Equal(dec, msg) {
		t.Errorf("got:%x want:%x (%+v)", dec, msg, priv)
	}
}

func TestAllocations(t *testing.T) {
	cryptotest.SkipTestAllocations(t)

	m := []byte("Hello Gophers")
	c, err := EncryptPKCS1v15(rand.Reader, &test2048Key.PublicKey, m)
	if err != nil {
		t.Fatal(err)
	}

	if allocs := testing.AllocsPerRun(100, func() {
		p, err := DecryptPKCS1v15(nil, test2048Key, c)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(p, m) {
			t.Fatalf("unexpected output: %q", p)
		}
	}); allocs > 10 {
		t.Errorf("expected less than 10 allocations, got %0.1f", allocs)
	}
}

var allFlag = flag.Bool("all", false, "test all key sizes up to 2048")

func TestEverything(t *testing.T) {
	if testing.Short() {
		// Skip key generation, but still test real sizes.
		for _, key := range []*PrivateKey{test1024Key, test2048Key} {
			t.Run(fmt.Sprintf("%d", key.N.BitLen()), func(t *testing.T) {
				t.Parallel()
				testEverything(t, key)
			})
		}
		return
	}

	t.Setenv("GODEBUG", "rsa1024min=0")
	min := 32
	max := 560 // any smaller than this and not all tests will run
	if *allFlag {
		max = 2048
	}
	for size := min; size <= max; size++ {
		size := size
		t.Run(fmt.Sprintf("%d", size), func(t *testing.T) {
			t.Parallel()
			priv, err := GenerateKey(rand.Reader, size)
			if err != nil {
				t.Fatalf("GenerateKey(%d): %v", size, err)
			}
			if bits := priv.N.BitLen(); bits != size {
				t.Errorf("key too short (%d vs %d)", bits, size)
			}
			testEverything(t, priv)
		})
	}
}

func testEverything(t *testing.T, priv *PrivateKey) {
	if err := priv.Validate(); err != nil {
		t.Errorf("Validate() failed: %s", err)
	}

	msg := []byte("test")
	enc, err := EncryptPKCS1v15(rand.Reader, &priv.PublicKey, msg)
	if err == ErrMessageTooLong {
		t.Log("key too small for EncryptPKCS1v15")
	} else if err != nil {
		t.Errorf("EncryptPKCS1v15: %v", err)
	}
	if err == nil {
		dec, err := DecryptPKCS1v15(nil, priv, enc)
		if err != nil {
			t.Errorf("DecryptPKCS1v15: %v", err)
		}
		err = DecryptPKCS1v15SessionKey(nil, priv, enc, make([]byte, 4))
		if err != nil {
			t.Errorf("DecryptPKCS1v15SessionKey: %v", err)
		}
		if !bytes.Equal(dec, msg) {
			t.Errorf("got:%x want:%x (%+v)", dec, msg, priv)
		}
	}

	label := []byte("label")
	enc, err = EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, msg, label)
	if err == ErrMessageTooLong {
		t.Log("key too small for EncryptOAEP")
	} else if err != nil {
		t.Errorf("EncryptOAEP: %v", err)
	}
	if err == nil {
		dec, err := DecryptOAEP(sha256.New(), nil, priv, enc, label)
		if err != nil {
			t.Errorf("DecryptOAEP: %v", err)
		}
		if !bytes.Equal(dec, msg) {
			t.Errorf("got:%x want:%x (%+v)", dec, msg, priv)
		}
	}

	const hashMsg = "crypto/rsa: input must be hashed message"
	sig, err := SignPKCS1v15(nil, priv, crypto.SHA256, msg)
	if err == nil || err.Error() != hashMsg {
		t.Errorf("SignPKCS1v15 with bad hash: err = %q, want %q", err, hashMsg)
	}

	hash := sha256.Sum256(msg)
	sig, err = SignPKCS1v15(nil, priv, crypto.SHA256, hash[:])
	if err == ErrMessageTooLong {
		t.Log("key too small for SignPKCS1v15")
	} else if err != nil {
		t.Errorf("SignPKCS1v15: %v", err)
	}
	if err == nil {
		err = VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, hash[:], sig)
		if err != nil {
			t.Errorf("VerifyPKCS1v15: %v", err)
		}
		sig[1] ^= 0x80
		err = VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, hash[:], sig)
		if err == nil {
			t.Errorf("VerifyPKCS1v15 success for tampered signature")
		}
		sig[1] ^= 0x80
		hash[1] ^= 0x80
		err = VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, hash[:], sig)
		if err == nil {
			t.Errorf("VerifyPKCS1v15 success for tampered message")
		}
		hash[1] ^= 0x80
	}

	opts := &PSSOptions{SaltLength: PSSSaltLengthAuto}
	sig, err = SignPSS(rand.Reader, priv, crypto.SHA256, hash[:], opts)
	if err == ErrMessageTooLong {
		t.Log("key too small for SignPSS with PSSSaltLengthAuto")
	} else if err != nil {
		t.Errorf("SignPSS: %v", err)
	}
	if err == nil {
		err = VerifyPSS(&priv.PublicKey, crypto.SHA256, hash[:], sig, opts)
		if err != nil {
			t.Errorf("VerifyPSS: %v", err)
		}
		sig[1] ^= 0x80
		err = VerifyPSS(&priv.PublicKey, crypto.SHA256, hash[:], sig, opts)
		if err == nil {
			t.Errorf("VerifyPSS success for tampered signature")
		}
		sig[1] ^= 0x80
		hash[1] ^= 0x80
		err = VerifyPSS(&priv.PublicKey, crypto.SHA256, hash[:], sig, opts)
		if err == nil {
			t.Errorf("VerifyPSS success for tampered message")
		}
		hash[1] ^= 0x80
	}

	opts.SaltLength = PSSSaltLengthEqualsHash
	sig, err = SignPSS(rand.Reader, priv, crypto.SHA256, hash[:], opts)
	if err == ErrMessageTooLong {
		t.Log("key too small for SignPSS with PSSSaltLengthEqualsHash")
	} else if err != nil {
		t.Errorf("SignPSS: %v", err)
	}
	if err == nil {
		err = VerifyPSS(&priv.PublicKey, crypto.SHA256, hash[:], sig, opts)
		if err != nil {
			t.Errorf("VerifyPSS: %v", err)
		}
		sig[1] ^= 0x80
		err = VerifyPSS(&priv.PublicKey, crypto.SHA256, hash[:], sig, opts)
		if err == nil {
			t.Errorf("VerifyPSS success for tampered signature")
		}
		sig[1] ^= 0x80
		hash[1] ^= 0x80
		err = VerifyPSS(&priv.PublicKey, crypto.SHA256, hash[:], sig, opts)
		if err == nil {
			t.Errorf("VerifyPSS success for tampered message")
		}
		hash[1] ^= 0x80
	}

	// Check that an input bigger than the modulus is handled correctly,
	// whether it is longer than the byte size of the modulus or not.
	c := bytes.Repeat([]byte{0xff}, priv.Size())
	err = VerifyPSS(&priv.PublicKey, crypto.SHA256, hash[:], c, opts)
	if err == nil {
		t.Errorf("VerifyPSS accepted a large signature")
	}
	_, err = DecryptPKCS1v15(nil, priv, c)
	if err == nil {
		t.Errorf("DecryptPKCS1v15 accepted a large ciphertext")
	}
	c = append(c, 0xff)
	err = VerifyPSS(&priv.PublicKey, crypto.SHA256, hash[:], c, opts)
	if err == nil {
		t.Errorf("VerifyPSS accepted a long signature")
	}
	_, err = DecryptPKCS1v15(nil, priv, c)
	if err == nil {
		t.Errorf("DecryptPKCS1v15 accepted a long ciphertext")
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Errorf("MarshalPKCS8PrivateKey: %v", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Errorf("ParsePKCS8PrivateKey: %v", err)
	}
	if !key.(*PrivateKey).Equal(priv) {
		t.Errorf("private key mismatch")
	}

	der, err = x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Errorf("MarshalPKIXPublicKey: %v", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Errorf("ParsePKIXPublicKey: %v", err)
	}
	if !pub.(*PublicKey).Equal(&priv.PublicKey) {
		t.Errorf("public key mismatch")
	}
}

func TestKeyTooSmall(t *testing.T) {
	checkErr := func(err error) {
		t.Helper()
		if err == nil {
			t.Error("expected error")
		}
		if !strings.Contains(err.Error(), "insecure") {
			t.Errorf("unexpected error: %v", err)
		}
	}
	checkErr2 := func(_ []byte, err error) {
		t.Helper()
		checkErr(err)
	}

	buf := make([]byte, 512/8)
	checkErr2(test512Key.Sign(rand.Reader, buf, crypto.SHA512))
	checkErr2(test512Key.Sign(rand.Reader, buf, &PSSOptions{SaltLength: PSSSaltLengthEqualsHash}))
	checkErr2(test512Key.Decrypt(rand.Reader, buf, &PKCS1v15DecryptOptions{}))
	checkErr2(test512Key.Decrypt(rand.Reader, buf, &OAEPOptions{Hash: crypto.SHA512}))
	checkErr(VerifyPKCS1v15(&test512Key.PublicKey, crypto.SHA512, buf, buf))
	checkErr(VerifyPSS(&test512Key.PublicKey, crypto.SHA512, buf, buf, &PSSOptions{SaltLength: PSSSaltLengthEqualsHash}))
	checkErr2(SignPKCS1v15(rand.Reader, test512Key, crypto.SHA512, buf))
	checkErr2(SignPSS(rand.Reader, test512Key, crypto.SHA512, buf, &PSSOptions{SaltLength: PSSSaltLengthEqualsHash}))
	checkErr2(EncryptPKCS1v15(rand.Reader, &test512Key.PublicKey, buf))
	checkErr2(EncryptOAEP(sha512.New(), rand.Reader, &test512Key.PublicKey, buf, nil))
	checkErr2(DecryptPKCS1v15(nil, test512Key, buf))
	checkErr2(DecryptOAEP(sha512.New(), nil, test512Key, buf, nil))
	checkErr(DecryptPKCS1v15SessionKey(nil, test512Key, buf, buf))
}

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }

func parseKey(s string) *PrivateKey {
	p, _ := pem.Decode([]byte(s))
	if p.Type == "PRIVATE KEY" {
		k, err := x509.ParsePKCS8PrivateKey(p.Bytes)
		if err != nil {
			panic(err)
		}
		return k.(*PrivateKey)
	}
	k, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		panic(err)
	}
	return k
}

var rsaPrivateKey = test1024Key

var test512Key = parseKey(testingKey(`-----BEGIN RSA TESTING KEY-----
MIIBOgIBAAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0
fd7Ai2KW5ToIwzFofvJcS/STa6HA5gQenRUCAwEAAQJBAIq9amn00aS0h/CrjXqu
/ThglAXJmZhOMPVn4eiu7/ROixi9sex436MaVeMqSNf7Ex9a8fRNfWss7Sqd9eWu
RTUCIQDasvGASLqmjeffBNLTXV2A5g4t+kLVCpsEIZAycV5GswIhANEPLmax0ME/
EO+ZJ79TJKN5yiGBRsv5yvx5UiHxajEXAiAhAol5N4EUyq6I9w1rYdhPMGpLfk7A
IU2snfRJ6Nq2CQIgFrPsWRCkV+gOYcajD17rEqmuLrdIRexpg8N1DOSXoJ8CIGlS
tAboUGBxTDq3ZroNism3DaMIbKPyYrAqhKov1h5V
-----END RSA TESTING KEY-----`))

var test512KeyTwo = parseKey(testingKey(`-----BEGIN TESTING KEY-----
MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEA0wLCoguSfgskR8tY
Fh2AzXQzBpSEmPucxtVe93HzPdQpxvtSTvZe5kIsdvPc7QZ0dCc/qbnUBRbuGIAl
Ir0c9QIDAQABAkAzul+AXhnhcFXKi9ziPwVOWIgRuuLupe//BluriXG53BEBSVrV
Hr7qFqwnSLSLroMzqhZwoqyRgjsLYyGEHDGBAiEA8T0sDPuht3w2Qv61IAvBwjLH
H4HXjRUEWYRn1XjHqAUCIQDf7BYlANRqFfvg1YK3VCM4YyK2mH1UivDi8wdPlJRk
MQIhAMp5i2WCNeNpD6n/WkqBU6kJMXPSaPZy82mm5feYHgt5AiEAkg/QnhB9fjma
1BzRqD4Uv0pDMXIkhooe+Rrn0OwtI3ECIQDP6nxML3JOjbAS7ydFBv176uVsMJib
r4PZozCXKuuGNg==
-----END PRIVATE KEY-----`))

var test1024Key = parseKey(testingKey(`-----BEGIN RSA TESTING KEY-----
MIICXQIBAAKBgQCw0YNSqI9T1VFvRsIOejZ9feiKz1SgGfbe9Xq5tEzt2yJCsbyg
+xtcuCswNhdqY5A1ZN7G60HbL4/Hh/TlLhFJ4zNHVylz9mDDx3yp4IIcK2lb566d
fTD0B5EQ9Iqub4twLUdLKQCBfyhmJJvsEqKxm4J4QWgI+Brh/Pm3d4piPwIDAQAB
AoGASC6fj6TkLfMNdYHLQqG9kOlPfys4fstarpZD7X+fUBJ/H/7y5DzeZLGCYAIU
+QeAHWv6TfZIQjReW7Qy00RFJdgwFlTFRCsKXhG5x+IB+jL0Grr08KbgPPDgy4Jm
xirRHZVtU8lGbkiZX+omDIU28EHLNWL6rFEcTWao/tERspECQQDp2G5Nw0qYWn7H
Wm9Up1zkUTnkUkCzhqtxHbeRvNmHGKE7ryGMJEk2RmgHVstQpsvuFY4lIUSZEjAc
DUFJERhFAkEAwZH6O1ULORp8sHKDdidyleYcZU8L7y9Y3OXJYqELfddfBgFUZeVQ
duRmJj7ryu0g0uurOTE+i8VnMg/ostxiswJBAOc64Dd8uLJWKa6uug+XPr91oi0n
OFtM+xHrNK2jc+WmcSg3UJDnAI3uqMc5B+pERLq0Dc6hStehqHjUko3RnZECQEGZ
eRYWciE+Cre5dzfZkomeXE0xBrhecV0bOq6EKWLSVE+yr6mAl05ThRK9DCfPSOpy
F6rgN3QiyCA9J/1FluUCQQC5nX+PTU1FXx+6Ri2ZCi6EjEKMHr7gHcABhMinZYOt
N59pra9UdVQw9jxCU9G7eMyb0jJkNACAuEwakX3gi27b
-----END RSA TESTING KEY-----`))

var test2048KeyPEM = testingKey(`-----BEGIN TESTING KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDNoyFUYeDuqw+k
iyv47iBy/udbWmQdpbUZ8JobHv8uQrvL7sQN6l83teHgNJsXqtiLF3MC+K+XI6Dq
hxUWfQwLip8WEnv7Jx/+53S8yp/CS4Jw86Q1bQHbZjFDpcoqSuwAxlegw18HNZCY
fpipYnA1lYCm+MTjtgXJQbjA0dwUGCf4BDMqt+76Jk3XZF5975rftbkGoT9eu8Jt
Xs5F5Xkwd8q3fkQz+fpLW4u9jrfFyQ61RRFkYrCjlhtGjYIzBHGgQM4n/sNXhiy5
h0tA7Xa6NyYrN/OXe/Y1K8Rz/tzlvbMoxgZgtBuKo1N3m8ckFi7hUVK2eNv7GoAb
teTTPrg/AgMBAAECggEAAnfsVpmsL3R0Bh4gXRpPeM63H6e1a8B8kyVwiO9o0cXX
gKp9+P39izfB0Kt6lyCj/Wg+wOQT7rg5qy1yIw7fBHGmcjquxh3uN0s3YZ+Vcym6
SAY5f0vh/OyJN9r3Uv8+Pc4jtb7So7QDzdWeZurssBmUB0avAMRdGNFGP5SyILcz
l3Q59hTxQ4czRHKjZ06L1/sA+tFVbO1j39FN8nMOU/ovLF4lAmZTkQ6AP6n6XPHP
B8Nq7jSYz6RDO200jzp6UsdrnjjkJRbzOxN/fn+ckCP+WYuq+y/d05ET9PdVa4qI
Jyr80D9QgHmfztcecvYwoskGnkb2F4Tmp0WnAj/xVQKBgQD4TrMLyyHdbAr5hoSi
p+r7qBQxnHxPe2FKO7aqagi4iPEHauEDgwPIcsOYota1ACiSs3BaESdJAClbqPYd
HDI4c2DZ6opux6WYkSju+tVXYW6qarR3fzrP3fUCdz2c2NfruWOqq8YmjzAhTNPm
YzvtzTdwheNYV0Vi71t1SfZmfQKBgQDUAgSUcrgXdGDnSbaNe6KwjY5oZWOQfZe2
DUhqfN/JRFZj+EMfIIh6OQXnZqkp0FeRdfRAFl8Yz8ESHEs4j+TikLJEeOdfmYLS
TWxlMPDTUGbUvSf4g358NJ8TlfYA7dYpSTNPXMRSLtsz1palmaDBTE/V2xKtTH6p
VglRNRUKawKBgCPqBh2TkN9czC2RFkgMb4FcqycN0jEQ0F6TSnVVhtNiAzKmc8s1
POvWJZJDIzjkv/mP+JUeXAdD/bdjNc26EU126rA6KzGgsMPjYv9FymusDPybGGUc
Qt5j5RcpNgEkn/5ZPyAlXjCfjz+RxChTfAyGHRmqU9qoLMIFir3pJ7llAoGBAMNH
sIxENwlzqyafoUUlEq/pU7kZWuJmrO2FwqRDraYoCiM/NCRhxRQ/ng6NY1gejepw
abD2alXiV4alBSxubne6rFmhvA00y2mG40c6Ezmxn2ZpbX3dMQ6bMcPKp7QnXtLc
mCSL4FGK02ImUNDsd0RVVFw51DRId4rmsuJYMK9NAoGAKlYdc4784ixTD2ZICIOC
ZWPxPAyQUEA7EkuUhAX1bVNG6UJTYA8kmGcUCG4jPTgWzi00IyUUr8jK7efyU/zs
qiJuVs1bia+flYIQpysMl1VzZh8gW1nkB4SVPm5l2wBvVJDIr9Mc6rueC/oVNkh2
fLVGuFoTVIu2bF0cWAjNNMg=
-----END TESTING KEY-----`)

var test2048Key = parseKey(test2048KeyPEM)

var test3072Key = parseKey(testingKey(`-----BEGIN TESTING KEY-----
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
8h02sdAMB9Yc2A4EgzOySWoD
-----END TESTING KEY-----`))

var test4096Key = parseKey(testingKey(`-----BEGIN TESTING KEY-----
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
Axreud3rJ0rekUp6rI1joG717Wls
-----END TESTING KEY-----`))

func BenchmarkDecryptPKCS1v15(b *testing.B) {
	b.Run("2048", func(b *testing.B) { benchmarkDecryptPKCS1v15(b, test2048Key) })
	b.Run("3072", func(b *testing.B) { benchmarkDecryptPKCS1v15(b, test3072Key) })
	b.Run("4096", func(b *testing.B) { benchmarkDecryptPKCS1v15(b, test4096Key) })
}

func benchmarkDecryptPKCS1v15(b *testing.B, k *PrivateKey) {
	r := bufio.NewReaderSize(rand.Reader, 1<<15)

	m := []byte("Hello Gophers")
	c, err := EncryptPKCS1v15(r, &k.PublicKey, m)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	var sink byte
	for i := 0; i < b.N; i++ {
		p, err := DecryptPKCS1v15(r, k, c)
		if err != nil {
			b.Fatal(err)
		}
		if !bytes.Equal(p, m) {
			b.Fatalf("unexpected output: %q", p)
		}
		sink ^= p[0]
	}
}

func BenchmarkEncryptPKCS1v15(b *testing.B) {
	b.Run("2048", func(b *testing.B) {
		r := bufio.NewReaderSize(rand.Reader, 1<<15)
		m := []byte("Hello Gophers")

		var sink byte
		for i := 0; i < b.N; i++ {
			c, err := EncryptPKCS1v15(r, &test2048Key.PublicKey, m)
			if err != nil {
				b.Fatal(err)
			}
			sink ^= c[0]
		}
	})
}

func BenchmarkDecryptOAEP(b *testing.B) {
	b.Run("2048", func(b *testing.B) {
		r := bufio.NewReaderSize(rand.Reader, 1<<15)

		m := []byte("Hello Gophers")
		c, err := EncryptOAEP(sha256.New(), r, &test2048Key.PublicKey, m, nil)
		if err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		var sink byte
		for i := 0; i < b.N; i++ {
			p, err := DecryptOAEP(sha256.New(), r, test2048Key, c, nil)
			if err != nil {
				b.Fatal(err)
			}
			if !bytes.Equal(p, m) {
				b.Fatalf("unexpected output: %q", p)
			}
			sink ^= p[0]
		}
	})
}

func BenchmarkEncryptOAEP(b *testing.B) {
	b.Run("2048", func(b *testing.B) {
		r := bufio.NewReaderSize(rand.Reader, 1<<15)
		m := []byte("Hello Gophers")

		var sink byte
		for i := 0; i < b.N; i++ {
			c, err := EncryptOAEP(sha256.New(), r, &test2048Key.PublicKey, m, nil)
			if err != nil {
				b.Fatal(err)
			}
			sink ^= c[0]
		}
	})
}

func BenchmarkSignPKCS1v15(b *testing.B) {
	b.Run("2048", func(b *testing.B) {
		hashed := sha256.Sum256([]byte("testing"))

		var sink byte
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			s, err := SignPKCS1v15(rand.Reader, test2048Key, crypto.SHA256, hashed[:])
			if err != nil {
				b.Fatal(err)
			}
			sink ^= s[0]
		}
	})
}

func BenchmarkVerifyPKCS1v15(b *testing.B) {
	b.Run("2048", func(b *testing.B) {
		hashed := sha256.Sum256([]byte("testing"))
		s, err := SignPKCS1v15(rand.Reader, test2048Key, crypto.SHA256, hashed[:])
		if err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := VerifyPKCS1v15(&test2048Key.PublicKey, crypto.SHA256, hashed[:], s)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkSignPSS(b *testing.B) {
	b.Run("2048", func(b *testing.B) {
		hashed := sha256.Sum256([]byte("testing"))

		var sink byte
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			s, err := SignPSS(rand.Reader, test2048Key, crypto.SHA256, hashed[:], nil)
			if err != nil {
				b.Fatal(err)
			}
			sink ^= s[0]
		}
	})
}

func BenchmarkVerifyPSS(b *testing.B) {
	b.Run("2048", func(b *testing.B) {
		hashed := sha256.Sum256([]byte("testing"))
		s, err := SignPSS(rand.Reader, test2048Key, crypto.SHA256, hashed[:], nil)
		if err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := VerifyPSS(&test2048Key.PublicKey, crypto.SHA256, hashed[:], s, nil)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkGenerateKey(b *testing.B) {
	b.Run("2048", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := GenerateKey(rand.Reader, 2048); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkParsePKCS8PrivateKey(b *testing.B) {
	b.Run("2048", func(b *testing.B) {
		p, _ := pem.Decode([]byte(test2048KeyPEM))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := x509.ParsePKCS8PrivateKey(p.Bytes); err != nil {
				b.Fatal(err)
			}
		}
	})
}

type testEncryptOAEPMessage struct {
	in   []byte
	seed []byte
	out  []byte
}

type testEncryptOAEPStruct struct {
	modulus string
	e       int
	d       string
	msgs    []testEncryptOAEPMessage
}

func TestEncryptOAEP(t *testing.T) {
	sha1 := sha1.New()
	n := new(big.Int)
	for i, test := range testEncryptOAEPData {
		n.SetString(test.modulus, 16)
		public := PublicKey{N: n, E: test.e}

		for j, message := range test.msgs {
			randomSource := bytes.NewReader(message.seed)
			out, err := EncryptOAEP(sha1, randomSource, &public, message.in, nil)
			if err != nil {
				t.Errorf("#%d,%d error: %s", i, j, err)
			}
			if !bytes.Equal(out, message.out) {
				t.Errorf("#%d,%d bad result: %x (want %x)", i, j, out, message.out)
			}
		}
	}
}

func TestDecryptOAEP(t *testing.T) {
	random := rand.Reader

	sha1 := sha1.New()
	n := new(big.Int)
	d := new(big.Int)
	for i, test := range testEncryptOAEPData {
		n.SetString(test.modulus, 16)
		d.SetString(test.d, 16)
		private := new(PrivateKey)
		private.PublicKey = PublicKey{N: n, E: test.e}
		private.D = d

		for j, message := range test.msgs {
			out, err := DecryptOAEP(sha1, nil, private, message.out, nil)
			if err != nil {
				t.Errorf("#%d,%d error: %s", i, j, err)
			} else if !bytes.Equal(out, message.in) {
				t.Errorf("#%d,%d bad result: %#v (want %#v)", i, j, out, message.in)
			}

			// Decrypt with blinding.
			out, err = DecryptOAEP(sha1, random, private, message.out, nil)
			if err != nil {
				t.Errorf("#%d,%d (blind) error: %s", i, j, err)
			} else if !bytes.Equal(out, message.in) {
				t.Errorf("#%d,%d (blind) bad result: %#v (want %#v)", i, j, out, message.in)
			}
		}
		if testing.Short() {
			break
		}
	}
}

func Test2DecryptOAEP(t *testing.T) {
	random := rand.Reader

	msg := []byte{0xed, 0x36, 0x90, 0x8d, 0xbe, 0xfc, 0x35, 0x40, 0x70, 0x4f, 0xf5, 0x9d, 0x6e, 0xc2, 0xeb, 0xf5, 0x27, 0xae, 0x65, 0xb0, 0x59, 0x29, 0x45, 0x25, 0x8c, 0xc1, 0x91, 0x22}
	in := []byte{0x72, 0x26, 0x84, 0xc9, 0xcf, 0xd6, 0xa8, 0x96, 0x04, 0x3e, 0x34, 0x07, 0x2c, 0x4f, 0xe6, 0x52, 0xbe, 0x46, 0x3c, 0xcf, 0x79, 0x21, 0x09, 0x64, 0xe7, 0x33, 0x66, 0x9b, 0xf8, 0x14, 0x22, 0x43, 0xfe, 0x8e, 0x52, 0x8b, 0xe0, 0x5f, 0x98, 0xef, 0x54, 0xac, 0x6b, 0xc6, 0x26, 0xac, 0x5b, 0x1b, 0x4b, 0x7d, 0x2e, 0xd7, 0x69, 0x28, 0x5a, 0x2f, 0x4a, 0x95, 0x89, 0x6c, 0xc7, 0x53, 0x95, 0xc7, 0xd2, 0x89, 0x04, 0x6f, 0x94, 0x74, 0x9b, 0x09, 0x0d, 0xf4, 0x61, 0x2e, 0xab, 0x48, 0x57, 0x4a, 0xbf, 0x95, 0xcb, 0xff, 0x15, 0xe2, 0xa0, 0x66, 0x58, 0xf7, 0x46, 0xf8, 0xc7, 0x0b, 0xb5, 0x1e, 0xa7, 0xba, 0x36, 0xce, 0xdd, 0x36, 0x41, 0x98, 0x6e, 0x10, 0xf9, 0x3b, 0x70, 0xbb, 0xa1, 0xda, 0x00, 0x40, 0xd5, 0xa5, 0x3f, 0x87, 0x64, 0x32, 0x7c, 0xbc, 0x50, 0x52, 0x0e, 0x4f, 0x21, 0xbd}

	n := new(big.Int)
	d := new(big.Int)
	n.SetString(testEncryptOAEPData[0].modulus, 16)
	d.SetString(testEncryptOAEPData[0].d, 16)
	priv := new(PrivateKey)
	priv.PublicKey = PublicKey{N: n, E: testEncryptOAEPData[0].e}
	priv.D = d
	sha1 := crypto.SHA1
	sha256 := crypto.SHA256

	out, err := priv.Decrypt(random, in, &OAEPOptions{MGFHash: sha1, Hash: sha256})

	if err != nil {
		t.Errorf("error: %s", err)
	} else if !bytes.Equal(out, msg) {
		t.Errorf("bad result %#v (want %#v)", out, msg)
	}
}

func TestEncryptDecryptOAEP(t *testing.T) {
	sha256 := sha256.New()
	n := new(big.Int)
	d := new(big.Int)
	for i, test := range testEncryptOAEPData {
		n.SetString(test.modulus, 16)
		d.SetString(test.d, 16)
		priv := new(PrivateKey)
		priv.PublicKey = PublicKey{N: n, E: test.e}
		priv.D = d

		for j, message := range test.msgs {
			label := []byte(fmt.Sprintf("hi#%d", j))
			enc, err := EncryptOAEP(sha256, rand.Reader, &priv.PublicKey, message.in, label)
			if err != nil {
				t.Errorf("#%d,%d: EncryptOAEP: %v", i, j, err)
				continue
			}
			dec, err := DecryptOAEP(sha256, rand.Reader, priv, enc, label)
			if err != nil {
				t.Errorf("#%d,%d: DecryptOAEP: %v", i, j, err)
				continue
			}
			if !bytes.Equal(dec, message.in) {
				t.Errorf("#%d,%d: round trip %q -> %q", i, j, message.in, dec)
			}
		}
	}
}

// testEncryptOAEPData contains a subset of the vectors from RSA's "Test vectors for RSA-OAEP".
var testEncryptOAEPData = []testEncryptOAEPStruct{
	// Key 1
	{"a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0abc4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb5148ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb",
		65537,
		"53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9fa5af0e7f55fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbfb78ad884f84d5beb04724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1",
		[]testEncryptOAEPMessage{
			// Example 1.1
			{
				[]byte{0x66, 0x28, 0x19, 0x4e, 0x12, 0x07, 0x3d, 0xb0,
					0x3b, 0xa9, 0x4c, 0xda, 0x9e, 0xf9, 0x53, 0x23, 0x97,
					0xd5, 0x0d, 0xba, 0x79, 0xb9, 0x87, 0x00, 0x4a, 0xfe,
					0xfe, 0x34,
				},
				[]byte{0x18, 0xb7, 0x76, 0xea, 0x21, 0x06, 0x9d, 0x69,
					0x77, 0x6a, 0x33, 0xe9, 0x6b, 0xad, 0x48, 0xe1, 0xdd,
					0xa0, 0xa5, 0xef,
				},
				[]byte{0x35, 0x4f, 0xe6, 0x7b, 0x4a, 0x12, 0x6d, 0x5d,
					0x35, 0xfe, 0x36, 0xc7, 0x77, 0x79, 0x1a, 0x3f, 0x7b,
					0xa1, 0x3d, 0xef, 0x48, 0x4e, 0x2d, 0x39, 0x08, 0xaf,
					0xf7, 0x22, 0xfa, 0xd4, 0x68, 0xfb, 0x21, 0x69, 0x6d,
					0xe9, 0x5d, 0x0b, 0xe9, 0x11, 0xc2, 0xd3, 0x17, 0x4f,
					0x8a, 0xfc, 0xc2, 0x01, 0x03, 0x5f, 0x7b, 0x6d, 0x8e,
					0x69, 0x40, 0x2d, 0xe5, 0x45, 0x16, 0x18, 0xc2, 0x1a,
					0x53, 0x5f, 0xa9, 0xd7, 0xbf, 0xc5, 0xb8, 0xdd, 0x9f,
					0xc2, 0x43, 0xf8, 0xcf, 0x92, 0x7d, 0xb3, 0x13, 0x22,
					0xd6, 0xe8, 0x81, 0xea, 0xa9, 0x1a, 0x99, 0x61, 0x70,
					0xe6, 0x57, 0xa0, 0x5a, 0x26, 0x64, 0x26, 0xd9, 0x8c,
					0x88, 0x00, 0x3f, 0x84, 0x77, 0xc1, 0x22, 0x70, 0x94,
					0xa0, 0xd9, 0xfa, 0x1e, 0x8c, 0x40, 0x24, 0x30, 0x9c,
					0xe1, 0xec, 0xcc, 0xb5, 0x21, 0x00, 0x35, 0xd4, 0x7a,
					0xc7, 0x2e, 0x8a,
				},
			},
			// Example 1.2
			{
				[]byte{0x75, 0x0c, 0x40, 0x47, 0xf5, 0x47, 0xe8, 0xe4,
					0x14, 0x11, 0x85, 0x65, 0x23, 0x29, 0x8a, 0xc9, 0xba,
					0xe2, 0x45, 0xef, 0xaf, 0x13, 0x97, 0xfb, 0xe5, 0x6f,
					0x9d, 0xd5,
				},
				[]byte{0x0c, 0xc7, 0x42, 0xce, 0x4a, 0x9b, 0x7f, 0x32,
					0xf9, 0x51, 0xbc, 0xb2, 0x51, 0xef, 0xd9, 0x25, 0xfe,
					0x4f, 0xe3, 0x5f,
				},
				[]byte{0x64, 0x0d, 0xb1, 0xac, 0xc5, 0x8e, 0x05, 0x68,
					0xfe, 0x54, 0x07, 0xe5, 0xf9, 0xb7, 0x01, 0xdf, 0xf8,
					0xc3, 0xc9, 0x1e, 0x71, 0x6c, 0x53, 0x6f, 0xc7, 0xfc,
					0xec, 0x6c, 0xb5, 0xb7, 0x1c, 0x11, 0x65, 0x98, 0x8d,
					0x4a, 0x27, 0x9e, 0x15, 0x77, 0xd7, 0x30, 0xfc, 0x7a,
					0x29, 0x93, 0x2e, 0x3f, 0x00, 0xc8, 0x15, 0x15, 0x23,
					0x6d, 0x8d, 0x8e, 0x31, 0x01, 0x7a, 0x7a, 0x09, 0xdf,
					0x43, 0x52, 0xd9, 0x04, 0xcd, 0xeb, 0x79, 0xaa, 0x58,
					0x3a, 0xdc, 0xc3, 0x1e, 0xa6, 0x98, 0xa4, 0xc0, 0x52,
					0x83, 0xda, 0xba, 0x90, 0x89, 0xbe, 0x54, 0x91, 0xf6,
					0x7c, 0x1a, 0x4e, 0xe4, 0x8d, 0xc7, 0x4b, 0xbb, 0xe6,
					0x64, 0x3a, 0xef, 0x84, 0x66, 0x79, 0xb4, 0xcb, 0x39,
					0x5a, 0x35, 0x2d, 0x5e, 0xd1, 0x15, 0x91, 0x2d, 0xf6,
					0x96, 0xff, 0xe0, 0x70, 0x29, 0x32, 0x94, 0x6d, 0x71,
					0x49, 0x2b, 0x44,
				},
			},
			// Example 1.3
			{
				[]byte{0xd9, 0x4a, 0xe0, 0x83, 0x2e, 0x64, 0x45, 0xce,
					0x42, 0x33, 0x1c, 0xb0, 0x6d, 0x53, 0x1a, 0x82, 0xb1,
					0xdb, 0x4b, 0xaa, 0xd3, 0x0f, 0x74, 0x6d, 0xc9, 0x16,
					0xdf, 0x24, 0xd4, 0xe3, 0xc2, 0x45, 0x1f, 0xff, 0x59,
					0xa6, 0x42, 0x3e, 0xb0, 0xe1, 0xd0, 0x2d, 0x4f, 0xe6,
					0x46, 0xcf, 0x69, 0x9d, 0xfd, 0x81, 0x8c, 0x6e, 0x97,
					0xb0, 0x51,
				},
				[]byte{0x25, 0x14, 0xdf, 0x46, 0x95, 0x75, 0x5a, 0x67,
					0xb2, 0x88, 0xea, 0xf4, 0x90, 0x5c, 0x36, 0xee, 0xc6,
					0x6f, 0xd2, 0xfd,
				},
				[]byte{0x42, 0x37, 0x36, 0xed, 0x03, 0x5f, 0x60, 0x26,
					0xaf, 0x27, 0x6c, 0x35, 0xc0, 0xb3, 0x74, 0x1b, 0x36,
					0x5e, 0x5f, 0x76, 0xca, 0x09, 0x1b, 0x4e, 0x8c, 0x29,
					0xe2, 0xf0, 0xbe, 0xfe, 0xe6, 0x03, 0x59, 0x5a, 0xa8,
					0x32, 0x2d, 0x60, 0x2d, 0x2e, 0x62, 0x5e, 0x95, 0xeb,
					0x81, 0xb2, 0xf1, 0xc9, 0x72, 0x4e, 0x82, 0x2e, 0xca,
					0x76, 0xdb, 0x86, 0x18, 0xcf, 0x09, 0xc5, 0x34, 0x35,
					0x03, 0xa4, 0x36, 0x08, 0x35, 0xb5, 0x90, 0x3b, 0xc6,
					0x37, 0xe3, 0x87, 0x9f, 0xb0, 0x5e, 0x0e, 0xf3, 0x26,
					0x85, 0xd5, 0xae, 0xc5, 0x06, 0x7c, 0xd7, 0xcc, 0x96,
					0xfe, 0x4b, 0x26, 0x70, 0xb6, 0xea, 0xc3, 0x06, 0x6b,
					0x1f, 0xcf, 0x56, 0x86, 0xb6, 0x85, 0x89, 0xaa, 0xfb,
					0x7d, 0x62, 0x9b, 0x02, 0xd8, 0xf8, 0x62, 0x5c, 0xa3,
					0x83, 0x36, 0x24, 0xd4, 0x80, 0x0f, 0xb0, 0x81, 0xb1,
					0xcf, 0x94, 0xeb,
				},
			},
		},
	},
	// Key 10
	{"ae45ed5601cec6b8cc05f803935c674ddbe0d75c4c09fd7951fc6b0caec313a8df39970c518bffba5ed68f3f0d7f22a4029d413f1ae07e4ebe9e4177ce23e7f5404b569e4ee1bdcf3c1fb03ef113802d4f855eb9b5134b5a7c8085adcae6fa2fa1417ec3763be171b0c62b760ede23c12ad92b980884c641f5a8fac26bdad4a03381a22fe1b754885094c82506d4019a535a286afeb271bb9ba592de18dcf600c2aeeae56e02f7cf79fc14cf3bdc7cd84febbbf950ca90304b2219a7aa063aefa2c3c1980e560cd64afe779585b6107657b957857efde6010988ab7de417fc88d8f384c4e6e72c3f943e0c31c0c4a5cc36f879d8a3ac9d7d59860eaada6b83bb",
		65537,
		"056b04216fe5f354ac77250a4b6b0c8525a85c59b0bd80c56450a22d5f438e596a333aa875e291dd43f48cb88b9d5fc0d499f9fcd1c397f9afc070cd9e398c8d19e61db7c7410a6b2675dfbf5d345b804d201add502d5ce2dfcb091ce9997bbebe57306f383e4d588103f036f7e85d1934d152a323e4a8db451d6f4a5b1b0f102cc150e02feee2b88dea4ad4c1baccb24d84072d14e1d24a6771f7408ee30564fb86d4393a34bcf0b788501d193303f13a2284b001f0f649eaf79328d4ac5c430ab4414920a9460ed1b7bc40ec653e876d09abc509ae45b525190116a0c26101848298509c1c3bf3a483e7274054e15e97075036e989f60932807b5257751e79",
		[]testEncryptOAEPMessage{
			// Example 10.1
			{
				[]byte{0x8b, 0xba, 0x6b, 0xf8, 0x2a, 0x6c, 0x0f, 0x86,
					0xd5, 0xf1, 0x75, 0x6e, 0x97, 0x95, 0x68, 0x70, 0xb0,
					0x89, 0x53, 0xb0, 0x6b, 0x4e, 0xb2, 0x05, 0xbc, 0x16,
					0x94, 0xee,
				},
				[]byte{0x47, 0xe1, 0xab, 0x71, 0x19, 0xfe, 0xe5, 0x6c,
					0x95, 0xee, 0x5e, 0xaa, 0xd8, 0x6f, 0x40, 0xd0, 0xaa,
					0x63, 0xbd, 0x33,
				},
				[]byte{0x53, 0xea, 0x5d, 0xc0, 0x8c, 0xd2, 0x60, 0xfb,
					0x3b, 0x85, 0x85, 0x67, 0x28, 0x7f, 0xa9, 0x15, 0x52,
					0xc3, 0x0b, 0x2f, 0xeb, 0xfb, 0xa2, 0x13, 0xf0, 0xae,
					0x87, 0x70, 0x2d, 0x06, 0x8d, 0x19, 0xba, 0xb0, 0x7f,
					0xe5, 0x74, 0x52, 0x3d, 0xfb, 0x42, 0x13, 0x9d, 0x68,
					0xc3, 0xc5, 0xaf, 0xee, 0xe0, 0xbf, 0xe4, 0xcb, 0x79,
					0x69, 0xcb, 0xf3, 0x82, 0xb8, 0x04, 0xd6, 0xe6, 0x13,
					0x96, 0x14, 0x4e, 0x2d, 0x0e, 0x60, 0x74, 0x1f, 0x89,
					0x93, 0xc3, 0x01, 0x4b, 0x58, 0xb9, 0xb1, 0x95, 0x7a,
					0x8b, 0xab, 0xcd, 0x23, 0xaf, 0x85, 0x4f, 0x4c, 0x35,
					0x6f, 0xb1, 0x66, 0x2a, 0xa7, 0x2b, 0xfc, 0xc7, 0xe5,
					0x86, 0x55, 0x9d, 0xc4, 0x28, 0x0d, 0x16, 0x0c, 0x12,
					0x67, 0x85, 0xa7, 0x23, 0xeb, 0xee, 0xbe, 0xff, 0x71,
					0xf1, 0x15, 0x94, 0x44, 0x0a, 0xae, 0xf8, 0x7d, 0x10,
					0x79, 0x3a, 0x87, 0x74, 0xa2, 0x39, 0xd4, 0xa0, 0x4c,
					0x87, 0xfe, 0x14, 0x67, 0xb9, 0xda, 0xf8, 0x52, 0x08,
					0xec, 0x6c, 0x72, 0x55, 0x79, 0x4a, 0x96, 0xcc, 0x29,
					0x14, 0x2f, 0x9a, 0x8b, 0xd4, 0x18, 0xe3, 0xc1, 0xfd,
					0x67, 0x34, 0x4b, 0x0c, 0xd0, 0x82, 0x9d, 0xf3, 0xb2,
					0xbe, 0xc6, 0x02, 0x53, 0x19, 0x62, 0x93, 0xc6, 0xb3,
					0x4d, 0x3f, 0x75, 0xd3, 0x2f, 0x21, 0x3d, 0xd4, 0x5c,
					0x62, 0x73, 0xd5, 0x05, 0xad, 0xf4, 0xcc, 0xed, 0x10,
					0x57, 0xcb, 0x75, 0x8f, 0xc2, 0x6a, 0xee, 0xfa, 0x44,
					0x12, 0x55, 0xed, 0x4e, 0x64, 0xc1, 0x99, 0xee, 0x07,
					0x5e, 0x7f, 0x16, 0x64, 0x61, 0x82, 0xfd, 0xb4, 0x64,
					0x73, 0x9b, 0x68, 0xab, 0x5d, 0xaf, 0xf0, 0xe6, 0x3e,
					0x95, 0x52, 0x01, 0x68, 0x24, 0xf0, 0x54, 0xbf, 0x4d,
					0x3c, 0x8c, 0x90, 0xa9, 0x7b, 0xb6, 0xb6, 0x55, 0x32,
					0x84, 0xeb, 0x42, 0x9f, 0xcc,
				},
			},
		},
	},
}

func TestPSmallerThanQ(t *testing.T) {
	// This key has a 256-bit P and a 257-bit Q.
	k := parseKey(testingKey(`-----BEGIN RSA TESTING KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00
-----END RSA TESTING KEY-----`))
	t.Setenv("GODEBUG", "rsa1024min=0")
	if boring.Enabled {
		t.Skip("BoringCrypto mode returns the wrong error from SignPSS")
	}
	testEverything(t, k)
}
```