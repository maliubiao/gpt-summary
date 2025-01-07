Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The primary goal is to understand the functionality of the Go code located in `go/src/crypto/ed25519/ed25519_test.go`. Specifically, we need to identify what this code tests.

2. **Initial Scan and Keywords:** Quickly scan the code for common testing patterns and relevant keywords. Look for:
    * `package ed25519`:  Confirms this is related to the ed25519 cryptographic algorithm.
    * `import`:  See what other packages are used. `testing`, `bytes`, `crypto`, `encoding/hex`, `os`, `strings` are all strong indicators of testing and data manipulation.
    * Function names starting with `Test`: These are standard Go test functions. This is a major clue that the file is about *testing* the `ed25519` package.
    * Function names starting with `Benchmark`:  Indicates performance testing.
    * `Example_`: Shows usage examples.

3. **Categorize the Tests:** Based on the function names, categorize the tests:
    * **Key Generation:** `TestGenerateKey`, `BenchmarkKeyGeneration`, `BenchmarkNewKeyFromSeed`
    * **Signing and Verification:** `TestSignVerify`, `TestSignVerifyHashed`, `TestSignVerifyContext`, `BenchmarkSigning`, `BenchmarkVerification`
    * **Crypto.Signer Interface:** `TestCryptoSigner`
    * **Equality:** `TestEqual`
    * **Golden Tests (External Data):** `TestGolden`
    * **Malleability:** `TestMalleability`
    * **Allocation Testing:** `TestAllocations`
    * **Context Option:** `Example_ed25519ctx`

4. **Analyze Individual Test Functions:**  For each test function, determine what specific aspect of the `ed25519` package it's verifying.

    * **`TestGenerateKey`:** Checks if key generation produces keys of the correct size, that the public key matches the private key, and that generating keys multiple times produces different keys. It also verifies that generating from a seed works as expected.
    * **`TestSignVerify`:**  Tests basic signing and verification with a generated key pair.
    * **`TestSignVerifyHashed`:** Verifies signing and verifying pre-hashed messages, using test vectors from RFC 8032. It also explores the `Options` struct for specifying the hash function.
    * **`TestSignVerifyContext`:** Tests signing and verification using the `Context` option, also using RFC 8032 test vectors.
    * **`TestCryptoSigner`:** Checks if the `ed25519` private key correctly implements the `crypto.Signer` interface.
    * **`TestEqual`:**  Verifies the `Equal` method for public and private keys.
    * **`TestGolden`:**  Loads external test vectors from a file (`sign.input.gz`) and checks signing and verification against these known good values. This is crucial for ensuring compatibility and correctness.
    * **`TestMalleability`:**  Specifically tests for signature malleability, a security concern where a valid signature can be modified to create another valid signature for the same message. Ed25519 is designed to prevent this.
    * **`TestAllocations`:** Uses `cryptotest` to check if the signing and verification process allocates any memory. This is important for performance-sensitive applications.
    * **`Example_ed25519ctx`:** Demonstrates the usage of the `Context` option during signing and verification.

5. **Infer Go Functionality:** Based on the tests, deduce the core functionalities of the `ed25519` package:
    * **Key Generation:**  `GenerateKey`, `NewKeyFromSeed`
    * **Signing:** `Sign` (and the `Sign` method on the private key)
    * **Verification:** `Verify`, `VerifyWithOptions`
    * **Key Representation:** `PublicKey`, `PrivateKey`
    * **Options:**  The `Options` struct allows specifying hash functions and context.
    * **Crypto.Signer Interface Implementation:**  Allows using `ed25519.PrivateKey` with generic crypto functions.

6. **Create Go Code Examples:**  Construct illustrative Go code snippets demonstrating the inferred functionalities. Use clear variable names and comments. Include potential inputs and expected outputs where appropriate.

7. **Identify Potential Pitfalls:** Think about how a developer might misuse the `ed25519` package based on the tests:
    * **Mismatched Contexts:** The `TestSignVerifyContext` highlights the importance of using the same context during signing and verification.
    * **Incorrect Hashing:** The `TestSignVerifyHashed` shows that specifying the correct hash function is crucial when signing pre-hashed messages.

8. **Command-Line Arguments (If Applicable):** In this specific case, the code doesn't directly process command-line arguments. The `go test` command is used to run these tests, but the *test code itself* doesn't have explicit command-line handling logic.

9. **Structure the Answer:** Organize the findings logically using headings and bullet points for clarity. Start with a general overview and then delve into specifics. Provide code examples and explanations.

10. **Review and Refine:**  Read through the generated answer to ensure accuracy, completeness, and clarity. Correct any errors or omissions. Make sure the language is natural and easy to understand. For example, initially, I might have missed the nuance of `GenerateKey` being equivalent to `NewKeyFromSeed` when a seed is provided, but the test case clarifies this. Similarly,  paying attention to the import statements like `crypto` helps in understanding the role of the `crypto.Signer` interface.
这段代码是 Go 语言 `crypto/ed25519` 包的一部分，具体来说，是 `ed25519_test.go` 文件，它包含了对 `ed25519` 包中 Ed25519 签名算法的各种功能进行测试的代码。

以下是它主要的功能列表：

1. **测试密钥生成 (`TestGenerateKey`)**:
   - 验证 `GenerateKey` 函数是否能够正确生成公钥和私钥对。
   - 检查生成的公钥和私钥的长度是否符合预期 (`PublicKeySize`, `PrivateKeySize`)。
   - 验证从私钥中提取的公钥是否与生成的公钥一致。
   - 验证使用私钥的种子 (`Seed()`) 重新创建的私钥是否与原始私钥一致。
   - 确保多次调用 `GenerateKey` 生成的密钥对是不同的。

2. **测试基本的签名和验证 (`TestSignVerify`)**:
   - 使用 `GenerateKey` 生成密钥对。
   - 使用私钥对消息进行签名 (`Sign`)。
   - 使用公钥验证签名是否有效 (`Verify`)。
   - 验证对不同消息的签名无法通过验证。

3. **测试哈希消息的签名和验证 (`TestSignVerifyHashed`)**:
   - 使用预定义的密钥、消息和签名（来自 RFC 8032）。
   - 使用私钥对消息的哈希值进行签名 (`private.Sign(nil, hash[:], crypto.SHA512)`)。
   - 验证生成的签名是否与预期的签名一致。
   - 使用 `VerifyWithOptions` 函数并指定哈希算法 (`&Options{Hash: crypto.SHA512}`) 来验证签名。
   - 验证使用错误的哈希算法进行验证应该失败。
   - 验证对不同哈希值的签名无法通过验证。
   - 测试带上下文的哈希消息签名和验证 (`&Options{Hash: crypto.SHA512, Context: "123"}`).

4. **测试带上下文的签名和验证 (`TestSignVerifyContext`)**:
   - 使用预定义的密钥、消息、上下文和签名（来自 RFC 8032）。
   - 使用私钥对消息进行带上下文的签名 (`private.Sign(nil, message, &Options{Context: context})`)。
   - 验证生成的签名是否与预期的签名一致。
   - 使用 `VerifyWithOptions` 函数并指定相同的上下文来验证签名。
   - 验证使用不同的消息或上下文进行验证应该失败。

5. **测试 `crypto.Signer` 接口的实现 (`TestCryptoSigner`)**:
   - 验证 `ed25519.PrivateKey` 类型是否实现了 `crypto.Signer` 接口。
   - 检查通过 `crypto.Signer.Public()` 获取的公钥是否与原始公钥一致。
   - 使用 `crypto.Signer.Sign()` 方法进行签名，并验证签名结果。

6. **测试密钥的相等性 (`TestEqual`)**:
   - 验证公钥和私钥的 `Equal` 方法是否能正确判断密钥是否相等。

7. **进行黄金测试 (`TestGolden`)**:
   - 从外部文件 `testdata/sign.input.gz` 加载测试向量（包含私钥、公钥、消息和签名）。
   - 使用加载的私钥对消息进行签名，并与测试向量中的签名进行比较。
   - 使用加载的公钥验证签名是否有效。
   - 验证从种子重新生成的密钥对是否与测试向量中的密钥一致。

8. **测试签名的可塑性 (`TestMalleability`)**:
   - 验证 Ed25519 签名是否具有抗可塑性，即无法通过修改现有签名来创建另一个有效的签名。

9. **测试内存分配 (`TestAllocations`)**:
   - 使用 `cryptotest` 包检查密钥生成、签名和验证过程中是否发生了不必要的内存分配。

10. **性能基准测试 (`BenchmarkKeyGeneration`, `BenchmarkNewKeyFromSeed`, `BenchmarkSigning`, `BenchmarkVerification`)**:
    - 衡量密钥生成、从种子创建密钥、签名和验证操作的性能。

11. **示例代码 (`Example_ed25519ctx`)**:
    - 提供了一个使用带上下文签名的示例。

**推断的 Go 语言功能实现及代码示例:**

这段测试代码主要测试了 `crypto/ed25519` 包提供的以下功能：

* **密钥生成:** `GenerateKey(rand io.Reader)` 和 `NewKeyFromSeed(seed []byte) PrivateKey`
* **签名:** `Sign(privateKey PrivateKey, message []byte) []byte` 和 `(priv PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)`
* **验证:** `Verify(publicKey PublicKey, message, sig []byte) bool` 和 `VerifyWithOptions(pub PublicKey, message, sig []byte, opts *Options) error`
* **公钥和私钥类型:** `PublicKey` 和 `PrivateKey`
* **签名选项:** `Options` 结构体，用于指定签名时的选项，如上下文和哈希算法。

**Go 代码示例:**

```go
package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
)

func main() {
	// 密钥生成
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("公钥: %x\n", public)
	fmt.Printf("私钥: %x\n", private)

	// 签名
	message := []byte("这是一个测试消息")
	signature := ed25519.Sign(private, message)
	fmt.Printf("签名: %x\n", signature)

	// 验证
	isValid := ed25519.Verify(public, message, signature)
	fmt.Println("签名是否有效:", isValid)

	// 使用 Options 进行带上下文的签名和验证
	ctx := "my_application"
	sigWithOptions, err := private.Sign(rand.Reader, message, &ed25519.Options{Context: ctx})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("带上下文的签名: %x\n", sigWithOptions)

	isValidWithOptions := ed25519.VerifyWithOptions(public, message, sigWithOptions, &ed25519.Options{Context: ctx})
	fmt.Println("带上下文的签名是否有效:", isValidWithOptions)

	// 使用 Options 指定哈希算法进行签名和验证 (针对预哈希的消息)
	hashedMessage := crypto.SHA512.New().Sum(message)
	sigWithHash, err := private.Sign(rand.Reader, hashedMessage, &ed25519.Options{Hash: crypto.SHA512})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("带哈希的签名: %x\n", sigWithHash)

	isValidWithHash := ed25519.VerifyWithOptions(public, hashedMessage, sigWithHash, &ed25519.Options{Hash: crypto.SHA512})
	fmt.Println("带哈希的签名是否有效:", isValidWithHash)
}
```

**假设的输入与输出:**

由于密钥是随机生成的，每次运行的结果都会不同。但输出格式会类似：

```
公钥: [一串1]
私钥: [一串2]
签名: [一串3]
签名是否有效: true
带上下文的签名: [一串4]
带上下文的签名是否有效: true
带哈希的签名: [一串5]
带哈希的签名是否有效: true
```

**命令行参数处理:**

这段测试代码本身不直接处理命令行参数。它是通过 Go 的 `testing` 包来运行的，通常使用 `go test ./crypto/ed25519` 命令。 `go test` 命令本身有一些参数，例如 `-v` (显示详细输出) 和 `-bench` (运行基准测试)，但这与 `ed25519_test.go` 的内部逻辑无关。

**使用者易犯错的点:**

1. **上下文不匹配:**  使用 `Options` 中的 `Context` 进行签名后，**验证时必须使用相同的 `Context`**。如果上下文不一致，验证将会失败。

   ```go
   // 签名时使用上下文 "app1"
   sig, _ := private.Sign(rand.Reader, message, &ed25519.Options{Context: "app1"})

   // 验证时使用错误的上下文 "app2"，验证会失败
   isValid := ed25519.VerifyWithOptions(public, message, sig, &ed25519.Options{Context: "app2"})
   fmt.Println("验证是否有效:", isValid) // 输出: false
   ```

2. **哈希算法不匹配:**  如果使用 `Options` 中的 `Hash` 指定了哈希算法进行签名，**验证时也必须指定相同的哈希算法**。

   ```go
   // 使用 SHA512 对消息的哈希进行签名
   hashed := crypto.SHA512.Sum(message)
   sig, _ := private.Sign(rand.Reader, hashed[:], &ed25519.Options{Hash: crypto.SHA512})

   // 验证时错误地使用了 SHA256，验证会失败
   isValid := ed25519.VerifyWithOptions(public, hashed[:], sig, &ed25519.Options{Hash: crypto.SHA256})
   fmt.Println("验证是否有效:", isValid) // 输出: false
   ```

总而言之，`ed25519_test.go` 是一个全面的测试文件，用于确保 `crypto/ed25519` 包提供的 Ed25519 签名算法的实现是正确、安全且高效的。它覆盖了密钥生成、签名、验证以及使用各种选项的场景。

Prompt: 
```
这是路径为go/src/crypto/ed25519/ed25519_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ed25519

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/internal/cryptotest"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"log"
	"os"
	"strings"
	"testing"
)

func Example_ed25519ctx() {
	pub, priv, err := GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("The quick brown fox jumps over the lazy dog")

	sig, err := priv.Sign(nil, msg, &Options{
		Context: "Example_ed25519ctx",
	})
	if err != nil {
		log.Fatal(err)
	}

	if err := VerifyWithOptions(pub, msg, sig, &Options{
		Context: "Example_ed25519ctx",
	}); err != nil {
		log.Fatal("invalid signature")
	}
}

func TestGenerateKey(t *testing.T) {
	// nil is like using crypto/rand.Reader.
	public, private, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(public) != PublicKeySize {
		t.Errorf("public key has the wrong size: %d", len(public))
	}
	if len(private) != PrivateKeySize {
		t.Errorf("private key has the wrong size: %d", len(private))
	}
	if !bytes.Equal(private.Public().(PublicKey), public) {
		t.Errorf("public key doesn't match private key")
	}
	fromSeed := NewKeyFromSeed(private.Seed())
	if !bytes.Equal(private, fromSeed) {
		t.Errorf("recreating key pair from seed gave different private key")
	}

	_, k2, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(private, k2) {
		t.Errorf("GenerateKey returned the same private key twice")
	}

	_, k3, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(private, k3) {
		t.Errorf("GenerateKey returned the same private key twice")
	}

	// GenerateKey is documented to be the same as NewKeyFromSeed.
	seed := make([]byte, SeedSize)
	rand.Read(seed)
	_, k4, err := GenerateKey(bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	k4n := NewKeyFromSeed(seed)
	if !bytes.Equal(k4, k4n) {
		t.Errorf("GenerateKey with seed gave different private key")
	}
}

type zeroReader struct{}

func (zeroReader) Read(buf []byte) (int, error) {
	clear(buf)
	return len(buf), nil
}

func TestSignVerify(t *testing.T) {
	var zero zeroReader
	public, private, _ := GenerateKey(zero)

	message := []byte("test message")
	sig := Sign(private, message)
	if !Verify(public, message, sig) {
		t.Errorf("valid signature rejected")
	}

	wrongMessage := []byte("wrong message")
	if Verify(public, wrongMessage, sig) {
		t.Errorf("signature of different message accepted")
	}
}

func TestSignVerifyHashed(t *testing.T) {
	// From RFC 8032, Section 7.3
	key, _ := hex.DecodeString("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")
	expectedSig, _ := hex.DecodeString("98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406")
	message, _ := hex.DecodeString("616263")

	private := PrivateKey(key)
	public := private.Public().(PublicKey)
	hash := sha512.Sum512(message)
	sig, err := private.Sign(nil, hash[:], crypto.SHA512)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, expectedSig) {
		t.Error("signature doesn't match test vector")
	}
	sig, err = private.Sign(nil, hash[:], &Options{Hash: crypto.SHA512})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, expectedSig) {
		t.Error("signature doesn't match test vector")
	}
	if err := VerifyWithOptions(public, hash[:], sig, &Options{Hash: crypto.SHA512}); err != nil {
		t.Errorf("valid signature rejected: %v", err)
	}

	if err := VerifyWithOptions(public, hash[:], sig, &Options{Hash: crypto.SHA256}); err == nil {
		t.Errorf("expected error for wrong hash")
	}

	wrongHash := sha512.Sum512([]byte("wrong message"))
	if VerifyWithOptions(public, wrongHash[:], sig, &Options{Hash: crypto.SHA512}) == nil {
		t.Errorf("signature of different message accepted")
	}

	sig[0] ^= 0xff
	if VerifyWithOptions(public, hash[:], sig, &Options{Hash: crypto.SHA512}) == nil {
		t.Errorf("invalid signature accepted")
	}
	sig[0] ^= 0xff
	sig[SignatureSize-1] ^= 0xff
	if VerifyWithOptions(public, hash[:], sig, &Options{Hash: crypto.SHA512}) == nil {
		t.Errorf("invalid signature accepted")
	}

	// The RFC provides no test vectors for Ed25519ph with context, so just sign
	// and verify something.
	sig, err = private.Sign(nil, hash[:], &Options{Hash: crypto.SHA512, Context: "123"})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWithOptions(public, hash[:], sig, &Options{Hash: crypto.SHA512, Context: "123"}); err != nil {
		t.Errorf("valid signature rejected: %v", err)
	}
	if err := VerifyWithOptions(public, hash[:], sig, &Options{Hash: crypto.SHA512, Context: "321"}); err == nil {
		t.Errorf("expected error for wrong context")
	}
	if err := VerifyWithOptions(public, hash[:], sig, &Options{Hash: crypto.SHA256, Context: "123"}); err == nil {
		t.Errorf("expected error for wrong hash")
	}
}

func TestSignVerifyContext(t *testing.T) {
	// From RFC 8032, Section 7.2
	key, _ := hex.DecodeString("0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292")
	expectedSig, _ := hex.DecodeString("55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d")
	message, _ := hex.DecodeString("f726936d19c800494e3fdaff20b276a8")
	context := "foo"

	private := PrivateKey(key)
	public := private.Public().(PublicKey)
	sig, err := private.Sign(nil, message, &Options{Context: context})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, expectedSig) {
		t.Error("signature doesn't match test vector")
	}
	if err := VerifyWithOptions(public, message, sig, &Options{Context: context}); err != nil {
		t.Errorf("valid signature rejected: %v", err)
	}

	if VerifyWithOptions(public, []byte("bar"), sig, &Options{Context: context}) == nil {
		t.Errorf("signature of different message accepted")
	}
	if VerifyWithOptions(public, message, sig, &Options{Context: "bar"}) == nil {
		t.Errorf("signature with different context accepted")
	}

	sig[0] ^= 0xff
	if VerifyWithOptions(public, message, sig, &Options{Context: context}) == nil {
		t.Errorf("invalid signature accepted")
	}
	sig[0] ^= 0xff
	sig[SignatureSize-1] ^= 0xff
	if VerifyWithOptions(public, message, sig, &Options{Context: context}) == nil {
		t.Errorf("invalid signature accepted")
	}
}

func TestCryptoSigner(t *testing.T) {
	var zero zeroReader
	public, private, _ := GenerateKey(zero)

	signer := crypto.Signer(private)

	publicInterface := signer.Public()
	public2, ok := publicInterface.(PublicKey)
	if !ok {
		t.Fatalf("expected PublicKey from Public() but got %T", publicInterface)
	}

	if !bytes.Equal(public, public2) {
		t.Errorf("public keys do not match: original:%x vs Public():%x", public, public2)
	}

	message := []byte("message")
	var noHash crypto.Hash
	signature, err := signer.Sign(zero, message, noHash)
	if err != nil {
		t.Fatalf("error from Sign(): %s", err)
	}

	signature2, err := signer.Sign(zero, message, &Options{Hash: noHash})
	if err != nil {
		t.Fatalf("error from Sign(): %s", err)
	}
	if !bytes.Equal(signature, signature2) {
		t.Errorf("signatures keys do not match")
	}

	if !Verify(public, message, signature) {
		t.Errorf("Verify failed on signature from Sign()")
	}
}

func TestEqual(t *testing.T) {
	public, private, _ := GenerateKey(rand.Reader)

	if !public.Equal(public) {
		t.Errorf("public key is not equal to itself: %q", public)
	}
	if !public.Equal(crypto.Signer(private).Public()) {
		t.Errorf("private.Public() is not Equal to public: %q", public)
	}
	if !private.Equal(private) {
		t.Errorf("private key is not equal to itself: %q", private)
	}

	otherPub, otherPriv, _ := GenerateKey(rand.Reader)
	if public.Equal(otherPub) {
		t.Errorf("different public keys are Equal")
	}
	if private.Equal(otherPriv) {
		t.Errorf("different private keys are Equal")
	}
}

func TestGolden(t *testing.T) {
	// sign.input.gz is a selection of test cases from
	// https://ed25519.cr.yp.to/python/sign.input
	testDataZ, err := os.Open("testdata/sign.input.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer testDataZ.Close()
	testData, err := gzip.NewReader(testDataZ)
	if err != nil {
		t.Fatal(err)
	}
	defer testData.Close()

	scanner := bufio.NewScanner(testData)
	lineNo := 0

	for scanner.Scan() {
		lineNo++

		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) != 5 {
			t.Fatalf("bad number of parts on line %d", lineNo)
		}

		privBytes, _ := hex.DecodeString(parts[0])
		pubKey, _ := hex.DecodeString(parts[1])
		msg, _ := hex.DecodeString(parts[2])
		sig, _ := hex.DecodeString(parts[3])
		// The signatures in the test vectors also include the message
		// at the end, but we just want R and S.
		sig = sig[:SignatureSize]

		if l := len(pubKey); l != PublicKeySize {
			t.Fatalf("bad public key length on line %d: got %d bytes", lineNo, l)
		}

		var priv [PrivateKeySize]byte
		copy(priv[:], privBytes)
		copy(priv[32:], pubKey)

		sig2 := Sign(priv[:], msg)
		if !bytes.Equal(sig, sig2[:]) {
			t.Errorf("different signature result on line %d: %x vs %x", lineNo, sig, sig2)
		}

		if !Verify(pubKey, msg, sig2) {
			t.Errorf("signature failed to verify on line %d", lineNo)
		}

		priv2 := NewKeyFromSeed(priv[:32])
		if !bytes.Equal(priv[:], priv2) {
			t.Errorf("recreating key pair gave different private key on line %d: %x vs %x", lineNo, priv[:], priv2)
		}

		if pubKey2 := priv2.Public().(PublicKey); !bytes.Equal(pubKey, pubKey2) {
			t.Errorf("recreating key pair gave different public key on line %d: %x vs %x", lineNo, pubKey, pubKey2)
		}

		if seed := priv2.Seed(); !bytes.Equal(priv[:32], seed) {
			t.Errorf("recreating key pair gave different seed on line %d: %x vs %x", lineNo, priv[:32], seed)
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("error reading test data: %s", err)
	}
}

func TestMalleability(t *testing.T) {
	// https://tools.ietf.org/html/rfc8032#section-5.1.7 adds an additional test
	// that s be in [0, order). This prevents someone from adding a multiple of
	// order to s and obtaining a second valid signature for the same message.
	msg := []byte{0x54, 0x65, 0x73, 0x74}
	sig := []byte{
		0x7c, 0x38, 0xe0, 0x26, 0xf2, 0x9e, 0x14, 0xaa, 0xbd, 0x05, 0x9a,
		0x0f, 0x2d, 0xb8, 0xb0, 0xcd, 0x78, 0x30, 0x40, 0x60, 0x9a, 0x8b,
		0xe6, 0x84, 0xdb, 0x12, 0xf8, 0x2a, 0x27, 0x77, 0x4a, 0xb0, 0x67,
		0x65, 0x4b, 0xce, 0x38, 0x32, 0xc2, 0xd7, 0x6f, 0x8f, 0x6f, 0x5d,
		0xaf, 0xc0, 0x8d, 0x93, 0x39, 0xd4, 0xee, 0xf6, 0x76, 0x57, 0x33,
		0x36, 0xa5, 0xc5, 0x1e, 0xb6, 0xf9, 0x46, 0xb3, 0x1d,
	}
	publicKey := []byte{
		0x7d, 0x4d, 0x0e, 0x7f, 0x61, 0x53, 0xa6, 0x9b, 0x62, 0x42, 0xb5,
		0x22, 0xab, 0xbe, 0xe6, 0x85, 0xfd, 0xa4, 0x42, 0x0f, 0x88, 0x34,
		0xb1, 0x08, 0xc3, 0xbd, 0xae, 0x36, 0x9e, 0xf5, 0x49, 0xfa,
	}

	if Verify(publicKey, msg, sig) {
		t.Fatal("non-canonical signature accepted")
	}
}

func TestAllocations(t *testing.T) {
	cryptotest.SkipTestAllocations(t)
	if allocs := testing.AllocsPerRun(100, func() {
		seed := make([]byte, SeedSize)
		message := []byte("Hello, world!")
		priv := NewKeyFromSeed(seed)
		pub := priv.Public().(PublicKey)
		signature := Sign(priv, message)
		if !Verify(pub, message, signature) {
			t.Fatal("signature didn't verify")
		}
	}); allocs > 0 {
		t.Errorf("expected zero allocations, got %0.1f", allocs)
	}
}

func BenchmarkKeyGeneration(b *testing.B) {
	var zero zeroReader
	for i := 0; i < b.N; i++ {
		if _, _, err := GenerateKey(zero); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewKeyFromSeed(b *testing.B) {
	seed := make([]byte, SeedSize)
	for i := 0; i < b.N; i++ {
		_ = NewKeyFromSeed(seed)
	}
}

func BenchmarkSigning(b *testing.B) {
	var zero zeroReader
	_, priv, err := GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sign(priv, message)
	}
}

func BenchmarkVerification(b *testing.B) {
	var zero zeroReader
	pub, priv, err := GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	signature := Sign(priv, message)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(pub, message, signature)
	}
}

"""



```