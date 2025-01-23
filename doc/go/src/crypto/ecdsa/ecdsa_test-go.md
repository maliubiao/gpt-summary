Response:
Let's break down the thought process to analyze the provided Go code snippet.

1. **Identify the Purpose:** The file path `go/src/crypto/ecdsa/ecdsa_test.go` immediately suggests this is a test file for the `ecdsa` package in Go's standard library. The `_test.go` suffix confirms this.

2. **High-Level Overview:**  Scan the import statements. They reveal the core functionalities being tested: `crypto`, `crypto/elliptic` (for elliptic curve cryptography), hashing algorithms (`sha1`, `sha256`, `sha512`), random number generation (`crypto/rand`), encoding (`encoding/hex`), input/output (`io`, `os`, `bufio`, `compress/bzip2`), and the testing framework (`testing`). This gives a good initial grasp of the scope.

3. **Core Functionality Focus:** The package name `ecdsa` tells us this is about the Elliptic Curve Digital Signature Algorithm. Therefore, the tests will likely revolve around key generation, signing, and verification.

4. **Test Function Analysis (Iterative Approach):**  Go through each test function:
    * `TestAllCurves`:  A helper function. It iterates through standard elliptic curves (P224, P256, P384, P521) and calls a provided function `f` for each. The `cryptotest.TestAllImplementations` part suggests it's also testing different underlying implementations if they exist. The `genericParamsForCurve` function is interesting – it seems designed to force the usage of a generic, non-optimized curve implementation.
    * `TestKeyGeneration`: Tests the `GenerateKey` function. It checks if the generated public key lies on the expected elliptic curve.
    * `TestSignAndVerify`: Tests the basic signing (`Sign`) and verification (`Verify`) process. It verifies that a valid signature works and an altered message fails verification.
    * `TestSignAndVerifyASN1`: Similar to the previous one, but uses `SignASN1` and `VerifyASN1`, indicating testing of signatures encoded in ASN.1 format.
    * `TestNonceSafety`:  Focuses on ensuring the signing process uses a unique nonce (random number) for different messages, even with the same key. The `zeroReader` is a clever way to force deterministic nonce generation for testing purposes. This is crucial for the security of ECDSA.
    * `TestINDCCA`: Tests the Indistinguishability under Chosen-Ciphertext Attack property (though adapted for signatures). It verifies that two signatures of the *same* message are different, highlighting the randomness in the signing process.
    * `TestVectors`: This is crucial. The comment clearly states it's loading and verifying signatures against NIST test vectors. This is a standard practice to ensure the implementation conforms to the specification. Pay attention to how it reads the compressed file, parses the lines, and extracts parameters.
    * `TestNegativeInputs`, `TestZeroHashSignature`, `TestZeroSignature`, `TestNegativeSignature`, `TestRPlusNSignature`, `TestRMinusNSignature`: These test edge cases and potential vulnerabilities. They check how the implementation handles invalid or unusual inputs for the signature components (r and s) and the message hash. These are important for robustness.
    * `TestRFC6979`: Tests the implementation of RFC 6979, a standard for deterministic ECDSA signature generation. It uses hardcoded private keys, public keys, messages, and expected signatures to verify correctness.
    * `BenchmarkSign`, `BenchmarkVerify`, `BenchmarkGenerateKey`: These are performance tests (benchmarks) to measure the speed of key generation, signing, and verification for different curves.

5. **Inferring Go Language Features:** Based on the tested functions and imports, infer the corresponding Go functions:
    * Key generation: Likely `ecdsa.GenerateKey(elliptic.Curve, io.Reader) (*ecdsa.PrivateKey, error)`
    * Signing: Likely `ecdsa.Sign(io.Reader, *ecdsa.PrivateKey, []byte) (*big.Int, *big.Int, error)` (raw r, s) and `ecdsa.SignASN1(io.Reader, *ecdsa.PrivateKey, []byte) ([]byte, error)` (ASN.1 encoded).
    * Verification: Likely `ecdsa.Verify(*ecdsa.PublicKey, []byte, *big.Int, *big.Int) bool` and `ecdsa.VerifyASN1(*ecdsa.PublicKey, []byte, []byte) bool`.

6. **Code Example Construction:** Select a representative test, like `TestSignAndVerify`, and construct a simplified example demonstrating the core functionality. Include the necessary imports and steps. Think about basic inputs and expected outputs.

7. **Command-Line Parameters:** Since this is a test file, it doesn't directly process command-line arguments for its *own* execution. However, the `testing` package itself uses command-line flags like `-test.short` which affects the `TestAllCurves` function.

8. **Common Mistakes:** Think about potential errors users might make when *using* the `ecdsa` package, based on the tests:
    * Reusing nonces (addressed by `TestNonceSafety`).
    * Not hashing the message correctly before signing/verifying.
    * Using the wrong public key for verification.
    * Mishandling ASN.1 encoding if using `SignASN1`/`VerifyASN1`.

9. **Review and Refine:**  Go back through the analysis to ensure accuracy and completeness. Check if the code examples are clear and the explanations are easy to understand.

This systematic approach, focusing on understanding the purpose, analyzing individual tests, inferring functionality, and considering user implications, allows for a comprehensive analysis of the provided Go code.
这段代码是Go语言标准库 `crypto/ecdsa` 包的一部分，它是一个测试文件 (`ecdsa_test.go`)，专门用于测试椭圆曲线数字签名算法 (ECDSA) 的实现是否正确。

**功能列表:**

1. **测试不同椭圆曲线的密钥生成:**  `TestKeyGeneration` 和 `testKeyGeneration` 函数会针对不同的椭圆曲线 (P224, P256, P384, P521) 测试密钥对的生成功能。它会检查生成的公钥是否确实在所选的椭圆曲线上。
2. **测试签名和验证功能 (原始格式):** `TestSignAndVerify` 和 `testSignAndVerify` 函数测试使用原始的 `r` 和 `s` 值进行签名和验证的功能。它会生成一个签名，然后验证该签名对于原始消息是否有效，并验证修改后的消息是否无法通过验证。
3. **测试签名和验证功能 (ASN.1 格式):** `TestSignAndVerifyASN1` 和 `testSignAndVerifyASN1` 函数测试使用 ASN.1 编码的签名进行签名和验证的功能。类似于原始格式的测试，它也会验证正确签名和错误签名的场景。
4. **测试签名的随机性 (Nonce 安全性):** `TestNonceSafety` 和 `testNonceSafety` 函数旨在验证 ECDSA 签名过程中使用的随机数 (nonce) 的安全性。它会使用相同的密钥对两个不同的消息进行签名，并断言生成的签名不同。这防止了攻击者通过观察多个签名来推断私钥。
5. **测试签名的不可区分性 (IND-CCA):** `TestINDCCA` 和 `testINDCCA` 函数测试对相同消息进行多次签名是否会产生不同的结果。这验证了签名过程的随机性，防止攻击者通过多次签名来获取额外信息。
6. **使用 NIST 测试向量进行验证:** `TestVectors` 和 `testVectors` 函数使用来自 NIST (美国国家标准与技术研究院) 的官方测试向量来验证 ECDSA 实现的正确性。它会读取包含预先计算好的密钥、消息和签名的文件，并用当前的实现进行验证，确保结果一致。这对于确保与其他 ECDSA 实现的互操作性至关重要。
7. **测试负面输入:** `TestNegativeInputs` 和 `testNegativeInputs` 函数测试当输入无效的签名值 (例如，负数的 `r` 值) 时，验证功能是否会正确拒绝。这有助于提高代码的鲁棒性。
8. **测试零哈希签名:** `TestZeroHashSignature` 和 `testZeroHashSignature` 函数测试对一个全部为零的哈希值进行签名和验证的情况。
9. **测试零签名:** `TestZeroSignature` 和 `testZeroSignature` 函数测试当签名值 `r` 和 `s` 都为零时，验证功能是否会正确拒绝。
10. **测试负签名值:** `TestNegativeSignature` 和 `testNegativeSignature` 函数测试当签名值 `r` 为负数时，验证功能是否会正确拒绝。
11. **测试 `r + n` 和 `r - n` 的签名值:** `TestRPlusNSignature` 和 `TestRMinusNSignature` 函数测试当签名值 `r` 为 `r + n` 或 `r - n` (其中 `n` 是椭圆曲线的阶) 时，验证功能是否会正确拒绝。这是因为在数学上，`r` 和 `r +/- n` 代表相同的点。
12. **测试 RFC 6979 规定的确定性签名:** `TestRFC6979` 和 `testRFC6979` 函数测试了 RFC 6979 中定义的确定性 ECDSA 签名生成方法。它使用预定义的密钥和消息来生成签名，并与预期的签名进行比较，确保实现的正确性。确定性签名对于避免因随机数生成器的缺陷而导致的安全漏洞非常重要。
13. **性能基准测试:** `BenchmarkSign`, `BenchmarkVerify`, 和 `BenchmarkGenerateKey` 函数用于衡量签名、验证和密钥生成操作的性能。

**推理它是什么 Go 语言功能的实现:**

基于测试内容，可以推断出 `crypto/ecdsa` 包实现了以下 Go 语言功能：

* **密钥对生成:**  生成 ECDSA 的公钥和私钥对。
* **签名:** 使用私钥对消息的哈希值进行签名，可以生成原始的 `r` 和 `s` 值，也可以生成 ASN.1 编码的签名。
* **验证:** 使用公钥验证给定消息哈希值和签名的有效性。
* **支持多种椭圆曲线:**  支持 NIST 定义的常用椭圆曲线，如 P224, P256, P384, P521。
* **确定性签名 (RFC 6979):**  实现了 RFC 6979 中定义的确定性签名生成方法。

**Go 代码举例说明:**

```go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

func main() {
	// 1. 生成 ECDSA 密钥对 (使用 P256 曲线)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("Error generating key:", err)
		return
	}
	publicKey := &privateKey.PublicKey

	// 2. 要签名的消息
	message := []byte("This is a test message")

	// 3. 计算消息的 SHA256 哈希值
	hashed := sha256.Sum256(message)

	// 4. 使用私钥对哈希值进行签名 (生成原始的 r 和 s 值)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
	if err != nil {
		fmt.Println("Error signing:", err)
		return
	}
	fmt.Printf("Signature (r, s): %x, %x\n", r, s)

	// 5. 使用私钥对哈希值进行签名 (生成 ASN.1 编码的签名)
	signatureASN1, err := ecdsa.SignASN1(rand.Reader, privateKey, hashed[:])
	if err != nil {
		fmt.Println("Error signing (ASN.1):", err)
		return
	}
	fmt.Printf("Signature (ASN.1): %x\n", signatureASN1)

	// 6. 使用公钥验证原始签名
	isValid := ecdsa.Verify(publicKey, hashed[:], r, s)
	fmt.Println("Verify (raw):", isValid)

	// 7. 使用公钥验证 ASN.1 签名
	isValidASN1 := ecdsa.VerifyASN1(publicKey, hashed[:], signatureASN1)
	fmt.Println("Verify (ASN.1):", isValidASN1)

	// 8. 尝试验证修改后的消息
	modifiedMessage := []byte("This is a modified message")
	modifiedHashed := sha256.Sum256(modifiedMessage)
	isStillValid := ecdsa.Verify(publicKey, modifiedHashed[:], r, s)
	fmt.Println("Verify modified message:", isStillValid) // 预期为 false
}
```

**假设的输入与输出 (针对 `TestSignAndVerify`):**

**假设输入:**

* 使用 `elliptic.P256()` 生成的私钥 `priv`。
* 要签名的消息 `hashed := []byte("testing")`。
* `rand.Reader` 作为随机数源。

**预期输出:**

* `Sign` 函数成功返回 `r` 和 `s` (大整数)，并且 `err` 为 `nil`。
* `Verify` 函数返回 `true`，表示签名有效。
* 当 `hashed` 的第一个字节被修改后，`Verify` 函数返回 `false`。

**使用者易犯错的点:**

1. **不正确的哈希:**  ECDSA 是对消息的哈希值进行签名，而不是直接对消息签名。使用者可能会忘记先对消息进行哈希处理，或者使用了错误的哈希算法。

   ```go
   // 错误示例：直接对消息签名
   // r, s, err := ecdsa.Sign(rand.Reader, privateKey, message)

   // 正确示例：先计算哈希值
   hashed := sha256.Sum256(message)
   r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
   ```

2. **使用错误的公钥进行验证:**  验证签名时必须使用与签名时使用的私钥对应的公钥。使用不匹配的公钥会导致验证失败。

   ```go
   // 错误示例：使用了错误的公钥
   // wrongPublicKey := ...
   // isValid := ecdsa.Verify(wrongPublicKey, hashed[:], r, s)

   // 正确示例：使用正确的公钥
   isValid := ecdsa.Verify(publicKey, hashed[:], r, s)
   ```

3. **ASN.1 编码和原始格式的混淆:**  如果使用 `SignASN1` 生成了 ASN.1 编码的签名，就必须使用 `VerifyASN1` 进行验证。反之亦然。不能混用。

   ```go
   // 使用 SignASN1 生成签名
   signatureASN1, _ := ecdsa.SignASN1(rand.Reader, privateKey, hashed[:])

   // 必须使用 VerifyASN1 验证
   isValidASN1 := ecdsa.VerifyASN1(publicKey, hashed[:], signatureASN1)

   // 错误示例：使用 Verify 验证 ASN.1 签名
   // isValid := ecdsa.Verify(publicKey, hashed[:], /* 如何解析 ASN.1 获取 r 和 s 是另一回事 */)
   ```

4. **随机数生成器的错误使用:** 虽然代码中使用了 `rand.Reader`，但在某些特定场景下，用户可能需要使用更安全的随机数生成器，或者需要理解 `rand.Reader` 的局限性。对于测试目的，代码中使用了 `zeroReader` 来模拟 nonce 重用，这在实际应用中是极其危险的。

总而言之，这段测试代码覆盖了 `crypto/ecdsa` 包的核心功能，并使用多种测试方法来确保其实现的正确性和安全性。通过阅读这些测试用例，可以更深入地了解 ECDSA 算法的运作方式以及 `crypto/ecdsa` 包的使用方法。

### 提示词
```
这是路径为go/src/crypto/ecdsa/ecdsa_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ecdsa

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"crypto"
	"crypto/elliptic"
	"crypto/internal/cryptotest"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"
)

func testAllCurves(t *testing.T, f func(*testing.T, elliptic.Curve)) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P256", elliptic.P256()},
		{"P224", elliptic.P224()},
		{"P384", elliptic.P384()},
		{"P521", elliptic.P521()},
		{"P256/Generic", genericParamsForCurve(elliptic.P256())},
	}
	if testing.Short() {
		tests = tests[:1]
	}
	for _, test := range tests {
		curve := test.curve
		cryptotest.TestAllImplementations(t, "ecdsa", func(t *testing.T) {
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()
				f(t, curve)
			})
		})
	}
}

// genericParamsForCurve returns the dereferenced CurveParams for
// the specified curve. This is used to avoid the logic for
// upgrading a curve to its specific implementation, forcing
// usage of the generic implementation.
func genericParamsForCurve(c elliptic.Curve) *elliptic.CurveParams {
	d := *(c.Params())
	return &d
}

func TestKeyGeneration(t *testing.T) {
	testAllCurves(t, testKeyGeneration)
}

func testKeyGeneration(t *testing.T, c elliptic.Curve) {
	priv, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Errorf("public key invalid: %s", err)
	}
}

func TestSignAndVerify(t *testing.T) {
	testAllCurves(t, testSignAndVerify)
}

func testSignAndVerify(t *testing.T, c elliptic.Curve) {
	priv, _ := GenerateKey(c, rand.Reader)

	hashed := []byte("testing")
	r, s, err := Sign(rand.Reader, priv, hashed)
	if err != nil {
		t.Errorf("error signing: %s", err)
		return
	}

	if !Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("Verify failed")
	}

	hashed[0] ^= 0xff
	if Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("Verify always works!")
	}
}

func TestSignAndVerifyASN1(t *testing.T) {
	testAllCurves(t, testSignAndVerifyASN1)
}

func testSignAndVerifyASN1(t *testing.T, c elliptic.Curve) {
	priv, _ := GenerateKey(c, rand.Reader)

	hashed := []byte("testing")
	sig, err := SignASN1(rand.Reader, priv, hashed)
	if err != nil {
		t.Errorf("error signing: %s", err)
		return
	}

	if !VerifyASN1(&priv.PublicKey, hashed, sig) {
		t.Errorf("VerifyASN1 failed")
	}

	hashed[0] ^= 0xff
	if VerifyASN1(&priv.PublicKey, hashed, sig) {
		t.Errorf("VerifyASN1 always works!")
	}
}

func TestNonceSafety(t *testing.T) {
	testAllCurves(t, testNonceSafety)
}

func testNonceSafety(t *testing.T, c elliptic.Curve) {
	priv, _ := GenerateKey(c, rand.Reader)

	hashed := []byte("testing")
	r0, s0, err := Sign(zeroReader, priv, hashed)
	if err != nil {
		t.Errorf("error signing: %s", err)
		return
	}

	hashed = []byte("testing...")
	r1, s1, err := Sign(zeroReader, priv, hashed)
	if err != nil {
		t.Errorf("error signing: %s", err)
		return
	}

	if s0.Cmp(s1) == 0 {
		// This should never happen.
		t.Errorf("the signatures on two different messages were the same")
	}

	if r0.Cmp(r1) == 0 {
		t.Errorf("the nonce used for two different messages was the same")
	}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(b []byte) (int, error) { return f(b) }

var zeroReader = readerFunc(func(b []byte) (int, error) {
	clear(b)
	return len(b), nil
})

func TestINDCCA(t *testing.T) {
	testAllCurves(t, testINDCCA)
}

func testINDCCA(t *testing.T, c elliptic.Curve) {
	priv, _ := GenerateKey(c, rand.Reader)

	hashed := []byte("testing")
	r0, s0, err := Sign(rand.Reader, priv, hashed)
	if err != nil {
		t.Errorf("error signing: %s", err)
		return
	}

	r1, s1, err := Sign(rand.Reader, priv, hashed)
	if err != nil {
		t.Errorf("error signing: %s", err)
		return
	}

	if s0.Cmp(s1) == 0 {
		t.Errorf("two signatures of the same message produced the same result")
	}

	if r0.Cmp(r1) == 0 {
		t.Errorf("two signatures of the same message produced the same nonce")
	}
}

func fromHex(s string) *big.Int {
	r, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("bad hex")
	}
	return r
}

func TestVectors(t *testing.T) {
	cryptotest.TestAllImplementations(t, "ecdsa", testVectors)
}

func testVectors(t *testing.T) {
	// This test runs the full set of NIST test vectors from
	// https://csrc.nist.gov/groups/STM/cavp/documents/dss/186-3ecdsatestvectors.zip
	//
	// The SigVer.rsp file has been edited to remove test vectors for
	// unsupported algorithms and has been compressed.

	if testing.Short() {
		return
	}

	f, err := os.Open("testdata/SigVer.rsp.bz2")
	if err != nil {
		t.Fatal(err)
	}

	buf := bufio.NewReader(bzip2.NewReader(f))

	lineNo := 1
	var h hash.Hash
	var msg []byte
	var hashed []byte
	var r, s *big.Int
	pub := new(PublicKey)

	for {
		line, err := buf.ReadString('\n')
		if len(line) == 0 {
			if err == io.EOF {
				break
			}
			t.Fatalf("error reading from input: %s", err)
		}
		lineNo++
		// Need to remove \r\n from the end of the line.
		if !strings.HasSuffix(line, "\r\n") {
			t.Fatalf("bad line ending (expected \\r\\n) on line %d", lineNo)
		}
		line = line[:len(line)-2]

		if len(line) == 0 || line[0] == '#' {
			continue
		}

		if line[0] == '[' {
			line = line[1 : len(line)-1]
			curve, hash, _ := strings.Cut(line, ",")

			switch curve {
			case "P-224":
				pub.Curve = elliptic.P224()
			case "P-256":
				pub.Curve = elliptic.P256()
			case "P-384":
				pub.Curve = elliptic.P384()
			case "P-521":
				pub.Curve = elliptic.P521()
			default:
				pub.Curve = nil
			}

			switch hash {
			case "SHA-1":
				h = sha1.New()
			case "SHA-224":
				h = sha256.New224()
			case "SHA-256":
				h = sha256.New()
			case "SHA-384":
				h = sha512.New384()
			case "SHA-512":
				h = sha512.New()
			default:
				h = nil
			}

			continue
		}

		if h == nil || pub.Curve == nil {
			continue
		}

		switch {
		case strings.HasPrefix(line, "Msg = "):
			if msg, err = hex.DecodeString(line[6:]); err != nil {
				t.Fatalf("failed to decode message on line %d: %s", lineNo, err)
			}
		case strings.HasPrefix(line, "Qx = "):
			pub.X = fromHex(line[5:])
		case strings.HasPrefix(line, "Qy = "):
			pub.Y = fromHex(line[5:])
		case strings.HasPrefix(line, "R = "):
			r = fromHex(line[4:])
		case strings.HasPrefix(line, "S = "):
			s = fromHex(line[4:])
		case strings.HasPrefix(line, "Result = "):
			expected := line[9] == 'P'
			h.Reset()
			h.Write(msg)
			hashed := h.Sum(hashed[:0])
			if Verify(pub, hashed, r, s) != expected {
				t.Fatalf("incorrect result on line %d", lineNo)
			}
		default:
			t.Fatalf("unknown variable on line %d: %s", lineNo, line)
		}
	}
}

func TestNegativeInputs(t *testing.T) {
	testAllCurves(t, testNegativeInputs)
}

func testNegativeInputs(t *testing.T, curve elliptic.Curve) {
	key, err := GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Errorf("failed to generate key")
	}

	var hash [32]byte
	r := new(big.Int).SetInt64(1)
	r.Lsh(r, 550 /* larger than any supported curve */)
	r.Neg(r)

	if Verify(&key.PublicKey, hash[:], r, r) {
		t.Errorf("bogus signature accepted")
	}
}

func TestZeroHashSignature(t *testing.T) {
	testAllCurves(t, testZeroHashSignature)
}

func testZeroHashSignature(t *testing.T, curve elliptic.Curve) {
	zeroHash := make([]byte, 64)

	privKey, err := GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	// Sign a hash consisting of all zeros.
	r, s, err := Sign(rand.Reader, privKey, zeroHash)
	if err != nil {
		panic(err)
	}

	// Confirm that it can be verified.
	if !Verify(&privKey.PublicKey, zeroHash, r, s) {
		t.Errorf("zero hash signature verify failed for %T", curve)
	}
}

func TestZeroSignature(t *testing.T) {
	testAllCurves(t, testZeroSignature)
}

func testZeroSignature(t *testing.T, curve elliptic.Curve) {
	privKey, err := GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	if Verify(&privKey.PublicKey, make([]byte, 64), big.NewInt(0), big.NewInt(0)) {
		t.Errorf("Verify with r,s=0 succeeded: %T", curve)
	}
}

func TestNegativeSignature(t *testing.T) {
	testAllCurves(t, testNegativeSignature)
}

func testNegativeSignature(t *testing.T, curve elliptic.Curve) {
	zeroHash := make([]byte, 64)

	privKey, err := GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	r, s, err := Sign(rand.Reader, privKey, zeroHash)
	if err != nil {
		panic(err)
	}

	r = r.Neg(r)
	if Verify(&privKey.PublicKey, zeroHash, r, s) {
		t.Errorf("Verify with r=-r succeeded: %T", curve)
	}
}

func TestRPlusNSignature(t *testing.T) {
	testAllCurves(t, testRPlusNSignature)
}

func testRPlusNSignature(t *testing.T, curve elliptic.Curve) {
	zeroHash := make([]byte, 64)

	privKey, err := GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	r, s, err := Sign(rand.Reader, privKey, zeroHash)
	if err != nil {
		panic(err)
	}

	r = r.Add(r, curve.Params().N)
	if Verify(&privKey.PublicKey, zeroHash, r, s) {
		t.Errorf("Verify with r=r+n succeeded: %T", curve)
	}
}

func TestRMinusNSignature(t *testing.T) {
	testAllCurves(t, testRMinusNSignature)
}

func testRMinusNSignature(t *testing.T, curve elliptic.Curve) {
	zeroHash := make([]byte, 64)

	privKey, err := GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	r, s, err := Sign(rand.Reader, privKey, zeroHash)
	if err != nil {
		panic(err)
	}

	r = r.Sub(r, curve.Params().N)
	if Verify(&privKey.PublicKey, zeroHash, r, s) {
		t.Errorf("Verify with r=r-n succeeded: %T", curve)
	}
}

func TestRFC6979(t *testing.T) {
	t.Run("P-224", func(t *testing.T) {
		testRFC6979(t, elliptic.P224(),
			"F220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1",
			"00CF08DA5AD719E42707FA431292DEA11244D64FC51610D94B130D6C",
			"EEAB6F3DEBE455E3DBF85416F7030CBD94F34F2D6F232C69F3C1385A",
			"sample",
			"61AA3DA010E8E8406C656BC477A7A7189895E7E840CDFE8FF42307BA",
			"BC814050DAB5D23770879494F9E0A680DC1AF7161991BDE692B10101")
		testRFC6979(t, elliptic.P224(),
			"F220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1",
			"00CF08DA5AD719E42707FA431292DEA11244D64FC51610D94B130D6C",
			"EEAB6F3DEBE455E3DBF85416F7030CBD94F34F2D6F232C69F3C1385A",
			"test",
			"AD04DDE87B84747A243A631EA47A1BA6D1FAA059149AD2440DE6FBA6",
			"178D49B1AE90E3D8B629BE3DB5683915F4E8C99FDF6E666CF37ADCFD")
	})
	t.Run("P-256", func(t *testing.T) {
		// This vector was bruteforced to find a message that causes the
		// generation of k to loop. It was checked against
		// github.com/codahale/rfc6979 (https://go.dev/play/p/FK5-fmKf7eK),
		// OpenSSL 3.2.0 (https://github.com/openssl/openssl/pull/23130),
		// and python-ecdsa:
		//
		//    ecdsa.keys.SigningKey.from_secret_exponent(
		//        0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721,
		//        ecdsa.curves.curve_by_name("NIST256p"), hashlib.sha256).sign_deterministic(
		//        b"wv[vnX", hashlib.sha256, lambda r, s, order: print(hex(r), hex(s)))
		//
		testRFC6979(t, elliptic.P256(),
			"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
			"60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
			"7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
			"wv[vnX",
			"EFD9073B652E76DA1B5A019C0E4A2E3FA529B035A6ABB91EF67F0ED7A1F21234",
			"3DB4706C9D9F4A4FE13BB5E08EF0FAB53A57DBAB2061C83A35FA411C68D2BA33")

		// The remaining vectors are from RFC 6979.
		testRFC6979(t, elliptic.P256(),
			"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
			"60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
			"7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
			"sample",
			"EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
			"F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")
		testRFC6979(t, elliptic.P256(),
			"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
			"60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
			"7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
			"test",
			"F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
			"019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083")
	})
	t.Run("P-384", func(t *testing.T) {
		testRFC6979(t, elliptic.P384(),
			"6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
			"EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13",
			"8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
			"sample",
			"21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A21D3DAA33BDE1E888E63355D92FA2B3C36D8FB2CD",
			"F3AA443FB107745BF4BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEBEFDC63ECCD1AC42EC0CB8668A4FA0AB0")
		testRFC6979(t, elliptic.P384(),
			"6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
			"EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13",
			"8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
			"test",
			"6D6DEFAC9AB64DABAFE36C6BF510352A4CC27001263638E5B16D9BB51D451559F918EEDAF2293BE5B475CC8F0188636B",
			"2D46F3BECBCC523D5F1A1256BF0C9B024D879BA9E838144C8BA6BAEB4B53B47D51AB373F9845C0514EEFB14024787265")
	})
	t.Run("P-521", func(t *testing.T) {
		testRFC6979(t, elliptic.P521(),
			"0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
			"1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4",
			"0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5",
			"sample",
			"1511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659D16876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E1A7",
			"04A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916E4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7ECFC")
		testRFC6979(t, elliptic.P521(),
			"0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
			"1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4",
			"0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5",
			"test",
			"00E871C4A14F993C6C7369501900C4BC1E9C7B0B4BA44E04868B30B41D8071042EB28C4C250411D0CE08CD197E4188EA4876F279F90B3D8D74A3C76E6F1E4656AA8",
			"0CD52DBAA33B063C3A6CD8058A1FB0A46A4754B034FCC644766CA14DA8CA5CA9FDE00E88C1AD60CCBA759025299079D7A427EC3CC5B619BFBC828E7769BCD694E86")
	})
}

func testRFC6979(t *testing.T, curve elliptic.Curve, D, X, Y, msg, r, s string) {
	priv := &PrivateKey{
		D: fromHex(D),
		PublicKey: PublicKey{
			Curve: curve,
			X:     fromHex(X),
			Y:     fromHex(Y),
		},
	}
	h := sha256.Sum256([]byte(msg))
	sig, err := priv.Sign(nil, h[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := encodeSignature(fromHex(r).Bytes(), fromHex(s).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, expected) {
		t.Errorf("signature mismatch:\n got: %x\nwant: %x", sig, expected)
	}
}

func benchmarkAllCurves(b *testing.B, f func(*testing.B, elliptic.Curve)) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P256", elliptic.P256()},
		{"P384", elliptic.P384()},
		{"P521", elliptic.P521()},
	}
	for _, test := range tests {
		curve := test.curve
		b.Run(test.name, func(b *testing.B) {
			f(b, curve)
		})
	}
}

func BenchmarkSign(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve elliptic.Curve) {
		r := bufio.NewReaderSize(rand.Reader, 1<<15)
		priv, err := GenerateKey(curve, r)
		if err != nil {
			b.Fatal(err)
		}
		hashed := []byte("testing")

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sig, err := SignASN1(r, priv, hashed)
			if err != nil {
				b.Fatal(err)
			}
			// Prevent the compiler from optimizing out the operation.
			hashed[0] = sig[0]
		}
	})
}

func BenchmarkVerify(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve elliptic.Curve) {
		r := bufio.NewReaderSize(rand.Reader, 1<<15)
		priv, err := GenerateKey(curve, r)
		if err != nil {
			b.Fatal(err)
		}
		hashed := []byte("testing")
		sig, err := SignASN1(r, priv, hashed)
		if err != nil {
			b.Fatal(err)
		}

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if !VerifyASN1(&priv.PublicKey, hashed, sig) {
				b.Fatal("verify failed")
			}
		}
	})
}

func BenchmarkGenerateKey(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve elliptic.Curve) {
		r := bufio.NewReaderSize(rand.Reader, 1<<15)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := GenerateKey(curve, r); err != nil {
				b.Fatal(err)
			}
		}
	})
}
```