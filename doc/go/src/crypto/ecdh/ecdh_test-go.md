Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request is to analyze a Go test file (`ecdh_test.go`) and explain its purpose, demonstrate its functionality with examples, and identify potential pitfalls for users.

2. **High-Level Overview (Package and Imports):**  The first step is to look at the `package` declaration and the `import` statements. This tells us the code is in the `ecdh_test` package (meaning it's a test file for the `ecdh` package) and that it uses various cryptographic and testing related Go standard library packages. Key packages like `crypto/ecdh`, `crypto/rand`, `testing`, and `bytes` immediately stand out as relevant to the core functionality.

3. **Identify Core Test Functions:**  Look for functions starting with `Test...`. These are the main test cases. The most prominent ones are:
    * `TestECDH`:  Likely tests the basic ECDH key exchange functionality.
    * `TestGenerateKey`:  Focuses on testing the key generation process.
    * `TestVectors`: Probably uses known test vectors to verify the correctness of the ECDH implementation against standard values.
    * `TestString`: Seems to test the string representation of the curve.
    * `TestX25519Failure`: Specifically tests error handling for X25519 with invalid inputs.
    * `TestNewPrivateKey` and `TestNewPublicKey`:  Focus on testing the creation of private and public keys from byte slices, including handling invalid inputs.
    * `TestLinker`:  A more advanced test related to how the code is linked and whether unused curve implementations are included.
    * `TestMismatchedCurves`: Checks for error handling when trying to perform ECDH with keys from different curves.

4. **Analyze Individual Test Functions (Mental Walkthrough and Note Key Operations):** For each `Test...` function, mentally walk through the code. What are the key operations? What are the assertions (using `t.Fatal`, `t.Error`, etc.)?

    * **`TestECDH`:** Generates Alice's and Bob's keys, encodes and decodes them, performs ECDH in both directions, and checks if the shared secrets match. This confirms the core ECDH logic.
    * **`TestGenerateKey`:**  Generates a key and checks the number of bytes read from the random source. This relates to the efficiency and correctness of the random number generation.
    * **`TestVectors`:**  Iterates through predefined test vectors (private key, public key, peer public key, shared secret) for different curves and verifies the implementation against these known values. This is crucial for interoperability.
    * **`TestString`:** Checks if the string representation of the curve starts with "P" or "X". Simple verification of string formatting.
    * **`TestX25519Failure`:**  Specifically tests what happens when using the identity point and a low-order point as public keys for X25519. It expects an error.
    * **`TestNewPrivateKey` and `TestNewPublicKey`:**  These tests iterate over lists of invalid private and public key byte strings and ensure that the `NewPrivateKey` and `NewPublicKey` functions correctly return errors.
    * **`TestLinker`:**  This test *compiles* a separate program that uses only `ecdh.P256()` and then uses `go tool nm` to inspect the compiled binary. The goal is to ensure that only symbols related to P256 are included, demonstrating that unused curve implementations aren't unnecessarily linked.
    * **`TestMismatchedCurves`:** Generates key pairs for different curves and tries to perform ECDH between them, expecting a specific error message.

5. **Identify Supporting Functions:** Notice functions like `testAllCurves`, `hexDecode`, `benchmarkAllCurves`, and the `countingReader` and `zr` types. These are helper functions and data structures used within the tests.

6. **Infer the Overall Goal (ECDH Implementation Testing):** By looking at the tests, the imported `ecdh` package, and the operations performed, it becomes clear that this file is for testing the implementation of the Elliptic-Curve Diffie-Hellman (ECDH) key exchange algorithm in Go's `crypto/ecdh` package.

7. **Construct the Explanation:**  Now, organize the findings into a coherent explanation based on the prompt's requirements:

    * **Functionality:** Describe the overall purpose and the specific functionalities tested by each `Test...` function.
    * **Go Language Feature:**  Identify that it tests the `crypto/ecdh` package, which provides ECDH key exchange functionality.
    * **Code Examples:**  Choose relevant test cases (like `TestECDH` and `TestGenerateKey`) and simplify them into illustrative examples. Make sure to include input and output where applicable (even if the output is just the absence of an error).
    * **Code Reasoning:** For more complex tests like `TestVectors` and `TestLinker`, explain the *why* behind the test and the logic being verified.
    * **Command-Line Arguments:** Focus on `TestLinker`, as it explicitly uses `go build` and `go tool nm`. Explain the purpose of these commands in the test.
    * **User Mistakes:**  Identify potential errors users might make, such as using keys from different curves (highlighted by `TestMismatchedCurves`) or providing invalid key data (highlighted by `TestNewPrivateKey` and `TestNewPublicKey`).

8. **Refine and Organize:**  Review the explanation for clarity, accuracy, and completeness. Ensure the language is clear and easy to understand. Use formatting (like code blocks) to make the information more digestible. Translate any internal thoughts and code understanding into clear, natural language.

Self-Correction Example During the Process: Initially, I might just say "tests key generation." But upon closer inspection of `TestGenerateKey`, I see it's also checking the number of random bytes consumed. So, I'd refine the description to include that aspect. Similarly, for `TestLinker`, simply stating it tests linking isn't enough; explaining *how* it does this using `go build` and `nm` is crucial.
这段代码是 Go 语言标准库 `crypto/ecdh` 包的测试文件 `ecdh_test.go` 的一部分。它的主要功能是 **测试 `crypto/ecdh` 包中椭圆曲线 Diffie-Hellman (ECDH) 密钥交换算法的实现是否正确。**

具体来说，它测试了以下几个方面：

1. **基本的 ECDH 密钥交换流程:**  验证使用 `ecdh` 包生成的密钥对进行密钥交换后，双方计算出的共享密钥是否一致。
2. **密钥的生成和编码/解码:** 测试 `GenerateKey` 函数生成密钥对的功能，以及公钥和私钥的 `Bytes()` 方法和 `NewPublicKey`/`NewPrivateKey` 函数的编码和解码功能是否正确。
3. **针对不同曲线的兼容性:**  通过 `testAllCurves` 函数，针对 `P256`, `P384`, `P521`, 和 `X25519` 等不同的椭圆曲线进行测试，确保 `ecdh` 包对这些曲线的支持是正确的。
4. **使用预定义的测试向量进行验证:** 使用 NIST 和 RFC 中定义的 ECDH 测试向量来验证实现的正确性，确保与标准实现一致。
5. **处理无效的密钥输入:** 测试 `NewPrivateKey` 和 `NewPublicKey` 函数在接收到无效的私钥或公钥字节切片时是否能正确地返回错误。
6. **X25519 曲线的特殊情况处理:**  测试了使用 X25519 曲线时，当使用恒等点或低阶点作为公钥进行密钥交换时，是否会返回预期的错误。
7. **性能基准测试:**  提供了 `BenchmarkECDH` 函数用于衡量不同曲线下 ECDH 密钥交换的性能。
8. **链接器测试:**  `TestLinker` 确保在只使用特定曲线的情况下，不会将所有其他曲线的实现都链接到最终的可执行文件中，这对于减小二进制文件大小和避免不必要的安全风险很重要。
9. **不同曲线密钥的互操作性检查:**  `TestMismatchedCurves` 确保当尝试使用不同曲线生成的公钥和私钥进行 ECDH 计算时，会返回预期的错误。

**推理的 Go 语言功能实现：椭圆曲线 Diffie-Hellman 密钥交换**

`crypto/ecdh` 包实现了 ECDH 密钥交换算法，允许两个参与者在不安全的信道上协商出一个共享秘密，该共享秘密可以用于后续的对称加密。

**Go 代码示例：基本的 ECDH 密钥交换**

```go
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"log"
)

func main() {
	// 假设 Alice 和 Bob 使用 P256 曲线
	curve := ecdh.P256()

	// Alice 生成密钥对
	aliceKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	alicePublicKey := aliceKey.PublicKey()

	// Bob 生成密钥对
	bobKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	bobPublicKey := bobKey.PublicKey()

	// Alice 计算共享密钥
	aliceSharedSecret, err := aliceKey.ECDH(bobPublicKey)
	if err != nil {
		log.Fatal(err)
	}

	// Bob 计算共享密钥
	bobSharedSecret, err := bobKey.ECDH(alicePublicKey)
	if err != nil {
		log.Fatal(err)
	}

	// 验证双方计算出的共享密钥是否一致
	if !equal(aliceSharedSecret, bobSharedSecret) {
		log.Fatal("共享密钥不一致")
	}

	fmt.Printf("Alice Shared Secret: %x\n", aliceSharedSecret)
	fmt.Printf("Bob Shared Secret: %x\n", bobSharedSecret)
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
```

**假设的输入与输出：**

在这个例子中，输入是随机数生成器 `rand.Reader` 用于生成密钥对。输出是 Alice 和 Bob 计算出的共享密钥的十六进制表示。由于密钥是随机生成的，每次运行的输出都会不同，但双方的共享密钥应该始终一致。

**代码推理：`TestGenerateKey`**

`TestGenerateKey` 函数测试了 `curve.GenerateKey(rand.Reader)` 的行为，它会生成一个新的私钥和对应的公钥。该测试的关键点在于验证 `GenerateKey` 从 `rand.Reader` 中读取的字节数是否在预期范围内。

**假设的输入与输出：**

* **输入:**  一个实现了 `io.Reader` 接口的随机数生成器 `rand.Reader`。
* **输出:**  生成的私钥 `k` 和可能发生的错误 `err`。

**推理过程：**

`GenerateKey` 的实现中，为了生成符合椭圆曲线要求的私钥，可能会进行多次尝试（拒绝采样）。`countingReader` 包装了 `rand.Reader`，用于统计实际读取的字节数。测试代码断言读取的字节数 `r.n` 不应超过私钥字节长度加 1。  这个加 1 是为了考虑某些曲线可能需要额外读取一个字节来确定是否需要重新采样。

**命令行参数的具体处理：**

这段代码本身是测试代码，通常不会直接通过命令行运行并处理参数。但是，其中的 `TestLinker` 函数间接地涉及到命令行工具 `go build` 和 `go tool nm`。

* **`go build -o hello.exe hello.go`:**  这个命令用于编译 `linkerTestProgram` 定义的 Go 源代码文件 `hello.go`，并生成一个名为 `hello.exe` 的可执行文件。`-o` 参数指定输出文件的名称。
* **`go tool nm hello.exe`:** 这个命令使用 Go 的 `nm` 工具来查看 `hello.exe` 文件中的符号表。符号表包含了程序中定义的函数、变量等符号信息。`TestLinker` 使用这个命令来验证在只使用了 `ecdh.P256()` 的情况下，是否只链接了与 P256 相关的符号，而没有包含其他曲线的符号。

**使用者易犯错的点：**

一个常见的错误是尝试使用不同曲线生成的公钥和私钥进行 ECDH 计算。

**示例：**

```go
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"log"
)

func main() {
	// Alice 使用 P256 曲线
	aliceCurve := ecdh.P256()
	aliceKey, _ := aliceCurve.GenerateKey(rand.Reader)
	alicePublicKey := aliceKey.PublicKey()

	// Bob 使用 X25519 曲线
	bobCurve := ecdh.X25519()
	bobKey, _ := bobCurve.GenerateKey(rand.Reader)
	bobPublicKey := bobKey.PublicKey()

	// Alice 尝试使用 Bob 的 X25519 公钥和自己的 P256 私钥计算共享密钥
	_, err := aliceKey.ECDH(bobPublicKey)
	if err != nil {
		fmt.Printf("错误：%s\n", err) // 输出：错误：crypto/ecdh: private key and public key curves do not match
	}

	// Bob 尝试使用 Alice 的 P256 公钥和自己的 X25519 私钥计算共享密钥
	_, err = bobKey.ECDH(alicePublicKey)
	if err != nil {
		fmt.Printf("错误：%s\n", err) // 输出：错误：crypto/ecdh: private key and public key curves do not match
	}
}
```

在这个例子中，由于 Alice 和 Bob 使用了不同的椭圆曲线 (P256 和 X25519)，尝试进行 ECDH 计算会返回错误 "crypto/ecdh: private key and public key curves do not match"。这是因为 ECDH 算法要求双方使用相同的椭圆曲线才能正确计算出共享密钥。

因此，使用者需要确保参与密钥交换的双方使用相同的 `ecdh.Curve` 类型。

Prompt: 
```
这是路径为go/src/crypto/ecdh/ecdh_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ecdh_test

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"internal/testenv"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20"
)

// Check that PublicKey and PrivateKey implement the interfaces documented in
// crypto.PublicKey and crypto.PrivateKey.
var _ interface {
	Equal(x crypto.PublicKey) bool
} = &ecdh.PublicKey{}
var _ interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
} = &ecdh.PrivateKey{}

func TestECDH(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve ecdh.Curve) {
		aliceKey, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		bobKey, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		alicePubKey, err := curve.NewPublicKey(aliceKey.PublicKey().Bytes())
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(aliceKey.PublicKey().Bytes(), alicePubKey.Bytes()) {
			t.Error("encoded and decoded public keys are different")
		}
		if !aliceKey.PublicKey().Equal(alicePubKey) {
			t.Error("encoded and decoded public keys are different")
		}

		alicePrivKey, err := curve.NewPrivateKey(aliceKey.Bytes())
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(aliceKey.Bytes(), alicePrivKey.Bytes()) {
			t.Error("encoded and decoded private keys are different")
		}
		if !aliceKey.Equal(alicePrivKey) {
			t.Error("encoded and decoded private keys are different")
		}

		bobSecret, err := bobKey.ECDH(aliceKey.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		aliceSecret, err := aliceKey.ECDH(bobKey.PublicKey())
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(bobSecret, aliceSecret) {
			t.Error("two ECDH computations came out different")
		}
	})
}

type countingReader struct {
	r io.Reader
	n int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += n
	return n, err
}

func TestGenerateKey(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve ecdh.Curve) {
		r := &countingReader{r: rand.Reader}
		k, err := curve.GenerateKey(r)
		if err != nil {
			t.Fatal(err)
		}

		// GenerateKey does rejection sampling. If the masking works correctly,
		// the probability of a rejection is 1-ord(G)/2^ceil(log2(ord(G))),
		// which for all curves is small enough (at most 2^-32, for P-256) that
		// a bit flip is more likely to make this test fail than bad luck.
		// Account for the extra MaybeReadByte byte, too.
		if got, expected := r.n, len(k.Bytes())+1; got > expected {
			t.Errorf("expected GenerateKey to consume at most %v bytes, got %v", expected, got)
		}
	})
}

var vectors = map[ecdh.Curve]struct {
	PrivateKey, PublicKey string
	PeerPublicKey         string
	SharedSecret          string
}{
	// NIST vectors from CAVS 14.1, ECC CDH Primitive (SP800-56A).
	ecdh.P256(): {
		PrivateKey: "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
		PublicKey: "04ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230" +
			"28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141",
		PeerPublicKey: "04700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287" +
			"db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
		SharedSecret: "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b",
	},
	ecdh.P384(): {
		PrivateKey: "3cc3122a68f0d95027ad38c067916ba0eb8c38894d22e1b15618b6818a661774ad463b205da88cf699ab4d43c9cf98a1",
		PublicKey: "049803807f2f6d2fd966cdd0290bd410c0190352fbec7ff6247de1302df86f25d34fe4a97bef60cff548355c015dbb3e5f" +
			"ba26ca69ec2f5b5d9dad20cc9da711383a9dbe34ea3fa5a2af75b46502629ad54dd8b7d73a8abb06a3a3be47d650cc99",
		PeerPublicKey: "04a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272734466b400091adbf2d68c58e0c50066" +
			"ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915ed0905a32b060992b468c64766fc8437a",
		SharedSecret: "5f9d29dc5e31a163060356213669c8ce132e22f57c9a04f40ba7fcead493b457e5621e766c40a2e3d4d6a04b25e533f1",
	},
	// For some reason all field elements in the test vector (both scalars and
	// base field elements), but not the shared secret output, have two extra
	// leading zero bytes (which in big-endian are irrelevant). Removed here.
	ecdh.P521(): {
		PrivateKey: "017eecc07ab4b329068fba65e56a1f8890aa935e57134ae0ffcce802735151f4eac6564f6ee9974c5e6887a1fefee5743ae2241bfeb95d5ce31ddcb6f9edb4d6fc47",
		PublicKey: "0400602f9d0cf9e526b29e22381c203c48a886c2b0673033366314f1ffbcba240ba42f4ef38a76174635f91e6b4ed34275eb01c8467d05ca80315bf1a7bbd945f550a5" +
			"01b7c85f26f5d4b2d7355cf6b02117659943762b6d1db5ab4f1dbc44ce7b2946eb6c7de342962893fd387d1b73d7a8672d1f236961170b7eb3579953ee5cdc88cd2d",
		PeerPublicKey: "0400685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2046d" +
			"01ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b739884a83bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302f676",
		SharedSecret: "005fc70477c3e63bc3954bd0df3ea0d1f41ee21746ed95fc5e1fdf90930d5e136672d72cc770742d1711c3c3a4c334a0ad9759436a4d3c5bf6e74b9578fac148c831",
	},
	// X25519 test vector from RFC 7748, Section 6.1.
	ecdh.X25519(): {
		PrivateKey:    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
		PublicKey:     "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
		PeerPublicKey: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
		SharedSecret:  "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
	},
}

func TestVectors(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve ecdh.Curve) {
		v := vectors[curve]
		key, err := curve.NewPrivateKey(hexDecode(t, v.PrivateKey))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(key.PublicKey().Bytes(), hexDecode(t, v.PublicKey)) {
			t.Error("public key derived from the private key does not match")
		}
		peer, err := curve.NewPublicKey(hexDecode(t, v.PeerPublicKey))
		if err != nil {
			t.Fatal(err)
		}
		secret, err := key.ECDH(peer)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(secret, hexDecode(t, v.SharedSecret)) {
			t.Errorf("shared secret does not match: %x %x %s %x", secret, sha256.Sum256(secret), v.SharedSecret,
				sha256.Sum256(hexDecode(t, v.SharedSecret)))
		}
	})
}

func hexDecode(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal("invalid hex string:", s)
	}
	return b
}

func TestString(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve ecdh.Curve) {
		s := fmt.Sprintf("%s", curve)
		if s[:1] != "P" && s[:1] != "X" {
			t.Errorf("unexpected Curve string encoding: %q", s)
		}
	})
}

func TestX25519Failure(t *testing.T) {
	identity := hexDecode(t, "0000000000000000000000000000000000000000000000000000000000000000")
	lowOrderPoint := hexDecode(t, "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
	randomScalar := make([]byte, 32)
	rand.Read(randomScalar)

	t.Run("identity point", func(t *testing.T) { testX25519Failure(t, randomScalar, identity) })
	t.Run("low order point", func(t *testing.T) { testX25519Failure(t, randomScalar, lowOrderPoint) })
}

func testX25519Failure(t *testing.T, private, public []byte) {
	priv, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := priv.ECDH(pub)
	if err == nil {
		t.Error("expected ECDH error")
	}
	if secret != nil {
		t.Errorf("unexpected ECDH output: %x", secret)
	}
}

var invalidPrivateKeys = map[ecdh.Curve][]string{
	ecdh.P256(): {
		// Bad lengths.
		"",
		"01",
		"01010101010101010101010101010101010101010101010101010101010101",
		"000101010101010101010101010101010101010101010101010101010101010101",
		strings.Repeat("01", 200),
		// Zero.
		"0000000000000000000000000000000000000000000000000000000000000000",
		// Order of the curve and above.
		"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
		"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	},
	ecdh.P384(): {
		// Bad lengths.
		"",
		"01",
		"0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101",
		"00010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101",
		strings.Repeat("01", 200),
		// Zero.
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		// Order of the curve and above.
		"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
		"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	},
	ecdh.P521(): {
		// Bad lengths.
		"",
		"01",
		"0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101",
		"00010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101",
		strings.Repeat("01", 200),
		// Zero.
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		// Order of the curve and above.
		"01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
		"01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138640a",
		"11fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
		"03fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4a30d0f077e5f2cd6ff980291ee134ba0776b937113388f5d76df6e3d2270c812",
	},
	ecdh.X25519(): {
		// X25519 only rejects bad lengths.
		"",
		"01",
		"01010101010101010101010101010101010101010101010101010101010101",
		"000101010101010101010101010101010101010101010101010101010101010101",
		strings.Repeat("01", 200),
	},
}

func TestNewPrivateKey(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve ecdh.Curve) {
		for _, input := range invalidPrivateKeys[curve] {
			k, err := curve.NewPrivateKey(hexDecode(t, input))
			if err == nil {
				t.Errorf("unexpectedly accepted %q", input)
			} else if k != nil {
				t.Error("PrivateKey was not nil on error")
			} else if strings.Contains(err.Error(), "boringcrypto") {
				t.Errorf("boringcrypto error leaked out: %v", err)
			}
		}
	})
}

var invalidPublicKeys = map[ecdh.Curve][]string{
	ecdh.P256(): {
		// Bad lengths.
		"",
		"04",
		strings.Repeat("04", 200),
		// Infinity.
		"00",
		// Compressed encodings.
		"036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
		"02e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852",
		// Points not on the curve.
		"046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f6",
		"0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	ecdh.P384(): {
		// Bad lengths.
		"",
		"04",
		strings.Repeat("04", 200),
		// Infinity.
		"00",
		// Compressed encodings.
		"03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
		"0208d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61",
		// Points not on the curve.
		"04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e60",
		"04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	ecdh.P521(): {
		// Bad lengths.
		"",
		"04",
		strings.Repeat("04", 200),
		// Infinity.
		"00",
		// Compressed encodings.
		"030035b5df64ae2ac204c354b483487c9070cdc61c891c5ff39afc06c5d55541d3ceac8659e24afe3d0750e8b88e9f078af066a1d5025b08e5a5e2fbc87412871902f3",
		"0200c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
		// Points not on the curve.
		"0400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16651",
		"04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	ecdh.X25519(): {},
}

func TestNewPublicKey(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve ecdh.Curve) {
		for _, input := range invalidPublicKeys[curve] {
			k, err := curve.NewPublicKey(hexDecode(t, input))
			if err == nil {
				t.Errorf("unexpectedly accepted %q", input)
			} else if k != nil {
				t.Error("PublicKey was not nil on error")
			} else if strings.Contains(err.Error(), "boringcrypto") {
				t.Errorf("boringcrypto error leaked out: %v", err)
			}
		}
	})
}

func testAllCurves(t *testing.T, f func(t *testing.T, curve ecdh.Curve)) {
	t.Run("P256", func(t *testing.T) { f(t, ecdh.P256()) })
	t.Run("P384", func(t *testing.T) { f(t, ecdh.P384()) })
	t.Run("P521", func(t *testing.T) { f(t, ecdh.P521()) })
	t.Run("X25519", func(t *testing.T) { f(t, ecdh.X25519()) })
}

func BenchmarkECDH(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve ecdh.Curve) {
		c, err := chacha20.NewUnauthenticatedCipher(make([]byte, 32), make([]byte, 12))
		if err != nil {
			b.Fatal(err)
		}
		rand := cipher.StreamReader{
			S: c, R: zeroReader,
		}

		peerKey, err := curve.GenerateKey(rand)
		if err != nil {
			b.Fatal(err)
		}
		peerShare := peerKey.PublicKey().Bytes()
		b.ResetTimer()
		b.ReportAllocs()

		var allocationsSink byte

		for i := 0; i < b.N; i++ {
			key, err := curve.GenerateKey(rand)
			if err != nil {
				b.Fatal(err)
			}
			share := key.PublicKey().Bytes()
			peerPubKey, err := curve.NewPublicKey(peerShare)
			if err != nil {
				b.Fatal(err)
			}
			secret, err := key.ECDH(peerPubKey)
			if err != nil {
				b.Fatal(err)
			}
			allocationsSink ^= secret[0] ^ share[0]
		}
	})
}

func benchmarkAllCurves(b *testing.B, f func(b *testing.B, curve ecdh.Curve)) {
	b.Run("P256", func(b *testing.B) { f(b, ecdh.P256()) })
	b.Run("P384", func(b *testing.B) { f(b, ecdh.P384()) })
	b.Run("P521", func(b *testing.B) { f(b, ecdh.P521()) })
	b.Run("X25519", func(b *testing.B) { f(b, ecdh.X25519()) })
}

type zr struct{}

// Read replaces the contents of dst with zeros. It is safe for concurrent use.
func (zr) Read(dst []byte) (n int, err error) {
	clear(dst)
	return len(dst), nil
}

var zeroReader = zr{}

const linkerTestProgram = `
package main
import "crypto/ecdh"
import "crypto/rand"
func main() {
	// Use P-256, since that's what the always-enabled CAST uses.
	curve := ecdh.P256()
	key, err := curve.GenerateKey(rand.Reader)
	if err != nil { panic(err) }
	_, err = curve.NewPublicKey(key.PublicKey().Bytes())
	if err != nil { panic(err) }
	_, err = curve.NewPrivateKey(key.Bytes())
	if err != nil { panic(err) }
	_, err = key.ECDH(key.PublicKey())
	if err != nil { panic(err) }
	println("OK")
}
`

// TestLinker ensures that using one curve does not bring all other
// implementations into the binary. This also guarantees that govulncheck can
// avoid warning about a curve-specific vulnerability if that curve is not used.
func TestLinker(t *testing.T) {
	if testing.Short() {
		t.Skip("test requires running 'go build'")
	}
	testenv.MustHaveGoBuild(t)

	dir := t.TempDir()
	hello := filepath.Join(dir, "hello.go")
	err := os.WriteFile(hello, []byte(linkerTestProgram), 0664)
	if err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) string {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, string(out))
		}
		return string(out)
	}

	goBin := testenv.GoToolPath(t)
	run(goBin, "build", "-o", "hello.exe", "hello.go")
	if out := run("./hello.exe"); out != "OK\n" {
		t.Error("unexpected output:", out)
	}

	// List all text symbols under crypto/... and make sure there are some for
	// P256, but none for the other curves.
	var consistent bool
	nm := run(goBin, "tool", "nm", "hello.exe")
	for _, match := range regexp.MustCompile(`(?m)T (crypto/.*)$`).FindAllStringSubmatch(nm, -1) {
		symbol := strings.ToLower(match[1])
		if strings.Contains(symbol, "p256") {
			consistent = true
		}
		if strings.Contains(symbol, "p224") || strings.Contains(symbol, "p384") || strings.Contains(symbol, "p521") {
			t.Errorf("unexpected symbol in program using only ecdh.P256: %s", match[1])
		}
	}
	if !consistent {
		t.Error("no P256 symbols found in program using ecdh.P256, test is broken")
	}
}

func TestMismatchedCurves(t *testing.T) {
	curves := []struct {
		name  string
		curve ecdh.Curve
	}{
		{"P256", ecdh.P256()},
		{"P384", ecdh.P384()},
		{"P521", ecdh.P521()},
		{"X25519", ecdh.X25519()},
	}

	for _, privCurve := range curves {
		priv, err := privCurve.curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate test key: %s", err)
		}

		for _, pubCurve := range curves {
			if privCurve == pubCurve {
				continue
			}
			t.Run(fmt.Sprintf("%s/%s", privCurve.name, pubCurve.name), func(t *testing.T) {
				pub, err := pubCurve.curve.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("failed to generate test key: %s", err)
				}
				expected := "crypto/ecdh: private key and public key curves do not match"
				_, err = priv.ECDH(pub.PublicKey())
				if err.Error() != expected {
					t.Fatalf("unexpected error: want %q, got %q", expected, err)
				}
			})
		}
	}
}

"""



```