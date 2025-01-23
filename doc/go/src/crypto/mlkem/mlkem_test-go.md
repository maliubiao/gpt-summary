Response:
Let's break down the thought process for analyzing the provided Go test code.

1. **Identify the Core Purpose:** The file name `mlkem_test.go` immediately suggests this is a test suite for an ML-KEM (Memory-Locked Key Encapsulation Mechanism) implementation. The `package mlkem` declaration confirms this.

2. **Scan for Key Data Structures and Functions:**  Look for type definitions and function signatures that define the core operations being tested.

    * `encapsulationKey` and `decapsulationKey` interfaces jump out as defining the fundamental actions: encapsulating and decapsulating.
    * Functions like `GenerateKey768`, `GenerateKey1024`, `NewEncapsulationKey768`, `NewDecapsulationKey768` clearly indicate key generation and key material creation. The `768` and `1024` suffixes likely relate to different security parameter sets or key sizes.
    * The `TestRoundTrip` and `TestBadLengths` functions signal testing of core functional correctness and error handling.

3. **Analyze Individual Test Functions:**

    * **`TestRoundTrip`:**  The name is a strong hint. It likely tests the fundamental KEM property: encapsulating with a public key and then decapsulating with the corresponding private key should yield the same shared secret. The nested `t.Run` calls suggest testing for different key sizes (768 and 1024). The internal calls to `testRoundTrip` with `GenerateKey...`, `NewEncapsulationKey...`, `NewDecapsulationKey...` confirm the different key size variants. The core logic involves generating a key pair, encapsulating, decapsulating, and comparing the resulting shared secrets. It also checks if reconstructing keys from their byte representations works correctly. Finally, it verifies that generating different key pairs results in different public and private keys, and that repeated encapsulation yields different ciphertexts and shared secrets.

    * **`testRoundTrip` (generic):**  This function contains the actual implementation of the round-trip test. The type parameters `E encapsulationKey` and `D decapsulationKey[E]` highlight the relationship between encapsulation and decapsulation keys. The steps involve: generating a key pair, encapsulating, decapsulating, comparing the shared secrets, reconstructing keys from bytes, and repeating the encapsulation/decapsulation with the reconstructed keys.

    * **`TestBadLengths`:**  This test function focuses on input validation. The name suggests it checks how the implementation handles invalid lengths for key materials and ciphertexts. The nested `t.Run` and the call to `testBadLengths` indicate testing for different key sizes. The internal loop iterates through various short and long lengths of key and ciphertext bytes, expecting errors when creating keys or decapsulating.

    * **`testBadLengths` (generic):**  This function implements the bad length testing. It generates a key pair, then iterates through shorter and longer versions of the private key, public key, and ciphertext, attempting to create keys or decapsulate and asserting that errors are returned.

    * **`TestAccumulated`:** This test uses a different approach. Instead of directly comparing individual encapsulation/decapsulation results, it generates a large number of random vectors and hashes the accumulated output. This is likely done to verify the overall statistical properties of the KEM and avoid storing massive test vectors. The `flag.Bool("million", ...)` and conditional logic based on `testing.Short()` suggest different test run modes with varying numbers of iterations. The hashing using `sha3.NewShake128` indicates a cryptographic check.

    * **Benchmark Functions (`BenchmarkKeyGen`, `BenchmarkEncaps`, `BenchmarkDecaps`, `BenchmarkRoundTrip`):** These functions measure the performance of key generation, encapsulation, decapsulation, and the combined round-trip operation. The `b.ResetTimer()` is standard Go benchmarking practice. The operations inside the loops exercise the core KEM functionalities.

    * **`TestConstantSizes`:** This test verifies that the constant values defined in the public API (e.g., `SharedKeySize`, `CiphertextSize768`) match the corresponding internal values in `crypto/internal/fips140/mlkem`. This ensures consistency between the public and internal implementations.

4. **Infer Functionality:** Based on the identified structures and tests, we can infer the primary functionality:

    * **Key Generation:** Generating key pairs (public and private keys) for ML-KEM.
    * **Encapsulation:**  Taking a recipient's public key and generating a ciphertext and a shared secret.
    * **Decapsulation:** Taking the ciphertext and the recipient's private key to recover the shared secret.
    * **Error Handling:**  Ensuring proper error handling for invalid input lengths.
    * **Performance Measurement:** Benchmarking the performance of key generation, encapsulation, and decapsulation.
    * **Constant Verification:** Ensuring consistency of key sizes and other constants.

5. **Code Examples (based on inferences):**  Construct basic Go code snippets that demonstrate how to use the identified functions for key generation, encapsulation, and decapsulation. Include error handling.

6. **Command-Line Arguments:** Note the `flag.Bool("million", ...)` in `TestAccumulated`. Explain how this flag is used to run a more extensive test.

7. **Common Mistakes:** Think about how a user might misuse this API. The `TestBadLengths` gives hints – incorrect key or ciphertext lengths are a likely source of errors. Also, reusing key material inappropriately is a common cryptographic pitfall.

8. **Structure the Answer:** Organize the findings into logical sections: Functionality, Go Language Feature (KEM), Code Examples, Command-Line Arguments, and Common Mistakes. Use clear and concise language.

By following this structured approach, we can effectively analyze and understand the purpose and functionality of the provided Go test code.这段代码是 Go 语言中 `crypto/mlkem` 包的一部分，专门用于测试 ML-KEM（Memory-Locked Key Encapsulation Mechanism）的实现。ML-KEM 是一种后量子密码学算法，用于密钥封装。

**功能列表：**

1. **`TestRoundTrip` 函数：**
   - 测试 ML-KEM 的基本流程：生成密钥对，使用公钥进行封装，使用私钥进行解封装，并验证解封装得到的密钥与封装时产生的密钥是否一致。
   - 针对不同的参数集（例如，密钥长度为 768 和 1024 的 ML-KEM 变体）运行测试。
   - 验证了从字节表示形式重新构造公钥和私钥后，仍然可以正常进行封装和解封装。
   - 验证了每次生成新的密钥对都会产生不同的公钥和私钥。
   - 验证了对于同一个公钥，多次封装会产生不同的密文和共享密钥。

2. **`testRoundTrip` 函数（泛型）：**
   - 是 `TestRoundTrip` 函数的辅助函数，实现了具体的密钥生成、封装和解封装的流程。
   - 使用泛型来支持不同类型的封装密钥和解封装密钥。

3. **`TestBadLengths` 函数：**
   - 测试当提供错误的密钥或密文长度时，ML-KEM 实现是否能正确处理并返回错误。
   - 针对不同的参数集（例如，密钥长度为 768 和 1024 的 ML-KEM 变体）运行测试。
   - 测试了过短和过长的密钥及密文。

4. **`testBadLengths` 函数（泛型）：**
   - 是 `TestBadLengths` 函数的辅助函数，实现了具体的错误长度测试流程。
   - 使用泛型来支持不同类型的封装密钥和解封装密钥。

5. **`TestAccumulated` 函数：**
   - 进行累积测试，生成大量的随机向量，并计算结果的哈希值。
   - 这是一种验证 ML-KEM 实现正确性的方法，避免存储大量的测试向量。
   - 可以通过命令行参数 `-million` 来运行更大量的测试（一百万次）。
   - 根据是否使用 `-million` 参数以及是否运行短测试 (`testing.Short()`)，会生成不同数量的随机向量，并期望得到不同的哈希值。

6. **Benchmark 函数 (`BenchmarkKeyGen`, `BenchmarkEncaps`, `BenchmarkDecaps`, `BenchmarkRoundTrip`)：**
   - 用于性能基准测试，衡量密钥生成、封装、解封装以及完整流程的性能。

7. **`TestConstantSizes` 函数：**
   - 验证公共 API 中定义的常量（如共享密钥大小、种子大小、密文大小等）是否与内部实现中使用的常量一致。

**它是什么 Go 语言功能的实现？**

这段代码是 **密钥封装机制 (Key Encapsulation Mechanism, KEM)** 的一种实现，具体来说是 **ML-KEM** 的测试代码。KEM 是一种加密技术，允许一方生成一个秘密密钥，并将该密钥安全地传递给另一方，而无需事先共享任何秘密。

**Go 代码举例说明：**

```go
package main

import (
	"crypto/mlkem"
	"fmt"
	"log"
)

func main() {
	// 1. 生成密钥对 (768 参数集)
	decapsulationKey768, err := mlkem.GenerateKey768()
	if err != nil {
		log.Fatal(err)
	}
	encapsulationKey768 := decapsulationKey768.EncapsulationKey()

	// 2. 封装 (使用公钥)
	ciphertext768, sharedSecretAlice768 := encapsulationKey768.Encapsulate()
	fmt.Printf("Ciphertext (768): %x\n", ciphertext768)
	fmt.Printf("Shared Secret (Alice, 768): %x\n", sharedSecretAlice768)

	// 3. 解封装 (使用私钥)
	sharedSecretBob768, err := decapsulationKey768.Decapsulate(ciphertext768)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Shared Secret (Bob, 768): %x\n", sharedSecretBob768)

	// 4. 验证共享密钥是否一致
	if equal := compareByteSlices(sharedSecretAlice768, sharedSecretBob768); equal {
		fmt.Println("Shared secrets match (768)")
	} else {
		fmt.Println("Shared secrets do NOT match (768)")
	}

	// 使用 1024 参数集进行相同的操作
	decapsulationKey1024, err := mlkem.GenerateKey1024()
	if err != nil {
		log.Fatal(err)
	}
	encapsulationKey1024 := decapsulationKey1024.EncapsulationKey()

	ciphertext1024, sharedSecretAlice1024 := encapsulationKey1024.Encapsulate()
	fmt.Printf("\nCiphertext (1024): %x\n", ciphertext1024)
	fmt.Printf("Shared Secret (Alice, 1024): %x\n", sharedSecretAlice1024)

	sharedSecretBob1024, err := decapsulationKey1024.Decapsulate(ciphertext1024)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Shared Secret (Bob, 1024): %x\n", sharedSecretBob1024)

	if equal := compareByteSlices(sharedSecretAlice1024, sharedSecretBob1024); equal {
		fmt.Println("Shared secrets match (1024)")
	} else {
		fmt.Println("Shared secrets do NOT match (1024)")
	}
}

func compareByteSlices(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
```

**假设的输入与输出：**

由于密钥生成和封装过程涉及到随机性，每次运行的输出会不同。但基本的流程是：

**输入：** 无（密钥生成会使用随机源）

**输出（示例）：**

```
Ciphertext (768): <一些十六进制字符串>
Shared Secret (Alice, 768): <一些十六进制字符串>
Shared Secret (Bob, 768): <相同的十六进制字符串>
Shared secrets match (768)

Ciphertext (1024): <一些十六进制字符串>
Shared Secret (Alice, 1024): <一些十六进制字符串>
Shared Secret (Bob, 1024): <相同的十六进制字符串>
Shared secrets match (1024)
```

**命令行参数的具体处理：**

`TestAccumulated` 函数中使用了 `flag` 包来处理命令行参数：

```go
var millionFlag = flag.Bool("million", false, "run the million vector test")
```

- **`flag.Bool("million", false, "run the million vector test")`**: 这行代码定义了一个名为 `million` 的布尔类型的命令行标志。
    - `"million"`: 是命令行标志的名称，用户可以通过 `-million` 或 `-million=true` 来设置它。
    - `false`: 是该标志的默认值，如果用户没有在命令行中指定，则默认为 `false`。
    - `"run the million vector test"`: 是该标志的描述，当用户使用 `-help` 或 `--help` 查看帮助信息时会显示。

在 `TestAccumulated` 函数中，会检查 `*millionFlag` 的值：

```go
if *millionFlag {
	n = 1000000
	expected = "424bf8f0e8ae99b78d788a6e2e8e9cdaf9773fc0c08a6f433507cb559edfd0f0"
}
```

如果用户在运行测试时添加了 `-million` 参数（例如，`go test -million`），那么 `*millionFlag` 的值将为 `true`，`TestAccumulated` 函数会生成一百万个随机向量进行测试，并使用对应的预期哈希值进行验证。

如果没有提供 `-million` 参数，则根据 `testing.Short()` 的结果，会运行较少次数的测试（100 或 10000 次）。

**使用者易犯错的点：**

1. **密钥或密文长度不匹配：**  ML-KEM 算法对密钥和密文的长度有严格的要求。如果使用了错误长度的字节切片来创建密钥对象或进行解封装，会导致错误。`TestBadLengths` 函数就是为了测试这种情况。

   ```go
   // 错误示例：使用错误的字节长度创建解封装密钥
   badKeyBytes := make([]byte, 10) // 假设正确的长度不是 10
   _, err := mlkem.NewDecapsulationKey768(badKeyBytes)
   if err == nil {
       fmt.Println("应该报错，但没有")
   }
   ```

2. **重用密钥进行多次封装：** 虽然对于同一个公钥可以进行多次封装，但每次封装都会产生不同的密文和共享密钥。使用者可能会错误地认为多次封装会产生相同的结果。`TestRoundTrip` 函数验证了这一点。

   ```go
   // 正确的做法：每次封装都会产生新的密文和共享密钥
   encapKey, _ := mlkem.NewEncapsulationKey768(somePublicKeyBytes)
   ciphertext1, secret1 := encapKey.Encapsulate()
   ciphertext2, secret2 := encapKey.Encapsulate()
   if compareByteSlices(ciphertext1, ciphertext2) {
       fmt.Println("密文不应该相同")
   }
   if compareByteSlices(secret1, secret2) {
       fmt.Println("共享密钥不应该相同")
   }
   ```

3. **混淆封装密钥和解封装密钥：**  封装操作需要封装密钥（本质上是公钥），解封装操作需要解封装密钥（本质上是私钥）。混淆使用会导致解封装失败。

   ```go
   // 错误示例：使用封装密钥进行解封装
   encapKey, _ := mlkem.NewEncapsulationKey768(somePublicKeyBytes)
   _, err := encapKey.key.(mlkem.DecapsulationKey).Decapsulate(someCiphertext) // 类型断言会失败，或者逻辑错误
   if err == nil {
       fmt.Println("应该报错，因为封装密钥不能用于解封装")
   }
   ```

总而言之，这段测试代码覆盖了 ML-KEM 的关键功能，并确保其在各种情况下的正确性和健壮性，包括正常流程、错误处理和性能基准。理解这些测试用例有助于更好地理解和使用 `crypto/mlkem` 包。

### 提示词
```
这是路径为go/src/crypto/mlkem/mlkem_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mlkem

import (
	"bytes"
	"crypto/internal/fips140/mlkem"
	"crypto/internal/fips140/sha3"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"testing"
)

type encapsulationKey interface {
	Bytes() []byte
	Encapsulate() ([]byte, []byte)
}

type decapsulationKey[E encapsulationKey] interface {
	Bytes() []byte
	Decapsulate([]byte) ([]byte, error)
	EncapsulationKey() E
}

func TestRoundTrip(t *testing.T) {
	t.Run("768", func(t *testing.T) {
		testRoundTrip(t, GenerateKey768, NewEncapsulationKey768, NewDecapsulationKey768)
	})
	t.Run("1024", func(t *testing.T) {
		testRoundTrip(t, GenerateKey1024, NewEncapsulationKey1024, NewDecapsulationKey1024)
	})
}

func testRoundTrip[E encapsulationKey, D decapsulationKey[E]](
	t *testing.T, generateKey func() (D, error),
	newEncapsulationKey func([]byte) (E, error),
	newDecapsulationKey func([]byte) (D, error)) {
	dk, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()
	c, Ke := ek.Encapsulate()
	Kd, err := dk.Decapsulate(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Ke, Kd) {
		t.Fail()
	}

	ek1, err := newEncapsulationKey(ek.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ek.Bytes(), ek1.Bytes()) {
		t.Fail()
	}
	dk1, err := newDecapsulationKey(dk.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dk.Bytes(), dk1.Bytes()) {
		t.Fail()
	}
	c1, Ke1 := ek1.Encapsulate()
	Kd1, err := dk1.Decapsulate(c1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Ke1, Kd1) {
		t.Fail()
	}

	dk2, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(dk.EncapsulationKey().Bytes(), dk2.EncapsulationKey().Bytes()) {
		t.Fail()
	}
	if bytes.Equal(dk.Bytes(), dk2.Bytes()) {
		t.Fail()
	}

	c2, Ke2 := dk.EncapsulationKey().Encapsulate()
	if bytes.Equal(c, c2) {
		t.Fail()
	}
	if bytes.Equal(Ke, Ke2) {
		t.Fail()
	}
}

func TestBadLengths(t *testing.T) {
	t.Run("768", func(t *testing.T) {
		testBadLengths(t, GenerateKey768, NewEncapsulationKey768, NewDecapsulationKey768)
	})
	t.Run("1024", func(t *testing.T) {
		testBadLengths(t, GenerateKey1024, NewEncapsulationKey1024, NewDecapsulationKey1024)
	})
}

func testBadLengths[E encapsulationKey, D decapsulationKey[E]](
	t *testing.T, generateKey func() (D, error),
	newEncapsulationKey func([]byte) (E, error),
	newDecapsulationKey func([]byte) (D, error)) {
	dk, err := generateKey()
	dkBytes := dk.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()
	ekBytes := dk.EncapsulationKey().Bytes()
	c, _ := ek.Encapsulate()

	for i := 0; i < len(dkBytes)-1; i++ {
		if _, err := newDecapsulationKey(dkBytes[:i]); err == nil {
			t.Errorf("expected error for dk length %d", i)
		}
	}
	dkLong := dkBytes
	for i := 0; i < 100; i++ {
		dkLong = append(dkLong, 0)
		if _, err := newDecapsulationKey(dkLong); err == nil {
			t.Errorf("expected error for dk length %d", len(dkLong))
		}
	}

	for i := 0; i < len(ekBytes)-1; i++ {
		if _, err := newEncapsulationKey(ekBytes[:i]); err == nil {
			t.Errorf("expected error for ek length %d", i)
		}
	}
	ekLong := ekBytes
	for i := 0; i < 100; i++ {
		ekLong = append(ekLong, 0)
		if _, err := newEncapsulationKey(ekLong); err == nil {
			t.Errorf("expected error for ek length %d", len(ekLong))
		}
	}

	for i := 0; i < len(c)-1; i++ {
		if _, err := dk.Decapsulate(c[:i]); err == nil {
			t.Errorf("expected error for c length %d", i)
		}
	}
	cLong := c
	for i := 0; i < 100; i++ {
		cLong = append(cLong, 0)
		if _, err := dk.Decapsulate(cLong); err == nil {
			t.Errorf("expected error for c length %d", len(cLong))
		}
	}
}

var millionFlag = flag.Bool("million", false, "run the million vector test")

// TestAccumulated accumulates 10k (or 100, or 1M) random vectors and checks the
// hash of the result, to avoid checking in 150MB of test vectors.
func TestAccumulated(t *testing.T) {
	n := 10000
	expected := "8a518cc63da366322a8e7a818c7a0d63483cb3528d34a4cf42f35d5ad73f22fc"
	if testing.Short() {
		n = 100
		expected = "1114b1b6699ed191734fa339376afa7e285c9e6acf6ff0177d346696ce564415"
	}
	if *millionFlag {
		n = 1000000
		expected = "424bf8f0e8ae99b78d788a6e2e8e9cdaf9773fc0c08a6f433507cb559edfd0f0"
	}

	s := sha3.NewShake128()
	o := sha3.NewShake128()
	seed := make([]byte, SeedSize)
	var msg [32]byte
	ct1 := make([]byte, CiphertextSize768)

	for i := 0; i < n; i++ {
		s.Read(seed)
		dk, err := NewDecapsulationKey768(seed)
		if err != nil {
			t.Fatal(err)
		}
		ek := dk.EncapsulationKey()
		o.Write(ek.Bytes())

		s.Read(msg[:])
		ct, k := ek.key.EncapsulateInternal(&msg)
		o.Write(ct)
		o.Write(k)

		kk, err := dk.Decapsulate(ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(kk, k) {
			t.Errorf("k: got %x, expected %x", kk, k)
		}

		s.Read(ct1)
		k1, err := dk.Decapsulate(ct1)
		if err != nil {
			t.Fatal(err)
		}
		o.Write(k1)
	}

	got := hex.EncodeToString(o.Sum(nil))
	if got != expected {
		t.Errorf("got %s, expected %s", got, expected)
	}
}

var sink byte

func BenchmarkKeyGen(b *testing.B) {
	var d, z [32]byte
	rand.Read(d[:])
	rand.Read(z[:])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dk := mlkem.GenerateKeyInternal768(&d, &z)
		sink ^= dk.EncapsulationKey().Bytes()[0]
	}
}

func BenchmarkEncaps(b *testing.B) {
	seed := make([]byte, SeedSize)
	rand.Read(seed)
	var m [32]byte
	rand.Read(m[:])
	dk, err := NewDecapsulationKey768(seed)
	if err != nil {
		b.Fatal(err)
	}
	ekBytes := dk.EncapsulationKey().Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ek, err := NewEncapsulationKey768(ekBytes)
		if err != nil {
			b.Fatal(err)
		}
		c, K := ek.key.EncapsulateInternal(&m)
		sink ^= c[0] ^ K[0]
	}
}

func BenchmarkDecaps(b *testing.B) {
	dk, err := GenerateKey768()
	if err != nil {
		b.Fatal(err)
	}
	ek := dk.EncapsulationKey()
	c, _ := ek.Encapsulate()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		K, _ := dk.Decapsulate(c)
		sink ^= K[0]
	}
}

func BenchmarkRoundTrip(b *testing.B) {
	dk, err := GenerateKey768()
	if err != nil {
		b.Fatal(err)
	}
	ek := dk.EncapsulationKey()
	ekBytes := ek.Bytes()
	c, _ := ek.Encapsulate()
	if err != nil {
		b.Fatal(err)
	}
	b.Run("Alice", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			dkS, err := GenerateKey768()
			if err != nil {
				b.Fatal(err)
			}
			ekS := dkS.EncapsulationKey().Bytes()
			sink ^= ekS[0]

			Ks, err := dk.Decapsulate(c)
			if err != nil {
				b.Fatal(err)
			}
			sink ^= Ks[0]
		}
	})
	b.Run("Bob", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ek, err := NewEncapsulationKey768(ekBytes)
			if err != nil {
				b.Fatal(err)
			}
			cS, Ks := ek.Encapsulate()
			if err != nil {
				b.Fatal(err)
			}
			sink ^= cS[0] ^ Ks[0]
		}
	})
}

// Test that the constants from the public API match the corresponding values from the internal API.
func TestConstantSizes(t *testing.T) {
	if SharedKeySize != mlkem.SharedKeySize {
		t.Errorf("SharedKeySize mismatch: got %d, want %d", SharedKeySize, mlkem.SharedKeySize)
	}

	if SeedSize != mlkem.SeedSize {
		t.Errorf("SeedSize mismatch: got %d, want %d", SeedSize, mlkem.SeedSize)
	}

	if CiphertextSize768 != mlkem.CiphertextSize768 {
		t.Errorf("CiphertextSize768 mismatch: got %d, want %d", CiphertextSize768, mlkem.CiphertextSize768)
	}

	if EncapsulationKeySize768 != mlkem.EncapsulationKeySize768 {
		t.Errorf("EncapsulationKeySize768 mismatch: got %d, want %d", EncapsulationKeySize768, mlkem.EncapsulationKeySize768)
	}

	if CiphertextSize1024 != mlkem.CiphertextSize1024 {
		t.Errorf("CiphertextSize1024 mismatch: got %d, want %d", CiphertextSize1024, mlkem.CiphertextSize1024)
	}

	if EncapsulationKeySize1024 != mlkem.EncapsulationKeySize1024 {
		t.Errorf("EncapsulationKeySize1024 mismatch: got %d, want %d", EncapsulationKeySize1024, mlkem.EncapsulationKeySize1024)
	}
}
```