Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding: Context and Purpose**

The first step is to read the initial comments. They immediately tell us:

* **Purpose:** Implementation of ML-KEM-768, a quantum-resistant key encapsulation method, as defined in NIST FIPS 203.
* **Key Goals:** Security, correctness, simplicity, readability, and reviewability. Constant-time operations are emphasized.
* **Naming Convention:**  Variable and function names align with the NIST FIPS 203 document.
* **Relation to ML-KEM-1024:** This file implements ML-KEM-768, and ML-KEM-1024 is auto-generated from it. This hints at parameterization and potential code duplication.

**2. Identifying Key Data Structures**

Next, I scanned for defined types and constants. This reveals the core data structures:

* **Constants:** `n`, `q`, various `encodingSizeX`, `messageSize`, `SharedKeySize`, `SeedSize`, `k`, `CiphertextSize768`, `EncapsulationKeySize768`, `k1024`, `CiphertextSize1024`, `EncapsulationKeySize1024`. These define the dimensions and sizes of cryptographic elements.
* **Structs:** `DecapsulationKey768`, `EncapsulationKey768`, `encryptionKey`, `decryptionKey`. These represent the core key materials. The comments within these structs are crucial for understanding their components (seeds, precomputed values, etc.).

**3. Analyzing Functions and Methods**

I then started looking at the functions and methods defined for these types:

* **`DecapsulationKey768` Methods:** `Bytes()`, `EncapsulationKey()`. These are standard ways to access the raw bytes of the secret key and to get the associated public key.
* **`EncapsulationKey768` Methods:** `Bytes()`, `bytes()`, `Encapsulate()`, `EncapsulateInternal()`. These provide ways to access the public key bytes and perform the encapsulation process.
* **Key Generation Functions:** `GenerateKey768()`, `GenerateKeyInternal768()`, `NewDecapsulationKey768()`, `newKeyFromSeed()`. These are responsible for creating key pairs. The "Internal" version suggests a test-specific function.
* **Core Cryptographic Functions:** `kemKeyGen()`, `kemPCT()`, `kemEncaps()`, `kemDecaps()`, `pkeEncrypt()`, `pkeDecrypt()`. These are the heart of the ML-KEM implementation. The comments often directly reference the corresponding algorithms in FIPS 203.
* **Parsing Function:** `NewEncapsulationKey768()`, `parseEK()`. These handle converting the byte representation of the public key into the structured `EncapsulationKey768` type.

**4. Inferring Functionality (and Guessing at Underlying Details)**

At this point, I started to infer the high-level functionality based on the names and comments:

* **Key Generation:**  Involves generating random seeds (`d`, `z`), expanding them, and computing public and private key components.
* **Encapsulation:** Takes a public key, generates a shared secret and ciphertext.
* **Decapsulation:** Takes a private key and ciphertext, and attempts to recover the shared secret.
* **PCT (Pairwise Consistency Test):** A standard test to ensure that the key generation and encapsulation/decapsulation processes work correctly by verifying that encapsulating and then decapsulating results in the same shared secret.

I also started making educated guesses about the underlying cryptographic primitives:

* **Hashing:** The frequent use of `sha3.New512()` and `sha3.New256()` suggests SHA-3 is used for various purposes like key derivation and randomness generation.
* **DRBG:**  The use of `drbg.Read()` indicates a Deterministic Random Bit Generator is used for generating cryptographic randomness.
* **Polynomial Arithmetic (implied):** The names `nttElement`, `ringElement`, and functions like `polyAdd`, `nttMul`, `inverseNTT`, `polyByteEncode`, `polyByteDecode`, `ringCompressAndEncode`, `ringDecodeAndDecompress` strongly suggest operations on polynomials in a specific ring, and the Number Theoretic Transform (NTT) for efficient polynomial multiplication. While the exact implementation of these functions isn't in this snippet, their presence is a major clue.

**5. Code Example Formulation (Iterative Process)**

To illustrate the functionality with Go code, I focused on the main use cases: key generation, encapsulation, and decapsulation. This involved:

* **Identifying the relevant functions:** `GenerateKey768()`, `Encapsulate()`, `Decapsulate()`.
* **Determining the necessary inputs and outputs:**  Key types, ciphertext, shared secret.
* **Writing basic Go code that calls these functions and prints the results.**  I started with very simple examples and then added error handling.

**6. Command-Line Arguments (Not Present in Snippet)**

The code snippet doesn't show any direct command-line argument processing. Therefore, the correct answer is that there are none. It's important to stick to what's in the provided text.

**7. Common Mistakes (Based on the API)**

I considered potential errors users might make based on the function signatures and comments:

* **Incorrect Key Sizes:** Passing keys of the wrong length to `NewDecapsulationKey768()` or `NewEncapsulationKey768()`.
* **Misunderstanding Secret Key Handling:**  Not keeping the `DecapsulationKey768` secret.
* **Incorrect Ciphertext Length:** Providing a ciphertext of the wrong size to `Decapsulate()`.

**8. Structuring the Answer**

Finally, I organized the information logically, starting with the main functions and then delving into details like data structures, code examples, and potential pitfalls. Using clear headings and bullet points makes the answer easier to read and understand.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe there's more complex logic involving the `go:generate` directive. **Correction:** Realized the directive is for *generating* another file, not directly part of the runtime functionality of this specific file. Focused on the code within `mlkem768.go`.
* **Initial thought:** Should I try to explain the NTT and polynomial arithmetic in detail? **Correction:**  The prompt asks for *functionality*. The detailed math is implementation-specific and would make the answer too long. Mentioning their presence is sufficient. The link in the comments about Kyber math is a good pointer for deeper understanding.
* **Initial thought:** Should I guess about potential security vulnerabilities? **Correction:** The prompt focuses on functionality and common usage errors. Security analysis is a separate concern.

By following these steps, combining code analysis with an understanding of cryptographic concepts, and iteratively refining my understanding, I arrived at the detailed explanation provided in the initial prompt.
这段Go语言代码是 `crypto/internal/fips140/mlkem/mlkem768.go` 文件的一部分，它实现了 **ML-KEM-768** 密钥封装方法。 ML-KEM (也称为 Kyber) 是一种后量子密码学算法，用于在不安全的信道上安全地协商共享密钥。 该代码的目标是安全、正确、简洁、可读和可审查性，并强调所有关键操作都在恒定时间内执行。

以下是该代码片段的主要功能：

1. **定义 ML-KEM-768 的参数：**
   - `n`, `q`: 环的维度和模数。
   - `encodingSizeX`: 不同压缩级别的编码大小。
   - `messageSize`: 消息的大小。
   - `SharedKeySize`: 共享密钥的大小 (32 字节)。
   - `SeedSize`: 密钥生成使用的种子大小 (64 字节)。
   - `k`: ML-KEM-768 的模块维度 (3)。
   - `CiphertextSize768`: ML-KEM-768 密文的大小。
   - `EncapsulationKeySize768`: ML-KEM-768 封装密钥（公钥）的大小。

2. **定义密钥结构体：**
   - `DecapsulationKey768` (解封装密钥/私钥)：包含解封装所需的秘密信息，包括种子 `d` 和 `z`，用于生成公钥的随机数种子 `ρ`，以及公钥哈希 `h`，以及加密密钥和解密密钥的内部表示。
   - `EncapsulationKey768` (封装密钥/公钥)：包含加密所需的公开信息，包括用于生成矩阵 A 的随机数种子 `ρ` 和公钥的哈希 `h`，以及加密密钥的内部表示。
   - `encryptionKey`:  公钥的解析和展开形式，包含多项式 `t` 和矩阵 `a` 的 NTT 表示。
   - `decryptionKey`: 私钥的解析和展开形式，包含多项式 `s` 的 NTT 表示。

3. **密钥生成功能：**
   - `GenerateKey768()`: 生成一个新的 ML-KEM-768 解封装密钥（私钥）。它使用 DRBG (Deterministic Random Bit Generator) 来生成随机字节。
   - `GenerateKeyInternal768()`: `GenerateKey768()` 的确定性版本，主要用于测试。它接受预先指定的种子 `d` 和 `z`。
   - `NewDecapsulationKey768()`: 从一个 64 字节的种子 ("d || z" 形式) 解析出一个解封装密钥。

4. **密钥导出功能：**
   - `(*DecapsulationKey768).Bytes()`: 将解封装密钥以 64 字节种子的形式返回。
   - `(*DecapsulationKey768).EncapsulationKey()`: 返回与解封装密钥关联的封装密钥（公钥）。
   - `(*EncapsulationKey768).Bytes()`: 将封装密钥以字节切片的形式返回。

5. **封装功能：**
   - `(*EncapsulationKey768).Encapsulate()`: 使用封装密钥（公钥）生成一个共享密钥和一个关联的密文。它使用 DRBG 生成随机字节。
   - `(*EncapsulationKey768).EncapsulateInternal()`: `Encapsulate()` 的确定性版本，主要用于测试。它接受一个预先指定的消息 `m`。
   - `NewEncapsulationKey768()`: 从其编码形式解析出一个封装密钥。

6. **解封装功能：**
   - `(*DecapsulationKey768).Decapsulate()`: 使用解封装密钥（私钥）从密文中提取出共享密钥。

7. **内部加密和解密功能 (PKE 部分)：**
   - `pkeEncrypt()`: 使用公钥加密一个消息，生成密文的 PKE (Public Key Encryption) 部分。
   - `pkeDecrypt()`: 使用私钥解密 PKE 密文，恢复消息。

8. **内部密钥生成、封装和解封装功能 (KEM 部分)：**
   - `kemKeyGen()`: 生成解封装密钥的内部逻辑，实现了 FIPS 203 的 Algorithm 16 和 Algorithm 13。
   - `kemEncaps()`: 生成共享密钥和密文的内部逻辑，实现了 FIPS 203 的 Algorithm 17。
   - `kemDecaps()`: 从密文恢复共享密钥的内部逻辑，实现了 FIPS 203 的 Algorithm 18。

9. **成对一致性测试 (PCT)：**
   - `kemPCT()`:  执行成对一致性测试，验证生成的密钥对是否能够正确地进行封装和解封装操作，确保生成的共享密钥一致。这是 FIPS 140-3 要求的。

**它是什么 Go 语言功能的实现？**

这段代码实现的是 **密钥封装机制 (Key Encapsulation Mechanism, KEM)**。 KEM 是一种公钥加密技术，允许一方（封装者）为另一方（解封装者）生成一个秘密的共享密钥，以及一个可以公开传输的密文。 只有拥有对应私钥的解封装者才能从密文中恢复出共享密钥。

**Go 代码示例：**

以下是一个使用 `mlkem768` 包进行密钥生成、封装和解封装的示例：

```go
package main

import (
	"fmt"
	"log"

	"crypto/internal/fips140/mlkem"
)

func main() {
	// 1. 生成密钥对
	decapsulationKey, err := mlkem.GenerateKey768()
	if err != nil {
		log.Fatalf("生成密钥对失败: %v", err)
	}
	encapsulationKey := decapsulationKey.EncapsulationKey()

	// 2. 封装
	ciphertext, sharedKey1 := encapsulationKey.Encapsulate()
	fmt.Printf("密文: %x\n", ciphertext)
	fmt.Printf("封装者生成的共享密钥: %x\n", sharedKey1)

	// 3. 解封装
	sharedKey2, err := decapsulationKey.Decapsulate(ciphertext)
	if err != nil {
		log.Fatalf("解封装失败: %v", err)
	}
	fmt.Printf("解封装者生成的共享密钥: %x\n", sharedKey2)

	// 验证共享密钥是否一致
	if string(sharedKey1) == string(sharedKey2) {
		fmt.Println("共享密钥一致")
	} else {
		fmt.Println("共享密钥不一致")
	}
}
```

**假设的输入与输出：**

由于密钥生成和封装过程涉及到随机数，所以每次运行的输出都会不同。以下是一个**可能的**输出示例：

```
密文: 8934abcf12...a9b0
封装者生成的共享密钥: 9a2b3c4d...f012
解封装者生成的共享密钥: 9a2b3c4d...f012
共享密钥一致
```

这里的 `...` 代表省略的字节，实际的密文和共享密钥会更长。

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。它是一个库，用于实现 ML-KEM-768 算法。如果需要通过命令行使用此功能，则需要编写一个使用此库的命令行工具，并处理相应的参数。例如，一个命令行工具可能会接受用于生成密钥的种子，或者接受公钥和消息来进行封装操作。

**使用者易犯错的点：**

1. **密钥管理不当：**  `DecapsulationKey768` 包含私钥信息，**必须严格保密**。泄露私钥会导致安全风险。使用者可能会错误地存储或传输私钥。

   **示例：**

   ```go
   // 错误的做法：将私钥打印出来
   fmt.Printf("私钥: %x\n", decapsulationKey.Bytes())

   // 错误的做法：将私钥存储在不安全的文件中
   // ...
   ```

2. **密文长度校验不足：** 在解封装时，如果不对输入的密文长度进行校验，可能会导致程序错误或安全漏洞。代码中已经进行了校验 (`len(ciphertext) != CiphertextSize768`)，但使用者在自己的代码中也需要注意。

   **示例：**

   ```go
   // 假设使用者忘记校验密文长度
   func processCiphertext(ciphertext []byte, dk *mlkem.DecapsulationKey768) {
       // 缺少 len(ciphertext) == mlkem.CiphertextSize768 的判断
       sharedKey, err := dk.Decapsulate(ciphertext)
       // ...
   }
   ```

3. **使用非随机的种子：**  `NewDecapsulationKey768` 接受一个种子，这个种子**必须是均匀随机的**。如果使用非随机或可预测的种子，会大大降低密钥的安全性。

   **示例：**

   ```go
   // 错误的做法：使用固定的字符串作为种子
   seed := []byte("this is not a random seed")
   dk, _ := mlkem.NewDecapsulationKey768(seed)
   ```

4. **混淆封装密钥和解封装密钥：** 封装操作需要使用 `EncapsulationKey768`（公钥），解封装操作需要使用 `DecapsulationKey768`（私钥）。 混淆使用会导致操作失败。

   **示例：**

   ```go
   // 错误的做法：尝试用解封装密钥进行封装
   // ciphertext, sharedKey := decapsulationKey.Encapsulate() // 编译错误，DecapsulationKey768 没有 Encapsulate 方法
   ```

理解这些功能和潜在的错误点，可以帮助开发者更安全、正确地使用 `mlkem768` 包。

Prompt: 
```
这是路径为go/src/crypto/internal/fips140/mlkem/mlkem768.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package mlkem implements the quantum-resistant key encapsulation method
// ML-KEM (formerly known as Kyber), as specified in [NIST FIPS 203].
//
// [NIST FIPS 203]: https://doi.org/10.6028/NIST.FIPS.203
package mlkem

// This package targets security, correctness, simplicity, readability, and
// reviewability as its primary goals. All critical operations are performed in
// constant time.
//
// Variable and function names, as well as code layout, are selected to
// facilitate reviewing the implementation against the NIST FIPS 203 document.
//
// Reviewers unfamiliar with polynomials or linear algebra might find the
// background at https://words.filippo.io/kyber-math/ useful.
//
// This file implements the recommended parameter set ML-KEM-768. The ML-KEM-1024
// parameter set implementation is auto-generated from this file.
//
//go:generate go run generate1024.go -input mlkem768.go -output mlkem1024.go

import (
	"crypto/internal/fips140"
	"crypto/internal/fips140/drbg"
	"crypto/internal/fips140/sha3"
	"crypto/internal/fips140/subtle"
	"errors"
)

const (
	// ML-KEM global constants.
	n = 256
	q = 3329

	// encodingSizeX is the byte size of a ringElement or nttElement encoded
	// by ByteEncode_X (FIPS 203, Algorithm 5).
	encodingSize12 = n * 12 / 8
	encodingSize11 = n * 11 / 8
	encodingSize10 = n * 10 / 8
	encodingSize5  = n * 5 / 8
	encodingSize4  = n * 4 / 8
	encodingSize1  = n * 1 / 8

	messageSize = encodingSize1

	SharedKeySize = 32
	SeedSize      = 32 + 32
)

// ML-KEM-768 parameters.
const (
	k = 3

	CiphertextSize768       = k*encodingSize10 + encodingSize4
	EncapsulationKeySize768 = k*encodingSize12 + 32
)

// ML-KEM-1024 parameters.
const (
	k1024 = 4

	CiphertextSize1024       = k1024*encodingSize11 + encodingSize5
	EncapsulationKeySize1024 = k1024*encodingSize12 + 32
)

// A DecapsulationKey768 is the secret key used to decapsulate a shared key from a
// ciphertext. It includes various precomputed values.
type DecapsulationKey768 struct {
	d [32]byte // decapsulation key seed
	z [32]byte // implicit rejection sampling seed

	ρ [32]byte // sampleNTT seed for A, stored for the encapsulation key
	h [32]byte // H(ek), stored for ML-KEM.Decaps_internal

	encryptionKey
	decryptionKey
}

// Bytes returns the decapsulation key as a 64-byte seed in the "d || z" form.
//
// The decapsulation key must be kept secret.
func (dk *DecapsulationKey768) Bytes() []byte {
	var b [SeedSize]byte
	copy(b[:], dk.d[:])
	copy(b[32:], dk.z[:])
	return b[:]
}

// EncapsulationKey returns the public encapsulation key necessary to produce
// ciphertexts.
func (dk *DecapsulationKey768) EncapsulationKey() *EncapsulationKey768 {
	return &EncapsulationKey768{
		ρ:             dk.ρ,
		h:             dk.h,
		encryptionKey: dk.encryptionKey,
	}
}

// An EncapsulationKey768 is the public key used to produce ciphertexts to be
// decapsulated by the corresponding [DecapsulationKey768].
type EncapsulationKey768 struct {
	ρ [32]byte // sampleNTT seed for A
	h [32]byte // H(ek)
	encryptionKey
}

// Bytes returns the encapsulation key as a byte slice.
func (ek *EncapsulationKey768) Bytes() []byte {
	// The actual logic is in a separate function to outline this allocation.
	b := make([]byte, 0, EncapsulationKeySize768)
	return ek.bytes(b)
}

func (ek *EncapsulationKey768) bytes(b []byte) []byte {
	for i := range ek.t {
		b = polyByteEncode(b, ek.t[i])
	}
	b = append(b, ek.ρ[:]...)
	return b
}

// encryptionKey is the parsed and expanded form of a PKE encryption key.
type encryptionKey struct {
	t [k]nttElement     // ByteDecode₁₂(ek[:384k])
	a [k * k]nttElement // A[i*k+j] = sampleNTT(ρ, j, i)
}

// decryptionKey is the parsed and expanded form of a PKE decryption key.
type decryptionKey struct {
	s [k]nttElement // ByteDecode₁₂(dk[:decryptionKeySize])
}

// GenerateKey768 generates a new decapsulation key, drawing random bytes from
// a DRBG. The decapsulation key must be kept secret.
func GenerateKey768() (*DecapsulationKey768, error) {
	// The actual logic is in a separate function to outline this allocation.
	dk := &DecapsulationKey768{}
	return generateKey(dk)
}

func generateKey(dk *DecapsulationKey768) (*DecapsulationKey768, error) {
	var d [32]byte
	drbg.Read(d[:])
	var z [32]byte
	drbg.Read(z[:])
	kemKeyGen(dk, &d, &z)
	if err := fips140.PCT("ML-KEM PCT", func() error { return kemPCT(dk) }); err != nil {
		// This clearly can't happen, but FIPS 140-3 requires us to check.
		panic(err)
	}
	fips140.RecordApproved()
	return dk, nil
}

// GenerateKeyInternal768 is a derandomized version of GenerateKey768,
// exclusively for use in tests.
func GenerateKeyInternal768(d, z *[32]byte) *DecapsulationKey768 {
	dk := &DecapsulationKey768{}
	kemKeyGen(dk, d, z)
	return dk
}

// NewDecapsulationKey768 parses a decapsulation key from a 64-byte
// seed in the "d || z" form. The seed must be uniformly random.
func NewDecapsulationKey768(seed []byte) (*DecapsulationKey768, error) {
	// The actual logic is in a separate function to outline this allocation.
	dk := &DecapsulationKey768{}
	return newKeyFromSeed(dk, seed)
}

func newKeyFromSeed(dk *DecapsulationKey768, seed []byte) (*DecapsulationKey768, error) {
	if len(seed) != SeedSize {
		return nil, errors.New("mlkem: invalid seed length")
	}
	d := (*[32]byte)(seed[:32])
	z := (*[32]byte)(seed[32:])
	kemKeyGen(dk, d, z)
	if err := fips140.PCT("ML-KEM PCT", func() error { return kemPCT(dk) }); err != nil {
		// This clearly can't happen, but FIPS 140-3 requires us to check.
		panic(err)
	}
	fips140.RecordApproved()
	return dk, nil
}

// kemKeyGen generates a decapsulation key.
//
// It implements ML-KEM.KeyGen_internal according to FIPS 203, Algorithm 16, and
// K-PKE.KeyGen according to FIPS 203, Algorithm 13. The two are merged to save
// copies and allocations.
func kemKeyGen(dk *DecapsulationKey768, d, z *[32]byte) {
	dk.d = *d
	dk.z = *z

	g := sha3.New512()
	g.Write(d[:])
	g.Write([]byte{k}) // Module dimension as a domain separator.
	G := g.Sum(make([]byte, 0, 64))
	ρ, σ := G[:32], G[32:]
	dk.ρ = [32]byte(ρ)

	A := &dk.a
	for i := byte(0); i < k; i++ {
		for j := byte(0); j < k; j++ {
			A[i*k+j] = sampleNTT(ρ, j, i)
		}
	}

	var N byte
	s := &dk.s
	for i := range s {
		s[i] = ntt(samplePolyCBD(σ, N))
		N++
	}
	e := make([]nttElement, k)
	for i := range e {
		e[i] = ntt(samplePolyCBD(σ, N))
		N++
	}

	t := &dk.t
	for i := range t { // t = A ◦ s + e
		t[i] = e[i]
		for j := range s {
			t[i] = polyAdd(t[i], nttMul(A[i*k+j], s[j]))
		}
	}

	H := sha3.New256()
	ek := dk.EncapsulationKey().Bytes()
	H.Write(ek)
	H.Sum(dk.h[:0])
}

// kemPCT performs a Pairwise Consistency Test per FIPS 140-3 IG 10.3.A
// Additional Comment 1: "For key pairs generated for use with approved KEMs in
// FIPS 203, the PCT shall consist of applying the encapsulation key ek to
// encapsulate a shared secret K leading to ciphertext c, and then applying
// decapsulation key dk to retrieve the same shared secret K. The PCT passes if
// the two shared secret K values are equal. The PCT shall be performed either
// when keys are generated/imported, prior to the first exportation, or prior to
// the first operational use (if not exported before the first use)."
func kemPCT(dk *DecapsulationKey768) error {
	ek := dk.EncapsulationKey()
	c, K := ek.Encapsulate()
	K1, err := dk.Decapsulate(c)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(K, K1) != 1 {
		return errors.New("mlkem: PCT failed")
	}
	return nil
}

// Encapsulate generates a shared key and an associated ciphertext from an
// encapsulation key, drawing random bytes from a DRBG.
//
// The shared key must be kept secret.
func (ek *EncapsulationKey768) Encapsulate() (ciphertext, sharedKey []byte) {
	// The actual logic is in a separate function to outline this allocation.
	var cc [CiphertextSize768]byte
	return ek.encapsulate(&cc)
}

func (ek *EncapsulationKey768) encapsulate(cc *[CiphertextSize768]byte) (ciphertext, sharedKey []byte) {
	var m [messageSize]byte
	drbg.Read(m[:])
	// Note that the modulus check (step 2 of the encapsulation key check from
	// FIPS 203, Section 7.2) is performed by polyByteDecode in parseEK.
	fips140.RecordApproved()
	return kemEncaps(cc, ek, &m)
}

// EncapsulateInternal is a derandomized version of Encapsulate, exclusively for
// use in tests.
func (ek *EncapsulationKey768) EncapsulateInternal(m *[32]byte) (ciphertext, sharedKey []byte) {
	cc := &[CiphertextSize768]byte{}
	return kemEncaps(cc, ek, m)
}

// kemEncaps generates a shared key and an associated ciphertext.
//
// It implements ML-KEM.Encaps_internal according to FIPS 203, Algorithm 17.
func kemEncaps(cc *[CiphertextSize768]byte, ek *EncapsulationKey768, m *[messageSize]byte) (c, K []byte) {
	g := sha3.New512()
	g.Write(m[:])
	g.Write(ek.h[:])
	G := g.Sum(nil)
	K, r := G[:SharedKeySize], G[SharedKeySize:]
	c = pkeEncrypt(cc, &ek.encryptionKey, m, r)
	return c, K
}

// NewEncapsulationKey768 parses an encapsulation key from its encoded form.
// If the encapsulation key is not valid, NewEncapsulationKey768 returns an error.
func NewEncapsulationKey768(encapsulationKey []byte) (*EncapsulationKey768, error) {
	// The actual logic is in a separate function to outline this allocation.
	ek := &EncapsulationKey768{}
	return parseEK(ek, encapsulationKey)
}

// parseEK parses an encryption key from its encoded form.
//
// It implements the initial stages of K-PKE.Encrypt according to FIPS 203,
// Algorithm 14.
func parseEK(ek *EncapsulationKey768, ekPKE []byte) (*EncapsulationKey768, error) {
	if len(ekPKE) != EncapsulationKeySize768 {
		return nil, errors.New("mlkem: invalid encapsulation key length")
	}

	h := sha3.New256()
	h.Write(ekPKE)
	h.Sum(ek.h[:0])

	for i := range ek.t {
		var err error
		ek.t[i], err = polyByteDecode[nttElement](ekPKE[:encodingSize12])
		if err != nil {
			return nil, err
		}
		ekPKE = ekPKE[encodingSize12:]
	}
	copy(ek.ρ[:], ekPKE)

	for i := byte(0); i < k; i++ {
		for j := byte(0); j < k; j++ {
			ek.a[i*k+j] = sampleNTT(ek.ρ[:], j, i)
		}
	}

	return ek, nil
}

// pkeEncrypt encrypt a plaintext message.
//
// It implements K-PKE.Encrypt according to FIPS 203, Algorithm 14, although the
// computation of t and AT is done in parseEK.
func pkeEncrypt(cc *[CiphertextSize768]byte, ex *encryptionKey, m *[messageSize]byte, rnd []byte) []byte {
	var N byte
	r, e1 := make([]nttElement, k), make([]ringElement, k)
	for i := range r {
		r[i] = ntt(samplePolyCBD(rnd, N))
		N++
	}
	for i := range e1 {
		e1[i] = samplePolyCBD(rnd, N)
		N++
	}
	e2 := samplePolyCBD(rnd, N)

	u := make([]ringElement, k) // NTT⁻¹(AT ◦ r) + e1
	for i := range u {
		u[i] = e1[i]
		for j := range r {
			// Note that i and j are inverted, as we need the transposed of A.
			u[i] = polyAdd(u[i], inverseNTT(nttMul(ex.a[j*k+i], r[j])))
		}
	}

	μ := ringDecodeAndDecompress1(m)

	var vNTT nttElement // t⊺ ◦ r
	for i := range ex.t {
		vNTT = polyAdd(vNTT, nttMul(ex.t[i], r[i]))
	}
	v := polyAdd(polyAdd(inverseNTT(vNTT), e2), μ)

	c := cc[:0]
	for _, f := range u {
		c = ringCompressAndEncode10(c, f)
	}
	c = ringCompressAndEncode4(c, v)

	return c
}

// Decapsulate generates a shared key from a ciphertext and a decapsulation key.
// If the ciphertext is not valid, Decapsulate returns an error.
//
// The shared key must be kept secret.
func (dk *DecapsulationKey768) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	if len(ciphertext) != CiphertextSize768 {
		return nil, errors.New("mlkem: invalid ciphertext length")
	}
	c := (*[CiphertextSize768]byte)(ciphertext)
	// Note that the hash check (step 3 of the decapsulation input check from
	// FIPS 203, Section 7.3) is foregone as a DecapsulationKey is always
	// validly generated by ML-KEM.KeyGen_internal.
	return kemDecaps(dk, c), nil
}

// kemDecaps produces a shared key from a ciphertext.
//
// It implements ML-KEM.Decaps_internal according to FIPS 203, Algorithm 18.
func kemDecaps(dk *DecapsulationKey768, c *[CiphertextSize768]byte) (K []byte) {
	fips140.RecordApproved()
	m := pkeDecrypt(&dk.decryptionKey, c)
	g := sha3.New512()
	g.Write(m[:])
	g.Write(dk.h[:])
	G := g.Sum(make([]byte, 0, 64))
	Kprime, r := G[:SharedKeySize], G[SharedKeySize:]
	J := sha3.NewShake256()
	J.Write(dk.z[:])
	J.Write(c[:])
	Kout := make([]byte, SharedKeySize)
	J.Read(Kout)
	var cc [CiphertextSize768]byte
	c1 := pkeEncrypt(&cc, &dk.encryptionKey, (*[32]byte)(m), r)

	subtle.ConstantTimeCopy(subtle.ConstantTimeCompare(c[:], c1), Kout, Kprime)
	return Kout
}

// pkeDecrypt decrypts a ciphertext.
//
// It implements K-PKE.Decrypt according to FIPS 203, Algorithm 15,
// although s is retained from kemKeyGen.
func pkeDecrypt(dx *decryptionKey, c *[CiphertextSize768]byte) []byte {
	u := make([]ringElement, k)
	for i := range u {
		b := (*[encodingSize10]byte)(c[encodingSize10*i : encodingSize10*(i+1)])
		u[i] = ringDecodeAndDecompress10(b)
	}

	b := (*[encodingSize4]byte)(c[encodingSize10*k:])
	v := ringDecodeAndDecompress4(b)

	var mask nttElement // s⊺ ◦ NTT(u)
	for i := range dx.s {
		mask = polyAdd(mask, nttMul(dx.s[i], ntt(u[i])))
	}
	w := polySub(v, inverseNTT(mask))

	return ringCompressAndEncode1(nil, w)
}

"""



```