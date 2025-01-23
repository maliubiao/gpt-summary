Response:
Let's break down the thought process to analyze the provided Go code.

1. **Understand the Context:** The file path `go/src/crypto/internal/fips140/ecdsa/ecdsa.go` immediately tells us this is part of Go's internal cryptographic library and specifically deals with ECDSA (Elliptic Curve Digital Signature Algorithm) within a FIPS 140 context. FIPS 140 is a US government standard for cryptographic modules, so security and adherence to specific algorithms are likely key.

2. **Identify Core Data Structures:** The code defines `PrivateKey`, `PublicKey`, `curveID`, `Curve`, and `Signature`. These are the fundamental building blocks. Notice the generic `Curve[P Point[P]]` which allows it to work with different elliptic curves. The `Point` interface constraint reveals the underlying point representation is likely from the `crypto/internal/fips140/nistec` package.

3. **Analyze Key Functions and Methods:** Go through the code and identify the purpose of each function and method.

    * **Data Structure Methods:**  `Bytes()`, `PublicKey()` on `PrivateKey`; `Bytes()` on `PublicKey`. These are standard ways to get the byte representations of the keys.

    * **Curve Creation:**  `P224()`, `P256()`, `P384()`, `P521()`. These are likely factory functions to get `Curve` instances for specific NIST curves. The `sync.OnceValue` pattern suggests these are initialized lazily and only once.

    * **Key Generation:** `NewPrivateKey()`, `NewPublicKey()`, `GenerateKey()`. These are the core functions for creating key pairs. `GenerateKey` clearly involves a random number generator.

    * **Signing and Verification:** `Sign()`, `SignDeterministic()`, `Verify()`. These implement the core ECDSA signing and verification operations. Notice the differences between `Sign` (uses a "hedged" approach) and `SignDeterministic` (FIPS 186-5 and RFC 6979).

    * **Internal Helper Functions:** `precomputeParams()`, `randomPoint()`, `bits2octets()`, `signGeneric()`, `inverse()`, `hashToNat()`, `rightShift()`, `verifyGeneric()`. These are internal functions that support the main operations. Pay attention to functions with "internal" in their name or those called only within the package.

4. **Infer the Overall Functionality:** Based on the identified data structures and functions, the primary function of this code is to provide FIPS 140 compliant ECDSA key generation, signing, and verification capabilities for specific NIST elliptic curves (P-224, P-256, P-384, P-521).

5. **Connect to Go Language Features:**

    * **Generics:** The use of `Curve[P Point[P]]` and the `Point` interface is a clear example of Go generics.
    * **Interfaces:** The `Point` interface defines the common behavior for different elliptic curve point types.
    * **`sync.OnceValue`:**  Used for lazy and thread-safe initialization of the `Curve` instances.
    * **Error Handling:**  The functions consistently return `error` values, which is standard Go practice.
    * **Byte Slices:** The keys and signatures are represented as `[]byte`, which is common for cryptographic data in Go.

6. **Develop Examples:** Create simple Go code snippets that demonstrate the usage of the key functions. Focus on key generation, signing, and verification. Think about what inputs are required and what outputs to expect.

7. **Consider Edge Cases and Potential Errors:**  Think about common mistakes developers might make when using this code.

    * **Mismatched Curves:** Attempting to sign with a private key for one curve and verify with a public key for another.
    * **Incorrect Hash Input:**  Using the wrong hashing algorithm or not hashing the message correctly before signing.
    * **Understanding Deterministic vs. Non-Deterministic Signing:**  Being unaware of the differences and using the wrong function.
    * **Direct Manipulation of Private Keys:**  Discourage direct manipulation of the internal `d` field of `PrivateKey`.

8. **Review and Refine:**  Read through the analysis and examples to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that need further explanation. For example, the "hedged" approach in `Sign` is a detail worth noting.

**Self-Correction Example During the Process:**

Initially, I might just say "it implements ECDSA". But then, looking at the package path (`fips140`), the presence of `fips140.RecordApproved()` and `fipsSelfTest()`,  I would correct myself to emphasize that this is specifically a *FIPS 140 compliant* implementation of ECDSA. Similarly, noticing `Sign` and `SignDeterministic` suggests a deeper dive into the differences between them is needed. The comments within the code (like the warnings about the `randomPoint` function) also provide valuable insights.
这个 `go/src/crypto/internal/fips140/ecdsa/ecdsa.go` 文件是 Go 语言 `crypto/ecdsa` 标准库中用于实现符合 FIPS 140-3 标准的椭圆曲线数字签名算法 (ECDSA) 的一部分。它提供了一组类型和函数，用于生成密钥对、签名和验证签名。

**主要功能：**

1. **定义了 ECDSA 密钥结构:**
   - `PrivateKey`: 表示 ECDSA 私钥，包含对应的公钥和私钥数值 (`d`)。
   - `PublicKey`: 表示 ECDSA 公钥，包含曲线 ID (`curveID`) 和公钥坐标 (`q`)。

2. **支持特定的 NIST 曲线:**
   - 定义了 `curveID` 类型和常量 `p224`, `p256`, `p384`, `p521`，分别对应 NIST 推荐的 P-224, P-256, P-384 和 P-521 椭圆曲线。
   - 提供了 `Curve` 泛型结构体，用于表示一个椭圆曲线，包含了曲线的参数和操作函数。
   - 提供了 `P224()`, `P256()`, `P384()`, `P521()` 函数，用于获取对应曲线的 `Curve` 实例。这些函数使用了 `sync.OnceValue` 来确保曲线参数只被初始化一次。

3. **密钥生成:**
   - `GenerateKey[P Point[P]](c *Curve[P], rand io.Reader) (*PrivateKey, error)`:  根据指定的椭圆曲线 `c` 和随机数生成器 `rand` 生成一个新的 ECDSA 私钥/公钥对。它内部使用了拒绝采样的方法 (`randomPoint`) 来生成符合要求的随机私钥。

4. **密钥的创建:**
   - `NewPrivateKey[P Point[P]](c *Curve[P], D, Q []byte) (*PrivateKey, error)`:  根据给定的私钥数值 `D` 和公钥坐标 `Q` 创建一个 `PrivateKey` 实例。
   - `NewPublicKey[P Point[P]](c *Curve[P], Q []byte) (*PublicKey, error)`: 根据给定的公钥坐标 `Q` 创建一个 `PublicKey` 实例。

5. **签名:**
   - `Sign[P Point[P], H fips140.Hash](c *Curve[P], h func() H, priv *PrivateKey, rand io.Reader, hash []byte) (*Signature, error)`: 使用指定的私钥 `priv` 对消息的哈希值 `hash` 进行签名。它使用了 "hedged" 的方法，结合了随机性和确定性成分，以增强安全性。
   - `SignDeterministic[P Point[P], H fips140.Hash](c *Curve[P], h func() H, priv *PrivateKey, hash []byte) (*Signature, error)`: 使用指定的私钥 `priv` 对消息的哈希值 `hash` 进行确定性签名，遵循 FIPS 186-5 和 RFC 6979 的规范。

6. **签名验证:**
   - `Verify[P Point[P]](c *Curve[P], pub *PublicKey, hash []byte, sig *Signature) error`: 使用指定的公钥 `pub` 验证签名 `sig` 对于消息的哈希值 `hash` 的有效性。

7. **内部辅助函数:**
   - `randomPoint`:  生成随机标量和对应的椭圆曲线点，用于密钥生成和签名过程。
   - `bits2octets`:  将哈希值转换为字节序列，用于确定性签名。
   - `signGeneric`:  执行实际的签名操作。
   - `inverse`:  计算模逆。
   - `hashToNat`:  将哈希值转换为大整数。
   - `rightShift`:  执行右移操作，用于处理 P-521 曲线的特殊情况。
   - `precomputeParams`: 预计算曲线参数。

**它是什么 Go 语言功能的实现：**

该文件是 `crypto/ecdsa` 包中符合 FIPS 140-3 标准的 ECDSA 实现。它利用了 Go 的以下特性：

- **包 (package):**  将相关的类型和函数组织在一起。
- **结构体 (struct):** 定义了 `PrivateKey`, `PublicKey`, `Curve`, `Signature` 等数据结构。
- **方法 (method):**  为结构体定义了相关操作，如 `PrivateKey.Bytes()`, `PublicKey.Bytes()`。
- **常量 (const):**  定义了曲线 ID 常量。
- **泛型 (generics):**  使用泛型 `Curve[P Point[P]]` 和接口 `Point` 来支持不同的椭圆曲线点类型。
- **接口 (interface):**  定义了 `Point` 接口，约束了椭圆曲线点的行为。
- **闭包 (closure):**  在 `sync.OnceValue` 中使用了闭包来延迟初始化。
- **错误处理 (error handling):**  函数通过返回 `error` 类型来处理错误。
- **同步 (sync):** 使用 `sync.OnceValue` 来保证曲线参数的线程安全初始化。

**Go 代码举例说明（密钥生成、签名和验证）：**

```go
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	fips_ecdsa "crypto/internal/fips140/ecdsa"
	fips_hash "crypto/internal/fips140/hash"
)

func main() {
	// 密钥生成
	curve := fips_ecdsa.P256()
	privateKey, err := fips_ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		fmt.Println("密钥生成失败:", err)
		return
	}
	publicKey := privateKey.PublicKey()

	// 待签名的消息
	message := []byte("这是一个需要签名的消息")

	// 计算消息的哈希值
	hashed := sha256.Sum256(message)

	// 签名
	var hashFunc func() fips_hash.Hash = func() fips_hash.Hash { return fips_hash.NewSHA256() }
	signature, err := fips_ecdsa.Sign(curve, hashFunc, privateKey, rand.Reader, hashed[:])
	if err != nil {
		fmt.Println("签名失败:", err)
		return
	}
	fmt.Printf("签名结果 (R: %X, S: %X)\n", signature.R, signature.S)

	// 验证签名
	err = fips_ecdsa.Verify(curve, publicKey, hashed[:], signature)
	if err != nil {
		fmt.Println("签名验证失败:", err)
		return
	}
	fmt.Println("签名验证成功!")
}
```

**假设的输入与输出：**

在这个例子中，输入主要是随机数生成器 `rand.Reader` 用于密钥生成和签名，以及待签名的消息 `message`。

输出会是：

- 成功生成的私钥和公钥（其内部表示是字节切片）。
- 使用私钥对消息哈希值生成的签名，包含 `R` 和 `S` 两个大整数的字节表示。
- 签名验证成功或失败的消息。

由于密钥生成和签名涉及到随机数，每次运行的结果会不同，但签名验证在没有篡改的情况下应该总是成功的。

**命令行参数的具体处理：**

该代码本身并不直接处理命令行参数。它是一个库，提供了 ECDSA 的功能。如果需要在命令行应用中使用，需要编写额外的代码来处理命令行参数，例如使用 `flag` 包来解析用户输入的密钥文件、消息文件等。

**使用者易犯错的点：**

1. **曲线不匹配:**  使用一个曲线的私钥对消息进行签名，然后尝试用另一个曲线的公钥进行验证，会导致验证失败。
   ```go
   // 错误示例：使用 P-256 的私钥和 P-384 的公钥
   privP256, _ := fips_ecdsa.GenerateKey(fips_ecdsa.P256(), rand.Reader)
   pubP384 := (func() *fips_ecdsa.PublicKey {
       priv, _ := fips_ecdsa.GenerateKey(fips_ecdsa.P384(), rand.Reader)
       return priv.PublicKey()
   })()

   hashed := sha256.Sum256([]byte("test"))
   var hashFunc func() fips_hash.Hash = func() fips_hash.Hash { return fips_hash.NewSHA256() }
   sig, _ := fips_ecdsa.Sign(fips_ecdsa.P256(), hashFunc, privP256, rand.Reader, hashed[:])
   err := fips_ecdsa.Verify(fips_ecdsa.P384(), pubP384, hashed[:], sig) // 验证会失败
   fmt.Println("验证结果:", err) // 输出类似：ecdsa: public key does not match curve
   ```

2. **哈希算法不一致:**  签名时使用的哈希算法与验证时使用的哈希算法不同，会导致验证失败。`Sign` 函数的类型签名中要求传入一个返回 `fips140.Hash` 接口的函数，这暗示了需要使用匹配的哈希算法。

3. **直接操作密钥的内部字段:** 虽然 `PrivateKey` 和 `PublicKey` 暴露了内部字段（如 `d` 和 `q`），但是直接修改这些字段可能会破坏密钥的有效性，应该通过提供的构造函数 (`NewPrivateKey`, `NewPublicKey`) 来创建密钥。

4. **不理解确定性签名与随机签名的区别:**  `Sign` 使用了随机性，同样的私钥和消息，每次签名结果可能不同。`SignDeterministic` 则保证同样的私钥和消息，签名结果总是相同的。根据应用场景选择合适的签名方法很重要。

5. **错误处理不当:**  忽略 `Sign` 和 `Verify` 等函数返回的错误，可能导致安全漏洞或程序崩溃。

理解这些功能和潜在的错误点，有助于正确使用 Go 语言的 FIPS 140-3 标准 ECDSA 实现。

### 提示词
```
这是路径为go/src/crypto/internal/fips140/ecdsa/ecdsa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ecdsa

import (
	"bytes"
	"crypto/internal/fips140"
	"crypto/internal/fips140/bigmod"
	"crypto/internal/fips140/drbg"
	"crypto/internal/fips140/nistec"
	"errors"
	"io"
	"sync"
)

// PrivateKey and PublicKey are not generic to make it possible to use them
// in other types without instantiating them with a specific point type.
// They are tied to one of the Curve types below through the curveID field.

type PrivateKey struct {
	pub PublicKey
	d   []byte // bigmod.(*Nat).Bytes output (same length as the curve order)
}

func (priv *PrivateKey) Bytes() []byte {
	return priv.d
}

func (priv *PrivateKey) PublicKey() *PublicKey {
	return &priv.pub
}

type PublicKey struct {
	curve curveID
	q     []byte // uncompressed nistec Point.Bytes output
}

func (pub *PublicKey) Bytes() []byte {
	return pub.q
}

type curveID string

const (
	p224 curveID = "P-224"
	p256 curveID = "P-256"
	p384 curveID = "P-384"
	p521 curveID = "P-521"
)

type Curve[P Point[P]] struct {
	curve      curveID
	newPoint   func() P
	ordInverse func([]byte) ([]byte, error)
	N          *bigmod.Modulus
	nMinus2    []byte
}

// Point is a generic constraint for the [nistec] Point types.
type Point[P any] interface {
	*nistec.P224Point | *nistec.P256Point | *nistec.P384Point | *nistec.P521Point
	Bytes() []byte
	BytesX() ([]byte, error)
	SetBytes([]byte) (P, error)
	ScalarMult(P, []byte) (P, error)
	ScalarBaseMult([]byte) (P, error)
	Add(p1, p2 P) P
}

func precomputeParams[P Point[P]](c *Curve[P], order []byte) {
	var err error
	c.N, err = bigmod.NewModulus(order)
	if err != nil {
		panic(err)
	}
	two, _ := bigmod.NewNat().SetBytes([]byte{2}, c.N)
	c.nMinus2 = bigmod.NewNat().ExpandFor(c.N).Sub(two, c.N).Bytes(c.N)
}

func P224() *Curve[*nistec.P224Point] { return _P224() }

var _P224 = sync.OnceValue(func() *Curve[*nistec.P224Point] {
	c := &Curve[*nistec.P224Point]{
		curve:    p224,
		newPoint: nistec.NewP224Point,
	}
	precomputeParams(c, p224Order)
	return c
})

var p224Order = []byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x16, 0xa2,
	0xe0, 0xb8, 0xf0, 0x3e, 0x13, 0xdd, 0x29, 0x45,
	0x5c, 0x5c, 0x2a, 0x3d,
}

func P256() *Curve[*nistec.P256Point] { return _P256() }

var _P256 = sync.OnceValue(func() *Curve[*nistec.P256Point] {
	c := &Curve[*nistec.P256Point]{
		curve:      p256,
		newPoint:   nistec.NewP256Point,
		ordInverse: nistec.P256OrdInverse,
	}
	precomputeParams(c, p256Order)
	return c
})

var p256Order = []byte{
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
	0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51}

func P384() *Curve[*nistec.P384Point] { return _P384() }

var _P384 = sync.OnceValue(func() *Curve[*nistec.P384Point] {
	c := &Curve[*nistec.P384Point]{
		curve:    p384,
		newPoint: nistec.NewP384Point,
	}
	precomputeParams(c, p384Order)
	return c
})

var p384Order = []byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
	0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a,
	0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73}

func P521() *Curve[*nistec.P521Point] { return _P521() }

var _P521 = sync.OnceValue(func() *Curve[*nistec.P521Point] {
	c := &Curve[*nistec.P521Point]{
		curve:    p521,
		newPoint: nistec.NewP521Point,
	}
	precomputeParams(c, p521Order)
	return c
})

var p521Order = []byte{0x01, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfa,
	0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b,
	0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09, 0xa5, 0xd0,
	0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae,
	0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38, 0x64, 0x09}

func NewPrivateKey[P Point[P]](c *Curve[P], D, Q []byte) (*PrivateKey, error) {
	fips140.RecordApproved()
	pub, err := NewPublicKey(c, Q)
	if err != nil {
		return nil, err
	}
	d, err := bigmod.NewNat().SetBytes(D, c.N)
	if err != nil {
		return nil, err
	}
	priv := &PrivateKey{pub: *pub, d: d.Bytes(c.N)}
	if err := fipsPCT(c, priv); err != nil {
		// This can happen if the application went out of its way to make an
		// ecdsa.PrivateKey with a mismatching PublicKey.
		return nil, err
	}
	return priv, nil
}

func NewPublicKey[P Point[P]](c *Curve[P], Q []byte) (*PublicKey, error) {
	// SetBytes checks that Q is a valid point on the curve, and that its
	// coordinates are reduced modulo p, fulfilling the requirements of SP
	// 800-89, Section 5.3.2.
	_, err := c.newPoint().SetBytes(Q)
	if err != nil {
		return nil, err
	}
	return &PublicKey{curve: c.curve, q: Q}, nil
}

// GenerateKey generates a new ECDSA private key pair for the specified curve.
func GenerateKey[P Point[P]](c *Curve[P], rand io.Reader) (*PrivateKey, error) {
	fips140.RecordApproved()

	k, Q, err := randomPoint(c, func(b []byte) error {
		return drbg.ReadWithReader(rand, b)
	})
	if err != nil {
		return nil, err
	}

	priv := &PrivateKey{
		pub: PublicKey{
			curve: c.curve,
			q:     Q.Bytes(),
		},
		d: k.Bytes(c.N),
	}
	if err := fipsPCT(c, priv); err != nil {
		// This clearly can't happen, but FIPS 140-3 mandates that we check it.
		panic(err)
	}
	return priv, nil
}

// randomPoint returns a random scalar and the corresponding point using a
// procedure equivalent to FIPS 186-5, Appendix A.2.2 (ECDSA Key Pair Generation
// by Rejection Sampling) and to Appendix A.3.2 (Per-Message Secret Number
// Generation of Private Keys by Rejection Sampling) or Appendix A.3.3
// (Per-Message Secret Number Generation for Deterministic ECDSA) followed by
// Step 5 of Section 6.4.1.
func randomPoint[P Point[P]](c *Curve[P], generate func([]byte) error) (k *bigmod.Nat, p P, err error) {
	for {
		b := make([]byte, c.N.Size())
		if err := generate(b); err != nil {
			return nil, nil, err
		}

		// Take only the leftmost bits of the generated random value. This is
		// both necessary to increase the chance of the random value being in
		// the correct range and to match the specification. It's unfortunate
		// that we need to do a shift instead of a mask, but see the comment on
		// rightShift.
		//
		// These are the most dangerous lines in the package and maybe in the
		// library: a single bit of bias in the selection of nonces would likely
		// lead to key recovery, but no tests would fail. Look but DO NOT TOUCH.
		if excess := len(b)*8 - c.N.BitLen(); excess > 0 {
			// Just to be safe, assert that this only happens for the one curve that
			// doesn't have a round number of bits.
			if c.curve != p521 {
				panic("ecdsa: internal error: unexpectedly masking off bits")
			}
			b = rightShift(b, excess)
		}

		// FIPS 186-5, Appendix A.4.2 makes us check x <= N - 2 and then return
		// x + 1. Note that it follows that 0 < x + 1 < N. Instead, SetBytes
		// checks that k < N, and we explicitly check 0 != k. Since k can't be
		// negative, this is strictly equivalent. None of this matters anyway
		// because the chance of selecting zero is cryptographically negligible.
		if k, err := bigmod.NewNat().SetBytes(b, c.N); err == nil && k.IsZero() == 0 {
			p, err := c.newPoint().ScalarBaseMult(k.Bytes(c.N))
			return k, p, err
		}

		if testingOnlyRejectionSamplingLooped != nil {
			testingOnlyRejectionSamplingLooped()
		}
	}
}

// testingOnlyRejectionSamplingLooped is called when rejection sampling in
// randomPoint rejects a candidate for being higher than the modulus.
var testingOnlyRejectionSamplingLooped func()

// Signature is an ECDSA signature, where r and s are represented as big-endian
// byte slices of the same length as the curve order.
type Signature struct {
	R, S []byte
}

// Sign signs a hash (which shall be the result of hashing a larger message with
// the hash function H) using the private key, priv. If the hash is longer than
// the bit-length of the private key's curve order, the hash will be truncated
// to that length.
func Sign[P Point[P], H fips140.Hash](c *Curve[P], h func() H, priv *PrivateKey, rand io.Reader, hash []byte) (*Signature, error) {
	if priv.pub.curve != c.curve {
		return nil, errors.New("ecdsa: private key does not match curve")
	}
	fips140.RecordApproved()
	fipsSelfTest()

	// Random ECDSA is dangerous, because a failure of the RNG would immediately
	// leak the private key. Instead, we use a "hedged" approach, as specified
	// in draft-irtf-cfrg-det-sigs-with-noise-04, Section 4. This has also the
	// advantage of closely resembling Deterministic ECDSA.

	Z := make([]byte, len(priv.d))
	if err := drbg.ReadWithReader(rand, Z); err != nil {
		return nil, err
	}

	// See https://github.com/cfrg/draft-irtf-cfrg-det-sigs-with-noise/issues/6
	// for the FIPS compliance of this method. In short Z is entropy from the
	// main DRBG, of length 3/2 of security_strength, so the nonce is optional
	// per SP 800-90Ar1, Section 8.6.7, and the rest is a personalization
	// string, which per SP 800-90Ar1, Section 8.7.1 may contain secret
	// information.
	drbg := newDRBG(h, Z, nil, blockAlignedPersonalizationString{priv.d, bits2octets(c, hash)})

	return sign(c, priv, drbg, hash)
}

// SignDeterministic signs a hash (which shall be the result of hashing a
// larger message with the hash function H) using the private key, priv. If the
// hash is longer than the bit-length of the private key's curve order, the hash
// will be truncated to that length. This applies Deterministic ECDSA as
// specified in FIPS 186-5 and RFC 6979.
func SignDeterministic[P Point[P], H fips140.Hash](c *Curve[P], h func() H, priv *PrivateKey, hash []byte) (*Signature, error) {
	if priv.pub.curve != c.curve {
		return nil, errors.New("ecdsa: private key does not match curve")
	}
	fips140.RecordApproved()
	fipsSelfTestDeterministic()
	drbg := newDRBG(h, priv.d, bits2octets(c, hash), nil) // RFC 6979, Section 3.3
	return sign(c, priv, drbg, hash)
}

// bits2octets as specified in FIPS 186-5, Appendix B.2.4 or RFC 6979,
// Section 2.3.4. See RFC 6979, Section 3.5 for the rationale.
func bits2octets[P Point[P]](c *Curve[P], hash []byte) []byte {
	e := bigmod.NewNat()
	hashToNat(c, e, hash)
	return e.Bytes(c.N)
}

func signGeneric[P Point[P]](c *Curve[P], priv *PrivateKey, drbg *hmacDRBG, hash []byte) (*Signature, error) {
	// FIPS 186-5, Section 6.4.1

	k, R, err := randomPoint(c, func(b []byte) error {
		drbg.Generate(b)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// kInv = k⁻¹
	kInv := bigmod.NewNat()
	inverse(c, kInv, k)

	Rx, err := R.BytesX()
	if err != nil {
		return nil, err
	}
	r, err := bigmod.NewNat().SetOverflowingBytes(Rx, c.N)
	if err != nil {
		return nil, err
	}

	// The spec wants us to retry here, but the chance of hitting this condition
	// on a large prime-order group like the NIST curves we support is
	// cryptographically negligible. If we hit it, something is awfully wrong.
	if r.IsZero() == 1 {
		return nil, errors.New("ecdsa: internal error: r is zero")
	}

	e := bigmod.NewNat()
	hashToNat(c, e, hash)

	s, err := bigmod.NewNat().SetBytes(priv.d, c.N)
	if err != nil {
		return nil, err
	}
	s.Mul(r, c.N)
	s.Add(e, c.N)
	s.Mul(kInv, c.N)

	// Again, the chance of this happening is cryptographically negligible.
	if s.IsZero() == 1 {
		return nil, errors.New("ecdsa: internal error: s is zero")
	}

	return &Signature{r.Bytes(c.N), s.Bytes(c.N)}, nil
}

// inverse sets kInv to the inverse of k modulo the order of the curve.
func inverse[P Point[P]](c *Curve[P], kInv, k *bigmod.Nat) {
	if c.ordInverse != nil {
		kBytes, err := c.ordInverse(k.Bytes(c.N))
		// Some platforms don't implement ordInverse, and always return an error.
		if err == nil {
			_, err := kInv.SetBytes(kBytes, c.N)
			if err != nil {
				panic("ecdsa: internal error: ordInverse produced an invalid value")
			}
			return
		}
	}

	// Calculate the inverse of s in GF(N) using Fermat's method
	// (exponentiation modulo P - 2, per Euler's theorem)
	kInv.Exp(k, c.nMinus2, c.N)
}

// hashToNat sets e to the left-most bits of hash, according to
// FIPS 186-5, Section 6.4.1, point 2 and Section 6.4.2, point 3.
func hashToNat[P Point[P]](c *Curve[P], e *bigmod.Nat, hash []byte) {
	// ECDSA asks us to take the left-most log2(N) bits of hash, and use them as
	// an integer modulo N. This is the absolute worst of all worlds: we still
	// have to reduce, because the result might still overflow N, but to take
	// the left-most bits for P-521 we have to do a right shift.
	if size := c.N.Size(); len(hash) >= size {
		hash = hash[:size]
		if excess := len(hash)*8 - c.N.BitLen(); excess > 0 {
			hash = rightShift(hash, excess)
		}
	}
	_, err := e.SetOverflowingBytes(hash, c.N)
	if err != nil {
		panic("ecdsa: internal error: truncated hash is too long")
	}
}

// rightShift implements the right shift necessary for bits2int, which takes the
// leftmost bits of either the hash or HMAC_DRBG output.
//
// Note how taking the rightmost bits would have been as easy as masking the
// first byte, but we can't have nice things.
func rightShift(b []byte, shift int) []byte {
	if shift <= 0 || shift >= 8 {
		panic("ecdsa: internal error: shift can only be by 1 to 7 bits")
	}
	b = bytes.Clone(b)
	for i := len(b) - 1; i >= 0; i-- {
		b[i] >>= shift
		if i > 0 {
			b[i] |= b[i-1] << (8 - shift)
		}
	}
	return b
}

// Verify verifies the signature, sig, of hash (which should be the result of
// hashing a larger message) using the public key, pub. If the hash is longer
// than the bit-length of the private key's curve order, the hash will be
// truncated to that length.
//
// The inputs are not considered confidential, and may leak through timing side
// channels, or if an attacker has control of part of the inputs.
func Verify[P Point[P]](c *Curve[P], pub *PublicKey, hash []byte, sig *Signature) error {
	if pub.curve != c.curve {
		return errors.New("ecdsa: public key does not match curve")
	}
	fips140.RecordApproved()
	fipsSelfTest()
	return verify(c, pub, hash, sig)
}

func verifyGeneric[P Point[P]](c *Curve[P], pub *PublicKey, hash []byte, sig *Signature) error {
	// FIPS 186-5, Section 6.4.2

	Q, err := c.newPoint().SetBytes(pub.q)
	if err != nil {
		return err
	}

	r, err := bigmod.NewNat().SetBytes(sig.R, c.N)
	if err != nil {
		return err
	}
	if r.IsZero() == 1 {
		return errors.New("ecdsa: invalid signature: r is zero")
	}
	s, err := bigmod.NewNat().SetBytes(sig.S, c.N)
	if err != nil {
		return err
	}
	if s.IsZero() == 1 {
		return errors.New("ecdsa: invalid signature: s is zero")
	}

	e := bigmod.NewNat()
	hashToNat(c, e, hash)

	// w = s⁻¹
	w := bigmod.NewNat()
	inverse(c, w, s)

	// p₁ = [e * s⁻¹]G
	p1, err := c.newPoint().ScalarBaseMult(e.Mul(w, c.N).Bytes(c.N))
	if err != nil {
		return err
	}
	// p₂ = [r * s⁻¹]Q
	p2, err := Q.ScalarMult(Q, w.Mul(r, c.N).Bytes(c.N))
	if err != nil {
		return err
	}
	// BytesX returns an error for the point at infinity.
	Rx, err := p1.Add(p1, p2).BytesX()
	if err != nil {
		return err
	}

	v, err := bigmod.NewNat().SetOverflowingBytes(Rx, c.N)
	if err != nil {
		return err
	}

	if v.Equal(r) != 1 {
		return errors.New("ecdsa: signature did not verify")
	}
	return nil
}
```