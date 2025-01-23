Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Read and High-Level Understanding:**

The first step is to read through the code to get a general idea of what it's doing. Keywords like `crypto`, `ecdh`, `aes`, `chacha20poly1305`, and names like `Encap`, `Decap`, `Seal`, `Open` immediately suggest cryptographic operations. The package name `hpke` further reinforces this. The comments also help confirm the purpose.

**2. Identifying Core Components:**

Next, identify the key data structures and functions:

* **Data Structures:**  `hkdfKDF`, `dhKEM`, `context`, `Sender`, `Receipient`, `uint128`. These represent the core building blocks of the functionality.
* **Key Functions:** `LabeledExtract`, `LabeledExpand`, `Encap`, `Decap`, `SetupSender`, `SetupReceipient`, `Seal`, `Open`. These functions indicate the main operations being performed.
* **Constants/Maps:** `KemID`, `SupportedKEMs`, `AEADID`, `SupportedAEADs`, `KDFID`, `SupportedKDFs`. These define the supported cryptographic algorithms.

**3. Deconstructing Core Concepts (HPKE Fundamentals):**

Recognizing the `hpke` package name, it's important to recall (or research if unfamiliar) the basics of HPKE (Hybrid Public Key Encryption). This helps frame the code's purpose:

* **Key Encapsulation Mechanism (KEM):**  Securely establishing a shared secret between sender and receiver. The `dhKEM` struct and its `Encap` and `Decap` methods clearly implement this.
* **Authenticated Encryption with Associated Data (AEAD):** Encrypting the actual message data while ensuring authenticity. The `context` struct holds the AEAD cipher, and the `Seal` and `Open` methods perform this.
* **Key Derivation Function (KDF):** Deriving cryptographic keys from a shared secret. The `hkdfKDF` struct implements this using HKDF.

**4. Analyzing Individual Components in Detail:**

Now, dive deeper into the individual parts:

* **`hkdfKDF`:**  Focus on `LabeledExtract` and `LabeledExpand`. Notice how they incorporate labels and suite IDs, which are standard practices in cryptographic protocols to ensure domain separation and prevent cross-protocol attacks. The use of `hkdf.Extract` and `hkdf.Expand` confirms its role.
* **`dhKEM`:**  Understand the `Encap` (sender-side KEM) and `Decap` (receiver-side KEM) processes. The use of ECDH (`privEph.ECDH(pubRecipient)`) is central to the Diffie-Hellman key exchange. The `ExtractAndExpand` method ties together the key exchange and KDF.
* **`context`:**  Recognize that this structure holds the state for both the sender and receiver after the key exchange. It contains the derived keys, nonces, and the AEAD cipher.
* **`Sender` and `Receipient`:** These are simple wrappers around the `context`, indicating the different roles in the HPKE process.
* **`SetupSender` and `SetupReceipient`:**  These functions orchestrate the initial setup, including the KEM and initial context creation.
* **`Seal` and `Open`:**  These implement the core AEAD encryption and decryption. The nonce management (`nextNonce` and `incrementNonce`) is crucial for the security of the AEAD.
* **`uint128`:** Notice this is a custom type for handling large sequence numbers, likely to prevent nonce reuse in the AEAD.

**5. Inferring Go Language Features:**

As the analysis progresses, identify the Go language features being used:

* **Structs:** For organizing data (`hkdfKDF`, `dhKEM`, etc.).
* **Methods:**  Functions associated with structs (e.g., `kdf.LabeledExtract`).
* **Interfaces:** The `crypto.Hash`, `cipher.AEAD`, and `ecdh.Curve` interfaces promote abstraction.
* **Maps:** For storing supported algorithms (`SupportedKEMs`, `SupportedAEADs`, `SupportedKDFs`).
* **Constants:** For defining algorithm identifiers (`DHKEM_X25519_HKDF_SHA256`, etc.).
* **Error Handling:** The use of `error` as a return type.
* **Slices and Appending:**  For building byte arrays (e.g., in `LabeledExtract`).
* **Closures:**  The `aesGCMNew` variable is a function assigned to a variable.
* **Packages:**  Importing standard library packages like `crypto`, `errors`, and external packages like `golang.org/x/crypto/chacha20poly1305`.

**6. Code Examples and Reasoning (Crucial for Understanding):**

This is where the understanding solidifies. For each major function, create a simple example to illustrate its use. This requires:

* **Identifying inputs and outputs:**  What data does the function take, and what does it return?
* **Making reasonable assumptions:** What kind of data would you pass to these functions in a real scenario?
* **Focusing on the core functionality:**  Keep the examples concise and focused on demonstrating the specific function's purpose.

For example, for `SetupSender`, you need a receiver's public key and the algorithm IDs. The output is the encapsulated key and a `Sender` object.

**7. Identifying Potential Pitfalls:**

Think about common mistakes developers might make when using this code:

* **Incorrect Algorithm IDs:**  Using unsupported or mismatched KEM, KDF, or AEAD IDs.
* **Nonce Reuse:** Not properly incrementing the nonce in `Seal` and `Open`.
* **Incorrect Key Handling:** Not securely storing or managing private keys.
* **Misunderstanding Associated Data (AAD):**  Not including the correct AAD during encryption and decryption.

**8. Structuring the Answer:**

Finally, organize the information clearly and concisely in Chinese, addressing all the points raised in the prompt:

* **功能列举:** List the primary functions provided by the code.
* **Go 语言功能实现推理和代码示例:** Identify the core cryptographic concepts and provide Go code examples for key functions. Explain the reasoning behind the examples.
* **代码推理的假设输入与输出:**  Explicitly state the assumptions made for the code examples.
* **命令行参数处理:**  Acknowledge if there are no command-line arguments.
* **使用者易犯错的点:**  Provide concrete examples of common mistakes.

By following this systematic approach, you can effectively analyze and explain the functionality of complex code like the HPKE implementation provided.
这段Go语言代码是关于 **混合公钥加密 (Hybrid Public Key Encryption, HPKE)** 的一个内部实现。HPKE 是一种在 RFC 9180 中定义的加密方案，它结合了公钥加密的密钥封装机制 (KEM) 和对称密钥加密的认证加密带关联数据 (AEAD) 机制，以提供高效且安全的通信。

**功能列举:**

1. **密钥封装 (Key Encapsulation, KEM):**
   - 实现了基于椭圆曲线 Diffie-Hellman (ECDH) 的密钥交换 (`dhKEM` 结构体)。
   - 支持 `DHKEM_X25519_HKDF_SHA256` 这种特定的 KEM 方案。
   - `Encap` 方法用于生成临时的公钥并将共享密钥封装给接收者。
   - `Decap` 方法用于使用接收者的私钥解封共享密钥。

2. **密钥派生函数 (Key Derivation Function, KDF):**
   - 实现了基于 HKDF (HMAC-based Extract-and-Expand Key Derivation Function) 的 KDF (`hkdfKDF` 结构体)。
   - `LabeledExtract` 方法用于带标签的密钥提取。
   - `LabeledExpand` 方法用于带标签的密钥扩展。
   - 支持 `KDF_HKDF_SHA256` 这种特定的 KDF 方案。

3. **认证加密带关联数据 (Authenticated Encryption with Associated Data, AEAD):**
   - 支持多种 AEAD 算法，例如 `AEAD_AES_128_GCM`, `AEAD_AES_256_GCM`, 和 `AEAD_ChaCha20Poly1305`。
   - 使用 `context` 结构体来管理加密上下文，包括共享密钥、密钥、基本 nonce 等。
   - `Seal` 方法用于加密并认证消息。
   - `Open` 方法用于解密并验证消息。
   - 使用 `uint128` 结构体来维护一个递增的序列号，用于生成唯一的 nonce，防止 nonce 重复使用。

4. **上下文管理:**
   - `newContext` 函数用于根据协商好的参数（共享密钥、KEM ID、KDF ID、AEAD ID 和 info）创建加密上下文。
   - `Sender` 和 `Receipient` 结构体分别代表发送者和接收者的上下文。

5. **协议设置:**
   - `SetupSender` 函数用于发送者初始化 HPKE 流程，包括执行 KEM 的封装操作并创建发送者上下文。
   - `SetupReceipient` 函数用于接收者初始化 HPKE 流程，包括执行 KEM 的解封操作并创建接收者上下文。

6. **辅助功能:**
   - `suiteID` 函数用于生成包含 KEM ID、KDF ID 和 AEAD ID 的套件标识符。
   - `ParseHPKEPublicKey` 和 `ParseHPKEPrivateKey` 函数用于将字节切片解析为 HPKE 公钥和私钥。

**Go 语言功能实现推理和代码示例:**

这段代码是 HPKE 协议的 Go 语言实现，它利用了 Go 的 `crypto` 标准库以及 `golang.org/x/crypto` 扩展库来提供密码学功能。

**示例：发送者初始化并加密消息**

```go
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"log"

	"crypto/internal/hpke"
)

func main() {
	// 假设接收者有一个固定的公钥
	recipientPriv, err := ecdh.GenerateKey(ecdh.X25519(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	recipientPub := recipientPriv.PublicKey()

	// 设置 HPKE 参数
	kemID := hpke.DHKEM_X25519_HKDF_SHA256
	kdfID := hpke.KDF_HKDF_SHA256
	aeadID := hpke.AEAD_AES_128_GCM
	info := []byte("application specific info") // 可选的应用特定信息

	// 发送者初始化
	encapsulatedKey, senderContext, err := hpke.SetupSender(kemID, kdfID, aeadID, recipientPub, info)
	if err != nil {
		log.Fatal(err)
	}

	// 要发送的消息
	plaintext := []byte("Hello, HPKE!")
	aad := []byte("additional authenticated data") // 关联数据

	// 加密消息
	ciphertext, err := senderContext.Seal(aad, plaintext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Encapsulated Key: %x\n", encapsulatedKey)
	fmt.Printf("Ciphertext: %x\n", ciphertext)

	// 接收者需要使用 encapsulatedKey 解密消息 (见下面的例子)
}
```

**假设的输入与输出 (上面的例子):**

* **输入 (发送者):**
    * 接收者的公钥 (`recipientPub`)
    * KEM ID: `hpke.DHKEM_X25519_HKDF_SHA256` (0x0020)
    * KDF ID: `hpke.KDF_HKDF_SHA256` (0x0001)
    * AEAD ID: `hpke.AEAD_AES_128_GCM` (0x0001)
    * `info`: `[]byte("application specific info")`
    * `plaintext`: `[]byte("Hello, HPKE!")`
    * `aad`: `[]byte("additional authenticated data")`

* **输出 (发送者):**
    * `encapsulatedKey`: 一段字节切片，代表封装的密钥，需要发送给接收者。例如: `[0x...]` (具体的十六进制值取决于随机数生成)
    * `ciphertext`: 加密后的消息。例如: `[0x...]` (具体的十六进制值取决于生成的密钥和 nonce)

**示例：接收者接收并解密消息**

```go
package main

import (
	"crypto/ecdh"
	"fmt"
	"log"

	"crypto/internal/hpke"
)

func main() {
	// 接收者的私钥 (与上面发送者例子中的 recipientPriv 对应)
	recipientPrivBytes := /* ... 从安全的地方加载或存储的私钥字节 ... */
	recipientPriv, err := hpke.ParseHPKEPrivateKey(hpke.DHKEM_X25519_HKDF_SHA256, recipientPrivBytes)
	if err != nil {
		log.Fatal(err)
	}

	// 从发送者接收到的数据
	kemID := hpke.DHKEM_X25519_HKDF_SHA256
	kdfID := hpke.KDF_HKDF_SHA256
	aeadID := hpke.AEAD_AES_128_GCM
	info := []byte("application specific info") // 必须与发送者使用的 info 相同
	encapsulatedKey := /* ... 从发送者接收到的 encapsulatedKey ... */
	ciphertext := /* ... 从发送者接收到的 ciphertext ... */
	aad := []byte("additional authenticated data") // 必须与发送者使用的 aad 相同

	// 接收者初始化
	receiverContext, err := hpke.SetupReceipient(kemID, kdfID, aeadID, recipientPriv, info, encapsulatedKey)
	if err != nil {
		log.Fatal(err)
	}

	// 解密消息
	plaintext, err := receiverContext.Open(aad, ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Plaintext: %s\n", string(plaintext))
}
```

**假设的输入与输出 (上面的例子):**

* **输入 (接收者):**
    * 接收者的私钥 (`recipientPriv`)
    * KEM ID: `hpke.DHKEM_X25519_HKDF_SHA256` (0x0020)
    * KDF ID: `hpke.KDF_HKDF_SHA256` (0x0001)
    * AEAD ID: `hpke.AEAD_AES_128_GCM` (0x0001)
    * `info`: `[]byte("application specific info")` (必须与发送者一致)
    * `encapsulatedKey`: 从发送者接收到的封装密钥，例如: `[0x...]`
    * `ciphertext`: 从发送者接收到的密文，例如: `[0x...]`
    * `aad`: `[]byte("additional authenticated data")` (必须与发送者一致)

* **输出 (接收者):**
    * `plaintext`: 解密后的消息: `"Hello, HPKE!"`

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。它是一个底层的密码学原语实现，通常会被更上层的应用程序或库使用。上层应用可能会使用像 `flag` 包来处理命令行参数，以便配置 HPKE 使用的算法 ID、密钥等。

**使用者易犯错的点:**

1. **算法 ID 不匹配:**  发送者和接收者必须使用相同的 KEM ID、KDF ID 和 AEAD ID。如果这些 ID 不匹配，会导致密钥协商失败或解密错误。

   ```go
   // 错误示例：发送者和接收者使用了不同的 AEAD ID
   // 发送者: aeadID := hpke.AEAD_AES_128_GCM
   // 接收者: aeadID := hpke.AEAD_ChaCha20Poly1305

   // 这会导致解密失败
   ```

2. **`info` 和 `aad` 不一致:**  `info` 参数在密钥派生过程中使用，`aad` (关联数据) 在 AEAD 加密和解密过程中使用。发送者和接收者必须使用相同的值，否则解密会失败或无法验证消息的完整性。

   ```go
   // 错误示例：发送者和接收者使用了不同的 info 值
   // 发送者: info := []byte("sender specific info")
   // 接收者: info := []byte("receiver specific info")

   // 这会导致密钥派生不同，解密失败
   ```

3. **Nonce 重复使用:**  虽然代码中使用了 `uint128` 来管理 nonce 并在每次加密后递增，但如果使用者错误地重用了 `Sender` 或 `Receipient` 对象进行多次加密而没有正确初始化，可能会导致 nonce 重复使用，严重破坏安全性。

   ```go
   // 潜在的错误使用方式 (过于简化，实际使用中应该避免手动管理 nonce)
   // senderContext := ...
   // aad := []byte("data")
   // plaintext1 := []byte("message1")
   // ciphertext1, _ := senderContext.Seal(aad, plaintext1) // 内部 nonce 递增

   // plaintext2 := []byte("message2")
   // // 如果 senderContext 的 nonce 没有被重置，直接调用 Seal 可能会导致问题
   // ciphertext2, _ := senderContext.Seal(aad, plaintext2)
   ```

4. **密钥管理不当:**  私钥必须安全地保存。如果私钥泄露，HPKE 提供的安全性将失效。这段代码本身不负责密钥的存储和管理，这需要由上层应用来处理。

总的来说，这段代码提供了一个相对底层的 HPKE 实现，使用者需要理解 HPKE 的基本原理和参数，并谨慎处理各种配置和输入，以确保安全通信。

### 提示词
```
这是路径为go/src/crypto/internal/hpke/hpke.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package hpke

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/internal/fips140/hkdf"
	"crypto/rand"
	"errors"
	"internal/byteorder"
	"math/bits"

	"golang.org/x/crypto/chacha20poly1305"
)

// testingOnlyGenerateKey is only used during testing, to provide
// a fixed test key to use when checking the RFC 9180 vectors.
var testingOnlyGenerateKey func() (*ecdh.PrivateKey, error)

type hkdfKDF struct {
	hash crypto.Hash
}

func (kdf *hkdfKDF) LabeledExtract(sid []byte, salt []byte, label string, inputKey []byte) []byte {
	labeledIKM := make([]byte, 0, 7+len(sid)+len(label)+len(inputKey))
	labeledIKM = append(labeledIKM, []byte("HPKE-v1")...)
	labeledIKM = append(labeledIKM, sid...)
	labeledIKM = append(labeledIKM, label...)
	labeledIKM = append(labeledIKM, inputKey...)
	return hkdf.Extract(kdf.hash.New, labeledIKM, salt)
}

func (kdf *hkdfKDF) LabeledExpand(suiteID []byte, randomKey []byte, label string, info []byte, length uint16) []byte {
	labeledInfo := make([]byte, 0, 2+7+len(suiteID)+len(label)+len(info))
	labeledInfo = byteorder.BEAppendUint16(labeledInfo, length)
	labeledInfo = append(labeledInfo, []byte("HPKE-v1")...)
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, label...)
	labeledInfo = append(labeledInfo, info...)
	return hkdf.Expand(kdf.hash.New, randomKey, string(labeledInfo), int(length))
}

// dhKEM implements the KEM specified in RFC 9180, Section 4.1.
type dhKEM struct {
	dh  ecdh.Curve
	kdf hkdfKDF

	suiteID []byte
	nSecret uint16
}

type KemID uint16

const DHKEM_X25519_HKDF_SHA256 = 0x0020

var SupportedKEMs = map[uint16]struct {
	curve   ecdh.Curve
	hash    crypto.Hash
	nSecret uint16
}{
	// RFC 9180 Section 7.1
	DHKEM_X25519_HKDF_SHA256: {ecdh.X25519(), crypto.SHA256, 32},
}

func newDHKem(kemID uint16) (*dhKEM, error) {
	suite, ok := SupportedKEMs[kemID]
	if !ok {
		return nil, errors.New("unsupported suite ID")
	}
	return &dhKEM{
		dh:      suite.curve,
		kdf:     hkdfKDF{suite.hash},
		suiteID: byteorder.BEAppendUint16([]byte("KEM"), kemID),
		nSecret: suite.nSecret,
	}, nil
}

func (dh *dhKEM) ExtractAndExpand(dhKey, kemContext []byte) []byte {
	eaePRK := dh.kdf.LabeledExtract(dh.suiteID[:], nil, "eae_prk", dhKey)
	return dh.kdf.LabeledExpand(dh.suiteID[:], eaePRK, "shared_secret", kemContext, dh.nSecret)
}

func (dh *dhKEM) Encap(pubRecipient *ecdh.PublicKey) (sharedSecret []byte, encapPub []byte, err error) {
	var privEph *ecdh.PrivateKey
	if testingOnlyGenerateKey != nil {
		privEph, err = testingOnlyGenerateKey()
	} else {
		privEph, err = dh.dh.GenerateKey(rand.Reader)
	}
	if err != nil {
		return nil, nil, err
	}
	dhVal, err := privEph.ECDH(pubRecipient)
	if err != nil {
		return nil, nil, err
	}
	encPubEph := privEph.PublicKey().Bytes()

	encPubRecip := pubRecipient.Bytes()
	kemContext := append(encPubEph, encPubRecip...)

	return dh.ExtractAndExpand(dhVal, kemContext), encPubEph, nil
}

func (dh *dhKEM) Decap(encPubEph []byte, secRecipient *ecdh.PrivateKey) ([]byte, error) {
	pubEph, err := dh.dh.NewPublicKey(encPubEph)
	if err != nil {
		return nil, err
	}
	dhVal, err := secRecipient.ECDH(pubEph)
	if err != nil {
		return nil, err
	}
	kemContext := append(encPubEph, secRecipient.PublicKey().Bytes()...)

	return dh.ExtractAndExpand(dhVal, kemContext), nil
}

type context struct {
	aead cipher.AEAD

	sharedSecret []byte

	suiteID []byte

	key            []byte
	baseNonce      []byte
	exporterSecret []byte

	seqNum uint128
}

type Sender struct {
	*context
}

type Receipient struct {
	*context
}

var aesGCMNew = func(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

type AEADID uint16

const (
	AEAD_AES_128_GCM      = 0x0001
	AEAD_AES_256_GCM      = 0x0002
	AEAD_ChaCha20Poly1305 = 0x0003
)

var SupportedAEADs = map[uint16]struct {
	keySize   int
	nonceSize int
	aead      func([]byte) (cipher.AEAD, error)
}{
	// RFC 9180, Section 7.3
	AEAD_AES_128_GCM:      {keySize: 16, nonceSize: 12, aead: aesGCMNew},
	AEAD_AES_256_GCM:      {keySize: 32, nonceSize: 12, aead: aesGCMNew},
	AEAD_ChaCha20Poly1305: {keySize: chacha20poly1305.KeySize, nonceSize: chacha20poly1305.NonceSize, aead: chacha20poly1305.New},
}

type KDFID uint16

const KDF_HKDF_SHA256 = 0x0001

var SupportedKDFs = map[uint16]func() *hkdfKDF{
	// RFC 9180, Section 7.2
	KDF_HKDF_SHA256: func() *hkdfKDF { return &hkdfKDF{crypto.SHA256} },
}

func newContext(sharedSecret []byte, kemID, kdfID, aeadID uint16, info []byte) (*context, error) {
	sid := suiteID(kemID, kdfID, aeadID)

	kdfInit, ok := SupportedKDFs[kdfID]
	if !ok {
		return nil, errors.New("unsupported KDF id")
	}
	kdf := kdfInit()

	aeadInfo, ok := SupportedAEADs[aeadID]
	if !ok {
		return nil, errors.New("unsupported AEAD id")
	}

	pskIDHash := kdf.LabeledExtract(sid, nil, "psk_id_hash", nil)
	infoHash := kdf.LabeledExtract(sid, nil, "info_hash", info)
	ksContext := append([]byte{0}, pskIDHash...)
	ksContext = append(ksContext, infoHash...)

	secret := kdf.LabeledExtract(sid, sharedSecret, "secret", nil)

	key := kdf.LabeledExpand(sid, secret, "key", ksContext, uint16(aeadInfo.keySize) /* Nk - key size for AEAD */)
	baseNonce := kdf.LabeledExpand(sid, secret, "base_nonce", ksContext, uint16(aeadInfo.nonceSize) /* Nn - nonce size for AEAD */)
	exporterSecret := kdf.LabeledExpand(sid, secret, "exp", ksContext, uint16(kdf.hash.Size()) /* Nh - hash output size of the kdf*/)

	aead, err := aeadInfo.aead(key)
	if err != nil {
		return nil, err
	}

	return &context{
		aead:           aead,
		sharedSecret:   sharedSecret,
		suiteID:        sid,
		key:            key,
		baseNonce:      baseNonce,
		exporterSecret: exporterSecret,
	}, nil
}

func SetupSender(kemID, kdfID, aeadID uint16, pub *ecdh.PublicKey, info []byte) ([]byte, *Sender, error) {
	kem, err := newDHKem(kemID)
	if err != nil {
		return nil, nil, err
	}
	sharedSecret, encapsulatedKey, err := kem.Encap(pub)
	if err != nil {
		return nil, nil, err
	}

	context, err := newContext(sharedSecret, kemID, kdfID, aeadID, info)
	if err != nil {
		return nil, nil, err
	}

	return encapsulatedKey, &Sender{context}, nil
}

func SetupReceipient(kemID, kdfID, aeadID uint16, priv *ecdh.PrivateKey, info, encPubEph []byte) (*Receipient, error) {
	kem, err := newDHKem(kemID)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := kem.Decap(encPubEph, priv)
	if err != nil {
		return nil, err
	}

	context, err := newContext(sharedSecret, kemID, kdfID, aeadID, info)
	if err != nil {
		return nil, err
	}

	return &Receipient{context}, nil
}

func (ctx *context) nextNonce() []byte {
	nonce := ctx.seqNum.bytes()[16-ctx.aead.NonceSize():]
	for i := range ctx.baseNonce {
		nonce[i] ^= ctx.baseNonce[i]
	}
	return nonce
}

func (ctx *context) incrementNonce() {
	// Message limit is, according to the RFC, 2^95+1, which
	// is somewhat confusing, but we do as we're told.
	if ctx.seqNum.bitLen() >= (ctx.aead.NonceSize()*8)-1 {
		panic("message limit reached")
	}
	ctx.seqNum = ctx.seqNum.addOne()
}

func (s *Sender) Seal(aad, plaintext []byte) ([]byte, error) {
	ciphertext := s.aead.Seal(nil, s.nextNonce(), plaintext, aad)
	s.incrementNonce()
	return ciphertext, nil
}

func (r *Receipient) Open(aad, ciphertext []byte) ([]byte, error) {
	plaintext, err := r.aead.Open(nil, r.nextNonce(), ciphertext, aad)
	if err != nil {
		return nil, err
	}
	r.incrementNonce()
	return plaintext, nil
}

func suiteID(kemID, kdfID, aeadID uint16) []byte {
	suiteID := make([]byte, 0, 4+2+2+2)
	suiteID = append(suiteID, []byte("HPKE")...)
	suiteID = byteorder.BEAppendUint16(suiteID, kemID)
	suiteID = byteorder.BEAppendUint16(suiteID, kdfID)
	suiteID = byteorder.BEAppendUint16(suiteID, aeadID)
	return suiteID
}

func ParseHPKEPublicKey(kemID uint16, bytes []byte) (*ecdh.PublicKey, error) {
	kemInfo, ok := SupportedKEMs[kemID]
	if !ok {
		return nil, errors.New("unsupported KEM id")
	}
	return kemInfo.curve.NewPublicKey(bytes)
}

func ParseHPKEPrivateKey(kemID uint16, bytes []byte) (*ecdh.PrivateKey, error) {
	kemInfo, ok := SupportedKEMs[kemID]
	if !ok {
		return nil, errors.New("unsupported KEM id")
	}
	return kemInfo.curve.NewPrivateKey(bytes)
}

type uint128 struct {
	hi, lo uint64
}

func (u uint128) addOne() uint128 {
	lo, carry := bits.Add64(u.lo, 1, 0)
	return uint128{u.hi + carry, lo}
}

func (u uint128) bitLen() int {
	return bits.Len64(u.hi) + bits.Len64(u.lo)
}

func (u uint128) bytes() []byte {
	b := make([]byte, 16)
	byteorder.BEPutUint64(b[0:], u.hi)
	byteorder.BEPutUint64(b[8:], u.lo)
	return b
}
```