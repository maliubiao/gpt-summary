Response:
Let's break down the thought process for answering the request about `key_agreement.go`.

**1. Understanding the Core Request:**

The fundamental goal is to understand the functionality of the provided Go code snippet and explain it clearly in Chinese. The request specifically asks for:

* **Functionality Listing:** What does this code do?
* **Go Feature Implementation:**  What broader Go/TLS concept does it represent? Illustrate with code.
* **Code Reasoning:** If there's logic to explain, do so with example inputs and outputs.
* **Command Line Arguments:**  Are there any relevant command-line flags?
* **Common Mistakes:**  What pitfalls should users avoid?

**2. Initial Code Scan and Keyword Identification:**

First, I scanned the code for key terms and structures. Keywords like `interface`, `struct`, `func`, `crypto`, `tls`, `rsa`, `ecdhe`, and message names like `serverKeyExchangeMsg` and `clientKeyExchangeMsg` stand out. The package name `tls` immediately signals its purpose. The comments, especially the one about TLS 1.0-1.2 key agreement, are crucial.

**3. Identifying the Central Interface:**

The `keyAgreement` interface is the heart of this code. It defines the contract for different key agreement mechanisms. The comments within the interface describe the client and server-side call order, which is essential for understanding the flow.

**4. Analyzing the Concrete Implementations:**

Next, I looked at the structs that implement `keyAgreement`: `rsaKeyAgreement` and `ecdheKeyAgreement`.

* **`rsaKeyAgreement`:** The comments mention "encrypts the pre-master secret to the server's public key." This points to the standard RSA key exchange in TLS. The functions `generateServerKeyExchange` (returns nil, nil, meaning no ServerKeyExchange message) and `processClientKeyExchange` (decrypts the pre-master secret) confirm this. `generateClientKeyExchange` encrypts the pre-master secret.

* **`ecdheKeyAgreement`:** The comments mention "ephemeral EC public/private key pair" and "ECDH." This indicates the Elliptic Curve Diffie-Hellman Ephemeral key exchange. The functions involve generating and processing server and client key exchange messages, including the ephemeral keys and signatures.

**5. Tracing the Key Exchange Flow (Conceptual):**

Based on the interface and implementations, I mentally sketched the client-server interaction for both RSA and ECDHE:

* **RSA:** Client encrypts pre-master secret with server's public key. Server decrypts. No ServerKeyExchange message.
* **ECDHE:** Server generates ephemeral key pair and sends it (signed) in ServerKeyExchange. Client generates its ephemeral key pair, calculates the shared secret using ECDH, and sends its public key in ClientKeyExchange. Both sides calculate the pre-master secret.

**6. Answering the Specific Questions:**

Now, I addressed each part of the request:

* **功能 (Functionality):**  This became a summary of the two key agreement methods.
* **Go 功能实现 (Go Feature Implementation):** The `interface` and struct implementation pattern is a core Go feature for achieving polymorphism. I chose to illustrate this with a simplified example.
* **代码推理 (Code Reasoning):**  I focused on the `processClientKeyExchange` function in `rsaKeyAgreement` because it has a clear decryption logic. I provided example ciphertext and walked through the decryption steps (assuming the private key is available). For `ecdheKeyAgreement`, I pointed to the ECDH calculation.
* **命令行参数 (Command Line Arguments):** I correctly identified that this specific code doesn't directly handle command-line arguments. TLS configuration is typically done through programmatic means.
* **易犯错的点 (Common Mistakes):**  For RSA, I highlighted the importance of the server's certificate containing an RSA key and the client correctly encrypting. For ECDHE, I focused on curve mismatch and signature verification failures.

**7. Writing in Chinese:**

Finally, I translated the explanations into clear and concise Chinese, using appropriate technical terminology.

**Self-Correction/Refinement during the process:**

* Initially, I considered explaining the details of the message structures (e.g., the byte layout). However, I realized that the request focused more on the *overall functionality* and key exchange process rather than low-level message parsing. I decided to keep the explanation at a higher level for better clarity.
* I made sure to emphasize the difference between the client and server roles in each key agreement.
* I double-checked the comments in the code to ensure my understanding was accurate. For example, the comment about constant-time RSA decryption is important.

This iterative process of reading, analyzing, conceptualizing, and explaining, with some refinement along the way, allowed me to construct a comprehensive and accurate answer to the request.
这段代码是 Go 语言 `crypto/tls` 包中负责 TLS 密钥协商（Key Agreement）功能的一部分。它定义了在 TLS 握手过程中，客户端和服务器如何协商生成共享密钥的关键步骤。

**主要功能列举：**

1. **定义密钥协商接口 (`keyAgreement`):**  定义了客户端和服务器在 TLS 1.0 到 1.2 版本中进行密钥协商协议需要实现的方法。
2. **RSA 密钥协商实现 (`rsaKeyAgreement`):**
   -  实现了客户端使用服务器的 RSA 公钥加密预主密钥（pre-master secret）的传统 RSA 密钥协商方法。
   -  `generateServerKeyExchange`:  对于 RSA 密钥协商，服务器不需要发送 `ServerKeyExchange` 消息，所以此方法返回 `nil, nil`。
   -  `processClientKeyExchange`:  服务器端处理客户端发送的 `ClientKeyExchange` 消息，解密其中加密的预主密钥。
   -  `processServerKeyExchange`:  对于 RSA 密钥协商，客户端不应收到 `ServerKeyExchange` 消息，如果收到则返回错误。
   -  `generateClientKeyExchange`: 客户端生成预主密钥，并使用服务器证书中的 RSA 公钥进行加密，构建 `ClientKeyExchange` 消息。
3. **ECDHE 密钥协商实现 (`ecdheKeyAgreement`):**
   - 实现了使用椭圆曲线 Diffie-Hellman 临时模式 (Ephemeral ECDH) 的密钥协商方法。
   -  `generateServerKeyExchange`: 服务器生成临时的 ECDH 公私钥对，并将其公钥以及一个签名包含在 `ServerKeyExchange` 消息中发送给客户端。签名使用服务器的证书私钥进行签名。
   -  `processClientKeyExchange`: 服务器端处理客户端发送的 `ClientKeyExchange` 消息，其中包含客户端的临时 ECDH 公钥。服务器使用自己的临时 ECDH 私钥和客户端的公钥计算出预主密钥。
   -  `processServerKeyExchange`: 客户端处理服务器发送的 `ServerKeyExchange` 消息，验证服务器的签名，并从中提取服务器的临时 ECDH 公钥。客户端生成自己的临时 ECDH 公钥，并使用服务器的公钥计算出预主密钥。
   -  `generateClientKeyExchange`: 客户端将自己的临时 ECDH 公钥包含在 `ClientKeyExchange` 消息中发送给服务器。
4. **辅助函数:**
   - `sha1Hash`: 计算 SHA1 哈希值。
   - `md5SHA1Hash`: 计算 MD5 和 SHA1 哈希值的级联，用于 TLS 1.0 的混合哈希。
   - `hashForServerKeyExchange`:  根据 TLS 版本和签名类型，为 `ServerKeyExchange` 消息计算需要签名的哈希值。
   - 错误变量 `errClientKeyExchange` 和 `errServerKeyExchange` 用于表示无效的消息。

**它是什么 Go 语言功能的实现：**

这段代码主要展示了 Go 语言中 **接口 (interface)** 和 **结构体 (struct)** 的使用来实现多态性。 `keyAgreement` 接口定义了一组方法，而 `rsaKeyAgreement` 和 `ecdheKeyAgreement` 结构体分别实现了这个接口，提供了不同的密钥协商策略。

**Go 代码举例说明 (使用接口):**

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// 假设这是简化版的 keyAgreement 接口
type KeyExchanger interface {
	GenerateClientKeyExchange() ([]byte, error)
	ProcessServerKeyExchange([]byte) error
}

// 假设这是简化版的 rsaKeyAgreement
type RSAKeyExchanger struct {
	serverPublicKey *rsa.PublicKey
}

func (r *RSAKeyExchanger) GenerateClientKeyExchange() ([]byte, error) {
	preMasterSecret := make([]byte, 48)
	rand.Read(preMasterSecret) // 生成预主密钥
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, r.serverPublicKey, preMasterSecret)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func (r *RSAKeyExchanger) ProcessServerKeyExchange(serverKeyExchange []byte) error {
	// RSA 不需要 ServerKeyExchange 消息
	if serverKeyExchange != nil {
		return fmt.Errorf("unexpected ServerKeyExchange for RSA")
	}
	return nil
}

// 假设这是简化版的 ecdheKeyAgreement (仅演示接口使用)
type ECDHEKeyExchanger struct{}

func (e *ECDHEKeyExchanger) GenerateClientKeyExchange() ([]byte, error) {
	return []byte("ECDHE Client Key Exchange Data"), nil
}

func (e *ECDHEKeyExchanger) ProcessServerKeyExchange(serverKeyExchange []byte) error {
	fmt.Println("Processing ECDHE Server Key Exchange:", string(serverKeyExchange))
	return nil
}

func main() {
	// 假设我们有服务器的 RSA 公钥
	serverPubKey := &rsa.PublicKey{ /* ... */ }

	// 可以根据协商的密码套件选择不同的密钥交换器
	var keyExchanger KeyExchanger

	// 假设协商选择了 RSA
	keyExchanger = &RSAKeyExchanger{serverPublicKey: serverPubKey}
	clientKeyExchangeRSA, err := keyExchanger.GenerateClientKeyExchange()
	if err != nil {
		fmt.Println("Error generating RSA ClientKeyExchange:", err)
	} else {
		fmt.Println("RSA ClientKeyExchange:", clientKeyExchangeRSA)
	}
	keyExchanger.ProcessServerKeyExchange(nil) // RSA 没有 ServerKeyExchange

	fmt.Println("---")

	// 假设协商选择了 ECDHE
	keyExchanger = &ECDHEKeyExchanger{}
	serverKeyExchangeData := []byte("ECDHE Server Key Exchange Data")
	keyExchanger.ProcessServerKeyExchange(serverKeyExchangeData)
	clientKeyExchangeECDHE, err := keyExchanger.GenerateClientKeyExchange()
	if err != nil {
		fmt.Println("Error generating ECDHE ClientKeyExchange:", err)
	} else {
		fmt.Println("ECDHE ClientKeyExchange:", clientKeyExchangeECDHE)
	}
}
```

**假设的输入与输出 (代码推理):**

以 `rsaKeyAgreement` 的 `processClientKeyExchange` 方法为例：

**假设输入:**

* `config`:  一个 `*tls.Config` 实例，包含随机数生成器等配置。
* `cert`: 一个 `*tls.Certificate` 实例，其中 `PrivateKey` 字段是服务器的 RSA 私钥。
* `ckx`: 一个 `*tls.clientKeyExchangeMsg` 实例，其 `ciphertext` 字段包含了客户端加密后的预主密钥。例如，`ckx.ciphertext` 的值为 `[]byte{0x00, 0x80, /* 128 字节的加密数据 */}`，其中前两个字节表示加密数据长度为 128。
* `version`: TLS 版本，例如 `tls.VersionTLS12`。

**假设输出:**

* 如果解密成功，返回一个 `[]byte`，包含 48 字节的预主密钥。例如，`[]byte{0x03, 0x03, /* 46 字节的随机数据 */}`，前两个字节通常表示客户端支持的最高 TLS 版本。
* 如果解密失败（例如，`ciphertext` 格式错误或私钥无法解密），返回 `nil` 和一个错误 `error`。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。TLS 的配置通常是通过编程方式进行的，例如在创建 `tls.Config` 结构体时设置各种选项（如证书、密钥、支持的密码套件等）。相关的命令行参数可能在调用此代码的更上层应用中处理，例如 web 服务器配置 TLS 证书和密钥的路径。

**使用者易犯错的点 (以 `ecdheKeyAgreement` 为例):**

1. **服务器证书类型与选择的密码套件不匹配:**  `ecdheKeyAgreement` 可以与 ECDSA 或 RSA 签名的证书一起使用，这取决于所选择的密码套件。如果配置了错误的证书或密码套件，`generateServerKeyExchange` 方法可能会返回错误，例如 "tls: certificate cannot be used with the selected cipher suite"。

   ```go
   // 错误示例：使用 RSA 证书但选择了 ECDHE_ECDSA 密码套件
   config := &tls.Config{
       Certificates: []tls.Certificate{serverCertWithRSA}, // serverCertWithRSA 的签名算法是 RSA
       CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
   }
   ```

2. **客户端和服务端支持的椭圆曲线不一致:**  在 ECDHE 握手过程中，客户端会在 `ClientHello` 消息中发送它支持的椭圆曲线列表。如果服务器不支持客户端提供的任何曲线，`generateServerKeyExchange` 方法会返回 "tls: no supported elliptic curves offered" 的错误。

   ```go
   // 假设客户端只支持 P-256
   clientHello := &clientHelloMsg{
       supportedCurves: []CurveID{CurveP256},
   }

   // 但服务器配置只支持 P-384
   config := &tls.Config{
       CurvePreferences: []tls.CurveID{tls.CurveP384},
   }

   // 这会导致握手失败
   ```

3. **签名验证失败:** 在 `processServerKeyExchange` 方法中，客户端会验证服务器 `ServerKeyExchange` 消息中的签名。如果签名算法不支持、签名数据错误或使用的公钥与证书不匹配，验证会失败，并返回 "tls: invalid signature by the server certificate" 的错误。这通常意味着服务器的配置或证书存在问题。

这段代码是 TLS 协议中至关重要的一部分，它确保了通信双方能够安全地协商出用于加密和解密后续数据的共享密钥。 理解其工作原理对于开发安全的网络应用至关重要。

### 提示词
```
这是路径为go/src/crypto/tls/key_agreement.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/ecdh"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
)

// A keyAgreement implements the client and server side of a TLS 1.0–1.2 key
// agreement protocol by generating and processing key exchange messages.
type keyAgreement interface {
	// On the server side, the first two methods are called in order.

	// In the case that the key agreement protocol doesn't use a
	// ServerKeyExchange message, generateServerKeyExchange can return nil,
	// nil.
	generateServerKeyExchange(*Config, *Certificate, *clientHelloMsg, *serverHelloMsg) (*serverKeyExchangeMsg, error)
	processClientKeyExchange(*Config, *Certificate, *clientKeyExchangeMsg, uint16) ([]byte, error)

	// On the client side, the next two methods are called in order.

	// This method may not be called if the server doesn't send a
	// ServerKeyExchange message.
	processServerKeyExchange(*Config, *clientHelloMsg, *serverHelloMsg, *x509.Certificate, *serverKeyExchangeMsg) error
	generateClientKeyExchange(*Config, *clientHelloMsg, *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error)
}

var errClientKeyExchange = errors.New("tls: invalid ClientKeyExchange message")
var errServerKeyExchange = errors.New("tls: invalid ServerKeyExchange message")

// rsaKeyAgreement implements the standard TLS key agreement where the client
// encrypts the pre-master secret to the server's public key.
type rsaKeyAgreement struct{}

func (ka rsaKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	return nil, nil
}

func (ka rsaKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	if len(ckx.ciphertext) < 2 {
		return nil, errClientKeyExchange
	}
	ciphertextLen := int(ckx.ciphertext[0])<<8 | int(ckx.ciphertext[1])
	if ciphertextLen != len(ckx.ciphertext)-2 {
		return nil, errClientKeyExchange
	}
	ciphertext := ckx.ciphertext[2:]

	priv, ok := cert.PrivateKey.(crypto.Decrypter)
	if !ok {
		return nil, errors.New("tls: certificate private key does not implement crypto.Decrypter")
	}
	// Perform constant time RSA PKCS #1 v1.5 decryption
	preMasterSecret, err := priv.Decrypt(config.rand(), ciphertext, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: 48})
	if err != nil {
		return nil, err
	}
	// We don't check the version number in the premaster secret. For one,
	// by checking it, we would leak information about the validity of the
	// encrypted pre-master secret. Secondly, it provides only a small
	// benefit against a downgrade attack and some implementations send the
	// wrong version anyway. See the discussion at the end of section
	// 7.4.7.1 of RFC 4346.
	return preMasterSecret, nil
}

func (ka rsaKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	return errors.New("tls: unexpected ServerKeyExchange")
}

func (ka rsaKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	preMasterSecret := make([]byte, 48)
	preMasterSecret[0] = byte(clientHello.vers >> 8)
	preMasterSecret[1] = byte(clientHello.vers)
	_, err := io.ReadFull(config.rand(), preMasterSecret[2:])
	if err != nil {
		return nil, nil, err
	}

	rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("tls: server certificate contains incorrect key type for selected ciphersuite")
	}
	encrypted, err := rsa.EncryptPKCS1v15(config.rand(), rsaKey, preMasterSecret)
	if err != nil {
		return nil, nil, err
	}
	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, len(encrypted)+2)
	ckx.ciphertext[0] = byte(len(encrypted) >> 8)
	ckx.ciphertext[1] = byte(len(encrypted))
	copy(ckx.ciphertext[2:], encrypted)
	return preMasterSecret, ckx, nil
}

// sha1Hash calculates a SHA1 hash over the given byte slices.
func sha1Hash(slices [][]byte) []byte {
	hsha1 := sha1.New()
	for _, slice := range slices {
		hsha1.Write(slice)
	}
	return hsha1.Sum(nil)
}

// md5SHA1Hash implements TLS 1.0's hybrid hash function which consists of the
// concatenation of an MD5 and SHA1 hash.
func md5SHA1Hash(slices [][]byte) []byte {
	md5sha1 := make([]byte, md5.Size+sha1.Size)
	hmd5 := md5.New()
	for _, slice := range slices {
		hmd5.Write(slice)
	}
	copy(md5sha1, hmd5.Sum(nil))
	copy(md5sha1[md5.Size:], sha1Hash(slices))
	return md5sha1
}

// hashForServerKeyExchange hashes the given slices and returns their digest
// using the given hash function (for TLS 1.2) or using a default based on
// the sigType (for earlier TLS versions). For Ed25519 signatures, which don't
// do pre-hashing, it returns the concatenation of the slices.
func hashForServerKeyExchange(sigType uint8, hashFunc crypto.Hash, version uint16, slices ...[]byte) []byte {
	if sigType == signatureEd25519 {
		var signed []byte
		for _, slice := range slices {
			signed = append(signed, slice...)
		}
		return signed
	}
	if version >= VersionTLS12 {
		h := hashFunc.New()
		for _, slice := range slices {
			h.Write(slice)
		}
		digest := h.Sum(nil)
		return digest
	}
	if sigType == signatureECDSA {
		return sha1Hash(slices)
	}
	return md5SHA1Hash(slices)
}

// ecdheKeyAgreement implements a TLS key agreement where the server
// generates an ephemeral EC public/private key pair and signs it. The
// pre-master secret is then calculated using ECDH. The signature may
// be ECDSA, Ed25519 or RSA.
type ecdheKeyAgreement struct {
	version uint16
	isRSA   bool
	key     *ecdh.PrivateKey

	// ckx and preMasterSecret are generated in processServerKeyExchange
	// and returned in generateClientKeyExchange.
	ckx             *clientKeyExchangeMsg
	preMasterSecret []byte
}

func (ka *ecdheKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	var curveID CurveID
	for _, c := range clientHello.supportedCurves {
		if config.supportsCurve(ka.version, c) {
			curveID = c
			break
		}
	}

	if curveID == 0 {
		return nil, errors.New("tls: no supported elliptic curves offered")
	}
	if _, ok := curveForCurveID(curveID); !ok {
		return nil, errors.New("tls: CurvePreferences includes unsupported curve")
	}

	key, err := generateECDHEKey(config.rand(), curveID)
	if err != nil {
		return nil, err
	}
	ka.key = key

	// See RFC 4492, Section 5.4.
	ecdhePublic := key.PublicKey().Bytes()
	serverECDHEParams := make([]byte, 1+2+1+len(ecdhePublic))
	serverECDHEParams[0] = 3 // named curve
	serverECDHEParams[1] = byte(curveID >> 8)
	serverECDHEParams[2] = byte(curveID)
	serverECDHEParams[3] = byte(len(ecdhePublic))
	copy(serverECDHEParams[4:], ecdhePublic)

	priv, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("tls: certificate private key of type %T does not implement crypto.Signer", cert.PrivateKey)
	}

	var signatureAlgorithm SignatureScheme
	var sigType uint8
	var sigHash crypto.Hash
	if ka.version >= VersionTLS12 {
		signatureAlgorithm, err = selectSignatureScheme(ka.version, cert, clientHello.supportedSignatureAlgorithms)
		if err != nil {
			return nil, err
		}
		sigType, sigHash, err = typeAndHashFromSignatureScheme(signatureAlgorithm)
		if err != nil {
			return nil, err
		}
	} else {
		sigType, sigHash, err = legacyTypeAndHashFromPublicKey(priv.Public())
		if err != nil {
			return nil, err
		}
	}
	if (sigType == signaturePKCS1v15 || sigType == signatureRSAPSS) != ka.isRSA {
		return nil, errors.New("tls: certificate cannot be used with the selected cipher suite")
	}

	signed := hashForServerKeyExchange(sigType, sigHash, ka.version, clientHello.random, hello.random, serverECDHEParams)

	signOpts := crypto.SignerOpts(sigHash)
	if sigType == signatureRSAPSS {
		signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
	}
	sig, err := priv.Sign(config.rand(), signed, signOpts)
	if err != nil {
		return nil, errors.New("tls: failed to sign ECDHE parameters: " + err.Error())
	}

	skx := new(serverKeyExchangeMsg)
	sigAndHashLen := 0
	if ka.version >= VersionTLS12 {
		sigAndHashLen = 2
	}
	skx.key = make([]byte, len(serverECDHEParams)+sigAndHashLen+2+len(sig))
	copy(skx.key, serverECDHEParams)
	k := skx.key[len(serverECDHEParams):]
	if ka.version >= VersionTLS12 {
		k[0] = byte(signatureAlgorithm >> 8)
		k[1] = byte(signatureAlgorithm)
		k = k[2:]
	}
	k[0] = byte(len(sig) >> 8)
	k[1] = byte(len(sig))
	copy(k[2:], sig)

	return skx, nil
}

func (ka *ecdheKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	if len(ckx.ciphertext) == 0 || int(ckx.ciphertext[0]) != len(ckx.ciphertext)-1 {
		return nil, errClientKeyExchange
	}

	peerKey, err := ka.key.Curve().NewPublicKey(ckx.ciphertext[1:])
	if err != nil {
		return nil, errClientKeyExchange
	}
	preMasterSecret, err := ka.key.ECDH(peerKey)
	if err != nil {
		return nil, errClientKeyExchange
	}

	return preMasterSecret, nil
}

func (ka *ecdheKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	if len(skx.key) < 4 {
		return errServerKeyExchange
	}
	if skx.key[0] != 3 { // named curve
		return errors.New("tls: server selected unsupported curve")
	}
	curveID := CurveID(skx.key[1])<<8 | CurveID(skx.key[2])

	publicLen := int(skx.key[3])
	if publicLen+4 > len(skx.key) {
		return errServerKeyExchange
	}
	serverECDHEParams := skx.key[:4+publicLen]
	publicKey := serverECDHEParams[4:]

	sig := skx.key[4+publicLen:]
	if len(sig) < 2 {
		return errServerKeyExchange
	}

	if _, ok := curveForCurveID(curveID); !ok {
		return errors.New("tls: server selected unsupported curve")
	}

	key, err := generateECDHEKey(config.rand(), curveID)
	if err != nil {
		return err
	}
	ka.key = key

	peerKey, err := key.Curve().NewPublicKey(publicKey)
	if err != nil {
		return errServerKeyExchange
	}
	ka.preMasterSecret, err = key.ECDH(peerKey)
	if err != nil {
		return errServerKeyExchange
	}

	ourPublicKey := key.PublicKey().Bytes()
	ka.ckx = new(clientKeyExchangeMsg)
	ka.ckx.ciphertext = make([]byte, 1+len(ourPublicKey))
	ka.ckx.ciphertext[0] = byte(len(ourPublicKey))
	copy(ka.ckx.ciphertext[1:], ourPublicKey)

	var sigType uint8
	var sigHash crypto.Hash
	if ka.version >= VersionTLS12 {
		signatureAlgorithm := SignatureScheme(sig[0])<<8 | SignatureScheme(sig[1])
		sig = sig[2:]
		if len(sig) < 2 {
			return errServerKeyExchange
		}

		if !isSupportedSignatureAlgorithm(signatureAlgorithm, clientHello.supportedSignatureAlgorithms) {
			return errors.New("tls: certificate used with invalid signature algorithm")
		}
		sigType, sigHash, err = typeAndHashFromSignatureScheme(signatureAlgorithm)
		if err != nil {
			return err
		}
	} else {
		sigType, sigHash, err = legacyTypeAndHashFromPublicKey(cert.PublicKey)
		if err != nil {
			return err
		}
	}
	if (sigType == signaturePKCS1v15 || sigType == signatureRSAPSS) != ka.isRSA {
		return errServerKeyExchange
	}

	sigLen := int(sig[0])<<8 | int(sig[1])
	if sigLen+2 != len(sig) {
		return errServerKeyExchange
	}
	sig = sig[2:]

	signed := hashForServerKeyExchange(sigType, sigHash, ka.version, clientHello.random, serverHello.random, serverECDHEParams)
	if err := verifyHandshakeSignature(sigType, cert.PublicKey, sigHash, signed, sig); err != nil {
		return errors.New("tls: invalid signature by the server certificate: " + err.Error())
	}
	return nil
}

func (ka *ecdheKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.ckx == nil {
		return nil, nil, errors.New("tls: missing ServerKeyExchange message")
	}

	return ka.preMasterSecret, ka.ckx, nil
}
```