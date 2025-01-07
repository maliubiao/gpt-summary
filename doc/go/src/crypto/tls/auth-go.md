Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Read and High-Level Understanding:**

The first step is to read through the code to get a general idea of its purpose. I see keywords like "signature," "verify," "handshake," "TLS," "crypto," and specific algorithm names (ECDSA, RSA, Ed25519). This immediately suggests the code is involved in cryptographic authentication within the TLS protocol, specifically related to verifying digital signatures during the handshake process.

**2. Identifying Key Functions and Their Roles:**

Next, I look for the main functions and try to understand what each one does.

* **`verifyHandshakeSignature`:** This function name is very descriptive. It clearly takes a signature type, public key, hash function, signed data, and signature as input and returns an error. The `switch` statement based on `sigType` indicates it handles different signature algorithms.

* **`signedMessage`:**  This function also seems important for signature generation (or preparation). It takes a hash function, context string, and a hash object representing a transcript. The padding and context suggest it's related to TLS 1.3's specific signature format.

* **`typeAndHashFromSignatureScheme`:** This function maps a `SignatureScheme` enum to the corresponding signature type and cryptographic hash. This is crucial for knowing which algorithm to use.

* **`legacyTypeAndHashFromPublicKey`:** This handles signature types for older TLS versions where signature algorithm negotiation wasn't in place. It infers the algorithm based on the public key type.

* **`signatureSchemesForCertificate`:**  This function determines the possible signature schemes a certificate can support, based on its private key type and the TLS version. The filtering by `SupportedSignatureAlgorithms` on the certificate is also noted.

* **`selectSignatureScheme`:** This is the selection logic. It takes the TLS version, the certificate, and the peer's supported algorithms, and attempts to find a mutually supported signature scheme. The handling of TLS 1.2's implicit SHA1 support is a key detail.

* **`unsupportedCertificateError`:**  This function provides more specific error messages for unsupported certificate/key combinations.

**3. Connecting the Functions and Inferring the Overall Functionality:**

Now, I start to see how the pieces fit together.

* The TLS handshake involves verifying the identities of the client and server.
* This verification often involves digital signatures.
* `verifyHandshakeSignature` is the core function for checking these signatures.
* `signedMessage` prepares the data to be signed.
* `typeAndHashFromSignatureScheme` and `legacyTypeAndHashFromPublicKey` help determine the correct cryptographic algorithms.
* `signatureSchemesForCertificate` and `selectSignatureScheme` are involved in the negotiation and selection of signature algorithms during the handshake.

Therefore, the primary function of this code is to **handle the verification of digital signatures during the TLS handshake, encompassing both modern (TLS 1.2/1.3) and older TLS versions.**  This includes determining the appropriate signature algorithm based on negotiation or public key type.

**4. Thinking About Examples and Test Cases (Mental Simulation):**

To solidify my understanding, I start thinking about how these functions might be used.

* **`verifyHandshakeSignature` Example:**  Imagine the server receives a `CertificateVerify` message from the client. This function would be used to check the signature in that message. I would need the client's public key, the signature algorithm used, the signed data (a hash of the handshake messages), and the signature itself.

* **`signedMessage` Example:** Before the client signs the `CertificateVerify` message, this function would be used to create the data to be signed, incorporating the "TLS 1.3, client CertificateVerify\x00" context.

* **`selectSignatureScheme` Example:** During the handshake, the client and server exchange lists of supported signature algorithms. This function would be used on the server side to pick a scheme that both the server's certificate and the client support.

**5. Considering Edge Cases and Potential Errors:**

I consider common pitfalls or areas where things might go wrong.

* **Mismatched Signature Algorithm:** The client uses one algorithm to sign, but the server expects another. `verifyHandshakeSignature` would return an error.
* **Unsupported Public Key:** The server's certificate uses an algorithm not supported by the client. `selectSignatureScheme` would fail.
* **Incorrectly Formatted Signature:** The signature data is corrupted. `verifyHandshakeSignature` would fail.

**6. Formulating the Answer Structure:**

Finally, I organize my understanding into a clear and structured answer, addressing each part of the prompt:

* **功能列举:** List the core functionalities based on the function analysis.
* **功能实现推理:**  Identify the broader Go language feature this code supports (TLS handshake authentication).
* **Go 代码举例:**  Provide concrete examples using the functions, including hypothetical inputs and outputs to illustrate their usage.
* **命令行参数处理:**  Recognize that this specific code doesn't directly handle command-line arguments, as it's a low-level crypto library component.
* **易犯错的点:**  Highlight the common errors, providing specific examples.

This step-by-step approach, combining code analysis, logical deduction, and mental simulation, helps to thoroughly understand the functionality of the provided Go code snippet and generate a comprehensive and accurate answer.
这段 Go 语言代码是 `crypto/tls` 包中 `auth.go` 文件的一部分，主要负责 **TLS 握手过程中的身份验证和签名验证**。它定义了一些用于验证数字签名的函数，以及用于确定和选择合适的签名算法的逻辑。

以下是代码的主要功能点：

1. **`verifyHandshakeSignature` 函数:**
   - **功能:**  验证针对预哈希（如果需要）的握手内容的签名。
   - **支持的签名类型:**  ECDSA, Ed25519, PKCS1v15 (RSA), RSAPSS。
   - **工作原理:** 根据提供的签名类型 (`sigType`) 和公钥类型，使用相应的 `crypto` 包中的函数（例如 `ecdsa.VerifyASN1`, `ed25519.Verify`, `rsa.VerifyPKCS1v15`, `rsa.VerifyPSS`) 来验证签名 (`sig`) 是否与签名的数据 (`signed`) 相匹配。
   - **输入:**
     - `sigType uint8`:  签名类型，例如 `signatureECDSA`, `signatureEd25519` 等。
     - `pubkey crypto.PublicKey`: 用于验证签名的公钥。
     - `hashFunc crypto.Hash`:  用于 RSA PKCS1v15 和 RSAPSS 签名的哈希函数。
     - `signed []byte`:  被签名的数据的哈希值。
     - `sig []byte`:  接收到的签名。
   - **输出:** `error`: 如果签名验证失败则返回错误，否则返回 `nil`。

2. **`signedMessage` 函数:**
   - **功能:**  为 TLS 1.3 中的证书密钥生成待签名的预哈希消息。
   - **TLS 1.3 特性:**  遵循 RFC 8446 Section 4.4.3 的规定，在签名前添加了固定的 padding 和 context。
   - **工作原理:**
     - 如果 `sigHash` 是 `directSigning`（通常用于 Ed25519），则直接拼接 padding、context 和 transcript 的哈希值。
     - 否则，创建一个新的哈希对象，写入 padding、context 和 transcript 的哈希值，然后返回最终的哈希值。
   - **输入:**
     - `sigHash crypto.Hash`:  用于生成最终哈希的哈希算法。
     - `context string`:  签名上下文，例如 "TLS 1.3, server CertificateVerify\x00" 或 "TLS 1.3, client CertificateVerify\x00"。
     - `transcript hash.Hash`:  握手消息的哈希值。
   - **输出:** `[]byte`:  待签名的数据。

3. **`typeAndHashFromSignatureScheme` 函数:**
   - **功能:**  根据 TLS 的 `SignatureScheme` 返回对应的签名类型 (`sigType`) 和 `crypto.Hash`。
   - **输入:** `signatureAlgorithm SignatureScheme`: TLS 定义的签名算法枚举值，例如 `PKCS1WithSHA256`, `ECDSAWithP256AndSHA256` 等。
   - **输出:**
     - `sigType uint8`:  签名类型。
     - `hash crypto.Hash`:  哈希算法。
     - `error`:  如果不支持该签名算法则返回错误。

4. **`legacyTypeAndHashFromPublicKey` 函数:**
   - **功能:**  为 TLS 1.0 和 1.1 版本，在没有签名算法协商的情况下，根据公钥类型返回固定的签名类型和哈希算法。
   - **输入:** `pub crypto.PublicKey`:  公钥。
   - **输出:**
     - `sigType uint8`:  签名类型。
     - `hash crypto.Hash`:  哈希算法。
     - `error`:  如果不支持该公钥类型则返回错误。

5. **`signatureSchemesForCertificate` 函数:**
   - **功能:**  根据证书的公钥类型和协议版本，返回证书支持的 `SignatureScheme` 列表。
   - **过滤:**  可以根据证书中显式指定的 `SupportedSignatureAlgorithms` 进行过滤。
   - **输入:**
     - `version uint16`:  TLS 协议版本。
     - `cert *Certificate`:  证书对象。
   - **输出:** `[]SignatureScheme`:  证书支持的签名算法列表。

6. **`selectSignatureScheme` 函数:**
   - **功能:**  从对端的偏好列表中选择一个与当前证书兼容的 `SignatureScheme`。
   - **协议版本限制:**  仅用于支持签名算法协商的协议版本，即 TLS 1.2 和 1.3。
   - **TLS 1.2 特殊处理:**  如果客户端没有发送 `signature_algorithms` 扩展，则默认其支持 SHA1。
   - **输入:**
     - `vers uint16`:  TLS 协议版本。
     - `c *Certificate`:  本地证书对象。
     - `peerAlgs []SignatureScheme`:  对端支持的签名算法列表。
   - **输出:**
     - `SignatureScheme`:  选择的签名算法。
     - `error`:  如果找不到双方都支持的签名算法则返回错误。

7. **`unsupportedCertificateError` 函数:**
   - **功能:**  为具有不支持的私钥的证书返回更友好的错误信息。
   - **输入:** `cert *Certificate`:  证书对象。
   - **输出:** `error`:  描述不支持的证书私钥的错误信息。

**推理它是什么 go 语言功能的实现:**

这段代码是 **TLS (Transport Layer Security) 协议中身份验证和完整性校验机制** 的一部分实现。更具体地说，它处理了 TLS 握手过程中 `CertificateVerify` 消息的生成和验证。`CertificateVerify` 消息用于证明客户端或服务器拥有其发送的证书的私钥。

**Go 代码举例说明:**

假设我们正在编写一个 TLS 服务器，并且需要验证客户端发送的 `CertificateVerify` 消息。

```go
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
)

func main() {
	// 假设我们已经有客户端的公钥和接收到的签名以及待签名的数据
	clientPublicKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signedData := []byte("some handshake data to be verified")
	// 模拟客户端使用私钥对 signedData 进行签名
	hashed := sha256.Sum256(signedData)
	sig, _ := ecdsa.SignASN1(rand.Reader, clientPublicKey, hashed[:])

	// 假设签名类型是 ECDSA
	sigType := tls.ECDSAWithP256AndSHA256 // 这里用的是 SignatureScheme，需要转换为内部的 sigType
	internalSigType, hashFunc, err := tls.TypeAndHashFromSignatureScheme(sigType)
	if err != nil {
		fmt.Println("Error getting signature type and hash:", err)
		return
	}

	// 调用 verifyHandshakeSignature 进行验证
	err = tls.VerifyHandshakeSignature(internalSigType, &clientPublicKey.PublicKey, hashFunc, hashed[:], sig)
	if err != nil {
		fmt.Println("Signature verification failed:", err)
	} else {
		fmt.Println("Signature verification successful!")
	}
}
```

**假设的输入与输出:**

在上面的例子中：

- **假设输入:**
  - `clientPublicKey`: 一个有效的 ECDSA 公钥。
  - `signedData`:  表示握手过程中需要验证的数据的字节切片。
  - `sig`: 使用与 `clientPublicKey` 对应的私钥对 `signedData` 的哈希值进行签名的结果。
  - `sigType`: `tls.ECDSAWithP256AndSHA256`，表示使用的签名算法。

- **预期输出:**
  - 如果签名验证成功，程序将打印 "Signature verification successful!"。
  - 如果签名验证失败（例如，使用了错误的公钥或签名数据被篡改），程序将打印 "Signature verification failed: ECDSA verification failure"。

**命令行参数的具体处理:**

这段代码本身 **没有直接处理命令行参数**。它是一个底层的 TLS 库实现，负责签名验证的逻辑。命令行参数的处理通常发生在更上层的应用程序代码中，例如使用 `crypto/tls` 包创建 TLS 服务器或客户端的程序。

**使用者易犯错的点:**

1. **签名类型与公钥类型不匹配:**
   ```go
   // 错误地尝试使用 RSA 公钥验证 ECDSA 签名
   var rsaPublicKey rsa.PublicKey
   err := tls.VerifyHandshakeSignature(tls.SignatureECDSA, &rsaPublicKey, crypto.SHA256, signedData, sig)
   // 错误信息可能是 "expected an ECDSA public key, got *rsa.PublicKey"
   ```
   **解决方法:** 确保 `verifyHandshakeSignature` 函数的 `pubkey` 参数类型与 `sigType` 参数指定的签名算法所需的公钥类型一致。

2. **使用了错误的哈希函数:**
   ```go
   // 使用 SHA1 哈希值尝试验证 SHA256 签名
   hashedSHA1 := sha1.Sum(signedData)
   err := tls.VerifyHandshakeSignature(tls.SignaturePKCS1v15, &rsaPublicKey, crypto.SHA256, hashedSHA1[:], sig)
   // 签名验证会失败，因为哈希值不匹配
   ```
   **解决方法:**  `verifyHandshakeSignature` 函数的 `hashFunc` 参数必须与生成签名时使用的哈希函数一致。

3. **在 TLS 1.3 中未使用正确的 `signedMessage` 生成待签名数据:**
   ```go
   // 在 TLS 1.3 中直接对 transcript 哈希签名，没有添加 padding 和 context
   // 这种方式的签名验证会失败
   ```
   **解决方法:**  在 TLS 1.3 中生成 `CertificateVerify` 消息的签名时，必须使用 `signedMessage` 函数来构造待签名的数据，确保包含正确的 padding 和 context。

总而言之，这段代码是 Go 语言 `crypto/tls` 包中实现安全通信的关键部分，它确保了 TLS 握手过程中的身份验证和数据完整性。理解其功能和使用方式对于构建安全的网络应用程序至关重要。

Prompt: 
```
这是路径为go/src/crypto/tls/auth.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls/internal/fips140tls"
	"errors"
	"fmt"
	"hash"
	"io"
)

// verifyHandshakeSignature verifies a signature against pre-hashed
// (if required) handshake contents.
func verifyHandshakeSignature(sigType uint8, pubkey crypto.PublicKey, hashFunc crypto.Hash, signed, sig []byte) error {
	switch sigType {
	case signatureECDSA:
		pubKey, ok := pubkey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected an ECDSA public key, got %T", pubkey)
		}
		if !ecdsa.VerifyASN1(pubKey, signed, sig) {
			return errors.New("ECDSA verification failure")
		}
	case signatureEd25519:
		pubKey, ok := pubkey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("expected an Ed25519 public key, got %T", pubkey)
		}
		if !ed25519.Verify(pubKey, signed, sig) {
			return errors.New("Ed25519 verification failure")
		}
	case signaturePKCS1v15:
		pubKey, ok := pubkey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected an RSA public key, got %T", pubkey)
		}
		if err := rsa.VerifyPKCS1v15(pubKey, hashFunc, signed, sig); err != nil {
			return err
		}
	case signatureRSAPSS:
		pubKey, ok := pubkey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected an RSA public key, got %T", pubkey)
		}
		signOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
		if err := rsa.VerifyPSS(pubKey, hashFunc, signed, sig, signOpts); err != nil {
			return err
		}
	default:
		return errors.New("internal error: unknown signature type")
	}
	return nil
}

const (
	serverSignatureContext = "TLS 1.3, server CertificateVerify\x00"
	clientSignatureContext = "TLS 1.3, client CertificateVerify\x00"
)

var signaturePadding = []byte{
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
}

// signedMessage returns the pre-hashed (if necessary) message to be signed by
// certificate keys in TLS 1.3. See RFC 8446, Section 4.4.3.
func signedMessage(sigHash crypto.Hash, context string, transcript hash.Hash) []byte {
	if sigHash == directSigning {
		b := &bytes.Buffer{}
		b.Write(signaturePadding)
		io.WriteString(b, context)
		b.Write(transcript.Sum(nil))
		return b.Bytes()
	}
	h := sigHash.New()
	h.Write(signaturePadding)
	io.WriteString(h, context)
	h.Write(transcript.Sum(nil))
	return h.Sum(nil)
}

// typeAndHashFromSignatureScheme returns the corresponding signature type and
// crypto.Hash for a given TLS SignatureScheme.
func typeAndHashFromSignatureScheme(signatureAlgorithm SignatureScheme) (sigType uint8, hash crypto.Hash, err error) {
	switch signatureAlgorithm {
	case PKCS1WithSHA1, PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512:
		sigType = signaturePKCS1v15
	case PSSWithSHA256, PSSWithSHA384, PSSWithSHA512:
		sigType = signatureRSAPSS
	case ECDSAWithSHA1, ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512:
		sigType = signatureECDSA
	case Ed25519:
		sigType = signatureEd25519
	default:
		return 0, 0, fmt.Errorf("unsupported signature algorithm: %v", signatureAlgorithm)
	}
	switch signatureAlgorithm {
	case PKCS1WithSHA1, ECDSAWithSHA1:
		hash = crypto.SHA1
	case PKCS1WithSHA256, PSSWithSHA256, ECDSAWithP256AndSHA256:
		hash = crypto.SHA256
	case PKCS1WithSHA384, PSSWithSHA384, ECDSAWithP384AndSHA384:
		hash = crypto.SHA384
	case PKCS1WithSHA512, PSSWithSHA512, ECDSAWithP521AndSHA512:
		hash = crypto.SHA512
	case Ed25519:
		hash = directSigning
	default:
		return 0, 0, fmt.Errorf("unsupported signature algorithm: %v", signatureAlgorithm)
	}
	return sigType, hash, nil
}

// legacyTypeAndHashFromPublicKey returns the fixed signature type and crypto.Hash for
// a given public key used with TLS 1.0 and 1.1, before the introduction of
// signature algorithm negotiation.
func legacyTypeAndHashFromPublicKey(pub crypto.PublicKey) (sigType uint8, hash crypto.Hash, err error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		return signaturePKCS1v15, crypto.MD5SHA1, nil
	case *ecdsa.PublicKey:
		return signatureECDSA, crypto.SHA1, nil
	case ed25519.PublicKey:
		// RFC 8422 specifies support for Ed25519 in TLS 1.0 and 1.1,
		// but it requires holding on to a handshake transcript to do a
		// full signature, and not even OpenSSL bothers with the
		// complexity, so we can't even test it properly.
		return 0, 0, fmt.Errorf("tls: Ed25519 public keys are not supported before TLS 1.2")
	default:
		return 0, 0, fmt.Errorf("tls: unsupported public key: %T", pub)
	}
}

var rsaSignatureSchemes = []struct {
	scheme          SignatureScheme
	minModulusBytes int
	maxVersion      uint16
}{
	// RSA-PSS is used with PSSSaltLengthEqualsHash, and requires
	//    emLen >= hLen + sLen + 2
	{PSSWithSHA256, crypto.SHA256.Size()*2 + 2, VersionTLS13},
	{PSSWithSHA384, crypto.SHA384.Size()*2 + 2, VersionTLS13},
	{PSSWithSHA512, crypto.SHA512.Size()*2 + 2, VersionTLS13},
	// PKCS #1 v1.5 uses prefixes from hashPrefixes in crypto/rsa, and requires
	//    emLen >= len(prefix) + hLen + 11
	// TLS 1.3 dropped support for PKCS #1 v1.5 in favor of RSA-PSS.
	{PKCS1WithSHA256, 19 + crypto.SHA256.Size() + 11, VersionTLS12},
	{PKCS1WithSHA384, 19 + crypto.SHA384.Size() + 11, VersionTLS12},
	{PKCS1WithSHA512, 19 + crypto.SHA512.Size() + 11, VersionTLS12},
	{PKCS1WithSHA1, 15 + crypto.SHA1.Size() + 11, VersionTLS12},
}

// signatureSchemesForCertificate returns the list of supported SignatureSchemes
// for a given certificate, based on the public key and the protocol version,
// and optionally filtered by its explicit SupportedSignatureAlgorithms.
//
// This function must be kept in sync with supportedSignatureAlgorithms.
// FIPS filtering is applied in the caller, selectSignatureScheme.
func signatureSchemesForCertificate(version uint16, cert *Certificate) []SignatureScheme {
	priv, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil
	}

	var sigAlgs []SignatureScheme
	switch pub := priv.Public().(type) {
	case *ecdsa.PublicKey:
		if version != VersionTLS13 {
			// In TLS 1.2 and earlier, ECDSA algorithms are not
			// constrained to a single curve.
			sigAlgs = []SignatureScheme{
				ECDSAWithP256AndSHA256,
				ECDSAWithP384AndSHA384,
				ECDSAWithP521AndSHA512,
				ECDSAWithSHA1,
			}
			break
		}
		switch pub.Curve {
		case elliptic.P256():
			sigAlgs = []SignatureScheme{ECDSAWithP256AndSHA256}
		case elliptic.P384():
			sigAlgs = []SignatureScheme{ECDSAWithP384AndSHA384}
		case elliptic.P521():
			sigAlgs = []SignatureScheme{ECDSAWithP521AndSHA512}
		default:
			return nil
		}
	case *rsa.PublicKey:
		size := pub.Size()
		sigAlgs = make([]SignatureScheme, 0, len(rsaSignatureSchemes))
		for _, candidate := range rsaSignatureSchemes {
			if size >= candidate.minModulusBytes && version <= candidate.maxVersion {
				sigAlgs = append(sigAlgs, candidate.scheme)
			}
		}
	case ed25519.PublicKey:
		sigAlgs = []SignatureScheme{Ed25519}
	default:
		return nil
	}

	if cert.SupportedSignatureAlgorithms != nil {
		var filteredSigAlgs []SignatureScheme
		for _, sigAlg := range sigAlgs {
			if isSupportedSignatureAlgorithm(sigAlg, cert.SupportedSignatureAlgorithms) {
				filteredSigAlgs = append(filteredSigAlgs, sigAlg)
			}
		}
		return filteredSigAlgs
	}
	return sigAlgs
}

// selectSignatureScheme picks a SignatureScheme from the peer's preference list
// that works with the selected certificate. It's only called for protocol
// versions that support signature algorithms, so TLS 1.2 and 1.3.
func selectSignatureScheme(vers uint16, c *Certificate, peerAlgs []SignatureScheme) (SignatureScheme, error) {
	supportedAlgs := signatureSchemesForCertificate(vers, c)
	if len(supportedAlgs) == 0 {
		return 0, unsupportedCertificateError(c)
	}
	if len(peerAlgs) == 0 && vers == VersionTLS12 {
		// For TLS 1.2, if the client didn't send signature_algorithms then we
		// can assume that it supports SHA1. See RFC 5246, Section 7.4.1.4.1.
		peerAlgs = []SignatureScheme{PKCS1WithSHA1, ECDSAWithSHA1}
	}
	// Pick signature scheme in the peer's preference order, as our
	// preference order is not configurable.
	for _, preferredAlg := range peerAlgs {
		if fips140tls.Required() && !isSupportedSignatureAlgorithm(preferredAlg, defaultSupportedSignatureAlgorithmsFIPS) {
			continue
		}
		if isSupportedSignatureAlgorithm(preferredAlg, supportedAlgs) {
			return preferredAlg, nil
		}
	}
	return 0, errors.New("tls: peer doesn't support any of the certificate's signature algorithms")
}

// unsupportedCertificateError returns a helpful error for certificates with
// an unsupported private key.
func unsupportedCertificateError(cert *Certificate) error {
	switch cert.PrivateKey.(type) {
	case rsa.PrivateKey, ecdsa.PrivateKey:
		return fmt.Errorf("tls: unsupported certificate: private key is %T, expected *%T",
			cert.PrivateKey, cert.PrivateKey)
	case *ed25519.PrivateKey:
		return fmt.Errorf("tls: unsupported certificate: private key is *ed25519.PrivateKey, expected ed25519.PrivateKey")
	}

	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("tls: certificate private key (%T) does not implement crypto.Signer",
			cert.PrivateKey)
	}

	switch pub := signer.Public().(type) {
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
		case elliptic.P384():
		case elliptic.P521():
		default:
			return fmt.Errorf("tls: unsupported certificate curve (%s)", pub.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		return fmt.Errorf("tls: certificate RSA key size too small for supported signature algorithms")
	case ed25519.PublicKey:
	default:
		return fmt.Errorf("tls: unsupported certificate key (%T)", pub)
	}

	if cert.SupportedSignatureAlgorithms != nil {
		return fmt.Errorf("tls: peer doesn't support the certificate custom signature algorithms")
	}

	return fmt.Errorf("tls: internal error: unsupported key (%T)", cert.PrivateKey)
}

"""



```