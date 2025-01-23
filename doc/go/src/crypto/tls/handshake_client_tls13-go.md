Response:
The user wants a breakdown of the provided Go code snippet, specifically the `handshake_client_tls13.go` file. I need to identify the functionalities implemented in this code, focusing on TLS 1.3 client-side handshake procedures. I should cover the following aspects:

1. **Core Functionalities:** What are the main steps involved in the TLS 1.3 client handshake as implemented here?
2. **Go Features:**  If the code utilizes specific Go features, I need to provide illustrative examples.
3. **Code Reasoning:** For any non-trivial logic, I should explain the reasoning, providing hypothetical inputs and outputs to demonstrate the flow.
4. **Command-line Arguments:**  If the code directly handles command-line arguments, I need to detail those. (Likely not in this file, but I should check).
5. **Common Mistakes:**  Highlight any potential pitfalls for developers using this code.

**Plan:**

1. **High-level Overview:**  Start by describing the overarching purpose of the code: implementing the TLS 1.3 client handshake.
2. **Function-by-Function Analysis:**  Go through the main functions (`handshake`, `checkServerHelloOrHRR`, `processHelloRetryRequest`, etc.) and describe their role in the handshake process.
3. **Key Data Structures:** Explain the purpose of `clientHandshakeStateTLS13` and its fields.
4. **Go Feature Identification:** Look for specific Go idioms or library usage (e.g., `context`, `crypto` packages, error handling patterns).
5. **Scenario Illustrations:**  For critical steps like HelloRetryRequest processing, provide hypothetical scenarios with simplified input and output.
6. **Command-line Check:** Scan the code for any direct usage of `os.Args` or similar for command-line handling.
7. **Error Prone Areas:** Based on the TLS 1.3 specification and common implementation errors, identify potential misuse scenarios.
这段代码是 Go 语言 `crypto/tls` 包中关于 TLS 1.3 客户端握手过程的实现。它定义了客户端握手状态和执行握手的具体步骤。

**主要功能列举:**

1. **`clientHandshakeStateTLS13` 结构体:**  定义了 TLS 1.3 客户端握手过程中的所有必要状态信息，例如连接对象 (`Conn`)、上下文 (`context.Context`)、客户端和服务器的 Hello 消息、密钥交换参数、会话状态、密钥信息、证书请求、使用的密码套件、握手消息的哈希值等等。

2. **`handshake()` 方法:**  这是客户端执行 TLS 1.3 握手的核心方法。它包含了从发送 ClientHello 到接收 ServerHello、证书、密钥交换信息，最终完成握手的整个流程。具体步骤包括：
    *   检查服务器是否在重新协商中选择了 TLS 1.3。
    *   验证密钥交换参数是否正确。
    *   处理服务器的 HelloRetryRequest (HRR) 消息（如果收到）。
    *   处理服务器的 ServerHello 消息。
    *   建立握手密钥。
    *   读取并处理服务器发送的加密扩展、证书、证书校验消息和 Finished 消息。
    *   发送客户端的证书（如果需要）。
    *   发送客户端的 Finished 消息。
    *   处理新的会话票据 (New Session Ticket)。

3. **`checkServerHelloOrHRR()` 方法:**  用于校验接收到的 ServerHello 或 HelloRetryRequest 消息的合法性，并设置协商好的密码套件。它会检查版本号、会话 ID、压缩方法以及其他扩展是否符合 TLS 1.3 规范。

4. **`sendDummyChangeCipherSpec()` 方法:**  为了兼容一些中间设备对 TLS 的错误实现，发送一个假的 ChangeCipherSpec 记录。这在 TLS 1.3 中并没有实际意义。

5. **`processHelloRetryRequest()` 方法:**  处理服务器发送的 HelloRetryRequest 消息。它会更新握手状态，重新发送修改后的 ClientHello 消息，并等待新的 ServerHello。这个过程可能涉及更新 Cookie、选择新的密钥共享组等。

6. **`processServerHello()` 方法:**  处理接收到的 ServerHello 消息。它会检查服务器是否返回了 HelloRetryRequest 以及其他的字段是否合法，例如 Cookie、选择的密钥共享组、选择的 PSK 身份等。

7. **`establishHandshakeKeys()` 方法:**  基于密钥交换的结果和早期密钥（如果存在），计算握手阶段的加密密钥。

8. **`readServerParameters()` 方法:**  读取并处理服务器发送的 EncryptedExtensions 消息，其中可能包含 ALPN 协议选择、QUIC 传输参数等信息。

9. **`readServerCertificate()` 方法:**  读取并验证服务器发送的证书和证书校验消息。如果启用了基于 PSK 的握手，则跳过此步骤。

10. **`readServerFinished()` 方法:**  读取并验证服务器发送的 Finished 消息，该消息包含了对之前所有握手消息的哈希值的 MAC。

11. **`sendClientCertificate()` 方法:**  根据服务器的 CertificateRequest 消息，获取客户端证书并发送给服务器。

12. **`sendClientFinished()` 方法:**  计算并发送客户端的 Finished 消息。

13. **`handleNewSessionTicket()` 方法:**  处理服务器发送的 New Session Ticket 消息，用于后续的会话恢复。

**功能实现推理及 Go 代码示例:**

这段代码主要实现了 TLS 1.3 客户端的握手流程。其中一个核心功能是处理密钥交换（Key Exchange）。TLS 1.3 主要使用椭圆曲线 Diffie-Hellman (ECDHE) 或混合密钥封装机制 (ML-KEM)。

**示例：处理服务器的密钥共享 (Key Share)**

假设客户端在 ClientHello 中发送了对 `CurveP256` 和 `X25519` 的支持，并且服务器在 ServerHello 中选择了 `X25519`。`processServerHello` 和 `establishHandshakeKeys` 方法会处理这个过程。

```go
// 假设的 clientHandshakeStateTLS13 结构体和相关方法的简化版本

type clientHandshakeStateTLS13 struct {
	c            *Conn
	hello        *clientHelloMsg
	serverHello  *serverHelloMsg
	keyShareKeys *keySharePrivateKeys
	suite         *cipherSuiteTLS13
	transcript    hash.Hash
	// ... 其他字段
}

type keySharePrivateKeys struct {
	curveID CurveID
	ecdhe   crypto.PrivateKey
	// ... 其他密钥
}

func (hs *clientHandshakeStateTLS13) processServerHello() error {
	// ... 省略其他代码

	if hs.serverHello.serverShare.group == 0 {
		// ... 错误处理
	}

	// 检查服务器选择的组是否在客户端支持的列表中
	found := false
	for _, ks := range hs.hello.keyShares {
		if ks.group == hs.serverHello.serverShare.group {
			found = true
			break
		}
	}
	if !found {
		// ... 错误处理
	}

	// ... 省略其他代码
	return nil
}

func (hs *clientHandshakeStateTLS13) establishHandshakeKeys() error {
	c := hs.c

	ecdhePeerData := hs.serverHello.serverShare.data
	peerKey, err := hs.keyShareKeys.ecdhe.Curve().NewPublicKey(ecdhePeerData)
	if err != nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: invalid server key share")
	}
	sharedKey, err := hs.keyShareKeys.ecdhe.ECDH(peerKey)
	if err != nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: invalid server key share")
	}

	// 使用共享密钥计算握手密钥
	handshakeSecret := tls13.NewEarlySecret(hs.suite.hash.New, nil).HandshakeSecret(sharedKey)

	// ... 使用握手密钥设置加密通道
	clientSecret := handshakeSecret.ClientHandshakeTrafficSecret(hs.transcript)
	c.out.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, clientSecret)

	return nil
}

// 假设的输入
// clientHello 包含对 CurveP256 和 X25519 的 keyShare
// serverHello 的 serverShare.group 是 X25519，serverShare.data 是服务器的 X25519 公钥

// 假设的输出
// establishHandshakeKeys 中计算出的 sharedKey 是客户端和服务器 X25519 私钥/公钥协商的结果
// c.out 使用基于 sharedKey 计算出的 clientSecret 设置了握手阶段的加密密钥
```

**命令行参数处理:**

这段代码本身并不直接处理命令行参数。`crypto/tls` 包通常被其他程序作为库使用，调用方会负责处理命令行参数。例如，一个使用 `net/http` 包创建 HTTPS 客户端的程序可能会通过命令行参数配置服务器地址、证书路径等，但这些参数不会直接传递到 `crypto/tls` 的握手代码中。`crypto/tls` 主要依赖于 `Config` 结构体中的配置信息。

**使用者易犯错的点:**

1. **配置不正确的 `Config`:**  `tls.Config` 结构体的配置对于 TLS 连接的建立至关重要。常见的错误包括：
    *   **未设置 `InsecureSkipVerify: true` 在生产环境:** 这会导致客户端不验证服务器证书，存在安全风险。
    *   **未提供合适的 `RootCAs`:** 如果服务器使用了自签名证书或私有 CA 签名的证书，客户端需要配置相应的根证书才能验证成功。
    *   **密码套件选择不当:** 客户端和服务端需要支持至少一个相同的密码套件。如果配置了不兼容的密码套件，握手会失败。
    *   **`ServerName` 配置错误:** 在连接到虚拟主机时，`ServerName` 必须正确设置，以便服务器选择正确的证书。

    **示例:**

    ```go
    package main

    import (
    	"crypto/tls"
    	"fmt"
    	"net/http"
    )

    func main() {
    	// 错误示例：在生产环境中使用 InsecureSkipVerify
    	tr := &http.Transport{
    		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    	}
    	client := &http.Client{Transport: tr}
    	resp, err := client.Get("https://example.com")
    	if err != nil {
    		fmt.Println("Error:", err)
    		return
    	}
    	defer resp.Body.Close()
    	fmt.Println("Status:", resp.Status)

    	// 正确示例：加载系统根证书或自定义根证书
    	// certPool, err := x509.SystemCertPool()
    	// if err != nil {
    	// 	fmt.Println("Error loading system cert pool:", err)
    	// 	return
    	// }
    	// // 如果需要加载自定义证书
    	// caCert, err := os.ReadFile("path/to/ca.crt")
    	// if err != nil {
    	// 	fmt.Println("Error reading CA cert:", err)
    	// 	return
    	// }
    	// certPool.AppendCertsFromPEM(caCert)

    	// tr := &http.Transport{
    	// 	TLSClientConfig: &tls.Config{RootCAs: certPool},
    	// }
    	// client := &http.Client{Transport: tr}
    	// // ... 进行安全的 HTTPS 请求
    }
    ```

2. **错误地处理握手失败:**  在建立 TLS 连接时可能会发生各种错误，例如证书验证失败、协议版本不兼容等。使用者需要正确地检查和处理这些错误，而不是简单地忽略。

    **示例:**

    ```go
    package main

    import (
    	"crypto/tls"
    	"fmt"
    	"net/smtp"
    )

    func main() {
    	// 连接到 SMTP 服务器
    	conn, err := tls.Dial("tcp", "mail.example.com:465", &tls.Config{})
    	if err != nil {
    		fmt.Println("Error dialing:", err)
    		// 错误地处理：直接返回，没有进一步的错误分析
    		return
    	}
    	defer conn.Close()

    	// 更好的处理方式：检查具体的错误类型
    	// if certErr, ok := err.(x509.UnknownAuthorityError); ok {
    	// 	fmt.Println("Certificate error:", certErr)
    	// 	// 提示用户配置正确的根证书
    	// } else {
    	// 	fmt.Println("Other TLS error:", err)
    	// }

    	fmt.Println("TLS connection established.")
    }
    ```

总而言之，这段代码实现了 TLS 1.3 客户端握手的核心逻辑，涉及到消息的发送和接收、密钥协商、身份验证等关键步骤。使用者需要理解 TLS 握手的流程和 `tls.Config` 的配置选项，才能正确地使用 `crypto/tls` 包建立安全的 TLS 连接。

### 提示词
```
这是路径为go/src/crypto/tls/handshake_client_tls13.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/internal/fips140/hkdf"
	"crypto/internal/fips140/mlkem"
	"crypto/internal/fips140/tls13"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"hash"
	"slices"
	"time"
)

type clientHandshakeStateTLS13 struct {
	c            *Conn
	ctx          context.Context
	serverHello  *serverHelloMsg
	hello        *clientHelloMsg
	keyShareKeys *keySharePrivateKeys

	session     *SessionState
	earlySecret *tls13.EarlySecret
	binderKey   []byte

	certReq       *certificateRequestMsgTLS13
	usingPSK      bool
	sentDummyCCS  bool
	suite         *cipherSuiteTLS13
	transcript    hash.Hash
	masterSecret  *tls13.MasterSecret
	trafficSecret []byte // client_application_traffic_secret_0

	echContext *echClientContext
}

// handshake requires hs.c, hs.hello, hs.serverHello, hs.keyShareKeys, and,
// optionally, hs.session, hs.earlySecret and hs.binderKey to be set.
func (hs *clientHandshakeStateTLS13) handshake() error {
	c := hs.c

	// The server must not select TLS 1.3 in a renegotiation. See RFC 8446,
	// sections 4.1.2 and 4.1.3.
	if c.handshakes > 0 {
		c.sendAlert(alertProtocolVersion)
		return errors.New("tls: server selected TLS 1.3 in a renegotiation")
	}

	// Consistency check on the presence of a keyShare and its parameters.
	if hs.keyShareKeys == nil || hs.keyShareKeys.ecdhe == nil || len(hs.hello.keyShares) == 0 {
		return c.sendAlert(alertInternalError)
	}

	if err := hs.checkServerHelloOrHRR(); err != nil {
		return err
	}

	hs.transcript = hs.suite.hash.New()

	if err := transcriptMsg(hs.hello, hs.transcript); err != nil {
		return err
	}

	if hs.echContext != nil {
		hs.echContext.innerTranscript = hs.suite.hash.New()
		if err := transcriptMsg(hs.echContext.innerHello, hs.echContext.innerTranscript); err != nil {
			return err
		}
	}

	if bytes.Equal(hs.serverHello.random, helloRetryRequestRandom) {
		if err := hs.sendDummyChangeCipherSpec(); err != nil {
			return err
		}
		if err := hs.processHelloRetryRequest(); err != nil {
			return err
		}
	}

	var echRetryConfigList []byte
	if hs.echContext != nil {
		confTranscript := cloneHash(hs.echContext.innerTranscript, hs.suite.hash)
		confTranscript.Write(hs.serverHello.original[:30])
		confTranscript.Write(make([]byte, 8))
		confTranscript.Write(hs.serverHello.original[38:])
		acceptConfirmation := tls13.ExpandLabel(hs.suite.hash.New,
			hkdf.Extract(hs.suite.hash.New, hs.echContext.innerHello.random, nil),
			"ech accept confirmation",
			confTranscript.Sum(nil),
			8,
		)
		if subtle.ConstantTimeCompare(acceptConfirmation, hs.serverHello.random[len(hs.serverHello.random)-8:]) == 1 {
			hs.hello = hs.echContext.innerHello
			c.serverName = c.config.ServerName
			hs.transcript = hs.echContext.innerTranscript
			c.echAccepted = true

			if hs.serverHello.encryptedClientHello != nil {
				c.sendAlert(alertUnsupportedExtension)
				return errors.New("tls: unexpected encrypted client hello extension in server hello despite ECH being accepted")
			}

			if hs.hello.serverName == "" && hs.serverHello.serverNameAck {
				c.sendAlert(alertUnsupportedExtension)
				return errors.New("tls: unexpected server_name extension in server hello")
			}
		} else {
			hs.echContext.echRejected = true
			// If the server sent us retry configs, we'll return these to
			// the user so they can update their Config.
			echRetryConfigList = hs.serverHello.encryptedClientHello
		}
	}

	if err := transcriptMsg(hs.serverHello, hs.transcript); err != nil {
		return err
	}

	c.buffering = true
	if err := hs.processServerHello(); err != nil {
		return err
	}
	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return err
	}
	if err := hs.establishHandshakeKeys(); err != nil {
		return err
	}
	if err := hs.readServerParameters(); err != nil {
		return err
	}
	if err := hs.readServerCertificate(); err != nil {
		return err
	}
	if err := hs.readServerFinished(); err != nil {
		return err
	}
	if err := hs.sendClientCertificate(); err != nil {
		return err
	}
	if err := hs.sendClientFinished(); err != nil {
		return err
	}
	if _, err := c.flush(); err != nil {
		return err
	}

	if hs.echContext != nil && hs.echContext.echRejected {
		c.sendAlert(alertECHRequired)
		return &ECHRejectionError{echRetryConfigList}
	}

	c.isHandshakeComplete.Store(true)

	return nil
}

// checkServerHelloOrHRR does validity checks that apply to both ServerHello and
// HelloRetryRequest messages. It sets hs.suite.
func (hs *clientHandshakeStateTLS13) checkServerHelloOrHRR() error {
	c := hs.c

	if hs.serverHello.supportedVersion == 0 {
		c.sendAlert(alertMissingExtension)
		return errors.New("tls: server selected TLS 1.3 using the legacy version field")
	}

	if hs.serverHello.supportedVersion != VersionTLS13 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected an invalid version after a HelloRetryRequest")
	}

	if hs.serverHello.vers != VersionTLS12 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server sent an incorrect legacy version")
	}

	if hs.serverHello.ocspStapling ||
		hs.serverHello.ticketSupported ||
		hs.serverHello.extendedMasterSecret ||
		hs.serverHello.secureRenegotiationSupported ||
		len(hs.serverHello.secureRenegotiation) != 0 ||
		len(hs.serverHello.alpnProtocol) != 0 ||
		len(hs.serverHello.scts) != 0 {
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: server sent a ServerHello extension forbidden in TLS 1.3")
	}

	if !bytes.Equal(hs.hello.sessionId, hs.serverHello.sessionId) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server did not echo the legacy session ID")
	}

	if hs.serverHello.compressionMethod != compressionNone {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected unsupported compression format")
	}

	selectedSuite := mutualCipherSuiteTLS13(hs.hello.cipherSuites, hs.serverHello.cipherSuite)
	if hs.suite != nil && selectedSuite != hs.suite {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server changed cipher suite after a HelloRetryRequest")
	}
	if selectedSuite == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server chose an unconfigured cipher suite")
	}
	hs.suite = selectedSuite
	c.cipherSuite = hs.suite.id

	return nil
}

// sendDummyChangeCipherSpec sends a ChangeCipherSpec record for compatibility
// with middleboxes that didn't implement TLS correctly. See RFC 8446, Appendix D.4.
func (hs *clientHandshakeStateTLS13) sendDummyChangeCipherSpec() error {
	if hs.c.quic != nil {
		return nil
	}
	if hs.sentDummyCCS {
		return nil
	}
	hs.sentDummyCCS = true

	return hs.c.writeChangeCipherRecord()
}

// processHelloRetryRequest handles the HRR in hs.serverHello, modifies and
// resends hs.hello, and reads the new ServerHello into hs.serverHello.
func (hs *clientHandshakeStateTLS13) processHelloRetryRequest() error {
	c := hs.c

	// The first ClientHello gets double-hashed into the transcript upon a
	// HelloRetryRequest. (The idea is that the server might offload transcript
	// storage to the client in the cookie.) See RFC 8446, Section 4.4.1.
	chHash := hs.transcript.Sum(nil)
	hs.transcript.Reset()
	hs.transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
	hs.transcript.Write(chHash)
	if err := transcriptMsg(hs.serverHello, hs.transcript); err != nil {
		return err
	}

	var isInnerHello bool
	hello := hs.hello
	if hs.echContext != nil {
		chHash = hs.echContext.innerTranscript.Sum(nil)
		hs.echContext.innerTranscript.Reset()
		hs.echContext.innerTranscript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
		hs.echContext.innerTranscript.Write(chHash)

		if hs.serverHello.encryptedClientHello != nil {
			if len(hs.serverHello.encryptedClientHello) != 8 {
				hs.c.sendAlert(alertDecodeError)
				return errors.New("tls: malformed encrypted client hello extension")
			}

			confTranscript := cloneHash(hs.echContext.innerTranscript, hs.suite.hash)
			hrrHello := make([]byte, len(hs.serverHello.original))
			copy(hrrHello, hs.serverHello.original)
			hrrHello = bytes.Replace(hrrHello, hs.serverHello.encryptedClientHello, make([]byte, 8), 1)
			confTranscript.Write(hrrHello)
			acceptConfirmation := tls13.ExpandLabel(hs.suite.hash.New,
				hkdf.Extract(hs.suite.hash.New, hs.echContext.innerHello.random, nil),
				"hrr ech accept confirmation",
				confTranscript.Sum(nil),
				8,
			)
			if subtle.ConstantTimeCompare(acceptConfirmation, hs.serverHello.encryptedClientHello) == 1 {
				hello = hs.echContext.innerHello
				c.serverName = c.config.ServerName
				isInnerHello = true
				c.echAccepted = true
			}
		}

		if err := transcriptMsg(hs.serverHello, hs.echContext.innerTranscript); err != nil {
			return err
		}
	} else if hs.serverHello.encryptedClientHello != nil {
		// Unsolicited ECH extension should be rejected
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: unexpected encrypted client hello extension in serverHello")
	}

	// The only HelloRetryRequest extensions we support are key_share and
	// cookie, and clients must abort the handshake if the HRR would not result
	// in any change in the ClientHello.
	if hs.serverHello.selectedGroup == 0 && hs.serverHello.cookie == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server sent an unnecessary HelloRetryRequest message")
	}

	if hs.serverHello.cookie != nil {
		hello.cookie = hs.serverHello.cookie
	}

	if hs.serverHello.serverShare.group != 0 {
		c.sendAlert(alertDecodeError)
		return errors.New("tls: received malformed key_share extension")
	}

	// If the server sent a key_share extension selecting a group, ensure it's
	// a group we advertised but did not send a key share for, and send a key
	// share for it this time.
	if curveID := hs.serverHello.selectedGroup; curveID != 0 {
		if !slices.Contains(hello.supportedCurves, curveID) {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: server selected unsupported group")
		}
		if slices.ContainsFunc(hs.hello.keyShares, func(ks keyShare) bool {
			return ks.group == curveID
		}) {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: server sent an unnecessary HelloRetryRequest key_share")
		}
		// Note: we don't support selecting X25519MLKEM768 in a HRR, because it
		// is currently first in preference order, so if it's enabled we'll
		// always send a key share for it.
		//
		// This will have to change once we support multiple hybrid KEMs.
		if _, ok := curveForCurveID(curveID); !ok {
			c.sendAlert(alertInternalError)
			return errors.New("tls: CurvePreferences includes unsupported curve")
		}
		key, err := generateECDHEKey(c.config.rand(), curveID)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		hs.keyShareKeys = &keySharePrivateKeys{curveID: curveID, ecdhe: key}
		hello.keyShares = []keyShare{{group: curveID, data: key.PublicKey().Bytes()}}
	}

	if len(hello.pskIdentities) > 0 {
		pskSuite := cipherSuiteTLS13ByID(hs.session.cipherSuite)
		if pskSuite == nil {
			return c.sendAlert(alertInternalError)
		}
		if pskSuite.hash == hs.suite.hash {
			// Update binders and obfuscated_ticket_age.
			ticketAge := c.config.time().Sub(time.Unix(int64(hs.session.createdAt), 0))
			hello.pskIdentities[0].obfuscatedTicketAge = uint32(ticketAge/time.Millisecond) + hs.session.ageAdd

			transcript := hs.suite.hash.New()
			transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
			transcript.Write(chHash)
			if err := transcriptMsg(hs.serverHello, transcript); err != nil {
				return err
			}

			if err := computeAndUpdatePSK(hello, hs.binderKey, transcript, hs.suite.finishedHash); err != nil {
				return err
			}
		} else {
			// Server selected a cipher suite incompatible with the PSK.
			hello.pskIdentities = nil
			hello.pskBinders = nil
		}
	}

	if hello.earlyData {
		hello.earlyData = false
		c.quicRejectedEarlyData()
	}

	if isInnerHello {
		// Any extensions which have changed in hello, but are mirrored in the
		// outer hello and compressed, need to be copied to the outer hello, so
		// they can be properly decompressed by the server. For now, the only
		// extension which may have changed is keyShares.
		hs.hello.keyShares = hello.keyShares
		hs.echContext.innerHello = hello
		if err := transcriptMsg(hs.echContext.innerHello, hs.echContext.innerTranscript); err != nil {
			return err
		}

		if err := computeAndUpdateOuterECHExtension(hs.hello, hs.echContext.innerHello, hs.echContext, false); err != nil {
			return err
		}
	} else {
		hs.hello = hello
	}

	if _, err := hs.c.writeHandshakeRecord(hs.hello, hs.transcript); err != nil {
		return err
	}

	// serverHelloMsg is not included in the transcript
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}
	hs.serverHello = serverHello

	if err := hs.checkServerHelloOrHRR(); err != nil {
		return err
	}

	c.didHRR = true
	return nil
}

func (hs *clientHandshakeStateTLS13) processServerHello() error {
	c := hs.c

	if bytes.Equal(hs.serverHello.random, helloRetryRequestRandom) {
		c.sendAlert(alertUnexpectedMessage)
		return errors.New("tls: server sent two HelloRetryRequest messages")
	}

	if len(hs.serverHello.cookie) != 0 {
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: server sent a cookie in a normal ServerHello")
	}

	if hs.serverHello.selectedGroup != 0 {
		c.sendAlert(alertDecodeError)
		return errors.New("tls: malformed key_share extension")
	}

	if hs.serverHello.serverShare.group == 0 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server did not send a key share")
	}
	if !slices.ContainsFunc(hs.hello.keyShares, func(ks keyShare) bool {
		return ks.group == hs.serverHello.serverShare.group
	}) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected unsupported group")
	}

	if !hs.serverHello.selectedIdentityPresent {
		return nil
	}

	if int(hs.serverHello.selectedIdentity) >= len(hs.hello.pskIdentities) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected an invalid PSK")
	}

	if len(hs.hello.pskIdentities) != 1 || hs.session == nil {
		return c.sendAlert(alertInternalError)
	}
	pskSuite := cipherSuiteTLS13ByID(hs.session.cipherSuite)
	if pskSuite == nil {
		return c.sendAlert(alertInternalError)
	}
	if pskSuite.hash != hs.suite.hash {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected an invalid PSK and cipher suite pair")
	}

	hs.usingPSK = true
	c.didResume = true
	c.peerCertificates = hs.session.peerCertificates
	c.activeCertHandles = hs.session.activeCertHandles
	c.verifiedChains = hs.session.verifiedChains
	c.ocspResponse = hs.session.ocspResponse
	c.scts = hs.session.scts
	return nil
}

func (hs *clientHandshakeStateTLS13) establishHandshakeKeys() error {
	c := hs.c

	ecdhePeerData := hs.serverHello.serverShare.data
	if hs.serverHello.serverShare.group == X25519MLKEM768 {
		if len(ecdhePeerData) != mlkem.CiphertextSize768+x25519PublicKeySize {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid server X25519MLKEM768 key share")
		}
		ecdhePeerData = hs.serverHello.serverShare.data[mlkem.CiphertextSize768:]
	}
	peerKey, err := hs.keyShareKeys.ecdhe.Curve().NewPublicKey(ecdhePeerData)
	if err != nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: invalid server key share")
	}
	sharedKey, err := hs.keyShareKeys.ecdhe.ECDH(peerKey)
	if err != nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: invalid server key share")
	}
	if hs.serverHello.serverShare.group == X25519MLKEM768 {
		if hs.keyShareKeys.mlkem == nil {
			return c.sendAlert(alertInternalError)
		}
		ciphertext := hs.serverHello.serverShare.data[:mlkem.CiphertextSize768]
		mlkemShared, err := hs.keyShareKeys.mlkem.Decapsulate(ciphertext)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid X25519MLKEM768 server key share")
		}
		sharedKey = append(mlkemShared, sharedKey...)
	}
	c.curveID = hs.serverHello.serverShare.group

	earlySecret := hs.earlySecret
	if !hs.usingPSK {
		earlySecret = tls13.NewEarlySecret(hs.suite.hash.New, nil)
	}

	handshakeSecret := earlySecret.HandshakeSecret(sharedKey)

	clientSecret := handshakeSecret.ClientHandshakeTrafficSecret(hs.transcript)
	c.out.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, clientSecret)
	serverSecret := handshakeSecret.ServerHandshakeTrafficSecret(hs.transcript)
	c.in.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, serverSecret)

	if c.quic != nil {
		if c.hand.Len() != 0 {
			c.sendAlert(alertUnexpectedMessage)
		}
		c.quicSetWriteSecret(QUICEncryptionLevelHandshake, hs.suite.id, clientSecret)
		c.quicSetReadSecret(QUICEncryptionLevelHandshake, hs.suite.id, serverSecret)
	}

	err = c.config.writeKeyLog(keyLogLabelClientHandshake, hs.hello.random, clientSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerHandshake, hs.hello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	hs.masterSecret = handshakeSecret.MasterSecret()

	return nil
}

func (hs *clientHandshakeStateTLS13) readServerParameters() error {
	c := hs.c

	msg, err := c.readHandshake(hs.transcript)
	if err != nil {
		return err
	}

	encryptedExtensions, ok := msg.(*encryptedExtensionsMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(encryptedExtensions, msg)
	}

	if err := checkALPN(hs.hello.alpnProtocols, encryptedExtensions.alpnProtocol, c.quic != nil); err != nil {
		// RFC 8446 specifies that no_application_protocol is sent by servers, but
		// does not specify how clients handle the selection of an incompatible protocol.
		// RFC 9001 Section 8.1 specifies that QUIC clients send no_application_protocol
		// in this case. Always sending no_application_protocol seems reasonable.
		c.sendAlert(alertNoApplicationProtocol)
		return err
	}
	c.clientProtocol = encryptedExtensions.alpnProtocol

	if c.quic != nil {
		if encryptedExtensions.quicTransportParameters == nil {
			// RFC 9001 Section 8.2.
			c.sendAlert(alertMissingExtension)
			return errors.New("tls: server did not send a quic_transport_parameters extension")
		}
		c.quicSetTransportParameters(encryptedExtensions.quicTransportParameters)
	} else {
		if encryptedExtensions.quicTransportParameters != nil {
			c.sendAlert(alertUnsupportedExtension)
			return errors.New("tls: server sent an unexpected quic_transport_parameters extension")
		}
	}

	if !hs.hello.earlyData && encryptedExtensions.earlyData {
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: server sent an unexpected early_data extension")
	}
	if hs.hello.earlyData && !encryptedExtensions.earlyData {
		c.quicRejectedEarlyData()
	}
	if encryptedExtensions.earlyData {
		if hs.session.cipherSuite != c.cipherSuite {
			c.sendAlert(alertHandshakeFailure)
			return errors.New("tls: server accepted 0-RTT with the wrong cipher suite")
		}
		if hs.session.alpnProtocol != c.clientProtocol {
			c.sendAlert(alertHandshakeFailure)
			return errors.New("tls: server accepted 0-RTT with the wrong ALPN")
		}
	}
	if hs.echContext != nil && !hs.echContext.echRejected && encryptedExtensions.echRetryConfigs != nil {
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: server sent encrypted client hello retry configs after accepting encrypted client hello")
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) readServerCertificate() error {
	c := hs.c

	// Either a PSK or a certificate is always used, but not both.
	// See RFC 8446, Section 4.1.1.
	if hs.usingPSK {
		// Make sure the connection is still being verified whether or not this
		// is a resumption. Resumptions currently don't reverify certificates so
		// they don't call verifyServerCertificate. See Issue 31641.
		if c.config.VerifyConnection != nil {
			if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}
		return nil
	}

	msg, err := c.readHandshake(hs.transcript)
	if err != nil {
		return err
	}

	certReq, ok := msg.(*certificateRequestMsgTLS13)
	if ok {
		hs.certReq = certReq

		msg, err = c.readHandshake(hs.transcript)
		if err != nil {
			return err
		}
	}

	certMsg, ok := msg.(*certificateMsgTLS13)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}
	if len(certMsg.certificate.Certificate) == 0 {
		c.sendAlert(alertDecodeError)
		return errors.New("tls: received empty certificates message")
	}

	c.scts = certMsg.certificate.SignedCertificateTimestamps
	c.ocspResponse = certMsg.certificate.OCSPStaple

	if err := c.verifyServerCertificate(certMsg.certificate.Certificate); err != nil {
		return err
	}

	// certificateVerifyMsg is included in the transcript, but not until
	// after we verify the handshake signature, since the state before
	// this message was sent is used.
	msg, err = c.readHandshake(nil)
	if err != nil {
		return err
	}

	certVerify, ok := msg.(*certificateVerifyMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certVerify, msg)
	}

	// See RFC 8446, Section 4.4.3.
	if !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, supportedSignatureAlgorithms()) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: certificate used with invalid signature algorithm")
	}
	sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}
	if sigType == signaturePKCS1v15 || sigHash == crypto.SHA1 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: certificate used with invalid signature algorithm")
	}
	signed := signedMessage(sigHash, serverSignatureContext, hs.transcript)
	if err := verifyHandshakeSignature(sigType, c.peerCertificates[0].PublicKey,
		sigHash, signed, certVerify.signature); err != nil {
		c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid signature by the server certificate: " + err.Error())
	}

	if err := transcriptMsg(certVerify, hs.transcript); err != nil {
		return err
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) readServerFinished() error {
	c := hs.c

	// finishedMsg is included in the transcript, but not until after we
	// check the client version, since the state before this message was
	// sent is used during verification.
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	finished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(finished, msg)
	}

	expectedMAC := hs.suite.finishedHash(c.in.trafficSecret, hs.transcript)
	if !hmac.Equal(expectedMAC, finished.verifyData) {
		c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid server finished hash")
	}

	if err := transcriptMsg(finished, hs.transcript); err != nil {
		return err
	}

	// Derive secrets that take context through the server Finished.

	hs.trafficSecret = hs.masterSecret.ClientApplicationTrafficSecret(hs.transcript)
	serverSecret := hs.masterSecret.ServerApplicationTrafficSecret(hs.transcript)
	c.in.setTrafficSecret(hs.suite, QUICEncryptionLevelApplication, serverSecret)

	err = c.config.writeKeyLog(keyLogLabelClientTraffic, hs.hello.random, hs.trafficSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerTraffic, hs.hello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	c.ekm = hs.suite.exportKeyingMaterial(hs.masterSecret, hs.transcript)

	return nil
}

func (hs *clientHandshakeStateTLS13) sendClientCertificate() error {
	c := hs.c

	if hs.certReq == nil {
		return nil
	}

	if hs.echContext != nil && hs.echContext.echRejected {
		if _, err := hs.c.writeHandshakeRecord(&certificateMsgTLS13{}, hs.transcript); err != nil {
			return err
		}
		return nil
	}

	cert, err := c.getClientCertificate(&CertificateRequestInfo{
		AcceptableCAs:    hs.certReq.certificateAuthorities,
		SignatureSchemes: hs.certReq.supportedSignatureAlgorithms,
		Version:          c.vers,
		ctx:              hs.ctx,
	})
	if err != nil {
		return err
	}

	certMsg := new(certificateMsgTLS13)

	certMsg.certificate = *cert
	certMsg.scts = hs.certReq.scts && len(cert.SignedCertificateTimestamps) > 0
	certMsg.ocspStapling = hs.certReq.ocspStapling && len(cert.OCSPStaple) > 0

	if _, err := hs.c.writeHandshakeRecord(certMsg, hs.transcript); err != nil {
		return err
	}

	// If we sent an empty certificate message, skip the CertificateVerify.
	if len(cert.Certificate) == 0 {
		return nil
	}

	certVerifyMsg := new(certificateVerifyMsg)
	certVerifyMsg.hasSignatureAlgorithm = true

	certVerifyMsg.signatureAlgorithm, err = selectSignatureScheme(c.vers, cert, hs.certReq.supportedSignatureAlgorithms)
	if err != nil {
		// getClientCertificate returned a certificate incompatible with the
		// CertificateRequestInfo supported signature algorithms.
		c.sendAlert(alertHandshakeFailure)
		return err
	}

	sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerifyMsg.signatureAlgorithm)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}

	signed := signedMessage(sigHash, clientSignatureContext, hs.transcript)
	signOpts := crypto.SignerOpts(sigHash)
	if sigType == signatureRSAPSS {
		signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
	}
	sig, err := cert.PrivateKey.(crypto.Signer).Sign(c.config.rand(), signed, signOpts)
	if err != nil {
		c.sendAlert(alertInternalError)
		return errors.New("tls: failed to sign handshake: " + err.Error())
	}
	certVerifyMsg.signature = sig

	if _, err := hs.c.writeHandshakeRecord(certVerifyMsg, hs.transcript); err != nil {
		return err
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) sendClientFinished() error {
	c := hs.c

	finished := &finishedMsg{
		verifyData: hs.suite.finishedHash(c.out.trafficSecret, hs.transcript),
	}

	if _, err := hs.c.writeHandshakeRecord(finished, hs.transcript); err != nil {
		return err
	}

	c.out.setTrafficSecret(hs.suite, QUICEncryptionLevelApplication, hs.trafficSecret)

	if !c.config.SessionTicketsDisabled && c.config.ClientSessionCache != nil {
		c.resumptionSecret = hs.masterSecret.ResumptionMasterSecret(hs.transcript)
	}

	if c.quic != nil {
		if c.hand.Len() != 0 {
			c.sendAlert(alertUnexpectedMessage)
		}
		c.quicSetWriteSecret(QUICEncryptionLevelApplication, hs.suite.id, hs.trafficSecret)
	}

	return nil
}

func (c *Conn) handleNewSessionTicket(msg *newSessionTicketMsgTLS13) error {
	if !c.isClient {
		c.sendAlert(alertUnexpectedMessage)
		return errors.New("tls: received new session ticket from a client")
	}

	if c.config.SessionTicketsDisabled || c.config.ClientSessionCache == nil {
		return nil
	}

	// See RFC 8446, Section 4.6.1.
	if msg.lifetime == 0 {
		return nil
	}
	lifetime := time.Duration(msg.lifetime) * time.Second
	if lifetime > maxSessionTicketLifetime {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: received a session ticket with invalid lifetime")
	}

	// RFC 9001, Section 4.6.1
	if c.quic != nil && msg.maxEarlyData != 0 && msg.maxEarlyData != 0xffffffff {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: invalid early data for QUIC connection")
	}

	cipherSuite := cipherSuiteTLS13ByID(c.cipherSuite)
	if cipherSuite == nil || c.resumptionSecret == nil {
		return c.sendAlert(alertInternalError)
	}

	psk := tls13.ExpandLabel(cipherSuite.hash.New, c.resumptionSecret, "resumption",
		msg.nonce, cipherSuite.hash.Size())

	session := c.sessionState()
	session.secret = psk
	session.useBy = uint64(c.config.time().Add(lifetime).Unix())
	session.ageAdd = msg.ageAdd
	session.EarlyData = c.quic != nil && msg.maxEarlyData == 0xffffffff // RFC 9001, Section 4.6.1
	session.ticket = msg.label
	if c.quic != nil && c.quic.enableSessionEvents {
		c.quicStoreSession(session)
		return nil
	}
	cs := &ClientSessionState{session: session}
	if cacheKey := c.clientSessionCacheKey(); cacheKey != "" {
		c.config.ClientSessionCache.Put(cacheKey, cs)
	}

	return nil
}
```